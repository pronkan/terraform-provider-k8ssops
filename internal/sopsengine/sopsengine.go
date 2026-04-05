package sopsengine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/getsops/sops/v3"
	sopsaes "github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/decrypt"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/kms"
	sopsyaml "github.com/getsops/sops/v3/stores/yaml"
	"gopkg.in/yaml.v3"
)

// KMSConfig holds KMS encryption configuration, supporting multiple cloud providers and key types.
// For local / test usage, populate AgeKeys with a 32-byte hex-encoded symmetric key; the engine
// will use AES-256-GCM encryption without any external KMS call.
type KMSConfig struct {
	AWSKMSARNs      []string
	GCPKMSResources []string
	AzureKVURLs     []string
	// AgeKeys holds 32-byte hex-encoded symmetric keys used for local / offline encryption
	// (no external KMS required). This is also the path exercised by unit tests.
	AgeKeys []string
	PGPKeys []string
	// AwsProfile is the named AWS profile passed to SOPS as SharedConfigProfile.
	// When empty, the AWS SDK default credential chain applies (AWS_PROFILE env var, then "default").
	AwsProfile string
	// AwsAssumeRoleARN is an optional IAM role ARN to assume before calling KMS.
	// Passed as the role parameter to kms.NewMasterKeyWithProfile.
	AwsAssumeRoleARN string
	// AwsAccessKeyID, AwsSecretAccessKey, AwsSessionToken, and AwsRegion are scoped
	// AWS credentials injected only for the duration of a single Encrypt/DecryptState
	// call via withAWSEnv. They never permanently mutate the process environment.
	AwsAccessKeyID     string
	AwsSecretAccessKey string
	AwsSessionToken    string
	AwsRegion          string
}

// awsEnvMu serializes all withAWSEnv calls so that snapshot/restore of AWS
// environment variables is atomic with respect to concurrent goroutines.
var awsEnvMu sync.Mutex

// withAWSEnv snapshots the current AWS environment variables, overlays the
// non-empty values from cfg, executes fn, then restores the originals via
// defer. The mutex guarantees that no two calls interleave their env mutations.
func withAWSEnv(cfg KMSConfig, fn func() error) error {
	awsEnvMu.Lock()
	defer awsEnvMu.Unlock()

	type envPair struct{ key, prev string }
	var restore []envPair
	set := func(key, val string) {
		if val == "" {
			return
		}
		restore = append(restore, envPair{key, os.Getenv(key)})
		os.Setenv(key, val) //nolint:errcheck // only errors on invalid key names
	}
	// AWS_PROFILE must be set so that SOPS's internal decrypt.Data call (which
	// creates its own AWS session via the SDK default chain) uses the same named
	// profile that was used for encryption. Without this, decrypt.Data silently
	// falls back to the "default" profile, which typically lacks KMS decrypt permission.
	// TODO: Need to figure out how to make SOPS use the same profile, region, keys passed for encryption to provider via API or session directly.
	set("AWS_PROFILE", cfg.AwsProfile)
	set("AWS_ACCESS_KEY_ID", cfg.AwsAccessKeyID)
	set("AWS_SECRET_ACCESS_KEY", cfg.AwsSecretAccessKey)
	set("AWS_SESSION_TOKEN", cfg.AwsSessionToken)
	set("AWS_DEFAULT_REGION", cfg.AwsRegion)

	defer func() {
		for _, p := range restore {
			if p.prev == "" {
				os.Unsetenv(p.key) //nolint:errcheck
			} else {
				os.Setenv(p.key, p.prev) //nolint:errcheck
			}
		}
	}()

	return fn()
}

// CalculateHash returns a deterministic SHA-256 hex digest of the combined
// fileData and stringData maps. It sorts map keys alphabetically before hashing
// to prevent non-deterministic Terraform drift due to Go's random map iteration.
//
// Domain separation: fixed sentinel bytes ("file_data:" and "string_data:") are
// written before each section so that moving a key/value pair from fileData to
// stringData (or vice versa) always produces a different digest even when the
// key name and value bytes are identical. Without this separator, such a move
// would produce the same hash and silently suppress re-encryption.
//
// WARNING: Changing this function invalidates all previously computed hashes
// stored in Terraform state. On the next apply each affected resource will
// detect a hash mismatch and trigger re-encryption. This is intentional and
// safe — re-encryption produces an equivalent ciphertext; no secret data is lost.
func CalculateHash(fileData map[string][]byte, stringData map[string]string) string {
	h := sha256.New()

	// Domain separator for the fileData section.
	h.Write([]byte("file_data:")) //nolint:errcheck // sha256.Write never returns an error

	var fileKeys []string
	for k := range fileData {
		fileKeys = append(fileKeys, k)
	}
	sort.Strings(fileKeys)

	for _, k := range fileKeys {
		writeWithLength(h, []byte(k))
		writeWithLength(h, fileData[k])
	}

	// Domain separator for the stringData section.
	h.Write([]byte("string_data:")) //nolint:errcheck

	var stringKeys []string
	for k := range stringData {
		stringKeys = append(stringKeys, k)
	}
	sort.Strings(stringKeys)

	for _, k := range stringKeys {
		writeWithLength(h, []byte(k))
		writeWithLength(h, []byte(stringData[k]))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// writeWithLength writes a 4-byte big-endian length prefix followed by data into w.
func writeWithLength(w io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	w.Write(lenBuf[:]) //nolint:errcheck // sha256.Write never returns an error
	w.Write(data)      //nolint:errcheck
}

// Encrypt encrypts plaintextYaml and returns ciphertext. When KMSConfig.AgeKeys is populated
// with a 32-byte hex-encoded key, AES-256-GCM is used directly — no external KMS call is made.
// This makes the function fully testable offline and in CI without cloud credentials.
// Otherwise, it wires up github.com/getsops/sops/v3 and the KMS package for AWS KMS ARNs.
func Encrypt(plaintextYaml []byte, config KMSConfig) ([]byte, error) {
	if len(config.AgeKeys) > 0 {
		return aesGCMEncrypt(plaintextYaml, config.AgeKeys[0])
	}

	if len(config.AWSKMSARNs) == 0 {
		return nil, errors.New("sopsengine: no supported KMS key configured")
	}

	var result []byte
	err := withAWSEnv(config, func() error {
		store := &sopsyaml.Store{}
		branches, err := store.LoadPlainFile(plaintextYaml)
		if err != nil {
			return fmt.Errorf("sopsengine: failed to load plaintext yaml: %w", err)
		}

		tree := sops.Tree{
			Branches: branches,
			Metadata: sops.Metadata{
				KeyGroups: []sops.KeyGroup{},
				Version:   "3.9.4",
				// Encrypt only the values under `data` and `stringData` keys so that
				// apiVersion, kind, and metadata remain human-readable in GitOps repositories.
				// Any cluster whose KMS key is in the KeyGroup can decrypt the secret.
				EncryptedRegex: `^(data|stringData)$`,
			},
		}

		var group sops.KeyGroup
		for _, arn := range config.AWSKMSARNs {
			k := kms.NewMasterKeyWithProfile(arn, config.AwsAssumeRoleARN, map[string]*string{}, config.AwsProfile)
			group = append(group, k)
		}
		tree.Metadata.KeyGroups = append(tree.Metadata.KeyGroups, group)

		dataKey, errs := tree.GenerateDataKeyWithKeyServices([]keyservice.KeyServiceClient{keyservice.NewLocalClient()})
		if len(errs) > 0 {
			return fmt.Errorf("sopsengine: failed to generate data key: %v", errs)
		}

		unencryptedMAC, encErr := tree.Encrypt(dataKey, sopsaes.NewCipher())
		if encErr != nil {
			return fmt.Errorf("sopsengine: failed to encrypt tree: %w", encErr)
		}
		tree.Metadata.LastModified = time.Now().UTC()
		tree.Metadata.MessageAuthenticationCode, err = sopsaes.NewCipher().Encrypt(
			unencryptedMAC, dataKey, tree.Metadata.LastModified.Format(time.RFC3339),
		)
		if err != nil {
			return fmt.Errorf("sopsengine: failed to encrypt MAC: %w", err)
		}

		// Clear AwsProfile from each KMS master key before serialization.
		// The profile is a local authentication artifact used only during
		// GenerateDataKeyWithKeyServices; embedding it in the output YAML
		// couples the encrypted file to a specific AWS CLI profile name and
		// leaks environment configuration into the GitOps repository.
		for _, grp := range tree.Metadata.KeyGroups {
			for _, key := range grp {
				if k, ok := key.(*kms.MasterKey); ok {
					k.AwsProfile = ""
				}
			}
		}

		raw, emitErr := store.EmitEncryptedFile(tree)
		if emitErr != nil {
			return fmt.Errorf("sopsengine: failed to emit encrypted file: %w", emitErr)
		}
		result, err = pruneEmptySOPSLists(raw)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// DecryptState decrypts ciphertext produced by Encrypt. When KMSConfig.AgeKeys is populated,
// AES-256-GCM is used directly. Otherwise, delegates to SOPS standard Decrypt flow logic.
//
// Unlike Encrypt, DecryptState does NOT require AWSKMSARNs: the KMS key ARN(s) are embedded
// in the ciphertext's SOPS metadata, so SOPS resolves them from the file. What IS required
// are the AWS credentials (profile, region, assume_role, …) so the SDK can authenticate to
// KMS — these are injected per-call via withAWSEnv from the provider or resource config.
func DecryptState(ciphertext []byte, config KMSConfig) ([]byte, error) {
	if len(config.AgeKeys) > 0 {
		return aesGCMDecrypt(ciphertext, config.AgeKeys[0])
	}

	var cleartext []byte
	err := withAWSEnv(config, func() error {
		var decErr error
		cleartext, decErr = decrypt.Data(ciphertext, "yaml")
		if decErr != nil {
			return fmt.Errorf("sopsengine: failed to decrypt using sops: %w", decErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cleartext, nil
}

// --- AES-256-GCM helpers (offline / test path) ---

// aesGCMEncrypt encrypts plaintext with the hex-encoded 32-byte key using AES-256-GCM.
func aesGCMEncrypt(plaintext []byte, hexKey string) ([]byte, error) {
	key, err := decodeKey(hexKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: creating GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("sopsengine: generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// Base64 encode to ensure UTF-8 compatibility for Terraform state when mocking offline encryption.
	// Production SOPS encrypts to valid YAML (text), so this is only necessary for the mock.
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(encoded, ciphertext)
	return encoded, nil
}

func aesGCMDecrypt(encodedCiphertext []byte, hexKey string) ([]byte, error) {
	// Base64 decode to undo the encoding done by aesGCMEncrypt mock.
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(encodedCiphertext)))
	n, err := base64.StdEncoding.Decode(ciphertext, encodedCiphertext)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: base64 decoding failed: %w", err)
	}
	ciphertext = ciphertext[:n]

	key, err := decodeKey(hexKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: creating GCM: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("sopsengine: ciphertext too short")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: AES-GCM decryption failed: %w", err)
	}
	return plaintext, nil
}

// decodeKey decodes a 32-byte AES-256 key from its hex string representation.
func decodeKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("sopsengine: invalid hex key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("sopsengine: AES-256 key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}

// pruneEmptySOPSLists removes empty sequence nodes (e.g. gcp_kms: [], age: []) from
// the top-level `sops` mapping in the emitted YAML. It uses gopkg.in/yaml.v3 — the
// same library SOPS uses internally — so all scalar values (including the encrypted MAC
// ENC[AES256_GCM,...] string) are preserved byte-for-byte without any JSON round-trip.
// Only empty YAML sequences inside the sops block are dropped; all other nodes are untouched.
func pruneEmptySOPSLists(yamlBytes []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(yamlBytes, &doc); err != nil || len(doc.Content) == 0 {
		return yamlBytes, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return yamlBytes, nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "sops" {
			sopsNode := root.Content[i+1]
			if sopsNode.Kind != yaml.MappingNode {
				break
			}
			filtered := make([]*yaml.Node, 0, len(sopsNode.Content))
			for j := 0; j+1 < len(sopsNode.Content); j += 2 {
				val := sopsNode.Content[j+1]
				if val.Kind == yaml.SequenceNode && len(val.Content) == 0 {
					continue
				}
				filtered = append(filtered, sopsNode.Content[j], val)
			}
			sopsNode.Content = filtered
			break
		}
	}
	return yaml.Marshal(&doc)
}
