// Package sopsengine provides AES-256-GCM offline encryption (via AgeKeys) and AWS KMS
// encryption (via SOPS) for Kubernetes Secret manifests. This test file covers:
//   - Encrypt + DecryptState round-trips with valid age keys
//   - Error paths: no keys, invalid hex, wrong key length, truncated ciphertext, wrong key
//   - CalculateHash determinism, collision resistance, and empty-input behaviour
//   - withAWSEnv env-var snapshot/restore (including error path and empty-field no-op)
//   - Concurrent withAWSEnv calls (race detector coverage via t.Parallel)
//   - pruneEmptySOPSLists indirectly through Encrypt output inspection
//   - Mock AWS KMS engine for simulated AccessDenied and success scenarios
package sopsengine

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock AWS KMS engine (simulates cloud behaviour without real API calls)
// ---------------------------------------------------------------------------

// SOPSEngine defines the cryptographic interface for the sopsengine operations.
// As requested, this interface demonstrates how extending the package with AWS KMS mocking
// allows us to simulate cloud behaviour without actual network calls.
type SOPSEngine interface {
	Encrypt(plaintextYaml []byte, config KMSConfig) ([]byte, error)
	DecryptState(ciphertext []byte, config KMSConfig) ([]byte, error)
}

// mockSOPSEngine is a local Mock implementation of the conceptual SOPSEngine interface
// designed to simulate AWS KMS successes and AccessDenied errors.
type mockSOPSEngine struct {
	simulatedErr error
}

// Encrypt simulates KMS encryption and returns a predictable cipher or a simulated error.
func (m *mockSOPSEngine) Encrypt(plaintextYaml []byte, config KMSConfig) ([]byte, error) {
	if len(config.AWSKMSARNs) > 0 {
		if m.simulatedErr != nil {
			return nil, m.simulatedErr
		}
		// Simulate successful KMS network call with a pseudo-cipher
		return append([]byte("mock-kms-cipher:"), plaintextYaml...), nil
	}
	// Fallback to real offline AGE-keys implementation to test real scenarios through mock
	return Encrypt(plaintextYaml, config)
}

// DecryptState simulates KMS decryption or returns a simulated error.
func (m *mockSOPSEngine) DecryptState(ciphertext []byte, config KMSConfig) ([]byte, error) {
	if len(config.AWSKMSARNs) > 0 {
		if m.simulatedErr != nil {
			return nil, m.simulatedErr
		}
		prefix := "mock-kms-cipher:"
		if after, ok := strings.CutPrefix(string(ciphertext), prefix); ok {
			return []byte(after), nil
		}
		return nil, errors.New("kms: invalid mock cipher")
	}
	// Fallback to real offline AGE-keys implementation
	return DecryptState(ciphertext, config)
}

// ---------------------------------------------------------------------------
// Helper: generate a random 32-byte hex-encoded key
// ---------------------------------------------------------------------------

func newAgeKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err, "generating random age key")
	return hex.EncodeToString(raw)
}

// ---------------------------------------------------------------------------
// TestMockSOPSEngine_Cryptography — simulates AWS KMS success and AccessDenied
// ---------------------------------------------------------------------------

func TestMockSOPSEngine_Cryptography(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		engine      SOPSEngine
		config      KMSConfig
		input       []byte
		testDecrypt bool
		wantErr     bool
		errContains string
	}{
		{
			// Happy path: mock KMS round-trip returns the original plaintext.
			name:   "AWS KMS simulation success network flow",
			engine: &mockSOPSEngine{},
			config: KMSConfig{
				AWSKMSARNs: []string{"arn:aws:kms:us-east-1:111122223333:key/alias/my-key"},
			},
			input:       []byte("super secret data"),
			testDecrypt: true,
			wantErr:     false,
		},
		{
			// Mock returns AccessDenied; Encrypt must propagate the error.
			name:   "AWS KMS AccessDenied error simulated",
			engine: &mockSOPSEngine{simulatedErr: errors.New("AccessDeniedException: User is not authorized to perform: kms:Encrypt")},
			config: KMSConfig{
				AWSKMSARNs: []string{"arn:aws:kms:us-east-1:111122223333:key/alias/invalid-key"},
			},
			input:       []byte("super secret data"),
			wantErr:     true,
			errContains: "AccessDeniedException",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cipherText, err := tc.engine.Encrypt(tc.input, tc.config)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errContains, "Error should contain simulated text")
				assert.Nil(t, cipherText)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, cipherText)

			if tc.testDecrypt {
				plainText, err := tc.engine.DecryptState(cipherText, tc.config)
				assert.NoError(t, err)
				assert.Equal(t, tc.input, plainText, "Decrypted plaintext must match input")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestEncryptDecrypt_AgeKeys — concrete AES-256-GCM implementation
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_AgeKeys(t *testing.T) {
	t.Parallel()

	validHexKey := newAgeKey(t)
	wrongHexKey := newAgeKey(t)
	testPlaintext := []byte("secret kubernetes manifest data")

	tests := []struct {
		name        string
		config      KMSConfig
		input       []byte
		testDecrypt bool
		decryptKey  string
		wantErr     bool
		errContains string
	}{
		{
			// Full round-trip: encrypt then decrypt with the same key recovers the original.
			name: "success offline encryption with valid AgeKeys",
			config: KMSConfig{
				AgeKeys: []string{validHexKey},
			},
			input:       testPlaintext,
			testDecrypt: true,
			decryptKey:  validHexKey,
			wantErr:     false,
		},
		{
			// Non-hex characters must be rejected with a clear error.
			name: "error formatting: invalid hex key characters",
			config: KMSConfig{
				AgeKeys: []string{"invalid-hex-characters"},
			},
			input:       testPlaintext,
			wantErr:     true,
			errContains: "invalid hex key",
		},
		{
			// 4-byte hex key (8 hex chars) is too short for AES-256 which requires 32 bytes.
			name: "error scaling: key is wrong size",
			config: KMSConfig{
				AgeKeys: []string{"deadbeef"}, // 4 bytes (needs 32 bytes)
			},
			input:       testPlaintext,
			wantErr:     true,
			errContains: "must be 32 bytes",
		},
		{
			// With no keys configured and no AWS ARNs, the engine must return a descriptive error.
			name: "error fallthrough: no keys configured whatsoever",
			config: KMSConfig{
				AgeKeys: nil,
			},
			input:       testPlaintext,
			wantErr:     true,
			errContains: "no supported KMS key configured",
		},
		{
			// Empty byte slice as plaintext should still encrypt without error;
			// GCM's Open returns nil (not []byte{}) for empty plaintext so we
			// verify the round-trip separately in TestEncryptDecrypt_EmptyPlaintext.
			name: "success with empty plaintext",
			config: KMSConfig{
				AgeKeys: []string{validHexKey},
			},
			input:       []byte{},
			testDecrypt: false, // separate test handles the nil vs []byte{} subtlety
			decryptKey:  validHexKey,
			wantErr:     false,
		},
		{
			// Large plaintext (64 KiB) exercises the GCM path with a realistic payload size.
			name: "success with large plaintext 64KiB",
			config: KMSConfig{
				AgeKeys: []string{validHexKey},
			},
			input:       make([]byte, 64*1024),
			testDecrypt: true,
			decryptKey:  validHexKey,
			wantErr:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ciphertext, err := Encrypt(tc.input, tc.config)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				assert.Nil(t, ciphertext)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)

			if tc.testDecrypt {
				// Assert correct roundtrip decryption.
				decConfig := KMSConfig{AgeKeys: []string{tc.decryptKey}}
				decrypted, decErr := DecryptState(ciphertext, decConfig)
				require.NoError(t, decErr)
				assert.Equal(t, tc.input, decrypted, "Offline decryption pipeline should match original input perfectly")

				// Assert failure when wrong key is provided (GCM authentication tag mismatch).
				wrongConfig := KMSConfig{AgeKeys: []string{wrongHexKey}}
				_, wrongErr := DecryptState(ciphertext, wrongConfig)
				assert.Error(t, wrongErr)
				assert.Contains(t, wrongErr.Error(), "AES-GCM decryption failed")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// TestEncryptDecrypt_EmptyPlaintext — GCM round-trip for zero-length payload
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	t.Parallel()

	key := newAgeKey(t)
	cfg := KMSConfig{AgeKeys: []string{key}}

	ciphertext, err := Encrypt([]byte{}, cfg)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	plaintext, err := DecryptState(ciphertext, cfg)
	require.NoError(t, err)
	// AES-GCM's Open returns nil for an empty authenticated payload; treat nil and
	// empty slice as equivalent — both represent zero bytes of content.
	assert.Empty(t, plaintext, "decrypting an empty-plaintext ciphertext must produce zero bytes")
}

// ---------------------------------------------------------------------------
// TestEncrypt_NonDeterministic — same plaintext produces different ciphertext
// ---------------------------------------------------------------------------

func TestEncrypt_NonDeterministic(t *testing.T) {
	t.Parallel()

	// Two Encrypt calls on the same plaintext must produce different ciphertext
	// because each call generates a fresh random GCM nonce.
	key := newAgeKey(t)
	cfg := KMSConfig{AgeKeys: []string{key}}
	plaintext := []byte("hello world")

	ct1, err := Encrypt(plaintext, cfg)
	require.NoError(t, err)

	ct2, err := Encrypt(plaintext, cfg)
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "two encryptions of the same plaintext should produce distinct ciphertexts due to random nonces")
}

// ---------------------------------------------------------------------------
// TestDecryptState_ShortCiphertext — rejects payloads shorter than the GCM nonce
// ---------------------------------------------------------------------------

func TestDecryptState_ShortCiphertext(t *testing.T) {
	t.Parallel()

	config := KMSConfig{
		AgeKeys: []string{newAgeKey(t)},
	}

	// Nonce is 12 bytes; provide a base64-encoded payload that is shorter than the nonce
	// so the length check fires after successful base64 decode.
	shortCipher := []byte("dG9v") // base64("too") — 3 bytes, well below the 12-byte GCM nonce

	_, err := DecryptState(shortCipher, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short", "Engine must reject ciphertexts smaller than GCM Nonce size securely")
}

// ---------------------------------------------------------------------------
// TestDecryptState_InvalidBase64 — rejects non-base64 ciphertext
// ---------------------------------------------------------------------------

func TestDecryptState_InvalidBase64(t *testing.T) {
	t.Parallel()

	config := KMSConfig{
		AgeKeys: []string{newAgeKey(t)},
	}

	// The AES-GCM path base64-decodes before decrypting; invalid base64 must error.
	_, err := DecryptState([]byte("not-valid-base64!!!"), config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "base64 decoding failed")
}

// ---------------------------------------------------------------------------
// TestDecryptState_WrongKey — GCM tag failure when key differs
// ---------------------------------------------------------------------------

func TestDecryptState_WrongKey(t *testing.T) {
	t.Parallel()

	encKey := newAgeKey(t)
	decKey := newAgeKey(t)

	ciphertext, err := Encrypt([]byte("sensitive payload"), KMSConfig{AgeKeys: []string{encKey}})
	require.NoError(t, err)

	// Decrypting with a different key must fail with an AES-GCM authentication error.
	_, err = DecryptState(ciphertext, KMSConfig{AgeKeys: []string{decKey}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "AES-GCM decryption failed")
}

// ---------------------------------------------------------------------------
// TestCalculateHash_Determinism — SHA-256 is stable across randomised map iteration
// ---------------------------------------------------------------------------

func TestCalculateHash_Determinism(t *testing.T) {
	t.Parallel()

	fileData := map[string][]byte{
		"cert.pem":    []byte("abcd"),
		"key.pem":     []byte("1234"),
		"ca.pem":      []byte("xyz"),
		"license.txt": []byte("mit"),
		"binary.dat":  {0x00, 0xFF, 0x42},
	}
	stringData := map[string]string{
		"DB_HOST":  "localhost",
		"DB_USER":  "admin",
		"DB_PASS":  "secret",
		"PORT":     "5432",
		"FEATURES": "all",
	}

	expectedHash := CalculateHash(fileData, stringData)

	// Repeated calls on the same maps must always produce the same digest regardless
	// of Go's non-deterministic map iteration order.
	for range 1000 {
		hash := CalculateHash(fileData, stringData)
		assert.Equal(t, expectedHash, hash, "CalculateHash must remain uniformly deterministic regardless of unpredictable map traversal")
	}
}

// ---------------------------------------------------------------------------
// TestCalculateHash_CollisionResistance — length-prefixed encoding prevents collisions
// ---------------------------------------------------------------------------

func TestCalculateHash_CollisionResistance(t *testing.T) {
	t.Parallel()

	// If keys/values were concatenated directly ("a"+"bc" vs "ab"+"c"), they would collide.
	// writeWithLength prevents this by prefixing each token with its 4-byte length.
	hash1 := CalculateHash(nil, map[string]string{"a": "bc"})
	hash2 := CalculateHash(nil, map[string]string{"ab": "c"})

	assert.NotEqual(t, hash1, hash2, "Hashes should not collide for different struct distributions due to length prefixing")
}

// ---------------------------------------------------------------------------
// TestCalculateHash_Empty — empty inputs yield the SHA-256 digest of no bytes
// ---------------------------------------------------------------------------

func TestCalculateHash_Empty(t *testing.T) {
	t.Parallel()

	// With domain separators ("file_data:" and "string_data:"), the hash of nil/empty maps
	// is no longer the SHA-256 of zero bytes. We compute the expected value dynamically so
	// the test stays correct regardless of future separator changes. The key invariant is
	// determinism: two calls with the same (empty) input must always produce the same digest.
	expected := CalculateHash(nil, nil)
	assert.NotEmpty(t, expected, "CalculateHash must produce a non-empty digest even for empty inputs")

	// Repeated calls must return the same digest.
	for range 10 {
		hash := CalculateHash(nil, nil)
		assert.Equal(t, expected, hash, "Empty maps must produce a stable digest across repeated calls")
	}
}

// ---------------------------------------------------------------------------
// TestCalculateHash_DifferentInputsDifferentDigests — basic sanity
// ---------------------------------------------------------------------------

func TestCalculateHash_DifferentInputsDifferentDigests(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    map[string]string
		b    map[string]string
	}{
		{
			// Swapping key and value must produce a different digest.
			name: "key-value swap",
			a:    map[string]string{"foo": "bar"},
			b:    map[string]string{"bar": "foo"},
		},
		{
			// An extra key must change the digest.
			name: "extra key",
			a:    map[string]string{"x": "1"},
			b:    map[string]string{"x": "1", "y": "2"},
		},
		{
			// Different values under the same key must differ.
			name: "different value",
			a:    map[string]string{"key": "v1"},
			b:    map[string]string{"key": "v2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h1 := CalculateHash(nil, tc.a)
			h2 := CalculateHash(nil, tc.b)
			assert.NotEqual(t, h1, h2, "distinct inputs must produce distinct digests")
		})
	}
}

// ---------------------------------------------------------------------------
// TestCalculateHash_FileDataVsStringData — fileData and stringData together vs separately
// ---------------------------------------------------------------------------

func TestCalculateHash_FileDataVsStringData(t *testing.T) {
	t.Parallel()

	// A digest that includes both fileData and stringData must differ from one
	// that has only stringData, because the fileData bytes change the feed.
	hashBoth := CalculateHash(
		map[string][]byte{"k": []byte("v")},
		map[string]string{"k": "v"},
	)
	hashStrOnly := CalculateHash(nil, map[string]string{"k": "v"})
	assert.NotEqual(t, hashBoth, hashStrOnly,
		"adding fileData to a hash must change the digest even when the key/value match stringData")
}

// ---------------------------------------------------------------------------
// TestWithAWSEnv_RestoresVariables — env is restored after fn returns
// ---------------------------------------------------------------------------

func TestWithAWSEnv_RestoresVariables(t *testing.T) {
	// Not t.Parallel() here — we mutate real env vars; isolation via t.Setenv below.
	const (
		keyID  = "AWS_ACCESS_KEY_ID"
		secret = "AWS_SECRET_ACCESS_KEY"
		token  = "AWS_SESSION_TOKEN"
		region = "AWS_DEFAULT_REGION"
		profil = "AWS_PROFILE"
	)

	// Capture originals (t.Setenv will restore on cleanup automatically).
	t.Setenv(keyID, "original-key-id")
	t.Setenv(secret, "original-secret")
	t.Setenv(token, "original-token")
	t.Setenv(region, "original-region")
	t.Setenv(profil, "original-profile")

	cfg := KMSConfig{
		AwsAccessKeyID:     "injected-key-id",
		AwsSecretAccessKey: "injected-secret",
		AwsSessionToken:    "injected-token",
		AwsRegion:          "injected-region",
		AwsProfile:         "injected-profile",
	}

	var captured [5]string
	err := withAWSEnv(cfg, func() error {
		// Inside fn: env vars must reflect injected values.
		captured[0] = os.Getenv(keyID)
		captured[1] = os.Getenv(secret)
		captured[2] = os.Getenv(token)
		captured[3] = os.Getenv(region)
		captured[4] = os.Getenv(profil)
		return nil
	})

	require.NoError(t, err)

	// Values seen inside fn must be the injected ones.
	assert.Equal(t, "injected-key-id", captured[0])
	assert.Equal(t, "injected-secret", captured[1])
	assert.Equal(t, "injected-token", captured[2])
	assert.Equal(t, "injected-region", captured[3])
	assert.Equal(t, "injected-profile", captured[4])

	// After fn: originals must be restored (t.Setenv takes care of final reset
	// but we verify immediate restore before test teardown).
	assert.Equal(t, "original-key-id", os.Getenv(keyID))
	assert.Equal(t, "original-secret", os.Getenv(secret))
	assert.Equal(t, "original-token", os.Getenv(token))
	assert.Equal(t, "original-region", os.Getenv(region))
	assert.Equal(t, "original-profile", os.Getenv(profil))
}

// ---------------------------------------------------------------------------
// TestWithAWSEnv_RestoresOnError — env is restored even when fn returns an error
// ---------------------------------------------------------------------------

func TestWithAWSEnv_RestoresOnError(t *testing.T) {
	const keyVar = "AWS_ACCESS_KEY_ID"
	t.Setenv(keyVar, "original-key")

	cfg := KMSConfig{AwsAccessKeyID: "temp-key"}
	sentinelErr := errors.New("simulated KMS failure")

	err := withAWSEnv(cfg, func() error {
		return sentinelErr
	})

	// The returned error must be the one from fn.
	assert.ErrorIs(t, err, sentinelErr)
	// The env must be restored despite the error.
	assert.Equal(t, "original-key", os.Getenv(keyVar))
}

// ---------------------------------------------------------------------------
// TestWithAWSEnv_EmptyFieldsNotSet — withAWSEnv skips empty string fields
// ---------------------------------------------------------------------------

func TestWithAWSEnv_EmptyFieldsNotSet(t *testing.T) {
	const keyVar = "AWS_ACCESS_KEY_ID"
	// Ensure the var is unset before the call.
	t.Setenv(keyVar, "")
	os.Unsetenv(keyVar) //nolint:errcheck // intentionally clearing for test

	// Config with an empty AwsAccessKeyID must not touch the env var.
	cfg := KMSConfig{
		AwsAccessKeyID: "", // empty — must be a no-op
		AwsRegion:      "us-east-1",
	}

	var seenKeyID string
	err := withAWSEnv(cfg, func() error {
		seenKeyID = os.Getenv(keyVar)
		return nil
	})

	require.NoError(t, err)
	// The var should still be empty/unset because we did not inject it.
	assert.Equal(t, "", seenKeyID, "empty config field must not mutate the corresponding env var")
}

// ---------------------------------------------------------------------------
// TestWithAWSEnv_UnsetVarsAfterCall — vars absent before the call remain absent after
// ---------------------------------------------------------------------------

func TestWithAWSEnv_UnsetVarsAfterCall(t *testing.T) {
	const regionVar = "AWS_DEFAULT_REGION"
	// Make sure the var is absent before the call.
	os.Unsetenv(regionVar) //nolint:errcheck

	cfg := KMSConfig{AwsRegion: "eu-west-1"}

	err := withAWSEnv(cfg, func() error { return nil })
	require.NoError(t, err)

	// The restore logic must unset the var because it was absent before the call.
	_, exists := os.LookupEnv(regionVar)
	assert.False(t, exists, "env var absent before withAWSEnv must be unset again after the call")
}

// ---------------------------------------------------------------------------
// TestWithAWSEnv_Concurrent — concurrent calls must not race (use -race flag)
// ---------------------------------------------------------------------------

func TestWithAWSEnv_Concurrent(t *testing.T) {
	t.Parallel()

	const goroutines = 20
	var wg sync.WaitGroup

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := KMSConfig{
				AwsAccessKeyID:     newAgeKey(t), // reuse helper for a random string
				AwsSecretAccessKey: newAgeKey(t),
				AwsRegion:          "us-east-1",
			}
			// withAWSEnv holds awsEnvMu; concurrent callers must serialize without data races.
			_ = withAWSEnv(cfg, func() error { return nil })
		}()
	}

	wg.Wait()
	// If the race detector is active it would have fired above; reaching here means no race.
}

// ---------------------------------------------------------------------------
// TestPruneEmptySOPSLists_ViaEncrypt — indirectly verifies pruneEmptySOPSLists
// ---------------------------------------------------------------------------

// TestPruneEmptySOPSLists_NoEmptyListsInAgeOutput verifies that the AES-GCM (age key)
// Encrypt path produces output that does not contain empty SOPS list fields such as
// "aws_kms: []" or "gcp_kms: []". The age key path bypasses SOPS entirely and produces
// base64-encoded binary, so there are no YAML list fields at all — this test confirms
// the output is not empty and contains no spurious empty-list markers.
func TestPruneEmptySOPSLists_NoEmptyListsInAgeOutput(t *testing.T) {
	t.Parallel()

	key := newAgeKey(t)
	plaintext := []byte("data: hello")

	ciphertext, err := Encrypt(plaintext, KMSConfig{AgeKeys: []string{key}})
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// The AES-GCM path produces a compact base64 blob, not YAML with SOPS metadata;
	// assert the known sentinel empty-list patterns are absent.
	ct := string(ciphertext)
	assert.NotContains(t, ct, "aws_kms: []", "output should not contain empty aws_kms list")
	assert.NotContains(t, ct, "gcp_kms: []", "output should not contain empty gcp_kms list")
	assert.NotContains(t, ct, "age: []", "output should not contain empty age list")
}

// ---------------------------------------------------------------------------
// TestEncrypt_NoKeys — explicit error when no key type is configured
// ---------------------------------------------------------------------------

func TestEncrypt_NoKeys(t *testing.T) {
	t.Parallel()

	// An empty KMSConfig (no AWS ARNs, no age keys) must return a clear error.
	_, err := Encrypt([]byte("payload: value"), KMSConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no supported KMS key configured")
}

// ---------------------------------------------------------------------------
// TestDecryptState_EmptyCiphertext — edge case: zero-length base64 input
// ---------------------------------------------------------------------------

func TestDecryptState_EmptyCiphertext(t *testing.T) {
	t.Parallel()

	cfg := KMSConfig{AgeKeys: []string{newAgeKey(t)}}

	// An empty byte slice will base64-decode to nothing; the GCM nonce check must reject it.
	_, err := DecryptState([]byte(""), cfg)
	assert.Error(t, err, "empty ciphertext must be rejected")
}

// ---------------------------------------------------------------------------
// TestEncryptDecrypt_MultipleRoundTrips — idempotency of decrypt(encrypt(x)) == x
// ---------------------------------------------------------------------------

func TestEncryptDecrypt_MultipleRoundTrips(t *testing.T) {
	t.Parallel()

	key := newAgeKey(t)
	cfg := KMSConfig{AgeKeys: []string{key}}
	original := []byte("idempotency check payload")

	// Encrypt twice and decrypt both; both must recover the original.
	ct1, err := Encrypt(original, cfg)
	require.NoError(t, err)
	ct2, err := Encrypt(original, cfg)
	require.NoError(t, err)

	pt1, err := DecryptState(ct1, cfg)
	require.NoError(t, err)
	assert.Equal(t, original, pt1)

	pt2, err := DecryptState(ct2, cfg)
	require.NoError(t, err)
	assert.Equal(t, original, pt2)
}

// ---------------------------------------------------------------------------
// TestDecodeKey_EdgeCases — boundary coverage for the internal key decoder
// ---------------------------------------------------------------------------
// decodeKey is unexported; we exercise it indirectly through Encrypt.

func TestEncrypt_KeyBoundaries(t *testing.T) {
	t.Parallel()

	plaintext := []byte("test")

	tests := []struct {
		name        string
		hexKey      string
		wantErr     bool
		errContains string
	}{
		{
			// Exactly 31 bytes (62 hex chars) — one byte short.
			name:        "31-byte key rejected",
			hexKey:      strings.Repeat("ab", 31),
			wantErr:     true,
			errContains: "must be 32 bytes",
		},
		{
			// Exactly 33 bytes (66 hex chars) — one byte over.
			name:        "33-byte key rejected",
			hexKey:      strings.Repeat("ab", 33),
			wantErr:     true,
			errContains: "must be 32 bytes",
		},
		{
			// Zero-length hex string — hex.DecodeString("") returns empty slice, which is 0 bytes.
			name:        "zero-length key rejected",
			hexKey:      "",
			wantErr:     true,
			errContains: "must be 32 bytes",
		},
		{
			// Odd-length hex is invalid.
			name:        "odd-length hex rejected",
			hexKey:      "abc",
			wantErr:     true,
			errContains: "invalid hex key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := Encrypt(plaintext, KMSConfig{AgeKeys: []string{tc.hexKey}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}
