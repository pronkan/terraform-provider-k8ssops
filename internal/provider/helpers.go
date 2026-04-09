package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/pronkan/terraform-provider-k8ssops/internal/k8sgen"
	"github.com/pronkan/terraform-provider-k8ssops/internal/sopsengine"
)

// validatePath ensures raw resolves to a path within the current working directory.
// It rejects paths that escape the working directory (do not share the cwd prefix)
// and paths containing ".." as an explicit defence-in-depth check.
//
// After resolving the absolute path with filepath.Abs, validatePath additionally
// calls filepath.EvalSymlinks when the path already exists on disk. This prevents
// a symlink inside the working directory from pointing to an arbitrary location
// outside it (e.g. ln -s /etc/shadow ./file.yaml). If the path does not yet exist
// (e.g. an output file that will be created later), EvalSymlinks is skipped.
func validatePath(raw string) error {
	if strings.Contains(raw, "..") {
		return fmt.Errorf("path %q is not allowed: contains \"..\"", raw)
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return fmt.Errorf("path %q could not be resolved: %w", raw, err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("could not determine working directory: %w", err)
	}

	// Attempt symlink resolution only when the path exists. For paths that do not
	// yet exist (output files being created on first apply), skip EvalSymlinks —
	// the lexical prefix check above is sufficient for non-existent paths.
	if _, statErr := os.Lstat(abs); statErr == nil {
		resolved, evalErr := filepath.EvalSymlinks(abs)
		if evalErr == nil {
			// Re-check the real on-disk path (symlinks fully resolved) against cwd.
			abs = resolved
		}
		// If EvalSymlinks itself fails (e.g. a dangling symlink), fall through to
		// the lexical check which will still catch obvious escapes.
	}

	prefix := cwd + string(os.PathSeparator)
	if abs != cwd && !strings.HasPrefix(abs, prefix) {
		return fmt.Errorf("path %q escapes the working directory", raw)
	}
	return nil
}

// applyProviderDefaults merges provider-level KMS defaults into cfg for any platform
// whose lists are still empty. It is called by both resolveKMS and resolveKMSFromLists
// to avoid duplicating this logic.
//
// forDecrypt must be true when building a KMSConfig for DecryptState. SOPS reads the
// KMS key ARN(s) directly from the ciphertext metadata — injecting provider-level ARNs
// during decryption is unnecessary and misleads operators into believing the provider's
// kms_arns must match the encrypted file. Credentials (profile, region, assume_role, …)
// are always applied regardless of direction.
func applyProviderDefaults(ctx context.Context, cfg *sopsengine.KMSConfig, providerData any, forDecrypt bool) diag.Diagnostics {
	var diags diag.Diagnostics
	p, ok := providerData.(K8ssopsProviderModel)
	if !ok {
		return diags
	}

	if p.AWS != nil {
		// Inject provider-level KMS ARNs only for encryption. Decryption resolves
		// the ARN from the ciphertext's embedded SOPS metadata, so pre-supplying
		// ARNs from the provider block would reference the wrong key for files
		// encrypted by a different provider alias or account.
		if !forDecrypt && len(cfg.AWSKMSARNs) == 0 {
			diags = append(diags, copyStringList(ctx, &cfg.AWSKMSARNs, p.AWS.KMSArns)...)
		}
		// Credential fields use empty-string guards so that resource- or
		// data-source-level values always take precedence over provider defaults,
		// consistent with the access-key / secret-key / session-token / region fields.
		if cfg.AwsProfile == "" && !p.AWS.Profile.IsNull() && !p.AWS.Profile.IsUnknown() {
			cfg.AwsProfile = p.AWS.Profile.ValueString()
		}
		if cfg.AwsAssumeRoleARN == "" && !p.AWS.AssumeRole.IsNull() && !p.AWS.AssumeRole.IsUnknown() {
			cfg.AwsAssumeRoleARN = p.AWS.AssumeRole.ValueString()
		}
		// Scoped credentials: only populated when the HCL block explicitly provides them.
		// withAWSEnv in sopsengine will inject these into the env for the duration of
		// each Encrypt/DecryptState call only — never globally.
		if cfg.AwsAccessKeyID == "" {
			cfg.AwsAccessKeyID = p.AWS.AccessKeyID.ValueString()
		}
		if cfg.AwsSecretAccessKey == "" {
			cfg.AwsSecretAccessKey = p.AWS.SecretAccessKey.ValueString()
		}
		if cfg.AwsSessionToken == "" {
			cfg.AwsSessionToken = p.AWS.SessionToken.ValueString()
		}
		if cfg.AwsRegion == "" {
			cfg.AwsRegion = p.AWS.Region.ValueString()
		}
	}
	if p.GCP != nil && len(cfg.GCPKMSResources) == 0 {
		diags = append(diags, copyStringList(ctx, &cfg.GCPKMSResources, p.GCP.KMSResources)...)
	}
	if p.Azure != nil && len(cfg.AzureKVURLs) == 0 {
		diags = append(diags, copyStringList(ctx, &cfg.AzureKVURLs, p.Azure.KVUrls)...)
	}
	if p.PGP != nil && len(cfg.PGPKeys) == 0 {
		diags = append(diags, copyStringList(ctx, &cfg.PGPKeys, p.PGP.Keys)...)
	}
	if p.Age != nil && len(cfg.AgeKeys) == 0 {
		diags = append(diags, copyStringList(ctx, &cfg.AgeKeys, p.Age.Keys)...)
	}
	return diags
}

// resolveKMS converts the Terraform state representations into a sopsengine.KMSConfig
// and propagates all diagnostics from list-conversion failures to the caller.
// The ctx parameter is the framework handler context and must not be replaced with
// context.Background() — it carries cancellation signals for any blocking operations.
func resolveKMS(ctx context.Context, providerData any, plan K8sSopsSecretResourceModel) (sopsengine.KMSConfig, diag.Diagnostics) {
	var diags diag.Diagnostics
	cfg := sopsengine.KMSConfig{}

	// Extract resource-level keys and propagate any type-conversion diagnostics so
	// that list parse failures surface as actionable Terraform errors rather than
	// silent empty-field fallbacks that produce an opaque "no supported KMS key" error.
	diags.Append(copyStringList(ctx, &cfg.AWSKMSARNs, plan.AwsKmsArns)...)
	diags.Append(copyStringList(ctx, &cfg.GCPKMSResources, plan.GcpKmsResources)...)
	diags.Append(copyStringList(ctx, &cfg.AzureKVURLs, plan.AzureKvUrls)...)
	diags.Append(copyStringList(ctx, &cfg.AgeKeys, plan.AgeKeys)...)
	diags.Append(copyStringList(ctx, &cfg.PGPKeys, plan.PgpKeys)...)

	// Fallback to provider defaults (encrypt path — ARNs may be injected).
	diags.Append(applyProviderDefaults(ctx, &cfg, providerData, false)...)
	return cfg, diags
}

// resolveKMSFromLists builds a sopsengine.KMSConfig for the decryption path from
// raw types.List values, then merges provider-level credential defaults. ARNs are
// NOT injected from the provider block because SOPS reads them from the ciphertext.
// Diagnostics are propagated to the caller so type-conversion errors surface
// as actionable Terraform errors rather than silent failures.
func resolveKMSFromLists(
	ctx context.Context,
	providerData any,
	awsKmsArns, gcpKmsResources, azureKvUrls, ageKeys, pgpKeys types.List,
	diags *diag.Diagnostics,
) sopsengine.KMSConfig {
	cfg := sopsengine.KMSConfig{}

	diags.Append(copyStringList(ctx, &cfg.AWSKMSARNs, awsKmsArns)...)
	diags.Append(copyStringList(ctx, &cfg.GCPKMSResources, gcpKmsResources)...)
	diags.Append(copyStringList(ctx, &cfg.AzureKVURLs, azureKvUrls)...)
	diags.Append(copyStringList(ctx, &cfg.AgeKeys, ageKeys)...)
	diags.Append(copyStringList(ctx, &cfg.PGPKeys, pgpKeys)...)

	// forDecrypt=true: provider-level KMS ARNs are NOT injected; only credentials are.
	diags.Append(applyProviderDefaults(ctx, &cfg, providerData, true)...)
	return cfg
}

// coalesceStringEnv returns val if it is non-null, non-unknown, and non-empty.
// Otherwise it returns the first non-empty value found among the provided env var names.
// HCL values therefore always take precedence over environment variables.
func coalesceStringEnv(val types.String, envKeys ...string) types.String {
	if !val.IsNull() && !val.IsUnknown() && val.ValueString() != "" {
		return val
	}
	for _, key := range envKeys {
		if v := os.Getenv(key); v != "" {
			return types.StringValue(v)
		}
	}
	return val
}

// copyStringList copies a types.List of strings into dest, returning any diagnostics
// from ElementsAs. Callers in Terraform framework handlers should append the returned
// diagnostics to resp.Diagnostics. A no-op when src is null or unknown.
func copyStringList(ctx context.Context, dest *[]string, src types.List) diag.Diagnostics {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var elements []string
	diags := src.ElementsAs(ctx, &elements, false)
	if !diags.HasError() {
		*dest = elements
	}
	return diags
}

// checkFilesExist verifies if all paths specified in the file_data map actually exist on disk.
// Returns true if the map is empty or all files exist. Returns false if any file is missing.
func checkFilesExist(ctx context.Context, fileData types.Map) bool {
	if fileData.IsNull() || fileData.IsUnknown() {
		return true
	}

	elements := make(map[string]string)
	fileData.ElementsAs(ctx, &elements, false) //nolint:errcheck // boolean return; caller checks existence, not element parse failure
	for _, p := range elements {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// readFiles reads all files in fileData map and returns a map of their contents.
// Each path is validated against the working directory before reading.
// Callers should ensure checkFilesExist() returns true before calling this to avoid errors.
func readFiles(ctx context.Context, fileData types.Map) (map[string][]byte, error) {
	result := make(map[string][]byte)
	if fileData.IsNull() || fileData.IsUnknown() {
		return result, nil
	}

	elements := make(map[string]string)
	fileData.ElementsAs(ctx, &elements, false) //nolint:errcheck // parse errors surfaced below via ReadFile

	for key, p := range elements {
		if err := validatePath(p); err != nil {
			return nil, fmt.Errorf("readFiles: invalid path: %w", err)
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("readFiles: reading %q: %w", p, err)
		}
		result[key] = content
	}

	return result, nil
}

func mapTypesToStringMap(t types.Map) map[string]string {
	result := make(map[string]string)
	if t.IsNull() || t.IsUnknown() {
		return result
	}
	t.ElementsAs(context.Background(), &result, false)
	return result
}

// mapsEqual returns true if two types.Map (of strings) are logically equivalent.
func mapsEqual(a, b types.Map) bool {
	if a.IsNull() && b.IsNull() {
		return true
	}
	if a.IsNull() || b.IsNull() {
		// one is null, the other is not. If the other is empty, they are effectively equal.
		mA := mapTypesToStringMap(a)
		mB := mapTypesToStringMap(b)
		return len(mA) == 0 && len(mB) == 0
	}

	mA := mapTypesToStringMap(a)
	mB := mapTypesToStringMap(b)
	if len(mA) != len(mB) {
		return false
	}
	for k, va := range mA {
		if vb, ok := mB[k]; !ok || va != vb {
			return false
		}
	}
	return true
}

// arnRedactRe matches AWS ARNs of the form arn:aws:<service>:<region>:<account>:<resource>.
// Capture groups: 1=service, 2=region, 3=account, 4=resource.
var arnRedactRe = regexp.MustCompile(`arn:aws:(\S+?):([^:]*):([^:]*):(\S+)`)

// redactARNs replaces sensitive components of AWS ARNs in s with redacted placeholders.
// For each ARN found:
//   - Region (group 2) is replaced with "***"
//   - Account ID (group 3) is replaced with "***"
//   - The resource identifier (group 4) retains only its last 4 characters, with the
//     rest replaced by "****". This keeps the service name and resource type visible
//     so operators can identify which key or role is involved without exposing full IDs.
//
// Example:
//
//	arn:aws:kms:us-west-2:482079862777:key/7613e3a4-7391-45bd-a189-18889afb11f9
//	→ arn:aws:kms:***:***:key/****11f9
func redactARNs(s string) string {
	return arnRedactRe.ReplaceAllStringFunc(s, func(match string) string {
		parts := arnRedactRe.FindStringSubmatch(match)
		if len(parts) != 5 {
			return match
		}
		service := parts[1]
		resource := parts[4]

		// Keep the last 4 chars of the resource component (after the final '/' if present).
		suffix := resource
		if idx := strings.LastIndex(resource, "/"); idx >= 0 {
			// Preserve the resource type prefix (e.g. "key/" or "role/") and redact the ID.
			resourceType := resource[:idx+1]
			resourceID := resource[idx+1:]
			if len(resourceID) > 4 {
				resourceID = "****" + resourceID[len(resourceID)-4:]
			}
			suffix = resourceType + resourceID
		} else {
			if len(suffix) > 4 {
				suffix = "****" + suffix[len(suffix)-4:]
			}
		}

		return "arn:aws:" + service + ":***:***:" + suffix
	})
}

// loadAndDecrypt resolves ciphertext from path or encrypted_yaml, builds a KMS
// config from the provided list fields, and decrypts the SOPS manifest. On any
// failure it appends a diagnostic to diags and returns nil. Callers must treat
// a nil return as a stop signal. ctx is propagated to KMS config resolution so
// cancellation is respected by any blocking operations in that path.
func loadAndDecrypt(
	ctx context.Context,
	providerData any,
	path, encryptedYAML types.String,
	awsKmsArns, gcpKmsResources, azureKvUrls, ageKeys, pgpKeys types.List,
	diags *diag.Diagnostics,
) []byte {
	ciphertext, err := resolveCiphertext(path, encryptedYAML)
	if err != nil {
		if isPathMutualExclusionError(err) {
			diags.AddError("Invalid Configuration", err.Error())
		} else {
			diags.AddError("File Read Error", "could not read the encrypted YAML file; verify the path exists and is readable")
		}
		return nil
	}

	kmsConfig := resolveKMSFromLists(ctx, providerData, awsKmsArns, gcpKmsResources, azureKvUrls, ageKeys, pgpKeys, diags)
	if diags.HasError() {
		return nil
	}

	plaintext, err := sopsengine.DecryptState(ciphertext, kmsConfig)
	if err != nil {
		// Redact full ARNs from the error message before surfacing it to the user.
		// SOPS error messages can contain KMS key ARNs and IAM role ARNs with
		// account IDs and region suffixes. We preserve the service name and resource
		// type (e.g. "key/" or "role/") plus the last 4 chars of the ID so operators
		// can identify which resource is involved without exposing account numbers.
		diags.AddError("Decryption Failed",
			fmt.Sprintf("SOPS decryption failed: %s\n\nVerify that the AWS profile, region, and assume_role in the provider configuration have kms:Decrypt permission for the key embedded in the encrypted file.", redactARNs(err.Error())))
		return nil
	}

	return plaintext
}

func getExtractSecretRaw(plaintextYaml []byte) (types.Map, error) {
	rawMap, err := k8sgen.ExtractSecretRaw(plaintextYaml)
	if err != nil {
		return types.MapNull(types.StringType), err
	}

	m := make(map[string]attr.Value)
	for k, v := range rawMap {
		m[k] = types.StringValue(v)
	}

	mapVal, diags := types.MapValue(types.StringType, m)
	if diags.HasError() {
		return types.MapNull(types.StringType), fmt.Errorf("failed to build map value")
	}
	return mapVal, nil
}
