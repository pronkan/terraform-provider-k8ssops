// Package k8sgen generates and parses well-formed Kubernetes Secret manifests.
// This test file covers:
//   - BuildManifest: happy paths (all fields, minimal, binary data, stringData, mixed),
//     error paths (empty name/namespace, invalid keys, bad regex, insecure regex safety gate),
//     and the log warning for AllowInsecureRegex.
//   - ExtractSecretRaw: data-only, stringData-only, both present with collision resolution,
//     both empty, and base64 decode correctness.
//   - MergeStringData: happy path, nil newStringData, invalid YAML input.
package k8sgen

import (
	"bytes"
	"encoding/base64"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// TestBuildManifest
// ---------------------------------------------------------------------------

func TestBuildManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		config     SecretConfig
		fileData   map[string][]byte
		stringData map[string]string
		wantErr    bool
		// assertions applied to the returned manifest bytes when wantErr is false.
		// Each check function receives the raw YAML / JSON bytes and the testing.T.
		assertFuncs []func(t *testing.T, manifest []byte)
	}{
		{
			// All optional fields populated; manifest must include name, namespace, labels, annotations.
			name: "valid generation with all fields populated",
			config: SecretConfig{
				Name:      "my-secret",
				Namespace: "production",
				Labels: map[string]string{
					"app":  "myapp",
					"tier": "backend",
				},
				Annotations: map[string]string{
					"managed-by": "k8sgen",
				},
			},
			fileData: map[string][]byte{
				"tls.crt": []byte("CERT_DATA"),
				"tls.key": []byte("KEY_DATA"),
			},
			stringData: map[string]string{
				"DB_HOST":     "postgres.svc",
				"DB_PASSWORD": "mock-db-password",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				// Manifest must be non-empty.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.NotEmpty(t, manifest, "manifest should not be empty for a fully populated config")
				},
				// Must contain the secret name.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "my-secret",
						"manifest should include the secret name")
				},
				// Must contain the namespace.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "production",
						"manifest should include the namespace")
				},
				// Must contain the label key & value.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					s := string(manifest)
					assert.Contains(t, s, "app", "manifest should include label key 'app'")
					assert.Contains(t, s, "myapp", "manifest should include label value 'myapp'")
				},
				// Must contain the annotation.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "managed-by",
						"manifest should include annotation key 'managed-by'")
				},
			},
		},
		{
			// Nil labels and annotations are allowed; manifest must still include name+namespace.
			name: "missing optional fields: no labels, no annotations",
			config: SecretConfig{
				Name:      "bare-secret",
				Namespace: "default",
				// Labels and Annotations intentionally omitted (nil maps).
			},
			fileData:   nil,
			stringData: nil,
			wantErr:    false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.NotEmpty(t, manifest,
						"manifest should still be produced when labels and annotations are absent")
				},
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "bare-secret",
						"manifest must include the secret name even without optional fields")
				},
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "default",
						"manifest must include the namespace even without optional fields")
				},
			},
		},
		{
			// A Secret without a Name must be rejected early to avoid an unidentifiable resource.
			name: "invalid: empty name",
			config: SecretConfig{
				Namespace: "default",
			},
			wantErr: true,
		},
		{
			// A Secret without a Namespace must be rejected to ensure correct scope on apply.
			name: "invalid: empty namespace",
			config: SecretConfig{
				Name: "my-secret",
			},
			wantErr: true,
		},
		{
			// fileData keys containing '!' violate the default Kubernetes key regex.
			name: "invalid: invalid key in fileData",
			config: SecretConfig{
				Name:      "my-secret",
				Namespace: "default",
			},
			fileData: map[string][]byte{
				"invalid_key!": []byte("data"),
			},
			wantErr: true,
		},
		{
			// stringData keys with '/' violate the default Kubernetes key regex.
			name: "invalid: invalid key in stringData",
			config: SecretConfig{
				Name:      "my-secret",
				Namespace: "default",
			},
			stringData: map[string]string{
				"invalid/key": "data",
			},
			wantErr: true,
		},
		{
			// Binary fileData values must be base64-encoded in the manifest's `data` field.
			name: "binary fileData is base64-encoded in the manifest",
			config: SecretConfig{
				Name:      "binary-secret",
				Namespace: "kube-system",
			},
			fileData: map[string][]byte{
				"ca.crt": {0xDE, 0xAD, 0xBE, 0xEF},
				"token":  {0x00, 0xFF, 0x42},
			},
			stringData: nil,
			wantErr:    false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.NotEmpty(t, manifest,
						"manifest should be produced for binary fileData")
				},
				// {0xDE, 0xAD, 0xBE, 0xEF} base64-encodes to "3q2+7w==".
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "3q2+7w==",
						"binary fileData[\"ca.crt\"] must appear base64-encoded in manifest")
				},
				// {0x00, 0xFF, 0x42} base64-encodes to "AP9C".
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "AP9C",
						"binary fileData[\"token\"] must appear base64-encoded in manifest")
				},
			},
		},
		{
			// stringData values must appear in the manifest as plain text.
			name: "stringData appears as plain text in the manifest",
			config: SecretConfig{
				Name:      "string-secret",
				Namespace: "staging",
			},
			fileData: nil,
			stringData: map[string]string{
				"API_KEY": "open-sesame",
				"REGION":  "us-east-1",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.NotEmpty(t, manifest,
						"manifest should be produced for stringData-only secret")
				},
				// Kubernetes allows stringData to remain un-encoded in the manifest.
				func(t *testing.T, manifest []byte) {
					t.Helper()
					s := string(manifest)
					assert.Contains(t, s, "API_KEY",
						"stringData key 'API_KEY' should appear in manifest")
					assert.Contains(t, s, "open-sesame",
						"stringData value 'open-sesame' should appear in manifest")
				},
				func(t *testing.T, manifest []byte) {
					t.Helper()
					s := string(manifest)
					assert.Contains(t, s, "REGION",
						"stringData key 'REGION' should appear in manifest")
					assert.Contains(t, s, "us-east-1",
						"stringData value 'us-east-1' should appear in manifest")
				},
			},
		},
		{
			// fileData and stringData can coexist; both must appear in the manifest.
			name: "fileData and stringData coexist in a single manifest",
			config: SecretConfig{
				Name:      "mixed-secret",
				Namespace: "prod",
				Labels:    map[string]string{"env": "prod"},
			},
			fileData: map[string][]byte{
				"server.key": []byte("PEM_KEY"),
			},
			stringData: map[string]string{
				"PASSWORD": "mock-password",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					s := string(manifest)
					assert.Contains(t, s, "server.key",
						"fileData key should appear in the manifest")
					assert.Contains(t, s, "PASSWORD",
						"stringData key should appear in the manifest")
				},
			},
		},
		{
			// An uncompilable regex must surface a clear error.
			name: "invalid: uncompilable custom KeyValidationRegex",
			config: SecretConfig{
				Name:               "my-secret",
				Namespace:          "default",
				KeyValidationRegex: "([a-z", // unmatched opening parenthesis
			},
			wantErr: true,
		},
		{
			// An empty KeyValidationRegex falls back to the strict default pattern.
			name: "invalid: empty KeyValidationRegex falls back to strict default",
			config: SecretConfig{
				Name:               "my-secret",
				Namespace:          "default",
				KeyValidationRegex: "",
			},
			fileData: map[string][]byte{
				"invalid_key!": []byte("data"), // '!' is banned by the default regex
			},
			wantErr: true,
		},
		{
			// Whitespace keys are rejected by the default regex.
			name: "invalid: empty keys and whitespace are rejected by default",
			config: SecretConfig{
				Name:      "my-secret",
				Namespace: "default",
			},
			fileData: map[string][]byte{
				"   ": []byte("data"),
			},
			wantErr: true,
		},
		{
			// A Unicode-aware custom regex correctly accepts Unicode letter keys.
			name: "valid: complex unicode regex evaluates correctly",
			config: SecretConfig{
				Name:               "unicode-secret",
				Namespace:          "default",
				KeyValidationRegex: `^[\p{L}0-9_]+$`,
			},
			stringData: map[string]string{
				"µ_service_key": "true",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "µ_service_key")
				},
			},
		},
		{
			// A dangerously permissive regex must be rejected unless explicitly acknowledged.
			name: "invalid: dangerously permissive regex fails without explicit acknowledgement",
			config: SecretConfig{
				Name:               "bad-secret",
				Namespace:          "default",
				KeyValidationRegex: `.*`,
				AllowInsecureRegex: false,
			},
			stringData: map[string]string{
				"   ": "empty",
			},
			wantErr: true,
		},
		{
			// With explicit acknowledgement, the dangerous regex is accepted and a warning is logged.
			name: "valid: dangerously permissive regex succeeds with explicit acknowledgement",
			config: SecretConfig{
				Name:               "bad-secret",
				Namespace:          "default",
				KeyValidationRegex: `.*`,
				AllowInsecureRegex: true,
			},
			stringData: map[string]string{
				"   ": "empty",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, manifest []byte){
				func(t *testing.T, manifest []byte) {
					t.Helper()
					assert.Contains(t, string(manifest), "bad-secret")
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := BuildManifest(tc.config, tc.fileData, tc.stringData)

			if tc.wantErr {
				assert.Error(t, err, "expected an error but got none")
				assert.Nil(t, got, "manifest bytes should be nil when an error occurs")
				return
			}

			assert.NoError(t, err, "unexpected error from BuildManifest")

			for _, fn := range tc.assertFuncs {
				fn(t, got)
			}
		})
	}
}

// TestBuildManifest_LogWarning explicitly tests that a securely bypassed regex correctly logs
// a runtime security warning. This is performed consecutively (not t.Parallel()) to securely
// capture the global log buffer without introducing potential race conditions against other routines.
func TestBuildManifest_LogWarning(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr) // Reset logger

	config := SecretConfig{
		Name:               "warning-secret",
		Namespace:          "default",
		KeyValidationRegex: `.*`,
		AllowInsecureRegex: true,
	}

	// Supply fake stringData to invoke key validation
	_, err := BuildManifest(config, nil, map[string]string{"foo": "bar"})
	if err != nil {
		t.Fatalf("expected no error building manifest, got: %v", err)
	}

	assert.Contains(t, buf.String(), "!!! CRITICAL SECURITY WARNING !!! k8sgen custom KeyValidationRegex")
}

// ---------------------------------------------------------------------------
// TestExtractSecretRaw
// ---------------------------------------------------------------------------

func TestExtractSecretRaw(t *testing.T) {
	t.Parallel()

	// validKey produces the standard base64 encoding of a value for embedding in YAML `data`.
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	tests := []struct {
		name        string
		yaml        string
		want        map[string]string
		wantErr     bool
		errContains string
	}{
		{
			// `data` field only: values must be base64-decoded by the k8s unmarshaler.
			name: "data-only: base64 values are decoded",
			yaml: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: default\ndata:\n  key1: " + b64("value1") + "\n  key2: " + b64("value2") + "\n",
			want: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			// `stringData` field only: values are passed through unchanged.
			name: "stringData-only: plain text values",
			yaml: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: default\nstringData:\n  DB_HOST: localhost\n  PORT: \"5432\"\n",
			want: map[string]string{
				"DB_HOST": "localhost",
				"PORT":    "5432",
			},
		},
		{
			// Both fields present; stringData wins on key collision.
			name: "both fields present: stringData wins on collision",
			yaml: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n  namespace: default\ndata:\n  shared: " + b64("from-data") + "\n  only-data: " + b64("data-value") + "\nstringData:\n  shared: from-stringData\n  only-string: string-value\n",
			want: map[string]string{
				"shared":      "from-stringData", // stringData takes precedence
				"only-data":   "data-value",
				"only-string": "string-value",
			},
		},
		{
			// Empty manifest (no data/stringData) must return an empty map without error.
			name: "both fields empty: returns empty map",
			yaml: "apiVersion: v1\nkind: Secret\nmetadata:\n  name: empty\n  namespace: default\n",
			want: map[string]string{},
		},
		{
			// Invalid YAML must return an error.
			name:        "invalid YAML returns error",
			yaml:        "not: valid: yaml: :::::",
			wantErr:     true,
			errContains: "failed to unmarshal",
		},
		{
			// Empty string input should produce an empty-ish Secret (no fields) without an error.
			name: "empty input: returns empty map",
			yaml: "",
			want: map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ExtractSecretRaw([]byte(tc.yaml))

			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestExtractSecretRaw_Base64Decode explicitly validates that binary bytes in the `data`
// field are correctly decoded (not double-decoded or string-cast raw).
func TestExtractSecretRaw_Base64Decode(t *testing.T) {
	t.Parallel()

	rawBytes := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	b64Val := base64.StdEncoding.EncodeToString(rawBytes)

	yaml := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: bin\n  namespace: ns\ndata:\n  key: " + b64Val + "\n"

	got, err := ExtractSecretRaw([]byte(yaml))
	require.NoError(t, err)

	// The corev1.Secret unmarshaler already base64-decodes `data` values into []byte;
	// ExtractSecretRaw should cast those bytes to string directly.
	assert.Equal(t, string(rawBytes), got["key"],
		"binary data field must be decoded from base64 to raw bytes then cast to string")
}

// ---------------------------------------------------------------------------
// TestMergeStringData
// ---------------------------------------------------------------------------

func TestMergeStringData(t *testing.T) {
	t.Parallel()

	// Build a base manifest to use as the existing state.
	baseYAML, err := BuildManifest(SecretConfig{
		Name:      "test-secret",
		Namespace: "default",
	}, nil, map[string]string{
		"OLD_KEY": "old-value",
		"STABLE":  "unchanged",
	})
	require.NoError(t, err)

	tests := []struct {
		name          string
		manifest      []byte
		newStringData map[string]string
		wantErr       bool
		errContains   string
		assertFuncs   []func(t *testing.T, out []byte)
	}{
		{
			// New stringData replaces old; keys absent from newStringData are gone.
			name:     "new stringData replaces existing",
			manifest: baseYAML,
			newStringData: map[string]string{
				"NEW_KEY": "new-value",
			},
			wantErr: false,
			assertFuncs: []func(t *testing.T, out []byte){
				func(t *testing.T, out []byte) {
					t.Helper()
					s := string(out)
					assert.Contains(t, s, "NEW_KEY", "new key must appear after merge")
					assert.Contains(t, s, "new-value", "new value must appear after merge")
				},
				// The secret name and namespace must be preserved.
				func(t *testing.T, out []byte) {
					t.Helper()
					s := string(out)
					assert.Contains(t, s, "test-secret")
					assert.Contains(t, s, "default")
				},
			},
		},
		{
			// A nil newStringData map clears the stringData field; manifest must still be valid.
			name:          "nil newStringData clears stringData field",
			manifest:      baseYAML,
			newStringData: nil,
			wantErr:       false,
			assertFuncs: []func(t *testing.T, out []byte){
				func(t *testing.T, out []byte) {
					t.Helper()
					assert.NotEmpty(t, out, "output must not be empty even with nil stringData")
					assert.Contains(t, string(out), "test-secret", "name must be preserved")
				},
			},
		},
		{
			// An empty map also clears stringData.
			name:          "empty newStringData map",
			manifest:      baseYAML,
			newStringData: map[string]string{},
			wantErr:       false,
			assertFuncs: []func(t *testing.T, out []byte){
				func(t *testing.T, out []byte) {
					t.Helper()
					assert.NotEmpty(t, out)
					assert.Contains(t, string(out), "test-secret")
				},
			},
		},
		{
			// Invalid YAML input must return a parse error.
			name:          "invalid YAML manifest returns error",
			manifest:      []byte("not: valid: yaml: :::::"),
			newStringData: map[string]string{"K": "V"},
			wantErr:       true,
			errContains:   "failed to unmarshal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			out, err := MergeStringData(tc.manifest, tc.newStringData)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, out)

			for _, fn := range tc.assertFuncs {
				fn(t, out)
			}
		})
	}
}

// TestMergeStringData_RoundTrip verifies that extracting after merging recovers the new data.
func TestMergeStringData_RoundTrip(t *testing.T) {
	t.Parallel()

	base, err := BuildManifest(SecretConfig{
		Name:      "rt-secret",
		Namespace: "ns",
	}, nil, map[string]string{"A": "1"})
	require.NoError(t, err)

	newData := map[string]string{"B": "2", "C": "3"}
	merged, err := MergeStringData(base, newData)
	require.NoError(t, err)

	extracted, err := ExtractSecretRaw(merged)
	require.NoError(t, err)

	// After a MergeStringData the stringData field holds newData; data field is preserved
	// (the base manifest had no `data`, so the result should contain exactly newData).
	assert.Equal(t, "2", extracted["B"])
	assert.Equal(t, "3", extracted["C"])
	// "A" was in stringData of the base; MergeStringData replaces StringData with newData
	// so "A" should no longer be present.
	_, hasA := extracted["A"]
	assert.False(t, hasA, "old stringData key must not survive MergeStringData")
}
