// Package provider contains the Terraform provider implementation for k8ssops.
// This test file covers the pure helper functions in helpers.go and datasource_secret.go:
//
//   - validatePath: accepts cwd-relative and absolute-within-cwd paths; rejects ".." and
//     paths outside the working directory.
//   - resolveCiphertext: mutual-exclusion logic (both set, neither set, path only, yaml only);
//     reads file content when path is set; returns inline bytes when encrypted_yaml is set.
//   - isPathMutualExclusionError: correctly identifies the sentinel error.
//   - mapsEqual: symmetric equality, nil vs empty, key/value mismatch.
//   - buildStringMapFromBytes: base64-encodes each []byte value correctly.
//   - buildStringMapFromStrings: converts string map to types.Map correctly.
//   - copyStringList: copies elements; no-op on null/unknown.
//   - checkFilesExist: returns true for empty map, false for missing file, true for existing.
package provider

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeStringList builds a non-null types.List from the provided string elements.
func makeStringList(t *testing.T, elements ...string) types.List {
	t.Helper()
	vals := make([]attr.Value, len(elements))
	for i, e := range elements {
		vals[i] = types.StringValue(e)
	}
	list, diags := types.ListValue(types.StringType, vals)
	require.False(t, diags.HasError(), "makeStringList: %v", diags)
	return list
}

// makeStringMap builds a non-null types.Map from the provided key/value pairs.
func makeStringMap(t *testing.T, kv map[string]string) types.Map {
	t.Helper()
	if kv == nil {
		return types.MapNull(types.StringType)
	}
	m := make(map[string]attr.Value, len(kv))
	for k, v := range kv {
		m[k] = types.StringValue(v)
	}
	mapVal, diags := types.MapValue(types.StringType, m)
	require.False(t, diags.HasError(), "makeStringMap: %v", diags)
	return mapVal
}

// ---------------------------------------------------------------------------
// TestValidatePath
// ---------------------------------------------------------------------------

func TestValidatePath(t *testing.T) {
	t.Parallel()

	cwd, err := os.Getwd()
	require.NoError(t, err)

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			// A filename directly inside cwd must be accepted.
			name:    "filename in cwd is accepted",
			path:    "somefile.yaml",
			wantErr: false,
		},
		{
			// A subdir path within cwd must be accepted.
			name:    "subdirectory path within cwd is accepted",
			path:    "subdir/file.yaml",
			wantErr: false,
		},
		{
			// An absolute path pointing inside cwd must be accepted.
			name:    "absolute path inside cwd is accepted",
			path:    filepath.Join(cwd, "output.yaml"),
			wantErr: false,
		},
		{
			// A path starting with ".." must be rejected regardless of where it resolves.
			name:    ".. prefix is rejected",
			path:    "../etc/passwd",
			wantErr: true,
		},
		{
			// A path containing ".." in the middle must be rejected.
			name:    "embedded .. segment is rejected",
			path:    "subdir/../../../etc/shadow",
			wantErr: true,
		},
		{
			// An absolute path pointing outside cwd must be rejected.
			name:    "absolute path outside cwd is rejected",
			path:    "/etc/passwd",
			wantErr: true,
		},
		{
			// A path that resolves to the cwd itself (just ".") must be accepted
			// because abs==cwd is allowed by the implementation.
			name:    "dot resolves to cwd itself and is accepted",
			path:    ".",
			wantErr: false,
		},
		{
			// Home-relative path that escapes cwd when resolved absolutely.
			name:    "tilde-expanded path outside cwd is rejected",
			path:    "/tmp/escape",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePath(tc.path)
			if tc.wantErr {
				assert.Error(t, err, "expected validatePath to reject %q", tc.path)
			} else {
				assert.NoError(t, err, "expected validatePath to accept %q", tc.path)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestResolveCiphertext
// ---------------------------------------------------------------------------

func TestResolveCiphertext(t *testing.T) {
	t.Parallel()

	t.Run("both path and encrypted_yaml set: mutual-exclusion error", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		f := filepath.Join(tmpDir, "enc.yaml")
		require.NoError(t, os.WriteFile(f, []byte("ciphertext"), 0600))

		_, err := resolveCiphertext(
			types.StringValue(f),
			types.StringValue("inline-yaml"),
		)
		require.Error(t, err)
		assert.True(t, isPathMutualExclusionError(err),
			"should be identified as a mutual-exclusion error")
	})

	t.Run("neither path nor encrypted_yaml set: mutual-exclusion error", func(t *testing.T) {
		t.Parallel()

		// Both null — neither is set.
		_, err := resolveCiphertext(
			types.StringNull(),
			types.StringNull(),
		)
		require.Error(t, err)
		assert.True(t, isPathMutualExclusionError(err))
	})

	t.Run("only empty strings set: treated as neither set", func(t *testing.T) {
		t.Parallel()

		_, err := resolveCiphertext(
			types.StringValue(""),
			types.StringValue(""),
		)
		require.Error(t, err)
		assert.True(t, isPathMutualExclusionError(err))
	})

	t.Run("path set: reads file content", func(t *testing.T) {
		// Not t.Parallel(): writes a file relative to cwd which is process-global.

		// Write the file inside a subdirectory of the current working directory so
		// that validatePath (which now resolves symlinks) accepts it. t.TempDir()
		// places files under /tmp which is outside the test's working directory.
		cwd, err := os.Getwd()
		require.NoError(t, err)
		subdir := filepath.Join(cwd, "testdata_resolveciphertext")
		require.NoError(t, os.MkdirAll(subdir, 0750))
		t.Cleanup(func() { os.RemoveAll(subdir) }) //nolint:errcheck

		f := filepath.Join(subdir, "enc.yaml")
		expected := []byte("encrypted-yaml-content")
		require.NoError(t, os.WriteFile(f, expected, 0600))

		got, readErr := resolveCiphertext(
			types.StringValue(f),
			types.StringNull(),
		)
		require.NoError(t, readErr)
		assert.Equal(t, expected, got)
	})

	t.Run("path set to nonexistent file: file-read error (not mutual-exclusion)", func(t *testing.T) {
		t.Parallel()

		_, err := resolveCiphertext(
			types.StringValue("/nonexistent/path/file.yaml"),
			types.StringNull(),
		)
		require.Error(t, err)
		assert.False(t, isPathMutualExclusionError(err),
			"a missing file error should not be classified as mutual-exclusion")
	})

	t.Run("encrypted_yaml set: returns inline bytes", func(t *testing.T) {
		t.Parallel()

		inline := "inline-sops-yaml"
		got, err := resolveCiphertext(
			types.StringNull(),
			types.StringValue(inline),
		)
		require.NoError(t, err)
		assert.Equal(t, []byte(inline), got)
	})

	t.Run("path set as unknown: treated as not set, error", func(t *testing.T) {
		t.Parallel()

		_, err := resolveCiphertext(
			types.StringUnknown(),
			types.StringNull(),
		)
		require.Error(t, err)
		assert.True(t, isPathMutualExclusionError(err))
	})
}

// ---------------------------------------------------------------------------
// TestIsPathMutualExclusionError
// ---------------------------------------------------------------------------

func TestIsPathMutualExclusionError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			// The sentinel error must be detected.
			name: "sentinel errMutualExclusion is recognised",
			err:  errMutualExclusion,
			want: true,
		},
		{
			// A generic error must not be detected as mutual-exclusion.
			name: "unrelated error is not recognised",
			err:  os.ErrNotExist,
			want: false,
		},
		{
			// nil must not be detected as mutual-exclusion.
			name: "nil error is not recognised",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, isPathMutualExclusionError(tc.err))
		})
	}
}

// ---------------------------------------------------------------------------
// TestMapsEqual
// ---------------------------------------------------------------------------

func TestMapsEqual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b types.Map
		want bool
	}{
		{
			// Two null maps are logically equal.
			name: "both null: equal",
			a:    types.MapNull(types.StringType),
			b:    types.MapNull(types.StringType),
			want: true,
		},
		{
			// Null vs empty: both contain zero elements, treated as equal.
			name: "null vs empty map: equal (both zero-length)",
			a:    types.MapNull(types.StringType),
			b:    makeStringMap(t, map[string]string{}),
			want: true,
		},
		{
			// Two identical maps must be equal.
			name: "identical maps: equal",
			a:    makeStringMap(t, map[string]string{"k": "v"}),
			b:    makeStringMap(t, map[string]string{"k": "v"}),
			want: true,
		},
		{
			// Same keys, different values.
			name: "same keys different values: not equal",
			a:    makeStringMap(t, map[string]string{"k": "v1"}),
			b:    makeStringMap(t, map[string]string{"k": "v2"}),
			want: false,
		},
		{
			// Different number of keys.
			name: "different key count: not equal",
			a:    makeStringMap(t, map[string]string{"k1": "v1"}),
			b:    makeStringMap(t, map[string]string{"k1": "v1", "k2": "v2"}),
			want: false,
		},
		{
			// Different key names.
			name: "different key names: not equal",
			a:    makeStringMap(t, map[string]string{"a": "1"}),
			b:    makeStringMap(t, map[string]string{"b": "1"}),
			want: false,
		},
		{
			// Both empty (non-null).
			name: "both empty non-null: equal",
			a:    makeStringMap(t, map[string]string{}),
			b:    makeStringMap(t, map[string]string{}),
			want: true,
		},
		{
			// One null, one with content.
			name: "null vs non-empty: not equal",
			a:    types.MapNull(types.StringType),
			b:    makeStringMap(t, map[string]string{"k": "v"}),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, mapsEqual(tc.a, tc.b))
			// mapsEqual must be symmetric.
			assert.Equal(t, tc.want, mapsEqual(tc.b, tc.a),
				"mapsEqual must be symmetric")
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildStringMapFromBytes
// ---------------------------------------------------------------------------

func TestBuildStringMapFromBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		src    map[string][]byte
		checks map[string]string // expected base64-encoded values
	}{
		{
			// nil input must produce an empty map without error.
			name:   "nil input: empty map",
			src:    nil,
			checks: map[string]string{},
		},
		{
			// Empty map input must produce an empty map.
			name:   "empty map input: empty map",
			src:    map[string][]byte{},
			checks: map[string]string{},
		},
		{
			// ASCII bytes must be base64-encoded in the resulting map.
			name: "ASCII value is base64-encoded",
			src: map[string][]byte{
				"user": []byte("admin"),
			},
			checks: map[string]string{
				"user": base64.StdEncoding.EncodeToString([]byte("admin")),
			},
		},
		{
			// Binary bytes must be base64-encoded correctly.
			name: "binary value is base64-encoded",
			src: map[string][]byte{
				"key": {0xDE, 0xAD, 0xBE, 0xEF},
			},
			checks: map[string]string{
				"key": base64.StdEncoding.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
			},
		},
		{
			// Empty byte slice must be encoded as the base64 of empty string.
			name: "empty byte slice encodes to empty base64",
			src: map[string][]byte{
				"empty": {},
			},
			checks: map[string]string{
				"empty": base64.StdEncoding.EncodeToString([]byte{}),
			},
		},
		{
			// Multiple keys all encoded correctly.
			name: "multiple keys",
			src: map[string][]byte{
				"a": []byte("alpha"),
				"b": []byte("beta"),
			},
			checks: map[string]string{
				"a": base64.StdEncoding.EncodeToString([]byte("alpha")),
				"b": base64.StdEncoding.EncodeToString([]byte("beta")),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := buildStringMapFromBytes(tc.src)
			require.NoError(t, err)

			// Extract the elements and verify each expected key/value.
			elements := make(map[string]string)
			result.ElementsAs(context.Background(), &elements, false)

			assert.Equal(t, len(tc.checks), len(elements),
				"result must contain exactly the expected number of keys")

			for k, wantB64 := range tc.checks {
				gotB64, ok := elements[k]
				require.True(t, ok, "key %q must exist in the result map", k)
				assert.Equal(t, wantB64, gotB64,
					"value for key %q must be correctly base64-encoded", k)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildStringMapFromStrings
// ---------------------------------------------------------------------------

func TestBuildStringMapFromStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     map[string]string
		wantMap map[string]string
	}{
		{
			// nil input must produce an empty map.
			name:    "nil input: empty map",
			src:     nil,
			wantMap: map[string]string{},
		},
		{
			// Empty map must produce an empty types.Map.
			name:    "empty map: empty result",
			src:     map[string]string{},
			wantMap: map[string]string{},
		},
		{
			// Normal key/value pairs pass through unchanged.
			name:    "normal key-value pairs",
			src:     map[string]string{"DB_HOST": "localhost", "PORT": "5432"},
			wantMap: map[string]string{"DB_HOST": "localhost", "PORT": "5432"},
		},
		{
			// Empty string values are preserved.
			name:    "empty string value preserved",
			src:     map[string]string{"empty": ""},
			wantMap: map[string]string{"empty": ""},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			result, err := buildStringMapFromStrings(tc.src)
			require.NoError(t, err)

			elements := make(map[string]string)
			result.ElementsAs(context.Background(), &elements, false)

			assert.Equal(t, tc.wantMap, elements)
		})
	}
}

// ---------------------------------------------------------------------------
// TestCopyStringList
// ---------------------------------------------------------------------------

func TestCopyStringList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     types.List
		want    []string
		wantLen int
	}{
		{
			// A null list must be a no-op; dest remains its zero value.
			name:    "null list: no-op",
			src:     types.ListNull(types.StringType),
			want:    nil,
			wantLen: 0,
		},
		{
			// An unknown list must be a no-op; dest remains its zero value.
			name:    "unknown list: no-op",
			src:     types.ListUnknown(types.StringType),
			want:    nil,
			wantLen: 0,
		},
		{
			// An empty list must set dest to an empty slice.
			name:    "empty list: sets empty slice",
			src:     makeStringList(t),
			want:    []string{},
			wantLen: 0,
		},
		{
			// A populated list must copy all elements in order.
			name:    "populated list: copies elements",
			src:     makeStringList(t, "arn:aws:kms:us-east-1:1234:key/abc", "arn:aws:kms:eu-west-1:5678:key/def"),
			want:    []string{"arn:aws:kms:us-east-1:1234:key/abc", "arn:aws:kms:eu-west-1:5678:key/def"},
			wantLen: 2,
		},
		{
			// A single-element list.
			name:    "single-element list",
			src:     makeStringList(t, "only-one"),
			want:    []string{"only-one"},
			wantLen: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var dest []string
			diags := copyStringList(context.Background(), &dest, tc.src)
			assert.False(t, diags.HasError(), "copyStringList should not produce diagnostics: %v", diags)

			if tc.src.IsNull() || tc.src.IsUnknown() {
				// No-op: dest should remain nil.
				assert.Nil(t, dest)
			} else {
				require.NotNil(t, dest)
				assert.Equal(t, tc.want, dest)
				assert.Len(t, dest, tc.wantLen)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCheckFilesExist
// ---------------------------------------------------------------------------

func TestCheckFilesExist(t *testing.T) {
	t.Parallel()

	t.Run("empty map: returns true", func(t *testing.T) {
		t.Parallel()

		m := makeStringMap(t, map[string]string{})
		assert.True(t, checkFilesExist(context.Background(), m),
			"empty file_data map must return true")
	})

	t.Run("null map: returns true", func(t *testing.T) {
		t.Parallel()

		assert.True(t, checkFilesExist(context.Background(), types.MapNull(types.StringType)),
			"null file_data map must return true")
	})

	t.Run("unknown map: returns true", func(t *testing.T) {
		t.Parallel()

		assert.True(t, checkFilesExist(context.Background(), types.MapUnknown(types.StringType)),
			"unknown file_data map must return true")
	})

	t.Run("all files exist: returns true", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		f1 := filepath.Join(tmpDir, "file1.txt")
		f2 := filepath.Join(tmpDir, "file2.txt")
		require.NoError(t, os.WriteFile(f1, []byte("a"), 0600))
		require.NoError(t, os.WriteFile(f2, []byte("b"), 0600))

		m := makeStringMap(t, map[string]string{
			"key1": f1,
			"key2": f2,
		})
		assert.True(t, checkFilesExist(context.Background(), m))
	})

	t.Run("one file missing: returns false", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		exists := filepath.Join(tmpDir, "exists.txt")
		require.NoError(t, os.WriteFile(exists, []byte("x"), 0600))
		missing := filepath.Join(tmpDir, "does-not-exist.txt")

		m := makeStringMap(t, map[string]string{
			"present": exists,
			"absent":  missing,
		})
		assert.False(t, checkFilesExist(context.Background(), m))
	})

	t.Run("all files missing: returns false", func(t *testing.T) {
		t.Parallel()

		m := makeStringMap(t, map[string]string{
			"k1": "/nonexistent/path/a.txt",
			"k2": "/nonexistent/path/b.txt",
		})
		assert.False(t, checkFilesExist(context.Background(), m))
	})
}

// ---------------------------------------------------------------------------
// TestValidatePath_TempDir — exercise the guard using a real temp directory
// ---------------------------------------------------------------------------

func TestValidatePath_TempDir(t *testing.T) {
	// Not parallel: os.Chdir is process-global.

	// Change working directory to a temp dir so we can construct paths inside/outside it.
	tmpDir := t.TempDir()
	origCwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() {
		_ = os.Chdir(origCwd)
	})

	// On macOS /tmp is a symlink to /private/tmp; os.Getwd() returns the real path after
	// Chdir, so construct all absolute paths via os.Getwd() not the original tmpDir string.
	realCwd, err := os.Getwd()
	require.NoError(t, err)

	t.Run("file directly in new cwd is accepted", func(t *testing.T) {
		err := validatePath("secret.yaml")
		assert.NoError(t, err)
	})

	t.Run("path escaping new cwd is rejected", func(t *testing.T) {
		err := validatePath("../escape.yaml")
		assert.Error(t, err)
	})

	t.Run("absolute path inside new cwd is accepted", func(t *testing.T) {
		// Construct the path from the real cwd (symlink-resolved) so validatePath
		// can verify it has the correct prefix.
		p := filepath.Join(realCwd, "subdir", "file.yaml")
		err := validatePath(p)
		assert.NoError(t, err)
	})
}
