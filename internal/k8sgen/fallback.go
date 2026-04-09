package k8sgen

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// MergeStringData parses an existing Kubernetes Secret manifest (in YAML format),
// replaces its StringData with the provided newStringData, clears the traditional Data field
// (as Kubernetes will regenerate it from StringData), and returns the reserialized YAML.
func MergeStringData(parsedManifestYAML []byte, newStringData map[string]string) ([]byte, error) {
	var secret corev1.Secret
	if err := yaml.Unmarshal(parsedManifestYAML, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal existing manifest: %w", err)
	}

	// We don't have the files. We keep the old `Data` intact and overwrite `StringData`.
	// K8s apiserver merges StringData into Data on apply, so this is safe for GitOps fallback.
	secret.StringData = newStringData

	raw, err := yaml.Marshal(&secret)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal merged manifest: %w", err)
	}
	return cleanEmptyFields(raw)
}

// ExtractSecretRaw parses a Kubernetes Secret manifest and extracts the plain text payload
// by decoding the `Data` field and combining it with `StringData`.
func ExtractSecretRaw(manifestYAML []byte) (map[string]string, error) {
	var secret corev1.Secret
	if err := yaml.Unmarshal(manifestYAML, &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest for raw extraction: %w", err)
	}

	raw := make(map[string]string)

	// Add file data (which is base64 decoded by k8s corev1.Secret unmarshaling automatically into []byte)
	for k, v := range secret.Data {
		raw[k] = string(v)
	}

	// Override with StringData if any
	for k, v := range secret.StringData {
		raw[k] = v
	}

	return raw, nil
}
