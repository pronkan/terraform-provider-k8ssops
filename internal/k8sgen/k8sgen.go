package k8sgen

import (
	"errors"
	"fmt"
	"log"
	"regexp"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

var defaultSecretKeyRegex = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)

// knownSecretTypes is the exhaustive set of built-in Kubernetes Secret types defined in
// the core API (k8s.io/api/core/v1). Any value outside this set will be rejected by
// BuildManifest to prevent typos from silently producing manifests that Kubernetes
// admission controllers will reject at apply time.
var knownSecretTypes = map[corev1.SecretType]struct{}{
	corev1.SecretTypeOpaque:              {},
	corev1.SecretTypeServiceAccountToken: {},
	corev1.SecretTypeDockercfg:           {},
	corev1.SecretTypeDockerConfigJson:    {},
	corev1.SecretTypeBasicAuth:           {},
	corev1.SecretTypeSSHAuth:             {},
	corev1.SecretTypeTLS:                 {},
	corev1.SecretTypeBootstrapToken:      {},
}

// SecretConfig holds K8s metadata for the secret.
type SecretConfig struct {
	Name      string
	Namespace string
	// Type controls the Kubernetes Secret type written into the manifest's `type` field.
	// Accepted values are the standard built-in types defined by the Kubernetes core API:
	//   - "Opaque"                            (default when empty)
	//   - "kubernetes.io/service-account-token"
	//   - "kubernetes.io/dockercfg"
	//   - "kubernetes.io/dockerconfigjson"
	//   - "kubernetes.io/basic-auth"
	//   - "kubernetes.io/ssh-auth"
	//   - "kubernetes.io/tls"
	//   - "bootstrap.kubernetes.io/token"
	// BuildManifest rejects any value not in this list to catch typos before the manifest
	// reaches the Kubernetes API server.
	Type string

	// Labels are optional key/value pairs attached to the resource.
	// If left unset or nil, the resulting manifest will omit the `labels` field.
	// Note: While structurally valid, omitted labels might prevent discovery by selection queries or controllers.
	Labels map[string]string

	// Annotations are optional key/value metadata payload fields.
	// If left unset or nil, the resulting manifest will omit the `annotations` field.
	Annotations map[string]string

	// KeyValidationRegex is an optional custom regex pattern for data keys.
	// WARNING: CAUTION MUST BE EXERCISED. Overriding this with an overly permissive pattern
	// completely bypasses standard safety constraints. This can lead to deployment-time rejections
	// by Kubernetes admission controllers or, more severely, introduce downstream security
	// vulnerabilities via injection attacks if keys containing illegal characters (like spaces
	// or shell meta-characters) are projected into pods as environment variables.
	// If unset, the standard K8s subset (^[-._a-zA-Z0-9]+$) is strictly enforced.
	KeyValidationRegex string

	// AllowInsecureRegex forces the caller to explicitly acknowledge the risks of an insecure
	// KeyValidationRegex.
	//
	// !!! CRITICAL SECURITY WARNING !!!
	// Setting this to true allows keys that could lead to severe downstream shell injection
	// or path traversal attacks if the resulting secret keys are mounted as files or projected
	// into CI/CD environment variables. Only set this to true if you are operating within a
	// hyper-controlled zero-trust pipeline that explicitly demands non-standard key names.
	AllowInsecureRegex bool
}

// BuildManifest generates a well-formed Kubernetes Secret manifest serialized in YAML.
// It requires Name and Namespace to be non-empty, validates Type against the known
// Kubernetes built-in secret types, and enforces Kubernetes-compliant key validation on
// fileData and stringData to guard against admission controller rejections at apply time.
//
// The key validation pattern defaults to the standard Kubernetes subset (^[-._a-zA-Z0-9]+$)
// but can be overridden via SecretConfig.KeyValidationRegex.
//
// Example usage:
//
//	config := SecretConfig{
//	    Name:      "db-secret",
//	    Namespace: "production",
//	    Type:      "Opaque", // or "kubernetes.io/tls", "kubernetes.io/basic-auth", etc.
//	}
//	fileData := map[string][]byte{"tls.crt": crtBytes}
//	stringData := map[string]string{"USER": "admin"}
//
//	manifestYAML, err := BuildManifest(config, fileData, stringData)
//	if err != nil {
//	    log.Fatalf("failed to build manifest: %v", err)
//	}
func BuildManifest(config SecretConfig, fileData map[string][]byte, stringData map[string]string) ([]byte, error) {
	if config.Name == "" {
		return nil, errors.New("secret name cannot be empty")
	}
	if config.Namespace == "" {
		return nil, errors.New("secret namespace cannot be empty")
	}

	validator := defaultSecretKeyRegex
	if config.KeyValidationRegex != "" {
		compiled, err := regexp.Compile(config.KeyValidationRegex)
		if err != nil {
			return nil, fmt.Errorf("failed to compile custom KeyValidationRegex %q: %w", config.KeyValidationRegex, err)
		}

		// Heuristic security check: Issue a runtime warning or error if the custom regex permits dangerous inputs.
		// We explicitly check for whitespace, empty strings, shell subshells, and directory traversal vectors.
		isDangerouslyPermissive := compiled.MatchString(" ") || compiled.MatchString("") || compiled.MatchString("$(") || compiled.MatchString("../../")

		if isDangerouslyPermissive {
			if !config.AllowInsecureRegex {
				return nil, fmt.Errorf("insecure KeyValidationRegex %q rejected: pattern dangerously allows whitespace, empty strings, shell injection, or path traversal vectors. Set AllowInsecureRegex to true to bypass this safeguard", config.KeyValidationRegex)
			}
			log.Printf("!!! CRITICAL SECURITY WARNING !!! k8sgen custom KeyValidationRegex %q is dangerously permissive. It allows whitespace, empty strings, path traversal, or shell injection characters. This poses a severe security risk.", config.KeyValidationRegex)
		}

		validator = compiled
	}

	for k := range fileData {
		if !validator.MatchString(k) {
			return nil, fmt.Errorf("invalid key in fileData: %q. Keys should match the pattern: %s", k, validator.String())
		}
	}
	for k := range stringData {
		if !validator.MatchString(k) {
			return nil, fmt.Errorf("invalid key in stringData: %q. Keys should match the pattern: %s", k, validator.String())
		}
	}

	secretType := corev1.SecretTypeOpaque
	if config.Type != "" {
		candidate := corev1.SecretType(config.Type)
		if _, ok := knownSecretTypes[candidate]; !ok {
			return nil, fmt.Errorf("unknown secret type %q: must be one of the Kubernetes built-in types (e.g. Opaque, kubernetes.io/tls, kubernetes.io/basic-auth)", config.Type)
		}
		secretType = candidate
	}

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        config.Name,
			Namespace:   config.Namespace,
			Labels:      config.Labels,
			Annotations: config.Annotations,
		},
		Data:       fileData,
		StringData: stringData,
		Type:       secretType,
	}

	raw, err := yaml.Marshal(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal secret manifest: %w", err)
	}
	return cleanEmptyFields(raw)
}

// cleanEmptyFields removes null values and empty maps/slices from a YAML document.
// Empty strings are preserved — they may be intentional secret values.
// This eliminates boilerplate fields emitted by the Kubernetes API types
// (e.g. "creationTimestamp: null", "status: {}") that add noise to GitOps diffs.
func cleanEmptyFields(yamlBytes []byte) ([]byte, error) {
	var tree interface{}
	if err := yaml.Unmarshal(yamlBytes, &tree); err != nil {
		return nil, fmt.Errorf("cleanEmptyFields: unmarshal: %w", err)
	}
	out, err := yaml.Marshal(pruneNulls(tree))
	if err != nil {
		return nil, fmt.Errorf("cleanEmptyFields: marshal: %w", err)
	}
	return out, nil
}

// pruneNulls recursively removes nil values and empty maps/slices from a generic tree
// produced by yaml.Unmarshal into interface{}. Empty strings pass through unchanged.
func pruneNulls(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch node := v.(type) {
	case map[string]interface{}:
		clean := make(map[string]interface{}, len(node))
		for k, val := range node {
			if pruned := pruneNulls(val); pruned != nil {
				clean[k] = pruned
			}
		}
		if len(clean) == 0 {
			return nil
		}
		return clean
	case []interface{}:
		clean := make([]interface{}, 0, len(node))
		for _, val := range node {
			if pruned := pruneNulls(val); pruned != nil {
				clean = append(clean, pruned)
			}
		}
		if len(clean) == 0 {
			return nil
		}
		return clean
	default:
		return v
	}
}
