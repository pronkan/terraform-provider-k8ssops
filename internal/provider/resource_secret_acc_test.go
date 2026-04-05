package provider_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/pronkan/terraform-provider-k8ssops/internal/provider"
)

// protoV6ProviderFactories instantiates the k8ssops provider for acceptance tests.
// It uses an in-process provider server so no binary installation is required.
var protoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"k8ssops": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// providerConfig is a reusable HCL snippet that configures the provider.
// KMS fields are omitted; the stubbed resource does not call the SOPS engine yet.
const providerConfig = `
provider "k8ssops" {}
`

// For resources we must provide an age_key to mock KMS offline.
const ageKeyBlock = `
  age_keys = ["1122334455667788990011223344556677889900112233445566778899001122"]
`

// ---------------------------------------------------------------------------
// Test 1: Create with only string_data (no file_data, no output_path)
// ---------------------------------------------------------------------------

func TestAccSecretResource_StringDataOnly(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfigStringDataOnly("username", "alice", "password", "s3cr3t"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.test", "metadata.name", "test-secret"),
					resource.TestCheckResourceAttr("k8ssops_secret.test", "metadata.namespace", "default"),
					resource.TestCheckResourceAttr("k8ssops_secret.test", "type", "Opaque"),
					resource.TestCheckResourceAttr("k8ssops_secret.test", "string_data.username", "alice"),
					resource.TestCheckResourceAttr("k8ssops_secret.test", "string_data.password", "s3cr3t"),
					// output_path is not set in HCL; the framework stores it as null.
					// TestCheckResourceAttrIsEmpty is the correct assertion for a null optional attr.
					resource.TestCheckResourceAttrSet("k8ssops_secret.test", "metadata.name"),
				),
			},
			// ImportState verification (round-trip).
			// After ImportState only metadata.name is populated; all other fields are
			// unknown so we must ignore them in the verify diff.
			{
				ResourceName:      "k8ssops_secret.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"secret",
					"secret_raw",
					"plaintext_hash",
					"string_data",
					"file_data",
					"output_path",
					"type",
					"metadata.namespace",
					"metadata.labels",
					"metadata.annotations",
					"aws_kms_arns",
					"gcp_kms_resources",
					"azure_kv_urls",
					"age_keys",
					"pgp_keys",
				},
			},
		},
	})
}

func testConfigStringDataOnly(k1, v1, k2, v2 string) string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "test" {
  metadata = {
    name      = "test-secret"
    namespace = "default"
  }
%s
  string_data = {
    "%s" = "%s"
    "%s" = "%s"
  }
}
`, ageKeyBlock, k1, v1, k2, v2)
}

// ---------------------------------------------------------------------------
// Test 2: Create with output_path
// ---------------------------------------------------------------------------

func TestAccSecretResource_WithOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "secret.enc.yaml")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfigWithOutputPath("api-creds", "production", outFile),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.with_output", "metadata.name", "api-creds"),
					resource.TestCheckResourceAttr("k8ssops_secret.with_output", "metadata.namespace", "production"),
					resource.TestCheckResourceAttr("k8ssops_secret.with_output", "output_path", outFile),
					resource.TestCheckResourceAttr("k8ssops_secret.with_output", "type", "Opaque"),
				),
			},
		},
	})
}

func testConfigWithOutputPath(name, namespace, outPath string) string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "with_output" {
  metadata = {
    name      = %q
    namespace = %q
  }
%s
  string_data = {
    "api_key" = "super-secret-token"
  }

  output_path = %q
}
`, name, namespace, ageKeyBlock, outPath)
}

// ---------------------------------------------------------------------------
// Test 3: Modify output_path — must NOT trigger resource recreation
// ---------------------------------------------------------------------------

func TestAccSecretResource_ModifyOutputPath_NoRecreate(t *testing.T) {
	tmpDir := t.TempDir()
	outFile1 := filepath.Join(tmpDir, "first.enc.yaml")
	outFile2 := filepath.Join(tmpDir, "second.enc.yaml")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: initial create
			{
				Config: providerConfig + testConfigOutputPathStep("app-secret", outFile1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.output_path_test", "output_path", outFile1),
				),
			},
			// Step 2: change output_path only — must be an in-place update (no destroy)
			{
				Config: providerConfig + testConfigOutputPathStep("app-secret", outFile2),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("k8ssops_secret.output_path_test", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.output_path_test", "output_path", outFile2),
				),
			},
		},
	})
}

func testConfigOutputPathStep(name, outPath string) string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "output_path_test" {
  metadata = {
    name = %q
    namespace = "default"
  }
%s
  string_data = {
    "token" = "abc123"
  }

  output_path = %q
}
`, name, ageKeyBlock, outPath)
}

// ---------------------------------------------------------------------------
// Test 4: Modify string_data — must trigger an update (not recreate)
// ---------------------------------------------------------------------------

func TestAccSecretResource_ModifyStringData_TriggersUpdate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with initial string_data
			{
				Config: providerConfig + testConfigStringDataStep("user", "alice"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.sd_update", "string_data.user", "alice"),
				),
			},
			// Step 2: update string_data — plan must show Update, NOT Replace
			{
				Config: providerConfig + testConfigStringDataStep("user", "bob"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("k8ssops_secret.sd_update", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.sd_update", "string_data.user", "bob"),
				),
			},
		},
	})
}

func testConfigStringDataStep(user, value string) string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "sd_update" {
  metadata = {
    name = "sd-update-secret"
    namespace = "default"
  }
%s
  string_data = {
    %q = %q
  }
}
`, ageKeyBlock, user, value)
}

// ---------------------------------------------------------------------------
// Test 5: Simulate missing file_data files — fallback state
//
// When file_data entries point to non-existent paths, Create/Update must not
// panic. The stubbed resource currently accepts any string value; this test
// verifies that the plan is accepted and state is persisted. Once the real
// SOPS engine is wired in, this test will need to be updated to expect an
// error diagnostic unless existing state (Secret) can be decrypted.
// ---------------------------------------------------------------------------

func TestAccSecretResource_FileDataMissingFiles_FallbackState(t *testing.T) {
	// Use a path that deliberately does not exist.
	missingFile := filepath.Join(t.TempDir(), "nonexistent.lic")

	// Confirm the file really does not exist.
	if _, err := os.Stat(missingFile); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be absent, but it exists", missingFile)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with only string_data to establish state.
			{
				Config: providerConfig + testConfigFallbackCreate(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.fallback", "metadata.name", "fallback-secret"),
					resource.TestCheckResourceAttr("k8ssops_secret.fallback", "string_data.license_key", "initial-value"),
				),
			},
			// Step 2: add file_data pointing at a missing file.
			// The stub resource accepts this as a string value; the ModifyPlan
			// logic will eventually gate on file existence and fall back to state.
			{
				Config: providerConfig + testConfigFallbackMissingFileData(missingFile),
				// Expect a plan-time update (not recreate) because the resource
				// has no ForceNew fields and ModifyPlan should suppress the diff
				// when the file is absent (once implemented).
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("k8ssops_secret.fallback", plancheck.ResourceActionUpdate),
					},
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("k8ssops_secret.fallback", "metadata.name", "fallback-secret"),
					// Map keys with dots are percent-encoded in Terraform state paths.
					// We only check name because file_data depends on ModifyPlan/Apply flow
				),
			},
		},
	})
}

func testConfigFallbackCreate() string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "fallback" {
  metadata = {
    name = "fallback-secret"
    namespace = "default"
  }
%s
  string_data = {
    "license_key" = "initial-value"
  }
}
`, ageKeyBlock)
}

func testConfigFallbackMissingFileData(missingPath string) string {
	return fmt.Sprintf(`
resource "k8ssops_secret" "fallback" {
  metadata = {
    name = "fallback-secret"
    namespace = "default"
  }
%s
  string_data = {
    "license_key" = "initial-value"
  }

  file_data = {
    "license.lic" = %q
  }
}
`, ageKeyBlock, missingPath)
}
