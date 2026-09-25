import unittest
import os
import shutil
import tempfile
import json

from app.parser.ast_extractor import parse_terraform_directory
from app.core.converter import convert_to_schema
from app.core.schema_validator import validate_schema, SchemaValidationError

class TestTerraformConverterStrictGeneric(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_tf(self, filename, content):
        path = os.path.join(self.test_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _convert(self):
        parsed_data, source_locations = parse_terraform_directory(self.test_dir)
        res = convert_to_schema(parsed_data, self.test_dir, source_locations)
        self.assertTrue(validate_schema(res))
        return res

    def test_01_aws_resources(self):
        self._write_tf("aws.tf", """
resource "aws_s3_bucket" "b" {
  bucket = "my-aws-bucket"
}
""")
        res = self._convert()
        self.assertEqual(len(res["resources"]), 1)
        r = res["resources"][0]
        self.assertEqual(r["type"], "aws_s3_bucket")
        self.assertEqual(r["provider"], "aws")

    def test_02_azure_resources(self):
        self._write_tf("azure.tf", """
resource "azurerm_resource_group" "rg" {
  name     = "my-rg"
  location = "westeurope"
}
""")
        res = self._convert()
        r = res["resources"][0]
        self.assertEqual(r["type"], "azurerm_resource_group")
        self.assertEqual(r["provider"], "azurerm")
        self.assertEqual(r["region"], "westeurope")

    def test_03_google_resources(self):
        self._write_tf("google.tf", """
resource "google_storage_bucket" "bucket" {
  name     = "my-gcp-bucket"
  location = "US"
}
""")
        res = self._convert()
        r = res["resources"][0]
        self.assertEqual(r["type"], "google_storage_bucket")
        self.assertEqual(r["provider"], "google")
        self.assertEqual(r["region"], "US")

    def test_04_kubernetes_resources(self):
        self._write_tf("k8s.tf", """
resource "kubernetes_pod" "nginx" {
  metadata {
    name = "nginx"
  }
}
""")
        res = self._convert()
        r = res["resources"][0]
        self.assertEqual(r["type"], "kubernetes_pod")
        self.assertEqual(r["provider"], "kubernetes")

    def test_05_unknown_custom_provider_and_resource(self):
        """Mandatory unknown provider and custom resource type test."""
        self._write_tf("unknown.tf", """
terraform {
  required_providers {
    example = {
      source = "example/example"
    }
  }
}

resource "example_custom_resource" "test" {
  custom_property = "hello"
  custom_number   = 42
}
""")
        res = self._convert()
        self.assertEqual(len(res["resources"]), 1)
        r = res["resources"][0]
        self.assertEqual(r["id"], "example_custom_resource.test")
        self.assertEqual(r["type"], "example_custom_resource")
        self.assertEqual(r["provider"], "example")
        self.assertEqual(r["attributes"]["custom_property"], "hello")
        self.assertEqual(r["attributes"]["custom_number"], 42)

        # Check null for unknown security properties
        sec = r["security"]
        self.assertIsNone(sec["encryption_enabled"])
        self.assertIsNone(sec["versioning_enabled"])
        self.assertIsNone(sec["backup_enabled"])

    def test_06_full_entities_and_relationships(self):
        """Test multiple resources, variables, outputs, modules, data sources, references and depends_on."""
        self._write_tf("full.tf", """
variable "db_password" {
  type      = string
  sensitive = true
}

data "custom_data" "info" {
  query = "latest"
}

resource "custom_db" "main" {
  password = var.db_password
}

resource "custom_replica" "rep" {
  primary_id = custom_db.main.id
  depends_on = [custom_db.main]
}

module "my_module" {
  source = "./modules/app"
  db_id  = custom_db.main.id
}

output "replica_id" {
  value = custom_replica.rep.id
}
""")
        res = self._convert()
        self.assertEqual(len(res["variables"]), 1)
        self.assertTrue(res["variables"][0]["sensitive"])

        self.assertEqual(len(res["data_sources"]), 1)
        self.assertEqual(len(res["resources"]), 2)
        self.assertEqual(len(res["modules"]), 1)
        self.assertEqual(len(res["outputs"]), 1)

        rep = [r for r in res["resources"] if r["name"] == "rep"][0]
        self.assertEqual(rep["depends_on"], ["custom_db.main"])

        # Secrets detection on custom resource
        main_db = [r for r in res["resources"] if r["name"] == "main"][0]
        self.assertEqual(len(main_db["security"]["secrets"]), 1)
        self.assertEqual(main_db["security"]["secrets"][0]["reference"], "var.db_password")

    def test_07_single_provider_metadata(self):
        """Single provider sets metadata.cloud_provider to provider name."""
        self._write_tf("main.tf", """
provider "google" {
  project = "my-project"
}
""")
        res = self._convert()
        self.assertEqual(res["metadata"]["cloud_provider"], "google")

    def test_08_multiple_providers_metadata_null(self):
        """Multiple providers set metadata.cloud_provider to null."""
        self._write_tf("main.tf", """
provider "aws" {
  region = "us-east-1"
}
provider "google" {
  project = "my-proj"
}
provider "azurerm" {
  features {}
}
""")
        res = self._convert()
        self.assertIsNone(res["metadata"]["cloud_provider"])

    def test_09_same_provider_with_aliases_metadata(self):
        """Same provider with aliases counts as single distinct provider."""
        self._write_tf("main.tf", """
provider "aws" {
  alias  = "primary"
  region = "us-east-1"
}
provider "aws" {
  alias  = "secondary"
  region = "us-west-2"
}
""")
        res = self._convert()
        self.assertEqual(res["metadata"]["cloud_provider"], "aws")

    def test_10_no_provider_metadata_null(self):
        """No provider sets metadata.cloud_provider to null."""
        self._write_tf("main.tf", """
variable "foo" {
  default = "bar"
}
""")
        res = self._convert()
        self.assertIsNone(res["metadata"]["cloud_provider"])

    def test_11_resource_explicit_region(self):
        """Resource with explicit region attribute preserves region."""
        self._write_tf("main.tf", """
resource "custom_server" "s1" {
  region = "eu-central-1"
}
""")
        res = self._convert()
        self.assertEqual(res["resources"][0]["region"], "eu-central-1")

    def test_12_resource_without_determinable_region_null(self):
        """Resource without region or location attribute has region == null."""
        self._write_tf("main.tf", """
resource "custom_server" "s2" {
  hostname = "web1"
}
""")
        res = self._convert()
        self.assertIsNone(res["resources"][0]["region"])

    def test_13_provider_region_isolation(self):
        """Provider or global variable region must not populate resource.region when resource lacks region attribute."""
        self._write_tf("main.tf", """
provider "aws" {
  region = "us-east-1"
}

variable "region" {
  default = "us-west-2"
}

resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
}
""")
        res = self._convert()
        self.assertIsNone(res["resources"][0]["region"])

    def test_14_metadata_region_concrete_static(self):
        """Concrete static region is preserved in metadata.region."""
        self._write_tf("main.tf", """
provider "custom_p" {
  region = "static-region-1"
}
""")
        res = self._convert()
        self.assertEqual(res["metadata"]["region"], "static-region-1")

    def test_15_metadata_region_unresolved_expression_null(self):
        """Unresolved region expression/reference results in metadata.region == null."""
        self._write_tf("main.tf", """
variable "unresolved_reg" {
  type = string
}

provider "custom_p" {
  region = var.unresolved_reg
}
""")
        res = self._convert()
        self.assertIsNone(res["metadata"]["region"])

    def test_16_metadata_region_missing_null(self):
        """Missing region results in metadata.region == null."""
        self._write_tf("main.tf", """
provider "custom_p" {
  name = "foo"
}
""")
        res = self._convert()
        self.assertIsNone(res["metadata"]["region"])

    def test_17_cloud_provider_plus_utility_provider(self):
        """One cloud provider plus unrelated utility provider evaluates metadata.cloud_provider to the single cloud provider."""
        self._write_tf("main.tf", """
provider "custom_cloud" {
  region = "reg-1"
}

resource "custom_cloud_server" "vm" {
  region = "reg-1"
}

resource "utility_item" "name" {
  prefix = "test"
}
""")
        res = self._convert()
        self.assertEqual(res["metadata"]["cloud_provider"], "custom_cloud")

    def test_18_mixed_multi_project_ambiguous_region_null(self):
        """Multi-project directory with conflicting regions evaluates metadata.region to null."""
        sub1 = os.path.join(self.test_dir, "proj1")
        sub2 = os.path.join(self.test_dir, "proj2")
        os.makedirs(sub1, exist_ok=True)
        os.makedirs(sub2, exist_ok=True)

        with open(os.path.join(sub1, "main.tf"), "w") as f:
            f.write('provider "custom_p1" { region = "region-alpha" }')
        with open(os.path.join(sub2, "main.tf"), "w") as f:
            f.write('provider "custom_p2" { region = "region-beta" }')

        res = self._convert()
        self.assertIsNone(res["metadata"]["region"])

    def test_19_security_booleans_no_evidence_null(self):
        """Resource with no security evidence has security booleans set to null."""
        self._write_tf("main.tf", """
resource "custom_db" "no_sec" {
  name = "testdb"
}
""")
        res = self._convert()
        sec = res["resources"][0]["security"]
        self.assertIsNone(sec["internet_exposed"])
        self.assertIsNone(sec["public_access"])
        self.assertIsNone(sec["public_ip"])
        self.assertIsNone(sec["encryption_enabled"])

    def test_20_security_booleans_explicit_evidence_true(self):
        """Explicit structural evidence for security boolean true sets boolean to True."""
        self._write_tf("main.tf", """
resource "custom_db" "public_db" {
  publicly_accessible = true
  storage_encrypted   = true
}
""")
        res = self._convert()
        sec = res["resources"][0]["security"]
        self.assertTrue(sec["public_access"])
        self.assertTrue(sec["internet_exposed"])
        self.assertTrue(sec["encryption_enabled"])

    def test_21_security_booleans_explicit_evidence_false(self):
        """Explicit structural evidence for security boolean false sets boolean to False."""
        self._write_tf("main.tf", """
resource "custom_db" "private_db" {
  publicly_accessible = false
  storage_encrypted   = false
}
""")
        res = self._convert()
        sec = res["resources"][0]["security"]
        self.assertFalse(sec["public_access"])
        self.assertFalse(sec["encryption_enabled"])

    def test_22_generic_ingress_egress_rules_extraction(self):
        """Generic ingress/egress rules preserve sources, destinations, protocol, ports, and description."""
        self._write_tf("main.tf", """
resource "test_network_resource" "example" {
  name = "security-test"

  ingress {
    protocol    = "tcp"
    from_port   = 1234
    to_port     = 5678
    sources     = ["10.0.0.0/16"]
    description = "internal ingress"
  }

  egress {
    protocol     = "tcp"
    from_port    = 8000
    to_port      = 9000
    destinations = ["10.1.0.0/16"]
    description  = "internal egress"
  }
}
""")
        res = self._convert()
        r = res["resources"][0]
        sec = r["security"]
        self.assertEqual(len(sec["ingress_rules"]), 1)
        self.assertEqual(sec["ingress_rules"][0], {
            "protocol": "tcp",
            "from_port": 1234,
            "to_port": 5678,
            "sources": ["10.0.0.0/16"],
            "description": "internal ingress"
        })
        self.assertEqual(len(sec["egress_rules"]), 1)
        self.assertEqual(sec["egress_rules"][0], {
            "protocol": "tcp",
            "from_port": 8000,
            "to_port": 9000,
            "destinations": ["10.1.0.0/16"],
            "description": "internal egress"
        })

if __name__ == "__main__":
    unittest.main()
