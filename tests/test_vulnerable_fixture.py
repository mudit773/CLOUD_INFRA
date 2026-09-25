import unittest
import os
import shutil
import tempfile
import json

from main import main

class TestVulnerableFixture(unittest.TestCase):
    """
    Controlled vulnerable test fixture to empirically verify attack-path reachability
    and choke-point analysis across entry points and crown jewels.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.input_dir = os.path.join(self.test_dir, "input")
        self.output_dir = os.path.join(self.test_dir, "output")
        os.makedirs(self.input_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def _write_tf(self, filename, content):
        path = os.path.join(self.input_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def test_end_to_end_vulnerable_attack_path(self):
        """
        Scenario:
        1. aws_security_group.public_ingress has open 0.0.0.0/0 port 80 (Entry Point)
        2. aws_instance.web_app uses public_ingress security group
        3. aws_db_instance.prod_db is a PostgreSQL database storing user records (Crown Jewel)
        4. aws_instance.web_app references aws_db_instance.prod_db endpoint & password
        """
        self._write_tf("vulnerable_infra.tf", """
variable "db_password" {
  type      = string
  default   = "SuperSecretPass123!"
  sensitive = true
}

resource "aws_security_group" "public_ingress" {
  name        = "public-web-sg"
  description = "Public HTTP ingress"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_app" {
  ami                    = "ami-12345678"
  instance_type          = "t3.medium"
  vpc_security_group_ids = [aws_security_group.public_ingress.id]
  user_data              = "connect to ${aws_db_instance.prod_db.endpoint} using ${var.db_password}"
}

resource "aws_db_instance" "prod_db" {
  identifier        = "production-customer-db"
  engine            = "postgres"
  instance_class    = "db.r5.large"
  allocated_storage = 100
  username          = "postgres"
  password          = var.db_password
  storage_encrypted = true

  tags = {
    DataClassification = "sensitive"
    Sensitivity        = "critical"
  }
}
""")

        tf_json_file = os.path.join(self.output_dir, "terraform.json")
        graph_json_file = os.path.join(self.output_dir, "graph_output.json")

        exit_code = main([
            "-i", self.input_dir,
            "-o", tf_json_file,
            "--graph-output", graph_json_file
        ])

        self.assertEqual(exit_code, 0)
        self.assertTrue(os.path.exists(graph_json_file))

        with open(graph_json_file, "r", encoding="utf-8") as f:
            graph_data = json.load(f)

        entry_points = graph_data.get("entry_points", [])
        crown_jewels = graph_data.get("crown_jewels", [])
        attack_paths = graph_data.get("attack_paths", [])
        choke_points = graph_data.get("choke_points", [])

        # Verify entry points include the exposed security group / instance
        self.assertTrue(len(entry_points) > 0, "Expected entry points to be detected")
        self.assertIn("aws_security_group.public_ingress", entry_points)

        # Verify crown jewels include the database
        self.assertTrue(len(crown_jewels) > 0, "Expected crown jewels to be detected")
        self.assertIn("aws_db_instance.prod_db", crown_jewels)

        # Verify attack paths trace reachability from internet/entry point to crown jewel
        self.assertTrue(len(attack_paths) > 0, "Expected at least 1 evidence-supported attack path")

        path_targets = {p["target"] for p in attack_paths}
        self.assertIn("aws_db_instance.prod_db", path_targets)

        # Verify choke points reflect intermediate resources along the attack path
        self.assertTrue(len(choke_points) > 0, "Expected choke points to be identified for attack paths")
        choke_resource_ids = {c["resource_id"] for c in choke_points}
        self.assertTrue(
            "aws_instance.web_app" in choke_resource_ids or "aws_security_group.public_ingress" in choke_resource_ids
        )

if __name__ == "__main__":
    unittest.main()
