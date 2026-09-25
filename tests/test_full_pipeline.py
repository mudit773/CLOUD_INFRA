import unittest
import os
import shutil
import tempfile
import json

from main import main

class TestFullPipeline(unittest.TestCase):

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

    def test_full_pipeline_tf_to_graph_output(self):
        """
        Tests the end-to-end flow:
        .tf -> terraform.json -> security + graph analysis -> graph_output.json
        """
        self._write_tf("main.tf", """
resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-test-bucket"
  acl    = "public-read"
}

resource "aws_security_group" "open_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.open_ssh.id]
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
        self.assertTrue(os.path.exists(tf_json_file), "terraform.json was not generated")
        self.assertTrue(os.path.exists(graph_json_file), "graph_output.json was not generated")

        # Verify terraform.json content
        with open(tf_json_file, "r", encoding="utf-8") as f:
            tf_data = json.load(f)
        self.assertEqual(len(tf_data["resources"]), 3)
        self.assertIn("metadata", tf_data)

        # Verify graph_output.json content
        with open(graph_json_file, "r", encoding="utf-8") as f:
            graph_data = json.load(f)

        self.assertIn("nodes", graph_data)
        self.assertIn("edges", graph_data)
        self.assertIn("entry_points", graph_data)
        self.assertIn("crown_jewels", graph_data)
        self.assertIn("attack_paths", graph_data)
        self.assertIn("choke_points", graph_data)
        self.assertIn("risk", graph_data)
        self.assertIn("risk_scores", graph_data)

        # Verify nodes and entry points in attack graph
        node_ids = {node["id"] for node in graph_data["nodes"]}
        self.assertIn("aws_s3_bucket.unencrypted_bucket", node_ids)
        self.assertIn("aws_security_group.open_ssh", node_ids)
        self.assertIn("aws_instance.web_server", node_ids)
        self.assertIn("internet", node_ids)

if __name__ == "__main__":
    unittest.main()
