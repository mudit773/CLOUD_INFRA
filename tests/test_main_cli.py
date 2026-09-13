import unittest
import os
import shutil
import tempfile
import json
import sys
from io import StringIO

from main import main

class TestMainCLI(unittest.TestCase):

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

    def test_01_default_arguments(self):
        """Test main with default args on existing input directory if present."""
        self._write_tf("main.tf", 'resource "aws_s3_bucket" "b" { bucket = "mybucket" }')
        output_file = os.path.join(self.output_dir, "terraform.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(output_file))

    def test_02_custom_input_path(self):
        """Test main with custom input path."""
        self._write_tf("main.tf", 'variable "vpc_cidr" { default = "10.0.0.0/16" }')
        output_file = os.path.join(self.output_dir, "out.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(output_file))

    def test_03_custom_output_path(self):
        """Test main with custom output path."""
        self._write_tf("main.tf", 'output "res" { value = "hello" }')
        custom_out = os.path.join(self.test_dir, "custom_folder", "result.json")
        code = main(["-i", self.input_dir, "-o", custom_out])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists(custom_out))

    def test_04_invalid_non_existent_input_directory(self):
        """Test non-existent input path returns exit code 1."""
        non_existent = os.path.join(self.test_dir, "does_not_exist")
        code = main(["-i", non_existent])
        self.assertNotEqual(code, 0)

    def test_05_input_is_file_not_directory(self):
        """Test input path being a file returns exit code 1."""
        file_path = os.path.join(self.test_dir, "some_file.txt")
        with open(file_path, "w") as f:
            f.write("hello")
        code = main(["-i", file_path])
        self.assertNotEqual(code, 0)

    def test_06_empty_directory_no_tf_files(self):
        """Test directory with no .tf files returns exit code 1."""
        empty_dir = os.path.join(self.test_dir, "empty_dir")
        os.makedirs(empty_dir, exist_ok=True)
        code = main(["-i", empty_dir])
        self.assertNotEqual(code, 0)

    def test_07_successful_output_generation(self):
        """Test that generated output is valid JSON matching expected content."""
        self._write_tf("main.tf", 'resource "azurerm_resource_group" "rg" { name = "rg1" location = "eastus" }')
        output_file = os.path.join(self.output_dir, "terraform.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)

        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["resources"]), 1)
        self.assertEqual(data["resources"][0]["type"], "azurerm_resource_group")

    def test_08_summary_flag(self):
        """Test --summary flag prints console summary."""
        self._write_tf("main.tf", 'resource "google_storage_bucket" "b" { name = "gbucket" }')
        output_file = os.path.join(self.output_dir, "terraform.json")

        captured_stdout = StringIO()
        sys.stdout = captured_stdout
        try:
            code = main(["-i", self.input_dir, "-o", output_file, "--summary"])
        finally:
            sys.stdout = sys.__stdout__

        self.assertEqual(code, 0)
        output_text = captured_stdout.getvalue()
        self.assertIn("Terraform Analysis Complete", output_text)
        self.assertIn("Resources:", output_text)
        self.assertIn("Schema: VALID", output_text)

    def test_09_strict_flag_success(self):
        """Test --strict flag returns exit code 0 when schema is valid."""
        self._write_tf("main.tf", 'resource "kubernetes_pod" "p" { metadata { name = "pod" } }')
        output_file = os.path.join(self.output_dir, "terraform.json")
        code = main(["-i", self.input_dir, "-o", output_file, "--strict"])
        self.assertEqual(code, 0)

    def test_10_single_tf_file_input(self):
        """Single .tf file input is accepted and parsed."""
        tf_file = os.path.join(self.test_dir, "single.tf")
        with open(tf_file, "w", encoding="utf-8") as f:
            f.write('resource "custom_res" "one" { prop = "val" }')
        output_file = os.path.join(self.output_dir, "single_out.json")
        code = main(["-i", tf_file, "-o", output_file])
        self.assertEqual(code, 0)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["resources"]), 1)
        self.assertEqual(data["resources"][0]["source_location"]["file"], "single.tf")

    def test_11_directory_tf_files_direct(self):
        """Directory with .tf files directly at root."""
        self._write_tf("direct.tf", 'resource "custom_res" "direct" { prop = 1 }')
        output_file = os.path.join(self.output_dir, "direct_out.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["resources"][0]["source_location"]["file"], "direct.tf")

    def test_12_directory_tf_files_nested_one_level(self):
        """Directory with .tf files nested one level deep."""
        sub_dir = os.path.join(self.input_dir, "sub")
        os.makedirs(sub_dir, exist_ok=True)
        with open(os.path.join(sub_dir, "nested.tf"), "w", encoding="utf-8") as f:
            f.write('resource "custom_res" "n1" { level = 1 }')

        output_file = os.path.join(self.output_dir, "nested1_out.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["resources"]), 1)
        self.assertEqual(data["resources"][0]["source_location"]["file"], "sub/nested.tf")

    def test_13_directory_tf_files_nested_many_levels(self):
        """Directory with .tf files nested many levels deep."""
        deep_dir = os.path.join(self.input_dir, "level1", "level2", "level3")
        os.makedirs(deep_dir, exist_ok=True)
        with open(os.path.join(deep_dir, "deep.tf"), "w", encoding="utf-8") as f:
            f.write('resource "custom_res" "deep" { depth = 3 }')

        output_file = os.path.join(self.output_dir, "deep_out.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["resources"]), 1)
        self.assertEqual(data["resources"][0]["source_location"]["file"], "level1/level2/level3/deep.tf")

    def test_14_mixed_nested_directories(self):
        """Directory with mixed nested directories containing .tf and non-.tf files."""
        os.makedirs(os.path.join(self.input_dir, "sub1"), exist_ok=True)
        os.makedirs(os.path.join(self.input_dir, "sub2"), exist_ok=True)

        self._write_tf("root.tf", 'resource "res_root" "r" {}')
        with open(os.path.join(self.input_dir, "README.md"), "w") as f:
            f.write("# Docs")
        with open(os.path.join(self.input_dir, "sub1", "mod.tf"), "w") as f:
            f.write('resource "res_sub1" "m" {}')
        with open(os.path.join(self.input_dir, "sub1", "data.json"), "w") as f:
            f.write('{}')
        with open(os.path.join(self.input_dir, "sub2", "script.sh"), "w") as f:
            f.write('#!/bin/bash')

        output_file = os.path.join(self.output_dir, "mixed_out.json")
        code = main(["-i", self.input_dir, "-o", output_file])
        self.assertEqual(code, 0)
        with open(output_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(len(data["resources"]), 2)
        files_found = {r["source_location"]["file"] for r in data["resources"]}
        self.assertEqual(files_found, {"root.tf", "sub1/mod.tf"})

    def test_15_directory_zero_tf_files(self):
        """Directory containing zero .tf files returns exit code 1."""
        os.makedirs(os.path.join(self.input_dir, "empty_sub"), exist_ok=True)
        with open(os.path.join(self.input_dir, "empty_sub", "notes.txt"), "w") as f:
            f.write("no terraform code here")

        code = main(["-i", self.input_dir])
        self.assertNotEqual(code, 0)

if __name__ == "__main__":
    unittest.main()
