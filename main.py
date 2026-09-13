import argparse
import os
import sys
import json
from datetime import datetime

from ast_extractor import parse_terraform_directory
from converter import convert_to_schema, save_json
from schema_validator import validate_schema, SchemaValidationError

def build_parser():
    parser = argparse.ArgumentParser(
        description="Terraform to Normalized JSON Converter and Security Analyzer"
    )
    parser.add_argument(
        "-i", "--input",
        default="./input",
        help="Input folder containing Terraform (.tf) files (default: ./input)"
    )
    parser.add_argument(
        "-o", "--output",
        default="./output/terraform.json",
        help="Output JSON file path (default: ./output/terraform.json)"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail with non-zero exit code if JSON schema validation fails"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print human-readable analysis summary to console"
    )
    return parser

def print_summary(data, schema_valid, input_path, output_path):
    print("\nTerraform Analysis Complete\n")
    print(f"Input:  {input_path}")
    print(f"Output: {output_path}\n")

    resources = data.get("resources", [])
    data_sources = data.get("data_sources", [])
    variables = data.get("variables", [])
    outputs = data.get("outputs", [])
    modules = data.get("modules", [])
    providers = data.get("providers", [])
    relationships = data.get("relationships", [])
    findings = data.get("security_findings", [])

    print(f"Resources:       {len(resources)}")
    print(f"Data Sources:    {len(data_sources)}")
    print(f"Variables:       {len(variables)}")
    print(f"Outputs:         {len(outputs)}")
    print(f"Modules:         {len(modules)}")
    print(f"Providers:       {len(providers)}")
    print(f"Relationships:   {len(relationships)}")
    print(f"Security Finds:  {len(findings)}\n")
    print(f"Schema: {'VALID' if schema_valid else 'INVALID'}\n")

def main(args=None):
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    input_path = os.path.abspath(parsed_args.input)
    output_path = os.path.abspath(parsed_args.output)

    # 1. Validate input path existence
    if not os.path.exists(input_path):
        print(f"Error: Input path does not exist: {input_path}", file=sys.stderr)
        return 1

    # 2. Parse & AST extraction (handles single file or directory recursively)
    try:
        parsed_data, source_locations = parse_terraform_directory(input_path)
    except Exception as e:
        print(f"Error parsing Terraform files: {e}", file=sys.stderr)
        return 1

    # 3. Ensure at least one .tf file was found and parsed
    if not parsed_data:
        print(f"Error: No .tf files found in input path: {input_path}", file=sys.stderr)
        return 1

    # 4. Convert to normalized schema
    try:
        converted_data = convert_to_schema(parsed_data, input_path, source_locations)
    except Exception as e:
        print(f"Error converting Terraform data: {e}", file=sys.stderr)
        return 1

    # 6. Schema validation
    schema_valid = False
    try:
        validate_schema(converted_data)
        schema_valid = True
    except SchemaValidationError as e:
        print(f"Schema Validation Error: {e}", file=sys.stderr)
        if parsed_args.strict:
            return 1
    except Exception as e:
        print(f"Validation Error: {e}", file=sys.stderr)
        if parsed_args.strict:
            return 1

    # 7. Write output JSON
    try:
        save_json(converted_data, output_path)
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        return 1

    print(f"Successfully generated normalized JSON at: {output_path}")

    # 8. Console summary if requested
    if parsed_args.summary:
        print_summary(converted_data, schema_valid, input_path, output_path)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
