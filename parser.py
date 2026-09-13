import os
from datetime import datetime
import json

from ast_extractor import parse_terraform_directory
from converter import convert_to_schema, save_json
from schema_validator import validate_schema

def parse_terraform_folder(folder_path):
    parsed_files, source_locations = parse_terraform_directory(folder_path)
    return parsed_files, source_locations

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        input_folder = sys.argv[1].strip()
    else:
        input_folder = input("Enter Terraform folder path: ").strip()

    input_folder = os.path.abspath(input_folder)
    output_file = os.path.abspath("output/terraform.json")

    print(f"Input folder:  {input_folder}")
    print(f"Output file:   {output_file}")

    if not os.path.isdir(input_folder):
        raise FileNotFoundError(f"Input folder does not exist: {input_folder}")

    output_dir = os.path.dirname(output_file)
    os.makedirs(output_dir, exist_ok=True)

    print("Parsing Terraform files...")
    parsed_data, source_locations = parse_terraform_folder(input_folder)
    print(f"Found {len(parsed_data)} .tf file(s): {list(parsed_data.keys())}")

    print("Converting to normalized JSON and validating schema...")
    final_data = convert_to_schema(parsed_data, input_folder, source_locations)

    print("Saving normalized JSON...")
    save_json(final_data, output_file)

    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        last_modified = datetime.fromtimestamp(os.path.getmtime(output_file))
        print(f"Done! JSON successfully generated at: {output_file}")
        print(f"  File size:      {file_size} bytes")
        print(f"  Last modified:  {last_modified}")
    else:
        print(f"WARNING: Output file was not found at {output_file}")