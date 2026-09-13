import os
import re
import hcl2

def clean_value(value):
    """
    Recursively clean values produced by the HCL parser.
    Removes parser-internal metadata keys beginning with '__'.
    """
    if isinstance(value, str):
        value = value.strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value

    if isinstance(value, list):
        return [clean_value(item) for item in value]

    if isinstance(value, dict):
        return {
            key: clean_value(val)
            for key, val in value.items()
            if not str(key).startswith("__")
        }

    return value

def extract_source_locations(file_path, display_path=None):
    """
    Scans raw .tf file text line by line to locate starting line and column numbers for:
      - resource "type" "name"
      - data "type" "name"
      - variable "name"
      - output "name"
      - module "name"
      - provider "name"
    Returns a dictionary keyed by block identifier.
    """
    locations = {}
    if not os.path.exists(file_path):
        return locations

    file_display = (display_path or os.path.basename(file_path)).replace("\\", "/")

    resource_pattern = re.compile(r'^\s*(resource)\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+["\']?([a-zA-Z0-9_-]+)["\']?')
    data_pattern = re.compile(r'^\s*(data)\s+["\']?([a-zA-Z0-9_-]+)["\']?\s+["\']?([a-zA-Z0-9_-]+)["\']?')
    named_block_pattern = re.compile(r'^\s*(variable|output|module|provider)\s+["\']?([a-zA-Z0-9_-]+)["\']?')

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            m_res = resource_pattern.match(line)
            if m_res:
                block_type, r_type, r_name = m_res.group(1), m_res.group(2), m_res.group(3)
                col = line.find("resource") + 1
                key = ("resource", r_type, r_name)
                if key not in locations:
                    locations[key] = {"file": file_display, "line": idx, "column": col}
                continue

            m_data = data_pattern.match(line)
            if m_data:
                block_type, d_type, d_name = m_data.group(1), m_data.group(2), m_data.group(3)
                col = line.find("data") + 1
                key = ("data", d_type, d_name)
                if key not in locations:
                    locations[key] = {"file": file_display, "line": idx, "column": col}
                continue

            m_named = named_block_pattern.match(line)
            if m_named:
                b_type, b_name = m_named.group(1), m_named.group(2)
                col = line.find(b_type) + 1
                key = (b_type, None, b_name)
                if key not in locations:
                    locations[key] = {"file": file_display, "line": idx, "column": col}

    return locations

def parse_terraform_directory(input_path):
    """
    Recursively discovers and parses all .tf files from a directory or single .tf file using hcl2.
    Determines relative file paths for source locations deterministically.
    """
    parsed_files = {}
    source_locations = {}

    if os.path.isfile(input_path):
        if not input_path.endswith(".tf"):
            raise ValueError(f"Input file is not a .tf file: {input_path}")
        file_key = os.path.basename(input_path)
        with open(input_path, "r", encoding="utf-8") as f:
            parsed_files[file_key] = hcl2.load(f)
        locs = extract_source_locations(input_path, display_path=file_key)
        source_locations.update(locs)
        return parsed_files, source_locations

    # Input path is a directory: discover all .tf files recursively
    discovered_files = []
    for root, _, files in os.walk(input_path):
        for file in files:
            if file.endswith(".tf"):
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, input_path).replace("\\", "/")
                discovered_files.append((rel_path, full_path))

    # Sort discovered paths deterministically
    discovered_files.sort(key=lambda x: x[0])

    for rel_path, full_path in discovered_files:
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                parsed_files[rel_path] = hcl2.load(f)
            locs = extract_source_locations(full_path, display_path=rel_path)
            source_locations.update(locs)
        except Exception:
            continue

    return parsed_files, source_locations
