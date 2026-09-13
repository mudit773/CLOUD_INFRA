import json
from datetime import datetime, timezone
import os
import re

from ast_extractor import clean_value
from security_analyzer import analyze_security, default_security
from relationships_extractor import extract_references, build_relationships, clean_dependency_reference
from findings_generator import generate_security_findings
from schema_validator import validate_schema

def clean_terraform_type(value):
    """
    Converts parser representations such as ${list(string)} into cleaner type strings.
    """
    value = clean_value(value)
    if not isinstance(value, str):
        return value
    if value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    return value

def is_utility_provider(provider_name, parsed_data):
    """
    Generically checks if a provider is a pure utility/support provider
    (no top-level provider block, and no infrastructure attributes across its resources).
    Zero hardcoded provider names or resource types.
    """
    # Check if there is an explicit provider block or required_providers for this provider_name
    for content in parsed_data.values():
        for prov_block in content.get("provider", []):
            if isinstance(prov_block, dict) and provider_name in prov_block:
                return False
        for terraform_block in content.get("terraform", []):
            if isinstance(terraform_block, dict):
                req_providers = terraform_block.get("required_providers", [])
                blocks = req_providers if isinstance(req_providers, list) else [req_providers]
                for req in blocks:
                    if isinstance(req, dict) and provider_name in req:
                        return False

    # Check if any resource under this provider has cloud infrastructure indicators
    infra_indicators = {
        "region", "location", "zone", "project", "credentials", "profile",
        "subscription_id", "features", "vpc", "cidr", "subnet", "network",
        "ip", "endpoint", "ami", "tier", "instance", "bucket", "storage",
        "database", "cluster", "security_group", "firewall", "iam", "role",
        "kms", "key_vault", "access_key", "secret_key", "account"
    }

    for content in parsed_data.values():
        for res_block in content.get("resource", []):
            if isinstance(res_block, dict):
                for rtype, rdata in res_block.items():
                    if str(rtype).startswith("__") or not isinstance(rdata, dict):
                        continue
                    if detect_resource_provider(str(rtype).strip('"\'')) == provider_name:
                        for rattrs in rdata.values():
                            if isinstance(rattrs, dict):
                                for k in rattrs.keys():
                                    if not str(k).startswith("__") and str(k).lower() in infra_indicators:
                                        return False

    return True

def detect_cloud_provider(parsed_data):
    """
    Dynamically discovers cloud infrastructure providers from AST.
    Distinguishes cloud providers from utility providers generically.
    Zero hardcoding of provider names or resource types.
    - 1 distinct cloud provider -> provider name (string)
    - 0 or >1 distinct cloud providers -> None (JSON null)
    """
    declared_providers = set()
    resource_providers = set()

    for content in parsed_data.values():
        # Top-level provider blocks
        for provider_block in content.get("provider", []):
            if isinstance(provider_block, dict):
                for provider_name in provider_block.keys():
                    if not str(provider_name).startswith("__"):
                        declared_providers.add(str(provider_name).strip('"\''))

        # terraform.required_providers blocks
        for terraform_block in content.get("terraform", []):
            if isinstance(terraform_block, dict):
                req_providers = terraform_block.get("required_providers", [])
                blocks = req_providers if isinstance(req_providers, list) else [req_providers]
                for req in blocks:
                    if isinstance(req, dict):
                        for pname in req.keys():
                            if not str(pname).startswith("__"):
                                declared_providers.add(str(pname).strip('"\''))

        # Resource blocks
        for res_block in content.get("resource", []):
            if isinstance(res_block, dict):
                for rtype in res_block.keys():
                    if not str(rtype).startswith("__"):
                        prov = detect_resource_provider(str(rtype).strip('"\''))
                        if prov:
                            resource_providers.add(prov)

        # Data source blocks
        for data_block in content.get("data", []):
            if isinstance(data_block, dict):
                for dtype in data_block.keys():
                    if not str(dtype).startswith("__"):
                        prov = detect_resource_provider(str(dtype).strip('"\''))
                        if prov:
                            resource_providers.add(prov)

    # Filter declared_providers (ignoring pure utility providers if any were declared without infra)
    if declared_providers:
        cloud_candidates = {p for p in declared_providers if not is_utility_provider(p, parsed_data)}
        active = cloud_candidates if cloud_candidates else declared_providers
        if len(active) == 1:
            return list(active)[0]
        return None

    # If no declared_providers exist, filter resource_providers
    cloud_candidates = {p for p in resource_providers if not is_utility_provider(p, parsed_data)}
    if len(cloud_candidates) == 1:
        return list(cloud_candidates)[0]

    return None

def is_static_concrete_value(val):
    """
    Returns True if val is a concrete, static scalar value (e.g. "us-central1"),
    and False if val is None, empty, or an unresolved Terraform expression/reference.
    Zero hardcoding of provider/region/variable names.
    """
    if val is None or not isinstance(val, str):
        return False
    val_str = val.strip()
    if not val_str:
        return False
    # Check for Terraform expression/reference patterns
    if "${" in val_str or "}" in val_str:
        return False
    if val_str.startswith("var.") or val_str.startswith("local.") or val_str.startswith("module.") or val_str.startswith("data.") or val_str.startswith("path.") or val_str.startswith("each.") or val_str.startswith("count."):
        return False
    return True

def detect_metadata_region(parsed_data, variable_defaults):
    """
    Determines metadata.region generically:
    - If exactly ONE unambiguous concrete static region is discovered across the parsed configuration, return it.
    - If multiple conflicting regions exist, or region is an unresolved expression/reference, return None (JSON null).
    - If no region can be determined, return None (JSON null).
    Zero hardcoding of provider names, variable names, or region strings.
    """
    discovered_regions = set()

    # Check if 'region' variable has a concrete static default value
    var_region = variable_defaults.get("region")
    if is_static_concrete_value(var_region):
        discovered_regions.add(var_region)

    # Check provider blocks for region attributes
    for content in parsed_data.values():
        for prov_block in content.get("provider", []):
            if isinstance(prov_block, dict):
                for pdata in prov_block.values():
                    if isinstance(pdata, dict):
                        raw_reg = pdata.get("region") or pdata.get("location")
                        if raw_reg is not None:
                            cleaned = clean_value(raw_reg)
                            if isinstance(cleaned, str):
                                ref_str = cleaned.strip()
                                if ref_str.startswith("${") and ref_str.endswith("}"):
                                    ref_str = ref_str[2:-1].strip()
                                if ref_str.startswith("var."):
                                    vname = ref_str[4:]
                                    resolved = variable_defaults.get(vname)
                                    if is_static_concrete_value(resolved):
                                        discovered_regions.add(resolved)
                                elif is_static_concrete_value(cleaned):
                                    discovered_regions.add(cleaned)

    if len(discovered_regions) == 1:
        return list(discovered_regions)[0]

    return None

def resolve_resource_region(clean_attrs, variable_defaults):
    """
    Generic resource region resolution.
    Only derives region if explicit region/location attribute exists on the resource.
    Resolves var references if variable_defaults is available.
    Returns None if region cannot be determined from resource attributes.
    """
    raw = None
    if "region" in clean_attrs:
        raw = clean_attrs["region"]
    elif "location" in clean_attrs:
        raw = clean_attrs["location"]

    if raw is None or raw == "":
        return None

    if isinstance(raw, str):
        ref_str = raw.strip()
        if ref_str.startswith("${") and ref_str.endswith("}"):
            ref_str = ref_str[2:-1].strip()
        if ref_str.startswith("var."):
            var_name = ref_str[4:]
            if var_name in variable_defaults and variable_defaults[var_name] is not None:
                return variable_defaults[var_name]
        return raw

    return raw

def detect_resource_provider(resource_type):
    """
    Dynamically derives provider name from resource type prefix.
    Zero provider hardcoding.
    """
    if not resource_type:
        return None
    if "_" in resource_type:
        return resource_type.split("_")[0]
    return resource_type

def get_variable_defaults_and_map(parsed_data):
    defaults = {}
    variables_map = {}
    for content in parsed_data.values():
        for var_block in content.get("variable", []):
            if isinstance(var_block, dict):
                for vname, vdata in var_block.items():
                    if str(vname).startswith("__"):
                        continue
                    vname_clean = str(vname).strip('"\'')
                    if not isinstance(vdata, dict):
                        vdata = {}
                    
                    val_default = clean_value(vdata.get("default"))
                    if "default" in vdata:
                        defaults[vname_clean] = val_default

                    variables_map[vname_clean] = {
                        "name": vname_clean,
                        "type": clean_terraform_type(vdata.get("type")),
                        "default": val_default,
                        "description": clean_value(vdata.get("description")),
                        "sensitive": bool(vdata.get("sensitive", False)),
                        "validation": clean_value(vdata.get("validation", {}))
                    }
    return defaults, variables_map

def get_terraform_version(parsed_data):
    for content in parsed_data.values():
        for tf_block in content.get("terraform", []):
            if isinstance(tf_block, dict) and "required_version" in tf_block:
                return clean_value(tf_block["required_version"])
    return None

def get_provider_versions(parsed_data):
    provider_versions = {}
    for content in parsed_data.values():
        for tf_block in content.get("terraform", []):
            if isinstance(tf_block, dict):
                req_providers = tf_block.get("required_providers", [])
                blocks = req_providers if isinstance(req_providers, list) else [req_providers]
                for req in blocks:
                    if isinstance(req, dict):
                        for pname, pdata in req.items():
                            if str(pname).startswith("__"):
                                continue
                            pname_clean = str(pname).strip('"\'')
                            ver = None
                            if isinstance(pdata, dict):
                                ver = clean_value(pdata.get("version"))
                            elif isinstance(pdata, str):
                                ver = clean_value(pdata)
                            provider_versions[pname_clean] = ver
    return provider_versions

def convert_to_schema(parsed_data, input_folder, source_locations=None):
    """
    Main conversion orchestrator: syntax-driven Terraform AST normalization.
    Converts ANY valid Terraform configuration into the exact target schema.
    """
    source_locations = source_locations or {}
    variable_defaults, variables_map = get_variable_defaults_and_map(parsed_data)
    cloud_provider = detect_cloud_provider(parsed_data)
    provider_versions = get_provider_versions(parsed_data)
    terraform_version = get_terraform_version(parsed_data)

    project_name = os.path.basename(os.path.normpath(input_folder))

    result = {
        "metadata": {
            "project_name": project_name,
            "terraform_version": terraform_version,
            "cloud_provider": cloud_provider,
            "region": detect_metadata_region(parsed_data, variable_defaults),
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "resources": [],
        "data_sources": [],
        "variables": [],
        "outputs": [],
        "modules": [],
        "providers": [],
        "relationships": [],
        "security_findings": []
    }

    # 1. Variables
    for var_info in variables_map.values():
        result["variables"].append(var_info)

    # 2. Collect known resource IDs dynamically
    known_resource_ids = set()
    for filename, content in parsed_data.items():
        for res_block in content.get("resource", []):
            if isinstance(res_block, dict):
                for rtype, rdata in res_block.items():
                    if str(rtype).startswith("__") or not isinstance(rdata, dict):
                        continue
                    rtype_clean = str(rtype).strip('"\'')
                    for rname in rdata.keys():
                        if not str(rname).startswith("__"):
                            rname_clean = str(rname).strip('"\'')
                            known_resource_ids.add(f"{rtype_clean}.{rname_clean}")

    # 3. Process Resources
    for filename, content in parsed_data.items():
        for res_block in content.get("resource", []):
            if not isinstance(res_block, dict):
                continue

            for rtype, rdata in res_block.items():
                if str(rtype).startswith("__") or not isinstance(rdata, dict):
                    continue

                rtype_clean = str(rtype).strip('"\'')
                for rname, rattrs in rdata.items():
                    if str(rname).startswith("__"):
                        continue

                    rname_clean = str(rname).strip('"\'')
                    if not isinstance(rattrs, dict):
                        rattrs = {}

                    clean_attrs = clean_value({
                        k: v for k, v in rattrs.items()
                        if not str(k).startswith("__")
                    })

                    res_id = f"{rtype_clean}.{rname_clean}"

                    # Source location
                    loc_key = ("resource", rtype_clean, rname_clean)
                    sloc = source_locations.get(loc_key, {"file": filename, "line": None, "column": None})

                    # Tags
                    tags = clean_attrs.get("tags", {})
                    if not isinstance(tags, dict):
                        tags = {}

                    # Depends_on
                    depends_on_list = []
                    if "depends_on" in clean_attrs:
                        raw_dep = clean_attrs.pop("depends_on")
                        if isinstance(raw_dep, list):
                            depends_on_list = [clean_dependency_reference(d) for d in raw_dep]
                        elif isinstance(raw_dep, str):
                            depends_on_list = [clean_dependency_reference(raw_dep)]

                    # Region resolution
                    region_val = resolve_resource_region(clean_attrs, variable_defaults)

                    # Extract references
                    all_refs = extract_references(clean_attrs, known_resource_ids)

                    # Security analysis
                    sec_obj = analyze_security(rtype_clean, clean_attrs, variables_map)

                    res_obj = {
                        "id": res_id,
                        "type": rtype_clean,
                        "name": rname_clean,
                        "provider": detect_resource_provider(rtype_clean),
                        "region": region_val,
                        "attributes": clean_attrs,
                        "tags": tags,
                        "security": sec_obj,
                        "references": all_refs,
                        "depends_on": depends_on_list,
                        "source_location": sloc
                    }

                    result["resources"].append(res_obj)

    # 4. Data Sources
    for filename, content in parsed_data.items():
        for data_block in content.get("data", []):
            if isinstance(data_block, dict):
                for dtype, ddata in data_block.items():
                    if str(dtype).startswith("__") or not isinstance(ddata, dict):
                        continue
                    dtype_clean = str(dtype).strip('"\'')
                    for dname, dattrs in ddata.items():
                        if str(dname).startswith("__"):
                            continue
                        dname_clean = str(dname).strip('"\'')
                        clean_dattrs = clean_value({
                            k: v for k, v in dattrs.items()
                            if not str(k).startswith("__")
                        })
                        ds_id = f"{dtype_clean}.{dname_clean}"
                        loc_key = ("data", dtype_clean, dname_clean)
                        sloc = source_locations.get(loc_key, {"file": filename, "line": None, "column": None})

                        result["data_sources"].append({
                            "id": ds_id,
                            "type": dtype_clean,
                            "name": dname_clean,
                            "provider": detect_resource_provider(dtype_clean),
                            "attributes": clean_dattrs,
                            "references": extract_references(clean_dattrs, known_resource_ids)
                        })

    # 5. Outputs
    for filename, content in parsed_data.items():
        for out_block in content.get("output", []):
            if isinstance(out_block, dict):
                for oname, odata in out_block.items():
                    if str(oname).startswith("__"):
                        continue
                    oname_clean = str(oname).strip('"\'')
                    if not isinstance(odata, dict):
                        odata = {}

                    result["outputs"].append({
                        "name": oname_clean,
                        "value": clean_value(odata.get("value")),
                        "description": clean_value(odata.get("description")),
                        "sensitive": bool(odata.get("sensitive", False))
                    })

    # 6. Modules
    for filename, content in parsed_data.items():
        for mod_block in content.get("module", []):
            if isinstance(mod_block, dict):
                for mname, mdata in mod_block.items():
                    if str(mname).startswith("__"):
                        continue
                    mname_clean = str(mname).strip('"\'')
                    if not isinstance(mdata, dict):
                        mdata = {}
                    clean_mdata = clean_value({
                        k: v for k, v in mdata.items()
                        if not str(k).startswith("__")
                    })
                    loc_key = ("module", None, mname_clean)
                    sloc = source_locations.get(loc_key, {"file": filename, "line": None, "column": None})

                    result["modules"].append({
                        "name": mname_clean,
                        "source": clean_mdata.get("source"),
                        "version": clean_mdata.get("version"),
                        "inputs": clean_mdata,
                        "outputs": {},
                        "source_location": sloc
                    })

    # 7. Providers
    configured_providers = set()
    for filename, content in parsed_data.items():
        for prov_block in content.get("provider", []):
            if isinstance(prov_block, dict):
                for pname, pdata in prov_block.items():
                    if str(pname).startswith("__"):
                        continue
                    pname_clean = str(pname).strip('"\'')
                    configured_providers.add(pname_clean)
                    if not isinstance(pdata, dict):
                        pdata = {}
                    clean_pdata = clean_value({
                        k: v for k, v in pdata.items()
                        if not str(k).startswith("__")
                    })

                    result["providers"].append({
                        "name": pname_clean,
                        "alias": clean_value(clean_pdata.get("alias")),
                        "version": provider_versions.get(pname_clean),
                        "configuration": clean_pdata
                    })

    for pname, ver in provider_versions.items():
        if pname not in configured_providers:
            result["providers"].append({
                "name": pname,
                "alias": None,
                "version": ver,
                "configuration": {}
            })

    # 8. Relationships
    result["relationships"] = build_relationships(
        result["resources"],
        result["data_sources"],
        result["modules"],
        result["variables"],
        result["outputs"]
    )

    # 9. Security Findings
    result["security_findings"] = generate_security_findings(result["resources"])

    # 10. Schema Validation
    validate_schema(result)

    return result

def save_json(data, output_file):
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)