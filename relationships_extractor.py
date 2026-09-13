import re

def extract_references(value, known_resource_ids=None):
    """
    Extracts cleaned Terraform references (without ${...} wrappers) from any object generically.
    Matches syntax-driven patterns:
      - var.name
      - resource_type.name.attribute
      - data.resource_type.name.attribute
      - module.name.output
      - local.name
    """
    references = []
    known_resource_ids = known_resource_ids or set()

    def extract_from_string(text):
        if not isinstance(text, str):
            return

        text_clean = text.strip()
        if text_clean.startswith("${") and text_clean.endswith("}"):
            text_clean = text_clean[2:-1].strip()

        plain_pattern = (
            r"\b("
            r"var\.[A-Za-z_][A-Za-z0-9_-]*"
            r"|data\.[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)?"
            r"|module\.[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)?"
            r"|local\.[A-Za-z_][A-Za-z0-9_-]*"
            r"|[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]*\.[A-Za-z_][A-Za-z0-9_-]+"
            r")\b"
        )

        for ref in re.findall(plain_pattern, text_clean):
            if ref in references:
                continue

            if (ref.startswith("var.") or
                ref.startswith("data.") or
                ref.startswith("module.") or
                ref.startswith("local.")):
                references.append(ref)
            else:
                parts = ref.split(".")
                if len(parts) >= 2:
                    target_res = f"{parts[0]}.{parts[1]}"
                    if target_res in known_resource_ids or "_" in parts[0]:
                        references.append(ref)

    def walk(obj):
        if isinstance(obj, str):
            extract_from_string(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if k in ["provider", "depends_on"]:
                    continue
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(value)
    return references

def clean_dependency_reference(dep_str):
    """
    Cleans dependency string expressions by removing ${...} wrappers if present.
    """
    if not isinstance(dep_str, str):
        return dep_str
    dep = dep_str.strip()
    if dep.startswith("${") and dep.endswith("}"):
        dep = dep[2:-1].strip()
    return dep

def build_relationships(resources, data_sources, modules, variables, outputs):
    """
    Generates relationship objects dynamically from references and depends_on across resources, modules, outputs.
    """
    relationships = []
    seen = set()

    def add_rel(source, target, rel_type, attrs=None, loc=None):
        key = (source, target, rel_type)
        if key in seen:
            return
        seen.add(key)

        loc_obj = loc if loc else {"file": None, "line": None, "column": None}
        relationships.append({
            "source": source,
            "target": target,
            "type": rel_type,
            "attributes": attrs or {},
            "source_location": loc_obj
        })

    # Resource relationships
    for res in resources:
        res_id = res["id"]
        loc = res.get("source_location")

        for dep in res.get("depends_on", []):
            clean_dep = clean_dependency_reference(dep)
            add_rel(res_id, clean_dep, "DEPENDS_ON", {}, loc)

        for ref in res.get("references", []):
            if ref.startswith("var."):
                add_rel(res_id, ref, "REFERENCES_VARIABLE", {"reference": ref}, loc)

            elif ref.startswith("data."):
                parts = ref.split(".")
                if len(parts) >= 3:
                    target_ds = ".".join(parts[:3])
                    add_rel(res_id, target_ds, "REFERENCES_DATA_SOURCE", {"reference": ref}, loc)

            elif ref.startswith("module."):
                parts = ref.split(".")
                if len(parts) >= 2:
                    target_mod = ".".join(parts[:2])
                    add_rel(res_id, target_mod, "REFERENCES_MODULE", {"reference": ref}, loc)

            elif "." in ref and not ref.startswith("local."):
                parts = ref.split(".")
                if len(parts) >= 2:
                    target_res = ".".join(parts[:2])
                    if target_res != res_id:
                        add_rel(res_id, target_res, "REFERENCES_RESOURCE", {"reference": ref}, loc)

    # Module relationships
    for mod in modules:
        mod_id = f"module.{mod['name']}"
        mod_inputs = mod.get("inputs", {})
        mod_loc = mod.get("source_location")
        refs = extract_references(mod_inputs)
        for ref in refs:
            if ref.startswith("var."):
                add_rel(mod_id, ref, "MODULE_INPUT", {"reference": ref}, mod_loc)
            elif "." in ref:
                parts = ref.split(".")
                if len(parts) >= 2:
                    target_res = ".".join(parts[:2])
                    add_rel(mod_id, target_res, "MODULE_INPUT", {"reference": ref}, mod_loc)

    return relationships
