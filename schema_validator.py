class SchemaValidationError(Exception):
    pass

def validate_schema(data):
    """
    Strictly validates the normalized JSON output against the target schema.
    Raises SchemaValidationError if any field is missing or malformed.
    """
    if not isinstance(data, dict):
        raise SchemaValidationError("Root structure must be a JSON object (dict)")

    required_root_keys = [
        "metadata", "resources", "data_sources", "variables",
        "outputs", "modules", "providers", "relationships", "security_findings"
    ]
    for key in required_root_keys:
        if key not in data:
            raise SchemaValidationError(f"Missing required root field: '{key}'")

    # 1. Metadata
    meta = data["metadata"]
    if not isinstance(meta, dict):
        raise SchemaValidationError("Root 'metadata' must be a dict")
    for fk in ["project_name", "terraform_version", "cloud_provider", "region", "generated_at"]:
        if fk not in meta:
            raise SchemaValidationError(f"Missing required metadata field: '{fk}'")

    # 2. Resources
    if not isinstance(data["resources"], list):
        raise SchemaValidationError("'resources' must be a list")

    for res in data["resources"]:
        if not isinstance(res, dict):
            raise SchemaValidationError("Each resource must be a dict")

        for rk in ["id", "type", "name", "provider", "region", "attributes", "tags", "security", "references", "depends_on", "source_location"]:
            if rk not in res:
                raise SchemaValidationError(f"Resource '{res.get('id', 'unknown')}' missing field '{rk}'")

        # Source location
        sl = res["source_location"]
        if not isinstance(sl, dict) or "file" not in sl or "line" not in sl or "column" not in sl:
            raise SchemaValidationError(f"Resource '{res['id']}' source_location must contain file, line, and column")

        # Security
        sec = res["security"]
        if not isinstance(sec, dict):
            raise SchemaValidationError(f"Resource '{res['id']}' security must be a dict")

        sec_bool_keys = [
            "internet_exposed", "public_access", "public_ip", "encryption_enabled",
            "logging_enabled", "authentication_required", "authorization_enabled",
            "least_privilege", "versioning_enabled", "backup_enabled", "deletion_protection"
        ]
        for sk in sec_bool_keys:
            if sk not in sec:
                raise SchemaValidationError(f"Resource '{res['id']}' security missing field '{sk}'")
            val = sec[sk]
            if val is not None and not isinstance(val, bool):
                raise SchemaValidationError(f"Resource '{res['id']}' security field '{sk}' must be bool or null, got {type(val).__name__}")

        if "encryption_type" not in sec:
            raise SchemaValidationError(f"Resource '{res['id']}' security missing encryption_type")

        # Ingress rules
        if not isinstance(sec["ingress_rules"], list):
            raise SchemaValidationError(f"Resource '{res['id']}' security.ingress_rules must be a list")
        for rule in sec["ingress_rules"]:
            if not isinstance(rule, dict):
                raise SchemaValidationError(f"Ingress rule in resource '{res['id']}' must be a dict")
            for irk in ["protocol", "from_port", "to_port", "sources", "description"]:
                if irk not in rule:
                    raise SchemaValidationError(f"Ingress rule missing field '{irk}'")

        # Egress rules
        if not isinstance(sec["egress_rules"], list):
            raise SchemaValidationError(f"Resource '{res['id']}' security.egress_rules must be a list")
        for rule in sec["egress_rules"]:
            if not isinstance(rule, dict):
                raise SchemaValidationError(f"Egress rule in resource '{res['id']}' must be a dict")
            for erk in ["protocol", "from_port", "to_port", "destinations", "description"]:
                if erk not in rule:
                    raise SchemaValidationError(f"Egress rule missing field '{erk}'")

        # IAM Permissions - MUST BE OBJECTS
        if not isinstance(sec["iam_permissions"], list):
            raise SchemaValidationError(f"Resource '{res['id']}' security.iam_permissions must be a list")
        for perm in sec["iam_permissions"]:
            if not isinstance(perm, dict):
                raise SchemaValidationError(f"IAM permission in resource '{res['id']}' MUST be an object/dict, got {type(perm).__name__}: {perm}")
            for pik in ["effect", "actions", "resources", "principals", "conditions"]:
                if pik not in perm:
                    raise SchemaValidationError(f"IAM permission object in resource '{res['id']}' missing field '{pik}'")
            if not isinstance(perm["actions"], list):
                raise SchemaValidationError(f"IAM permission 'actions' in resource '{res['id']}' must be a list")
            if not isinstance(perm["resources"], list):
                raise SchemaValidationError(f"IAM permission 'resources' in resource '{res['id']}' must be a list")

        # Secrets
        if not isinstance(sec["secrets"], list):
            raise SchemaValidationError(f"Resource '{res['id']}' security.secrets must be a list")
        for secret in sec["secrets"]:
            if not isinstance(secret, dict):
                raise SchemaValidationError(f"Secret in resource '{res['id']}' must be a dict")
            for sik in ["type", "reference", "exposed"]:
                if sik not in secret:
                    raise SchemaValidationError(f"Secret object in resource '{res['id']}' missing field '{sik}'")

    # 3. Data Sources
    if not isinstance(data["data_sources"], list):
        raise SchemaValidationError("'data_sources' must be a list")
    for ds in data["data_sources"]:
        for dsk in ["id", "type", "name", "provider", "attributes", "references"]:
            if dsk not in ds:
                raise SchemaValidationError(f"Data source '{ds.get('id', 'unknown')}' missing field '{dsk}'")

    # 4. Variables
    if not isinstance(data["variables"], list):
        raise SchemaValidationError("'variables' must be a list")
    for var in data["variables"]:
        for vk in ["name", "type", "default", "description", "sensitive", "validation"]:
            if vk not in var:
                raise SchemaValidationError(f"Variable '{var.get('name', 'unknown')}' missing field '{vk}'")

    # 5. Outputs
    if not isinstance(data["outputs"], list):
        raise SchemaValidationError("'outputs' must be a list")
    for out in data["outputs"]:
        for ok in ["name", "value", "description", "sensitive"]:
            if ok not in out:
                raise SchemaValidationError(f"Output '{out.get('name', 'unknown')}' missing field '{ok}'")

    # 6. Modules
    if not isinstance(data["modules"], list):
        raise SchemaValidationError("'modules' must be a list")
    for mod in data["modules"]:
        for mk in ["name", "source", "version", "inputs", "outputs"]:
            if mk not in mod:
                raise SchemaValidationError(f"Module '{mod.get('name', 'unknown')}' missing field '{mk}'")

    # 7. Providers
    if not isinstance(data["providers"], list):
        raise SchemaValidationError("'providers' must be a list")
    for prov in data["providers"]:
        for pk in ["name", "alias", "version", "configuration"]:
            if pk not in prov:
                raise SchemaValidationError(f"Provider '{prov.get('name', 'unknown')}' missing field '{pk}'")

    # 8. Relationships
    if not isinstance(data["relationships"], list):
        raise SchemaValidationError("'relationships' must be a list")
    for rel in data["relationships"]:
        for rlk in ["source", "target", "type", "attributes", "source_location"]:
            if rlk not in rel:
                raise SchemaValidationError(f"Relationship missing field '{rlk}'")
        loc = rel["source_location"]
        if not isinstance(loc, dict) or "file" not in loc or "line" not in loc or "column" not in loc:
            raise SchemaValidationError("Relationship source_location must contain file, line, and column")

    # 9. Security Findings
    if not isinstance(data["security_findings"], list):
        raise SchemaValidationError("'security_findings' must be a list")
    for sf in data["security_findings"]:
        for sfk in ["id", "severity", "category", "resource", "title", "description", "evidence", "attack_vector", "recommendation", "remediation"]:
            if sfk not in sf:
                raise SchemaValidationError(f"Security finding '{sf.get('id', 'unknown')}' missing field '{sfk}'")

    return True
