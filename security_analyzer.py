import json
import re

def default_security():
    """
    Returns the exact target security schema structure with default values.
    """
    return {
        "internet_exposed": None,
        "public_access": None,
        "public_ip": None,
        "encryption_enabled": None,
        "encryption_type": None,
        "logging_enabled": None,
        "authentication_required": None,
        "authorization_enabled": None,
        "least_privilege": None,
        "versioning_enabled": None,
        "backup_enabled": None,
        "deletion_protection": None,
        "ingress_rules": [],
        "egress_rules": [],
        "iam_permissions": [],
        "secrets": []
    }

def normalize_to_list(val):
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v).strip('"\'') for v in val if v is not None]
    return [str(val).strip('"\'')]

def normalize_principals(principal_val):
    if not principal_val:
        return []
    if isinstance(principal_val, str):
        p = principal_val.strip('"\'')
        if ":" in p and not p.startswith("arn:"):
            p = p.split(":", 1)[1].strip()
        return [p] if p else []
    if isinstance(principal_val, list):
        res = []
        for item in principal_val:
            res.extend(normalize_principals(item))
        return res
    if isinstance(principal_val, dict):
        res = []
        for k, v in principal_val.items():
            if isinstance(v, list):
                for sub in v:
                    val_str = str(sub).strip('"\'')
                    if ":" in val_str and not val_str.startswith("arn:"):
                        val_str = val_str.split(":", 1)[1].strip()
                    res.append(val_str)
            elif isinstance(v, dict):
                for dk, dv in v.items():
                    val_str = str(dv).strip('"\'')
                    if ":" in val_str and not val_str.startswith("arn:"):
                        val_str = val_str.split(":", 1)[1].strip()
                    res.append(val_str)
            else:
                val_str = str(v).strip('"\'')
                if ":" in val_str and not val_str.startswith("arn:"):
                    val_str = val_str.split(":", 1)[1].strip()
                res.append(val_str)
        return res
    return [str(principal_val)]

def parse_statement_dict(stmt):
    if not isinstance(stmt, dict):
        return None

    effect = stmt.get("Effect", stmt.get("effect", "Allow"))
    if isinstance(effect, str):
        effect = effect.strip('"\'')
    else:
        effect = "Allow"

    action_raw = stmt.get("Action", stmt.get("action", stmt.get("actions", [])))
    actions = normalize_to_list(action_raw)

    resource_raw = stmt.get("Resource", stmt.get("resource", stmt.get("resources", [])))
    resources = normalize_to_list(resource_raw)

    principal_raw = stmt.get("Principal", stmt.get("principal", stmt.get("principals", [])))
    principals = normalize_principals(principal_raw)

    condition_raw = stmt.get("Condition", stmt.get("condition", stmt.get("conditions", {})))
    conditions = condition_raw if isinstance(condition_raw, dict) else {}

    return {
        "effect": effect,
        "actions": actions,
        "resources": resources,
        "principals": principals,
        "conditions": conditions
    }

def parse_iam_policy_document(policy_val):
    """
    Parses permission representations (JSON string, HCL jsonencode string, dict, or list)
    into a list of permission objects matching:
      {
        "effect": str,
        "actions": [str],
        "resources": [str],
        "principals": [str],
        "conditions": dict
      }
    """
    permissions = []
    if not policy_val:
        return permissions

    if isinstance(policy_val, dict):
        stmt = policy_val.get("Statement", policy_val.get("statement", []))
        if isinstance(stmt, list):
            for s in stmt:
                p = parse_statement_dict(s)
                if p:
                    permissions.append(p)
        elif isinstance(stmt, dict):
            p = parse_statement_dict(stmt)
            if p:
                permissions.append(p)
        return permissions

    if isinstance(policy_val, list):
        for item in policy_val:
            permissions.extend(parse_iam_policy_document(item))
        return permissions

    if isinstance(policy_val, str):
        text = policy_val.strip()

        if text.startswith("${") and text.endswith("}"):
            text = text[2:-1].strip()

        if text.startswith("jsonencode(") and text.endswith(")"):
            text = text[11:-1].strip()

        try:
            parsed_json = json.loads(text)
            return parse_iam_policy_document(parsed_json)
        except Exception:
            pass

        statement_blocks = re.findall(r'\{[^{}]*Effect[^{}]*\}', text, re.DOTALL)
        if not statement_blocks:
            statement_blocks = re.findall(r'\{[^{}]*(?:Action|Resource)[^{}]*\}', text, re.DOTALL)

        if not statement_blocks:
            statement_blocks = [text]

        for block in statement_blocks:
            effect_m = re.search(r'Effect\s*[:=]\s*["\']?([A-Za-z]+)["\']?', block)
            effect = effect_m.group(1) if effect_m else "Allow"

            actions = []
            action_list_m = re.search(r'Action\s*[:=]\s*\[(.*?)\]', block, re.DOTALL)
            if action_list_m:
                actions = re.findall(r'["\']([^"\']+)["\']', action_list_m.group(1))
            else:
                action_str_m = re.search(r'Action\s*[:=]\s*["\']([^"\']+)["\']', block)
                if action_str_m:
                    actions = [action_str_m.group(1)]

            resources = []
            resource_list_m = re.search(r'Resource\s*[:=]\s*\[(.*?)\]', block, re.DOTALL)
            if resource_list_m:
                resources = re.findall(r'["\']([^"\']+)["\']', resource_list_m.group(1))
            else:
                resource_str_m = re.search(r'Resource\s*[:=]\s*["\']([^"\']+)["\']', block)
                if resource_str_m:
                    resources = [resource_str_m.group(1)]

            principals = []
            principal_m = re.search(r'Principal\s*[:=]\s*(?:\{([^}]+)\}|["\']([^"\']+)["\'])', block)
            if principal_m:
                if principal_m.group(2):
                    principals = [principal_m.group(2)]
                elif principal_m.group(1):
                    pairs = re.findall(r'([A-Za-z0-9_-]+)\s*[:=]\s*["\']?([^"\',}]+)["\']?', principal_m.group(1))
                    for k, v in pairs:
                        principals.append(v.strip())

            if actions:
                permissions.append({
                    "effect": effect,
                    "actions": actions,
                    "resources": resources,
                    "principals": principals,
                    "conditions": {}
                })

    return permissions

def detect_secrets(resource_type, attributes, variables_map=None):
    """
    Detects secret references or sensitive fields in resource attributes generically.
    Zero provider-specific resource hardcoding.
    """
    secrets = []
    if not isinstance(attributes, dict):
        return secrets

    variables_map = variables_map or {}
    secret_keywords = ["password", "secret", "token", "credential", "api_key", "private_key", "auth_key"]

    def walk_and_inspect(key_name, val):
        if isinstance(val, str):
            val_clean = val.strip()
            m_var = re.search(r'\bvar\.([A-Za-z0-9_-]+)\b', val_clean)
            if m_var:
                var_name = m_var.group(1)
                var_info = variables_map.get(var_name, {})
                is_sensitive = var_info.get("sensitive", False)
                is_secret_name = any(kw in var_name.lower() for kw in secret_keywords) or any(kw in str(key_name).lower() for kw in secret_keywords)

                if is_sensitive or is_secret_name:
                    stype = "password" if "password" in var_name.lower() or "password" in str(key_name).lower() else ("token" if "token" in var_name.lower() else "secret")
                    secrets.append({
                        "type": stype,
                        "reference": f"var.{var_name}",
                        "exposed": False
                    })
                    return

            if any(kw in str(key_name).lower() for kw in secret_keywords):
                m_ref = re.search(r'\b([a-z0-9_]+\.[a-z0-9_.]+|data\.[a-z0-9_.]+|module\.[a-z0-9_.]+)\b', val_clean)
                if m_ref:
                    secrets.append({
                        "type": str(key_name),
                        "reference": m_ref.group(1),
                        "exposed": False
                    })
                elif not val_clean.startswith("${") and len(val_clean) > 0:
                    secrets.append({
                        "type": str(key_name),
                        "reference": f"attribute:{key_name}",
                        "exposed": True
                    })

        elif isinstance(val, dict):
            for k, v in val.items():
                walk_and_inspect(k, v)
        elif isinstance(val, list):
            for item in val:
                walk_and_inspect(key_name, item)

    for k, v in attributes.items():
        walk_and_inspect(k, v)

    if "secret" in str(resource_type).lower():
        name_ref = attributes.get("name", attributes.get("secret_id", "secret"))
        secrets.append({
            "type": "secret_manager",
            "reference": str(name_ref),
            "exposed": False
        })

    return secrets

def extract_rule_sources(rule):
    if not isinstance(rule, dict):
        return []
    sources = []

    raw_src = (rule.get("sources") or rule.get("source") or rule.get("source_addresses") or 
               rule.get("source_address_prefix") or rule.get("source_address_prefixes") or 
               rule.get("cidr_blocks") or rule.get("cidr") or rule.get("cidrs"))

    if raw_src is not None:
        if isinstance(raw_src, list):
            for s in raw_src:
                if s is not None:
                    sources.append(str(s).strip('"\''))
        elif isinstance(raw_src, (str, int, float, bool)):
            sources.append(str(raw_src).strip('"\''))

    ipv6 = rule.get("ipv6_cidr_blocks") or rule.get("ipv6_cidrs")
    if ipv6 is not None:
        if isinstance(ipv6, list):
            for s in ipv6:
                if s is not None:
                    sources.append(str(s).strip('"\''))
        elif isinstance(ipv6, (str, int, float, bool)):
            sources.append(str(ipv6).strip('"\''))

    sg = rule.get("security_groups")
    if sg is not None:
        if isinstance(sg, list):
            for s in sg:
                if s is not None:
                    sources.append(str(s).strip('"\''))
        elif isinstance(sg, (str, int, float, bool)):
            sources.append(str(sg).strip('"\''))

    return sources

def extract_rule_destinations(rule):
    if not isinstance(rule, dict):
        return []
    destinations = []

    raw_dst = (rule.get("destinations") or rule.get("destination") or rule.get("destination_addresses") or 
               rule.get("destination_address_prefix") or rule.get("destination_address_prefixes") or 
               rule.get("cidr_blocks") or rule.get("cidr") or rule.get("cidrs"))

    if raw_dst is not None:
        if isinstance(raw_dst, list):
            for d in raw_dst:
                if d is not None:
                    destinations.append(str(d).strip('"\''))
        elif isinstance(raw_dst, (str, int, float, bool)):
            destinations.append(str(raw_dst).strip('"\''))

    ipv6 = rule.get("ipv6_cidr_blocks") or rule.get("ipv6_cidrs")
    if ipv6 is not None:
        if isinstance(ipv6, list):
            for d in ipv6:
                if d is not None:
                    destinations.append(str(d).strip('"\''))
        elif isinstance(ipv6, (str, int, float, bool)):
            destinations.append(str(ipv6).strip('"\''))

    return destinations

def parse_network_rules(attributes):
    ingress_rules = []
    egress_rules = []

    if not isinstance(attributes, dict):
        return ingress_rules, egress_rules

    # 1. Ingress blocks
    raw_ingress = attributes.get("ingress", [])
    if isinstance(raw_ingress, dict):
        raw_ingress = [raw_ingress]
    if isinstance(raw_ingress, list):
        for rule in raw_ingress:
            if not isinstance(rule, dict):
                continue
            sources = extract_rule_sources(rule)
            ingress_rules.append({
                "protocol": rule.get("protocol"),
                "from_port": rule.get("from_port"),
                "to_port": rule.get("to_port"),
                "sources": sources,
                "description": rule.get("description")
            })

    # 2. Egress blocks
    raw_egress = attributes.get("egress", [])
    if isinstance(raw_egress, dict):
        raw_egress = [raw_egress]
    if isinstance(raw_egress, list):
        for rule in raw_egress:
            if not isinstance(rule, dict):
                continue
            dests = extract_rule_destinations(rule)
            egress_rules.append({
                "protocol": rule.get("protocol"),
                "from_port": rule.get("from_port"),
                "to_port": rule.get("to_port"),
                "destinations": dests,
                "description": rule.get("description")
            })

    # 3. Direction-based security rules (security_rule)
    raw_sec_rules = attributes.get("security_rule", [])
    if isinstance(raw_sec_rules, dict):
        raw_sec_rules = [raw_sec_rules]
    if isinstance(raw_sec_rules, list):
        for rule in raw_sec_rules:
            if not isinstance(rule, dict):
                continue
            direction = str(rule.get("direction", "")).lower()
            proto = rule.get("protocol")
            f_port = rule.get("source_port_range")
            t_port = rule.get("destination_port_range")
            desc = rule.get("description")

            if direction == "inbound":
                sources = extract_rule_sources(rule)
                ingress_rules.append({
                    "protocol": proto,
                    "from_port": f_port,
                    "to_port": t_port,
                    "sources": sources,
                    "description": desc
                })
            elif direction == "outbound":
                destinations = extract_rule_destinations(rule)
                egress_rules.append({
                    "protocol": proto,
                    "from_port": f_port,
                    "to_port": t_port,
                    "destinations": destinations,
                    "description": desc
                })

    return ingress_rules, egress_rules

def analyze_security(resource_type, attributes, variables_map=None):
    """
    Analyzes resource attributes and populates the normalized security schema.
    Purely syntax-driven with zero provider or resource type hardcoding.
    """
    security = default_security()
    if not isinstance(attributes, dict):
        return security

    # 1. IAM permissions & Authentication/Authorization
    policy = attributes.get("policy")
    if policy:
        perms = parse_iam_policy_document(policy)
        security["iam_permissions"].extend(perms)
        if perms:
            security["authorization_enabled"] = True

    assume_role_policy = attributes.get("assume_role_policy")
    if assume_role_policy:
        perms = parse_iam_policy_document(assume_role_policy)
        security["iam_permissions"].extend(perms)
        security["authentication_required"] = True
        security["authorization_enabled"] = True

    inline_policies = attributes.get("inline_policy", [])
    if isinstance(inline_policies, list):
        for ip in inline_policies:
            if isinstance(ip, dict) and "policy" in ip:
                perms = parse_iam_policy_document(ip["policy"])
                security["iam_permissions"].extend(perms)
                if perms:
                    security["authorization_enabled"] = True

    if security["iam_permissions"]:
        wildcard_found = False
        for perm in security["iam_permissions"]:
            if "*" in perm.get("resources", []) or "*" in perm.get("actions", []):
                wildcard_found = True
                break
        security["least_privilege"] = not wildcard_found

    # 2. Ingress & Egress Rules
    ingress_rules, egress_rules = parse_network_rules(attributes)
    security["ingress_rules"] = ingress_rules
    security["egress_rules"] = egress_rules

    # 3. Public Exposure & Internet Exposure
    if attributes.get("publicly_accessible") is True:
        security["public_access"] = True
        security["internet_exposed"] = True
    elif attributes.get("publicly_accessible") is False:
        security["public_access"] = False

    if attributes.get("internal") is False:
        security["internet_exposed"] = True
        security["public_access"] = True
    elif attributes.get("internal") is True:
        security["internet_exposed"] = False

    if (attributes.get("associate_public_ip_address") is True or
        attributes.get("map_public_ip_on_launch") is True or
        attributes.get("public_ip_address_id")):
        security["public_ip"] = True
        security["internet_exposed"] = True
    elif (attributes.get("associate_public_ip_address") is False or
          attributes.get("map_public_ip_on_launch") is False):
        security["public_ip"] = False

    for rule in ingress_rules:
        for s in rule.get("sources", []):
            if s in ["0.0.0.0/0", "::/0", "*", "Internet"]:
                security["internet_exposed"] = True
                security["public_access"] = True

    # 4. Encryption
    if (attributes.get("storage_encrypted") is True or
        attributes.get("encrypted") is True or
        attributes.get("encryption_at_rest_enabled") is True or
        attributes.get("kms_key_id") or
        attributes.get("server_side_encryption_configuration")):
        security["encryption_enabled"] = True
        security["encryption_type"] = "at_rest"
    elif (attributes.get("storage_encrypted") is False or
          attributes.get("encrypted") is False):
        security["encryption_enabled"] = False
        security["encryption_type"] = None

    if attributes.get("infrastructure_encryption_enabled") is True:
        security["encryption_enabled"] = True
        security["encryption_type"] = "infrastructure"

    # 5. Versioning
    if attributes.get("versioning_enabled") is True:
        security["versioning_enabled"] = True
    elif attributes.get("versioning_enabled") is False:
        security["versioning_enabled"] = False

    versioning_config = attributes.get("versioning") or attributes.get("versioning_configuration")
    if isinstance(versioning_config, list):
        for block in versioning_config:
            if isinstance(block, dict):
                st = str(block.get("status", block.get("enabled", ""))).lower()
                if st in ["enabled", "true"]:
                    security["versioning_enabled"] = True
                elif st in ["disabled", "false", "suspended"]:
                    security["versioning_enabled"] = False
    elif isinstance(versioning_config, dict):
        st = str(versioning_config.get("status", versioning_config.get("enabled", ""))).lower()
        if st in ["enabled", "true"]:
            security["versioning_enabled"] = True
        elif st in ["disabled", "false", "suspended"]:
            security["versioning_enabled"] = False

    # 6. Deletion Protection
    if (attributes.get("deletion_protection") is True or
        attributes.get("purge_protection_enabled") is True or
        attributes.get("prevent_destroy") is True):
        security["deletion_protection"] = True
    elif (attributes.get("deletion_protection") is False or
          attributes.get("purge_protection_enabled") is False):
        security["deletion_protection"] = False

    # 7. Backup & Logging
    if attributes.get("backup_retention_period") or attributes.get("retention_policy"):
        security["backup_enabled"] = True

    if attributes.get("logging") or attributes.get("access_logs") or attributes.get("diagnostic_setting"):
        security["logging_enabled"] = True

    # 8. Secrets Detection
    security["secrets"] = detect_secrets(resource_type, attributes, variables_map)

    return security
