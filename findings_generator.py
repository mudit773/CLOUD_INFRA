def generate_security_findings(resources):
    """
    Generates deterministic, evidence-based security findings purely from generic normalized security state.
    Zero resource-type or port-number hardcoding.
    """
    findings = []
    seen_findings = set()

    def add_finding(fid, severity, category, resource_id, title, description, evidence, attack_vector, recommendation, remediation):
        if fid in seen_findings:
            return
        seen_findings.add(fid)
        findings.append({
            "id": fid,
            "severity": severity,
            "category": category,
            "resource": resource_id,
            "title": title,
            "description": description,
            "evidence": evidence or {},
            "attack_vector": attack_vector,
            "recommendation": recommendation,
            "remediation": remediation
        })

    for res in resources:
        res_id = res["id"]
        sec = res.get("security", {})

        # 1. Inbound Public Rules
        for idx, rule in enumerate(sec.get("ingress_rules", [])):
            sources = rule.get("sources", [])
            if any(s in ["0.0.0.0/0", "::/0", "*"] for s in sources):
                to_port = rule.get("to_port")
                from_port = rule.get("from_port")
                port_str = f"{to_port}" if to_port is not None else "all"

                add_finding(
                    f"PUBLIC_INGRESS_{res_id}_{idx}",
                    "HIGH",
                    "NETWORK_EXPOSURE",
                    res_id,
                    "Inbound traffic is exposed to the internet",
                    f"Inbound traffic on port {port_str} is permitted from open internet sources.",
                    {"protocol": rule.get("protocol"), "from_port": from_port, "to_port": to_port, "sources": sources},
                    f"An attacker on the internet can attempt connections to port {port_str}.",
                    "Restrict inbound access to approved CIDR ranges.",
                    "Modify security group or firewall ingress rules to remove wildcard sources."
                )

        # 2. Internet Exposed Resource
        if sec.get("internet_exposed") is True:
            add_finding(
                f"INTERNET_EXPOSED_{res_id}",
                "HIGH",
                "NETWORK_EXPOSURE",
                res_id,
                "Resource is exposed to the internet",
                "The resource configuration permits public network exposure.",
                {"public_access": sec.get("public_access"), "internet_exposed": True},
                "Publicly accessible resources increase attack surface for remote exploitation.",
                "Disable public network access unless explicitly required for public services.",
                "Set public network access to false or restrict inbound access."
            )

        # 3. Unencrypted Storage / Resource
        if sec.get("encryption_enabled") is False:
            add_finding(
                f"UNENCRYPTED_STORAGE_{res_id}",
                "HIGH",
                "DATA_PROTECTION",
                res_id,
                "Encryption at rest is explicitly disabled",
                "Resource configuration explicitly disables encryption at rest.",
                {"encryption_enabled": False},
                "Unauthorized physical or snapshot access could expose unencrypted data.",
                "Enable encryption at rest using provider-managed or KMS keys.",
                "Set encryption attribute to true."
            )

    return findings