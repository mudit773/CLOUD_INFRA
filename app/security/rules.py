"""
Security rules for the cloud security scanner.

Each rule receives one resource and returns a list of findings.

The scanner itself lives in scanner.py.
"""

from typing import Any, Dict, List


# ============================================================
# Helper Functions
# ============================================================

def get_security(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Safely return the security section of a resource."""
    return resource.get("security", {}) or {}


def get_attributes(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Safely return the attributes section of a resource."""
    return resource.get("attributes", {}) or {}


def get_location(resource: Dict[str, Any]) -> str:
    """Return Terraform source location."""
    location = resource.get("source_location", {})

    if isinstance(location, dict):
        file = location.get("file", "unknown")
        line = location.get("line", "?")
        return f"{file}:{line}"

    return str(location)


def make_finding(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    resource: Dict[str, Any],
    evidence: Dict[str, Any],
    recommendation: str,
) -> Dict[str, Any]:
    """Create a standardized security finding."""

    return {
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "resource_id": resource.get("id", "unknown"),
        "resource_type": resource.get("type", "unknown"),
        "source_location": get_location(resource),
        "evidence": evidence,
        "recommendation": recommendation,
    }


def is_public_source(source: str) -> bool:
    """Check whether an ingress source represents the whole internet."""
    return source in {
        "0.0.0.0/0",
        "::/0",
        "internet",
        "*",
    }


# ============================================================
# NETWORK SECURITY RULES
# ============================================================

def check_ssh_exposed(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    NET-SSH-001
    Detect SSH port 22 exposed to the internet.
    """

    findings = []

    security = get_security(resource)
    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        if from_port == 22 and to_port == 22:
            public_sources = [
                source for source in sources
                if is_public_source(source)
            ]

            if public_sources:
                findings.append(
                    make_finding(
                        rule_id="NET-SSH-001",
                        severity="HIGH",
                        title="SSH Port Exposed to Internet",
                        description=(
                            f"Resource '{resource.get('id')}' allows "
                            "public ingress on port 22."
                        ),
                        resource=resource,
                        evidence={
                            "port": 22,
                            "sources": public_sources,
                        },
                        recommendation=(
                            "Restrict SSH access to specific trusted IP "
                            "CIDRs or use AWS SSM."
                        ),
                    )
                )

    return findings


def check_rdp_exposed(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    NET-RDP-001
    Detect RDP port 3389 exposed to the internet.
    """

    findings = []

    security = get_security(resource)
    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        if from_port == 3389 and to_port == 3389:
            public_sources = [
                source for source in sources
                if is_public_source(source)
            ]

            if public_sources:
                findings.append(
                    make_finding(
                        rule_id="NET-RDP-001",
                        severity="HIGH",
                        title="RDP Port Exposed to Internet",
                        description=(
                            f"Resource '{resource.get('id')}' allows "
                            "public ingress on port 3389."
                        ),
                        resource=resource,
                        evidence={
                            "port": 3389,
                            "sources": public_sources,
                        },
                        recommendation=(
                            "Restrict RDP access to trusted networks or "
                            "use a secure remote-management mechanism."
                        ),
                    )
                )

    return findings


def check_database_port_exposed(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    NET-DB-001
    Detect common database ports exposed to the internet.
    """

    findings = []

    database_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "Microsoft SQL Server",
        1521: "Oracle",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
    }

    security = get_security(resource)
    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        if from_port != to_port:
            continue

        if from_port not in database_ports:
            continue

        public_sources = [
            source for source in sources
            if is_public_source(source)
        ]

        if public_sources:
            database_name = database_ports[from_port]

            findings.append(
                make_finding(
                    rule_id="NET-DB-001",
                    severity="CRITICAL",
                    title="Database Port Exposed to Internet",
                    description=(
                        f"{database_name} port {from_port} is exposed "
                        "to the internet."
                    ),
                    resource=resource,
                    evidence={
                        "port": from_port,
                        "database": database_name,
                        "sources": public_sources,
                    },
                    recommendation=(
                        "Remove public database access and restrict "
                        "database traffic to trusted application networks."
                    ),
                )
            )

    return findings


def check_all_ports_exposed(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    NET-PORT-001
    Detect unrestricted ingress allowing all ports.
    """

    findings = []

    security = get_security(resource)
    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        protocol = rule.get("protocol")
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        public_sources = [
            source for source in sources
            if is_public_source(source)
        ]

        if (
            protocol == "-1"
            and public_sources
        ):
            findings.append(
                make_finding(
                    rule_id="NET-PORT-001",
                    severity="CRITICAL",
                    title="All Network Ports Exposed to Internet",
                    description=(
                        f"Resource '{resource.get('id')}' allows "
                        "unrestricted inbound traffic from the internet."
                    ),
                    resource=resource,
                    evidence={
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "sources": public_sources,
                    },
                    recommendation=(
                        "Restrict inbound traffic to only the required "
                        "ports, protocols, and trusted sources."
                    ),
                )
            )

    return findings


def check_public_ip(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    NET-IP-001
    Detect publicly exposed compute resources with public IPs.
    """

    findings = []

    resource_type = resource.get("type")
    attributes = get_attributes(resource)
    security = get_security(resource)

    if resource_type not in {"ec2", "instance"}:
        return findings

    public_ip = (
        attributes.get("associate_public_ip_address") is True
        or security.get("public_ip") is True
    )

    internet_exposed = security.get("internet_exposed") is True

    if public_ip and internet_exposed:
        findings.append(
            make_finding(
                rule_id="NET-IP-001",
                severity="HIGH",
                title="Internet-Exposed Compute Resource Has Public IP",
                description=(
                    f"Compute resource '{resource.get('id')}' has a "
                    "public IP address and is internet exposed."
                ),
                resource=resource,
                evidence={
                    "public_ip": public_ip,
                    "internet_exposed": internet_exposed,
                },
                recommendation=(
                    "Remove unnecessary public IP assignment and place "
                    "the workload behind a controlled network boundary."
                ),
            )
        )

    return findings


def check_public_subnet(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    NET-SUBNET-001
    Detect subnets that automatically assign public IP addresses.
    """

    findings = []

    if resource.get("type") != "subnet":
        return findings

    attributes = get_attributes(resource)

    if attributes.get("map_public_ip_on_launch") is True:
        findings.append(
            make_finding(
                rule_id="NET-SUBNET-001",
                severity="MEDIUM",
                title="Subnet Automatically Assigns Public IP Addresses",
                description=(
                    f"Subnet '{resource.get('id')}' automatically "
                    "assigns public IP addresses to launched instances."
                ),
                resource=resource,
                evidence={
                    "map_public_ip_on_launch": True,
                },
                recommendation=(
                    "Disable automatic public IP assignment unless the "
                    "subnet is intentionally public."
                ),
            )
        )

    return findings


def check_unrestricted_egress(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    NET-EGRESS-001
    Detect unrestricted outbound traffic.
    """

    findings = []

    security = get_security(resource)
    egress_rules = security.get("egress_rules", [])

    for rule in egress_rules:
        protocol = rule.get("protocol")
        destinations = rule.get("destinations", [])

        if (
            protocol == "-1"
            and any(
                is_public_source(destination)
                for destination in destinations
            )
        ):
            findings.append(
                make_finding(
                    rule_id="NET-EGRESS-001",
                    severity="MEDIUM",
                    title="Unrestricted Outbound Network Traffic",
                    description=(
                        f"Resource '{resource.get('id')}' allows "
                        "unrestricted outbound traffic to the internet."
                    ),
                    resource=resource,
                    evidence={
                        "protocol": protocol,
                        "destinations": destinations,
                    },
                    recommendation=(
                        "Restrict outbound traffic to only the destinations "
                        "and protocols required by the workload."
                    ),
                )
            )

    return findings


# ============================================================
# IAM SECURITY RULES
# ============================================================

def check_wildcard_iam_actions(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    IAM-WILD-001
    Detect wildcard IAM actions.
    """

    findings = []

    security = get_security(resource)
    permissions = security.get("iam_permissions", [])

    for permission in permissions:
        actions = permission.get("actions", [])

        wildcard_actions = [
            action for action in actions
            if "*" in str(action)
        ]

        if wildcard_actions:
            findings.append(
                make_finding(
                    rule_id="IAM-WILD-001",
                    severity="HIGH",
                    title="Overly Permissive IAM Policy (Wildcard Actions)",
                    description=(
                        f"Resource '{resource.get('id')}' contains "
                        f"wildcard actions ({wildcard_actions}) "
                        f"on target "
                        f"('{permission.get('resources', ['*'])[0]}')."
                    ),
                    resource=resource,
                    evidence={
                        "actions": actions,
                        "resources": permission.get("resources", []),
                    },
                    recommendation=(
                        "Apply least-privilege scoping to IAM actions "
                        "and resource ARNs."
                    ),
                )
            )

    return findings


def check_wildcard_iam_resources(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    IAM-RES-001
    Detect IAM permissions applying to every resource.
    """

    findings = []

    security = get_security(resource)
    permissions = security.get("iam_permissions", [])

    for permission in permissions:
        resources = permission.get("resources", [])

        if "*" in resources:
            findings.append(
                make_finding(
                    rule_id="IAM-RES-001",
                    severity="HIGH",
                    title="IAM Permission Applies to All Resources",
                    description=(
                        f"Resource '{resource.get('id')}' contains an "
                        "IAM permission targeting all resources."
                    ),
                    resource=resource,
                    evidence={
                        "actions": permission.get("actions", []),
                        "resources": resources,
                    },
                    recommendation=(
                        "Replace wildcard resource permissions with "
                        "specific resource ARNs."
                    ),
                )
            )

    return findings


def check_admin_iam_permissions(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    IAM-ADMIN-001
    Detect full administrative permissions.
    """

    findings = []

    security = get_security(resource)
    permissions = security.get("iam_permissions", [])

    for permission in permissions:
        actions = permission.get("actions", [])
        resources = permission.get("resources", [])

        if "*" in actions and "*" in resources:
            findings.append(
                make_finding(
                    rule_id="IAM-ADMIN-001",
                    severity="CRITICAL",
                    title="Administrative IAM Permissions Detected",
                    description=(
                        f"Resource '{resource.get('id')}' has wildcard "
                        "actions on all resources."
                    ),
                    resource=resource,
                    evidence={
                        "actions": actions,
                        "resources": resources,
                    },
                    recommendation=(
                        "Remove administrative wildcard permissions and "
                        "apply strict least-privilege IAM policies."
                    ),
                )
            )

    return findings


# ============================================================
# S3 SECURITY RULES
# ============================================================

def check_s3_public(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    S3-PUBLIC-001
    Detect publicly accessible S3 buckets.
    """

    findings = []

    if resource.get("type") != "s3":
        return findings

    security = get_security(resource)

    if security.get("public_access") is True:
        findings.append(
            make_finding(
                rule_id="S3-PUBLIC-001",
                severity="CRITICAL",
                title="Publicly Accessible S3 Bucket",
                description=(
                    f"S3 bucket '{resource.get('id')}' allows public "
                    "access."
                ),
                resource=resource,
                evidence={
                    "public_access": True,
                },
                recommendation=(
                    "Enable S3 Block Public Access and restrict bucket "
                    "access through IAM policies."
                ),
            )
        )

    return findings


def check_s3_public_access_block(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    S3-PAB-001
    Detect disabled S3 Block Public Access.
    """

    findings = []

    if resource.get("type") != "s3":
        return findings

    attributes = get_attributes(resource)

    if attributes.get("public_access_block") is False:
        findings.append(
            make_finding(
                rule_id="S3-PAB-001",
                severity="HIGH",
                title="S3 Block Public Access Disabled",
                description=(
                    f"S3 bucket '{resource.get('id')}' does not have "
                    "Block Public Access enabled."
                ),
                resource=resource,
                evidence={
                    "public_access_block": False,
                },
                recommendation=(
                    "Enable all applicable S3 Block Public Access "
                    "settings."
                ),
            )
        )

    return findings


def check_s3_encryption(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    S3-ENC-001
    Detect S3 buckets without encryption.
    """

    findings = []

    if resource.get("type") != "s3":
        return findings

    security = get_security(resource)
    attributes = get_attributes(resource)

    encryption_enabled = (
        security.get("encryption_enabled")
        if "encryption_enabled" in security
        else attributes.get("encryption")
    )

    if encryption_enabled is False:
        findings.append(
            make_finding(
                rule_id="S3-ENC-001",
                severity="HIGH",
                title="Unencrypted S3 Bucket",
                description=(
                    f"S3 bucket '{resource.get('id')}' is configured "
                    "without default server-side encryption."
                ),
                resource=resource,
                evidence={
                    "encryption_enabled": False,
                },
                recommendation=(
                    "Enable default SSE-S3 or SSE-KMS server-side "
                    "encryption."
                ),
            )
        )

    return findings


def check_s3_logging(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    S3-LOG-001
    Detect sensitive S3 buckets without logging.
    """

    findings = []

    if resource.get("type") != "s3":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    sensitive = attributes.get("sensitive_data") is True
    logging_enabled = security.get("logging_enabled")

    if sensitive and logging_enabled is False:
        findings.append(
            make_finding(
                rule_id="S3-LOG-001",
                severity="MEDIUM",
                title="Sensitive S3 Bucket Has Logging Disabled",
                description=(
                    f"Sensitive S3 bucket '{resource.get('id')}' "
                    "does not have logging enabled."
                ),
                resource=resource,
                evidence={
                    "sensitive_data": True,
                    "logging_enabled": False,
                },
                recommendation=(
                    "Enable appropriate S3 access logging or CloudTrail "
                    "data-event monitoring."
                ),
            )
        )

    return findings


def check_s3_backup(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    S3-BACKUP-001
    Detect sensitive S3 buckets without versioning/backup protection.
    """

    findings = []

    if resource.get("type") != "s3":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    sensitive = attributes.get("sensitive_data") is True
    versioning = (
        attributes.get("versioning") is True
        or security.get("versioning_enabled") is True
    )

    backup = security.get("backup_enabled") is True

    if sensitive and not versioning and not backup:
        findings.append(
            make_finding(
                rule_id="S3-BACKUP-001",
                severity="MEDIUM",
                title="Sensitive S3 Bucket Lacks Recovery Protection",
                description=(
                    f"Sensitive S3 bucket '{resource.get('id')}' lacks "
                    "versioning and backup protection."
                ),
                resource=resource,
                evidence={
                    "versioning_enabled": versioning,
                    "backup_enabled": backup,
                },
                recommendation=(
                    "Enable versioning and an appropriate backup/recovery "
                    "strategy for sensitive data."
                ),
            )
        )

    return findings


# ============================================================
# RDS SECURITY RULES
# ============================================================

def check_rds_public(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    RDS-PUBLIC-001
    Detect publicly accessible RDS instances.
    """

    findings = []

    if resource.get("type") != "rds":
        return findings

    attributes = get_attributes(resource)

    if attributes.get("publicly_accessible") is True:
        findings.append(
            make_finding(
                rule_id="RDS-PUBLIC-001",
                severity="CRITICAL",
                title="Publicly Accessible Database",
                description=(
                    f"RDS instance '{resource.get('id')}' is configured "
                    "to be publicly accessible."
                ),
                resource=resource,
                evidence={
                    "publicly_accessible": True,
                },
                recommendation=(
                    "Disable public accessibility and keep the database "
                    "inside private network boundaries."
                ),
            )
        )

    return findings


def check_rds_encryption(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    RDS-ENC-001
    Detect unencrypted RDS storage.
    """

    findings = []

    if resource.get("type") != "rds":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    encrypted = (
        attributes.get("storage_encrypted")
        if "storage_encrypted" in attributes
        else security.get("encryption_enabled")
    )

    if encrypted is False:
        findings.append(
            make_finding(
                rule_id="RDS-ENC-001",
                severity="HIGH",
                title="RDS Storage Encryption Disabled",
                description=(
                    f"RDS instance '{resource.get('id')}' does not "
                    "have storage encryption enabled."
                ),
                resource=resource,
                evidence={
                    "storage_encrypted": False,
                },
                recommendation=(
                    "Enable RDS storage encryption using AWS KMS."
                ),
            )
        )

    return findings


def check_rds_backup(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    RDS-BACKUP-001
    Detect sensitive RDS databases without backup.
    """

    findings = []

    if resource.get("type") != "rds":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    sensitive = attributes.get("sensitive_data") is True
    backup_enabled = security.get("backup_enabled") is True

    if sensitive and not backup_enabled:
        findings.append(
            make_finding(
                rule_id="RDS-BACKUP-001",
                severity="HIGH",
                title="Sensitive RDS Database Has Backup Disabled",
                description=(
                    f"Sensitive database '{resource.get('id')}' "
                    "does not have backup protection enabled."
                ),
                resource=resource,
                evidence={
                    "sensitive_data": True,
                    "backup_enabled": False,
                },
                recommendation=(
                    "Enable automated backups and configure an "
                    "appropriate retention period."
                ),
            )
        )

    return findings


def check_rds_deletion_protection(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    RDS-DELETE-001
    Detect critical RDS databases without deletion protection.
    """

    findings = []

    if resource.get("type") != "rds":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    importance = attributes.get("importance")
    deletion_protection = security.get("deletion_protection")

    if (
        importance == "critical"
        and deletion_protection is False
    ):
        findings.append(
            make_finding(
                rule_id="RDS-DELETE-001",
                severity="MEDIUM",
                title="Critical RDS Database Lacks Deletion Protection",
                description=(
                    f"Critical database '{resource.get('id')}' does not "
                    "have deletion protection enabled."
                ),
                resource=resource,
                evidence={
                    "importance": importance,
                    "deletion_protection": False,
                },
                recommendation=(
                    "Enable deletion protection for critical production "
                    "databases."
                ),
            )
        )

    return findings


# ============================================================
# LOAD BALANCER RULES
# ============================================================

def check_http_listener(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    LB-HTTP-001
    Detect HTTP traffic accepted by an internet-facing load balancer.

    This is a verification finding rather than an automatic vulnerability,
    because HTTP may intentionally be used to redirect clients to HTTPS.
    """

    findings = []

    if resource.get("type") != "load_balancer":
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    internet_facing = (
        attributes.get("scheme") == "internet-facing"
        or security.get("internet_exposed") is True
    )

    if not internet_facing:
        return findings

    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        if (
            rule.get("protocol") == "tcp"
            and rule.get("from_port") == 80
            and rule.get("to_port") == 80
        ):
            findings.append(
                make_finding(
                    rule_id="LB-HTTP-001",
                    severity="MEDIUM",
                    title="Internet-Facing Load Balancer Accepts HTTP",
                    description=(
                        f"Load balancer '{resource.get('id')}' accepts "
                        "HTTP traffic from the internet."
                    ),
                    resource=resource,
                    evidence={
                        "port": 80,
                        "sources": rule.get("sources", []),
                    },
                    recommendation=(
                        "Verify that HTTP requests are redirected to HTTPS "
                        "and that sensitive traffic is never transmitted "
                        "over plaintext HTTP."
                    ),
                )
            )

    return findings


# ============================================================
# SECRET DETECTION
# ============================================================

def check_hardcoded_secrets(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    SEC-SECRET-001
    Detect obvious secret values in the normalized security data.
    """

    findings = []

    security = get_security(resource)
    secrets = security.get("secrets", [])

    if secrets:
        findings.append(
            make_finding(
                rule_id="SEC-SECRET-001",
                severity="CRITICAL",
                title="Potential Hardcoded Secret Detected",
                description=(
                    f"Potential secret material was detected in "
                    f"resource '{resource.get('id')}'."
                ),
                resource=resource,
                evidence={
                    "secret_count": len(secrets),
                },
                recommendation=(
                    "Remove secrets from Terraform configuration and "
                    "use AWS Secrets Manager, SSM Parameter Store, or "
                    "another secure secret-management solution."
                ),
            )
        )

    return findings


# ============================================================
# MANAGEMENT & CONTAINER SECURITY RULES
# ============================================================

def check_management_ports_exposed(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    NET-MGMT-001
    Detect sensitive management ports exposed to the internet.
    """
    findings = []
    management_ports = {
        21: "FTP",
        23: "Telnet",
        389: "LDAP",
        445: "SMB",
        5900: "VNC",
        6443: "Kubernetes API",
        8080: "HTTP Admin Console",
        8443: "HTTPS Admin Console",
    }

    security = get_security(resource)
    ingress_rules = security.get("ingress_rules", [])

    for rule in ingress_rules:
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        sources = rule.get("sources", [])

        if from_port not in management_ports or from_port != to_port:
            continue

        public_sources = [src for src in sources if is_public_source(src)]
        if public_sources:
            service_name = management_ports[from_port]
            findings.append(
                make_finding(
                    rule_id="NET-MGMT-001",
                    severity="HIGH",
                    title="Management Port Exposed to Internet",
                    description=(
                        f"Resource '{resource.get('id')}' exposes {service_name} "
                        f"port {from_port} to public sources."
                    ),
                    resource=resource,
                    evidence={
                        "port": from_port,
                        "service": service_name,
                        "sources": public_sources,
                    },
                    recommendation=(
                        "Restrict management access to internal VPNs or trusted IP ranges."
                    ),
                )
            )

    return findings


def check_ec2_imds_v1(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    EC2-IMDS-001
    Detect EC2 instances configured with vulnerable IMDSv1.
    """
    findings = []
    if resource.get("type") not in {"ec2", "instance"}:
        return findings

    attributes = get_attributes(resource)
    metadata_options = attributes.get("metadata_options", {}) or {}

    http_tokens = metadata_options.get("http_tokens")
    imds_v2_required = (http_tokens == "required")

    if not imds_v2_required:
        findings.append(
            make_finding(
                rule_id="EC2-IMDS-001",
                severity="HIGH",
                title="EC2 Instance Allows IMDSv1 (IMDSv2 Not Enforced)",
                description=(
                    f"EC2 instance '{resource.get('id')}' allows legacy IMDSv1, "
                    "increasing risk of IAM credential theft via SSRF."
                ),
                resource=resource,
                evidence={
                    "http_tokens": http_tokens or "optional",
                },
                recommendation=(
                    "Enforce IMDSv2 by setting http_tokens='required' in metadata options."
                ),
            )
        )

    return findings


def check_eks_public_endpoint(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    EKS-PUBLIC-001
    Detect Kubernetes cluster API endpoint exposed publicly.
    """
    findings = []
    if resource.get("type") not in {"eks", "k8s_cluster", "kubernetes"}:
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    endpoint_public = (
        attributes.get("endpoint_public_access") is True
        or security.get("internet_exposed") is True
    )
    public_cidrs = attributes.get("public_access_cidrs", ["0.0.0.0/0"])

    if endpoint_public and any(is_public_source(cidr) for cidr in public_cidrs):
        findings.append(
            make_finding(
                rule_id="EKS-PUBLIC-001",
                severity="HIGH",
                title="Kubernetes Cluster API Endpoint Publicly Exposed",
                description=(
                    f"Cluster '{resource.get('id')}' API endpoint is publicly accessible "
                    "from the internet."
                ),
                resource=resource,
                evidence={
                    "endpoint_public_access": True,
                    "public_access_cidrs": public_cidrs,
                },
                recommendation=(
                    "Disable public endpoint access or restrict API access to trusted CIDRs."
                ),
            )
        )

    return findings


# ============================================================
# ENCRYPTION & DATA PROTECTION RULES
# ============================================================

def check_kms_key_rotation(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    KMS-ROT-001
    Detect KMS customer managed keys with rotation disabled.
    """
    findings = []
    if resource.get("type") not in {"kms", "kms_key"}:
        return findings

    attributes = get_attributes(resource)
    rotation_enabled = attributes.get("enable_key_rotation") is True

    if not rotation_enabled:
        findings.append(
            make_finding(
                rule_id="KMS-ROT-001",
                severity="MEDIUM",
                title="KMS Key Automatic Rotation Disabled",
                description=(
                    f"KMS Key '{resource.get('id')}' does not have automatic key rotation enabled."
                ),
                resource=resource,
                evidence={
                    "enable_key_rotation": False,
                },
                recommendation=(
                    "Enable automatic annual rotation for KMS customer managed keys."
                ),
            )
        )

    return findings


def check_ebs_unencrypted(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    EBS-ENC-001
    Detect unencrypted EBS volumes.
    """
    findings = []
    if resource.get("type") not in {"ebs", "ebs_volume"}:
        return findings

    attributes = get_attributes(resource)
    security = get_security(resource)

    encrypted = (
        attributes.get("encrypted")
        if "encrypted" in attributes
        else security.get("encryption_enabled")
    )

    if encrypted is False:
        findings.append(
            make_finding(
                rule_id="EBS-ENC-001",
                severity="HIGH",
                title="Unencrypted EBS Storage Volume",
                description=(
                    f"EBS volume '{resource.get('id')}' is configured without encryption."
                ),
                resource=resource,
                evidence={
                    "encrypted": False,
                },
                recommendation=(
                    "Enable EBS encryption by default using AWS KMS keys."
                ),
            )
        )

    return findings


def check_rds_multi_az(
    resource: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    RDS-MAZ-001
    Detect production RDS databases without Multi-AZ enabled.
    """
    findings = []
    if resource.get("type") != "rds":
        return findings

    attributes = get_attributes(resource)
    importance = attributes.get("importance")
    multi_az = attributes.get("multi_az") is True

    if importance in {"critical", "high"} and not multi_az:
        findings.append(
            make_finding(
                rule_id="RDS-MAZ-001",
                severity="LOW",
                title="Production RDS Instance Lacks Multi-AZ High Availability",
                description=(
                    f"Production database '{resource.get('id')}' does not have Multi-AZ deployment enabled."
                ),
                resource=resource,
                evidence={
                    "importance": importance,
                    "multi_az": False,
                },
                recommendation=(
                    "Enable Multi-AZ deployment for production database fault tolerance."
                ),
            )
        )

    return findings


# ============================================================
# RESOURCE RULE REGISTRY
# ============================================================

RESOURCE_RULES = [
    # Network
    check_ssh_exposed,
    check_rdp_exposed,
    check_database_port_exposed,
    check_management_ports_exposed,
    check_all_ports_exposed,
    check_public_ip,
    check_public_subnet,
    check_unrestricted_egress,

    # IAM & Compute
    check_wildcard_iam_actions,
    check_wildcard_iam_resources,
    check_admin_iam_permissions,
    check_ec2_imds_v1,

    # Storage (S3 & EBS)
    check_s3_public,
    check_s3_public_access_block,
    check_s3_encryption,
    check_s3_logging,
    check_s3_backup,
    check_ebs_unencrypted,

    # Database (RDS)
    check_rds_public,
    check_rds_encryption,
    check_rds_backup,
    check_rds_deletion_protection,
    check_rds_multi_az,

    # Containers & Load Balancers
    check_eks_public_endpoint,
    check_http_listener,

    # KMS & Secrets
    check_kms_key_rotation,
    check_hardcoded_secrets,
]
