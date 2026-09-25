"""
Identify crown-jewel resources in the cloud infrastructure graph.
Generic, provider-agnostic classification based on sensitivity, metadata, and data assets.
"""

from typing import List
import networkx as nx
from app.graph.nodes import GraphNode


# Generic resource categories representing high-value assets across cloud providers.
SENSITIVE_RESOURCE_TYPES = {
    # AWS
    "aws_s3_bucket",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "aws_secretsmanager_secret",
    "aws_kms_key",

    # Azure
    "azurerm_storage_account",
    "azurerm_key_vault",
    "azurerm_key_vault_secret",
    "azurerm_mssql_database",
    "azurerm_cosmosdb_account",

    # GCP
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_secret_manager_secret",
    "google_kms_crypto_key",
    "google_bigquery_dataset",

    # Kubernetes / Vault
    "kubernetes_secret",
    "vault_generic_secret",
    "vault_aws_secret_backend",
    "vault_aws_secret_backend_role",
    "vault_kubernetes_auth_backend_role",
}


SENSITIVE_TYPE_KEYWORDS = (
    "database",
    "db_instance",
    "db",
    "rds",
    "storage_account",
    "storage_bucket",
    "s3_bucket",
    "secret",
    "key_vault",
    "keyvault",
    "kms",
    "crypto_key",
    "dynamodb",
    "sql",
    "bigquery",
    "cosmos",
    "spanner",
    "firestore",
    "redis",
    "memcached",
    "mongodb",
    "cassandra",
    "elasticsearch",
    "opensearch",
    "vault",
    "certificate",
)


# Ordinary infrastructure compute and network resources that MUST NOT be classified
# as crown jewels merely because they are exposed, critical, or connected.
NON_CROWN_JEWEL_KEYWORDS = (
    "instance",
    "virtual_machine",
    "vm",
    "subnet",
    "vpc",
    "security_group",
    "network_security_group",
    "firewall",
    "load_balancer",
    "lb",
    "alb",
    "nlb",
    "route_table",
    "internet_gateway",
    "network_interface",
    "nic",
    "endpoint",
    "dns",
)


def find_crown_jewels(graph: nx.DiGraph) -> List[str]:
    """
    Identify high-value resources using explicit sensitivity metadata,
    resource security configuration, and generic cloud-resource semantics.
    Ordinary compute instances, subnets, VPCs, security groups, and load balancers
    are excluded unless explicit sensitive_data attribute or sensitive tags exist.
    """

    crown_jewels = set()

    for node_id, data in graph.nodes(data=True):
        if node_id == "internet":
            continue

        node_obj: GraphNode = data.get("data")

        if not node_obj or node_obj.is_special:
            continue

        attr = node_obj.attributes or {}
        tags = node_obj.tags or {}
        node_type = str(node_obj.type or "").lower()
        sec = node_obj.security_config or {}

        # 1. Explicit data sensitivity indicators take highest priority.
        explicitly_sensitive = (
            attr.get("sensitive_data") is True
            or str(tags.get("DataClassification", "")).lower() in ["sensitive", "restricted", "confidential"]
            or str(tags.get("Sensitivity", "")).lower() in ["high", "critical"]
        )

        if explicitly_sensitive:
            crown_jewels.add(node_id)
            continue

        # 2. Exclude ordinary compute/network infrastructure resources (instances, subnets, SGs, LBs, VPCs)
        is_data_store_or_secret = any(
            kw in node_type for kw in ["db", "database", "sql", "rds", "secret", "vault", "kms", "storage", "bucket", "dynamodb"]
        )
        is_ordinary_infrastructure = any(
            kw in node_type for kw in NON_CROWN_JEWEL_KEYWORDS
        ) and not is_data_store_or_secret

        if is_ordinary_infrastructure:
            continue

        # 3. Known high-value cloud resource types.
        known_sensitive_type = node_type in SENSITIVE_RESOURCE_TYPES

        # 4. Generic keyword match on sensitive resource types.
        keyword_sensitive_type = any(
            keyword in node_type
            for keyword in SENSITIVE_TYPE_KEYWORDS
        )

        # 5. Resource contains detected secrets.
        has_secrets = bool(sec.get("secrets"))

        is_crown_jewel = (
            known_sensitive_type
            or keyword_sensitive_type
            or has_secrets
        )

        if is_crown_jewel:
            crown_jewels.add(node_id)

    return sorted(list(crown_jewels))