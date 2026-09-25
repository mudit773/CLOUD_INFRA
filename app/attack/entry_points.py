"""
Identify entry points into the cloud infrastructure graph.
Generic, provider-agnostic entry point detection based on exposure evidence.
"""

from typing import List
import networkx as nx
from app.graph.nodes import GraphNode


def find_entry_points(graph: nx.DiGraph) -> List[str]:
    """
    Identify resources reachable from the Internet based on infrastructure configuration,
    security findings, and graph topology.
    Returns a deduplicated list of entry point resource IDs.
    """
    entry_points = set()

    # 1. Any node with an incoming edge from internet
    if graph.has_node("internet"):
        for _, target in graph.out_edges("internet"):
            if target != "internet":
                entry_points.add(target)

    # 2. Check for exposure evidence directly on nodes
    for node_id, data in graph.nodes(data=True):
        if node_id == "internet":
            continue

        node_obj: GraphNode = data.get("data")
        if not node_obj or node_obj.is_special:
            continue

        sec = node_obj.security_config or {}
        attr = node_obj.attributes or {}
        findings = node_obj.findings or []

        # Security config flags
        sec_exposed = (
            sec.get("internet_exposed") is True
            or sec.get("public_access") is True
            or sec.get("public_ip") is True
        )

        # Ingress rules with wildcard sources
        ingress_exposed = False
        for rule in sec.get("ingress_rules", []):
            sources = rule.get("sources", [])
            if any(s in ["0.0.0.0/0", "::/0", "*", "Internet"] for s in sources):
                ingress_exposed = True
                break

        # Resource attribute indicators
        attr_exposed = (
            attr.get("associate_public_ip_address") is True
            or attr.get("publicly_accessible") is True
            or str(attr.get("scheme", "")).lower() in ["internet-facing", "public"]
            or str(attr.get("type", "")).lower() in ["loadbalancer", "nodeport"]
            or attr.get("assign_public_ip") is True
            or attr.get("public_ip_address_id") is not None
        )

        # Finding evidence
        finding_exposed = any(
            f.get("category") == "NETWORK_EXPOSURE"
            or str(f.get("rule_id", "")).startswith(("NET-", "LB-", "EKS-PUBLIC", "S3-PUBLIC", "PUBLIC_INGRESS", "INTERNET_EXPOSED"))
            for f in findings
        )

        if sec_exposed or ingress_exposed or attr_exposed or finding_exposed:
            entry_points.add(node_id)

    return sorted(list(entry_points))
