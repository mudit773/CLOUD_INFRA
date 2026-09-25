"""
Graph builder module for constructing NetworkX security attack graphs.
"""

from typing import Any, Dict, List, Optional
import networkx as nx

from .nodes import GraphNode, create_internet_node
from .edges import GraphEdge, RelationshipType


def build_graph(
    parsed_data: Dict[str, Any]
) -> nx.DiGraph:
    """
    Build a NetworkX directed graph from parsed infrastructure data and security findings.
    """
    graph = nx.DiGraph()

    # 1. Add Internet node
    internet_node = create_internet_node()
    graph.add_node(internet_node.id, data=internet_node)

    resources = parsed_data.get("resources", [])
    relationships = parsed_data.get("relationships", [])
    findings = parsed_data.get("findings", [])

    # 2. Add resource nodes
    for res_dict in resources:
        res_id = res_dict.get("id")
        if not res_id:
            continue
        node = GraphNode(
            node_id=res_id,
            node_type=res_dict.get("type", "unknown"),
            name=res_dict.get("name", res_id),
            provider=res_dict.get("provider", "aws"),
            attributes=res_dict.get("attributes", {}),
            tags=res_dict.get("tags", {}),
            security_config=res_dict.get("security", {}),
            findings=[],
            is_special=False,
        )
        graph.add_node(res_id, data=node)

    # 3. Add legitimate infrastructure relationships
    for rel_dict in relationships:
        source_id = rel_dict.get("source")
        target_id = rel_dict.get("target")
        rel_type = rel_dict.get("type", "related_to")

        if not source_id or not target_id:
            continue

        # Handle missing nodes gracefully
        if not graph.has_node(source_id):
            if source_id.lower() == "internet":
                source_id = "internet"
            else:
                graph.add_node(source_id, data=GraphNode(node_id=source_id, node_type="unknown"))

        if not graph.has_node(target_id):
            graph.add_node(target_id, data=GraphNode(node_id=target_id, node_type="unknown"))

        # Map string relationship types to standard enum strings
        mapped_type = map_relationship_type(rel_type)

        edge_data = GraphEdge(
            source=source_id,
            target=target_id,
            edge_type=mapped_type,
            metadata=rel_dict.get("attributes", {}),
        )

        graph.add_edge(source_id, target_id, **edge_data.to_dict())

    # 4. Correlate security findings onto nodes and add exposure/permission edges
    for finding in findings:
        res_id = finding.get("resource_id") or finding.get("resource")
        if not res_id:
            continue

        # Handle missing resource referenced in finding gracefully
        if not graph.has_node(res_id):
            res_type = finding.get("resource_type", "unknown")
            graph.add_node(res_id, data=GraphNode(node_id=res_id, node_type=res_type))

        node_obj: GraphNode = graph.nodes[res_id]["data"]
        node_obj.add_finding(finding)

        rule_id = finding.get("rule_id", finding.get("id", ""))
        evidence = finding.get("evidence", {}) or {}

        # Synthesize EXPOSED_TO edge for network exposure findings
        is_exposure_rule = (
            rule_id in {"NET-SSH-001", "NET-RDP-001", "NET-DB-001", "NET-PORT-001", "NET-MGMT-001", "NET-IP-001", "EKS-PUBLIC-001", "S3-PUBLIC-001", "STR-S3-002", "LB-HTTP-001"}
            or rule_id.startswith(("PUBLIC_INGRESS", "INTERNET_EXPOSED", "NET-", "LB-", "S3-PUBLIC"))
            or "EXPOSED" in rule_id
            or "PUBLIC" in rule_id
        )

        if is_exposure_rule:
            port = evidence.get("port") or evidence.get("to_port")
            sources = evidence.get("sources", ["0.0.0.0/0"])
            protocol = evidence.get("protocol", "tcp")
            edge = GraphEdge(
                source="internet",
                target=res_id,
                edge_type=RelationshipType.EXPOSED_TO,
                rule_id=rule_id,
                protocol=protocol,
                port=port,
                sources=sources,
            )
            graph.add_edge("internet", res_id, **edge.to_dict())

        elif rule_id in {"IAM-WILD-001", "IAM-RES-001", "IAM-ADMIN-001"}:
            actions = evidence.get("actions", [])
            resources_spec = evidence.get("resources", [])
            resolve_wildcard_iam(graph, res_id, actions, resources_spec, rule_id)

    return graph


def map_relationship_type(rel_type: str) -> str:
    """Map raw relationship type string to standardized type."""
    lower_type = rel_type.lower()
    mapping = {
        "assumes_role": RelationshipType.USES_ROLE,
        "uses_role": RelationshipType.USES_ROLE,
        "can_access": RelationshipType.IAM_ACCESS,
        "iam_access": RelationshipType.IAM_ACCESS,
        "resource_access": RelationshipType.RESOURCE_ACCESS,
        "routes_to": RelationshipType.ROUTES_TO,
        "can_connect": RelationshipType.NETWORK_ACCESS,
        "can_reach": RelationshipType.NETWORK_ACCESS,
        "belongs_to": RelationshipType.BELONGS_TO,
        "deployed_in": RelationshipType.DEPLOYED_IN,
        "protected_by": RelationshipType.PROTECTED_BY,
        "contains": RelationshipType.CONTAINS,
        "attached_to": RelationshipType.ATTACHED_TO,
    }
    return mapping.get(lower_type, rel_type.upper())


def resolve_wildcard_iam(
    graph: nx.DiGraph,
    source_id: str,
    actions: List[str],
    resources_spec: List[str],
    rule_id: str,
) -> None:
    """
    Resolve wildcard IAM permissions against actual resources in the graph.
    Do NOT create a literal '*' node.
    """
    if not actions:
        return

    action_str = " ".join(str(a) for a in actions).lower()

    # Determine target resource types based on IAM actions
    target_types = set()
    if "s3:" in action_str:
        target_types.update(["s3", "s3_bucket"])
    if "rds:" in action_str or "dynamodb:" in action_str:
        target_types.update(["rds", "database", "dynamodb"])
    if "ec2:" in action_str:
        target_types.update(["ec2", "instance"])

    if "*" in actions or "*:*" in actions or (not target_types and "*" in resources_spec):
        target_types = None  # matches any resource node

    for n_id, data in graph.nodes(data=True):
        if n_id in {source_id, "internet"}:
            continue
        node_obj: Optional[GraphNode] = data.get("data")
        if not node_obj or node_obj.is_special:
            continue

        if target_types is None or node_obj.type in target_types:
            edge = GraphEdge(
                source=source_id,
                target=n_id,
                edge_type=RelationshipType.IAM_ACCESS,
                rule_id=rule_id,
                actions=actions,
                resources=resources_spec,
            )
            graph.add_edge(source_id, n_id, **edge.to_dict())