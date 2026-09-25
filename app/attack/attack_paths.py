"""
Discover attack paths from entry points to crown-jewel resources.
Generic, evidence-based, provider-agnostic path reachability analysis.
"""

from typing import Any, Dict, List, Set
import networkx as nx


CONTAINER_KEYWORDS = {
    "subnet",
    "subnetwork",
    "vpc",
    "vnet",
    "virtual_network",
    "route_table",
    "network_interface",
}


def is_container_node(graph: nx.DiGraph, node_id: str) -> bool:
    """
    Check if a graph node represents a spatial/infrastructure container resource
    (e.g., subnet, VPC, route table, NIC) rather than an active workload, security boundary,
    or crown jewel.
    """
    if node_id == "internet" or not graph.has_node(node_id):
        return False
    node_entry = graph.nodes[node_id]
    data = node_entry.get("data")
    if data:
        r_type = getattr(data, "type", "") or ""
    else:
        r_type = node_entry.get("type", "") or ""
    r_type_lower = str(r_type).lower()
    return any(kw in r_type_lower for kw in CONTAINER_KEYWORDS)


def build_attack_traversal_graph(graph: nx.DiGraph, entry_points: List[str]) -> nx.DiGraph:
    """
    Construct a semantic attack-traversal graph G_attack from the infrastructure graph.
    Only security-relevant reachability and access relationships represent attacker movement.
    Does NOT modify the original infrastructure graph.
    """
    g_attack = nx.DiGraph()
    entry_set = set(entry_points)

    # Copy nodes and attributes
    for node_id, data in graph.nodes(data=True):
        g_attack.add_node(node_id, **data)

    for u, v, edge_data in graph.edges(data=True):
        rel_type = str(edge_data.get("type", "")).upper()

        # 1. Direct External Exposure Edges (internet -> entry point)
        if rel_type == "EXPOSED_TO" or u == "internet":
            g_attack.add_edge(u, v, **edge_data)

        # 2. IAM & Resource Access Permissions (identity/role -> target resource)
        elif rel_type in {"IAM_ACCESS", "RESOURCE_ACCESS"}:
            g_attack.add_edge(u, v, **edge_data)

        # 3. Role Usage (workload -> role/service account)
        elif rel_type in {"USES_ROLE", "ASSUMES_ROLE"}:
            g_attack.add_edge(u, v, **edge_data)

        # 4. Explicit Network Connectivity
        elif rel_type in {"NETWORK_ACCESS", "CAN_CONNECT", "CAN_REACH", "ROUTES_TO"}:
            g_attack.add_edge(u, v, **edge_data)

        # 5. Resource Attribute References (workload u referencing resource/credential v)
        elif rel_type == "REFERENCES_RESOURCE":
            # Forward edge: u referencing v's endpoint/credentials allows attacker at u to reach v
            g_attack.add_edge(u, v, **edge_data)

            # If v is an entry point boundary (security group, firewall, LB),
            # exposure at v allows entry into attached workload u
            if u != "internet":
                v_node_data = graph.nodes[v].get("data") if graph.has_node(v) else None
                v_type = str(v_node_data.type if v_node_data else "").lower()
                is_boundary = v in entry_set or any(
                    kw in v_type for kw in ["security_group", "firewall", "ingress", "load_balancer", "lb"]
                )
                if is_boundary:
                    g_attack.add_edge(v, u, **edge_data)

        # 6. Attachment / Deployment (workload deployed in subnet or attached to SG)
        elif rel_type in {"ATTACHED_TO", "DEPLOYED_IN", "CONTAINS", "PROTECTED_BY"}:
            u_node_data = graph.nodes[u].get("data") if graph.has_node(u) else None
            u_type = str(u_node_data.type if u_node_data else "").lower()
            is_u_boundary = u in entry_set or any(
                kw in u_type for kw in ["security_group", "firewall", "ingress", "load_balancer", "lb"]
            )
            if is_u_boundary:
                g_attack.add_edge(u, v, **edge_data)
            else:
                g_attack.add_edge(u, v, **edge_data)

        # Build ordering dependencies (DEPENDS_ON, REFERENCES_VARIABLE, REFERENCES_MODULE, BELONGS_TO)
        # are intentionally excluded from attacker movement.

    return g_attack


def canonicalize_attack_paths(raw_paths: List[Dict[str, Any]], graph: nx.DiGraph) -> List[Dict[str, Any]]:
    """
    Deduplicate and canonicalize attack paths into distinct security attack vectors.
    1. Prefer paths originating from 'internet' over sub-paths starting at intermediate entry points.
    2. Eliminate intermediate spatial container hops (subnets/VPCs) when direct/non-container
       security access vectors exist between the entry point and target crown jewel.
    """
    if not raw_paths:
        return []

    # Group paths by target crown jewel
    paths_by_target: Dict[str, List[Dict[str, Any]]] = {}
    for path_obj in raw_paths:
        target = path_obj["target"]
        paths_by_target.setdefault(target, []).append(path_obj)

    canonical_paths = []

    for target, group in paths_by_target.items():
        internet_paths = [p for p in group if p["source"] == "internet"]
        other_paths = [p for p in group if p["source"] != "internet"]

        primary_group = internet_paths if internet_paths else other_paths

        # Separate paths that avoid intermediate container hops vs those that use container hops
        clean_paths = []
        container_hop_paths = []

        for path_obj in primary_group:
            nodes = path_obj["nodes"]
            # Intermediate nodes are nodes strictly between source (index 0) and target (index -1)
            intermediate_nodes = nodes[1:-1]
            has_intermediate_container = any(is_container_node(graph, n) for n in intermediate_nodes)

            if has_intermediate_container:
                container_hop_paths.append(path_obj)
            else:
                clean_paths.append(path_obj)

        # If clean security vector paths exist, use them. Otherwise fall back to shortest container paths.
        selected = clean_paths if clean_paths else container_hop_paths

        # Deduplicate paths with identical node sequences
        seen_seqs = set()
        for path_obj in selected:
            seq = tuple(path_obj["nodes"])
            if seq not in seen_seqs:
                seen_seqs.add(seq)
                canonical_paths.append(path_obj)

    # Sort final canonical attack paths
    canonical_paths.sort(key=lambda p: (0 if p["source"] == "internet" else 1, p["length"], p["nodes"]))

    return canonical_paths


def find_attack_paths(
    graph: nx.DiGraph,
    entry_points: List[str],
    crown_jewels: List[str],
    max_depth: int = 6,
) -> List[Dict[str, Any]]:
    """
    Find simple reachability paths from entry points (or Internet) to crown jewels.

    STRICT CORRECTNESS GUARANTEES:
      - path[0] MUST be an entry point or 'internet'
      - path[-1] MUST be a crown jewel (present in crown_jewels list)
      - Intermediate nodes can be non-crown-jewel resources.
      - NEVER return a path whose target path[-1] is a non-crown-jewel resource.
      - Returns empty list [] if no evidence-supported path to a crown jewel exists.
    """
    if not entry_points or not crown_jewels:
        return []

    crown_jewels_set: Set[str] = set(crown_jewels)
    entry_points_set: Set[str] = set(entry_points)

    g_attack = build_attack_traversal_graph(graph, entry_points)

    raw_paths = []
    seen_paths = set()

    sources = set()
    if graph.has_node("internet") and graph.out_degree("internet") > 0:
        sources.add("internet")
    sources.update(entry_points)

    for source in sorted(list(sources)):
        if not g_attack.has_node(source):
            continue

        for target in sorted(list(crown_jewels)):
            if source == target or not g_attack.has_node(target):
                continue

            if target not in crown_jewels_set:
                continue

            try:
                paths = list(nx.all_simple_paths(g_attack, source=source, target=target, cutoff=max_depth))
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

            for path in paths:
                if path[-1] != target or path[-1] not in crown_jewels_set:
                    continue

                if path[0] not in sources and path[0] not in entry_points_set and path[0] != "internet":
                    continue

                path_tuple = tuple(path)
                if path_tuple in seen_paths:
                    continue
                seen_paths.add(path_tuple)

                edges_in_path = []
                rules_involved = set()

                for i in range(len(path) - 1):
                    u, v = path[i], path[i + 1]
                    edge_data = g_attack.get_edge_data(u, v) or graph.get_edge_data(u, v) or {}

                    edge_info = {
                        "source": u,
                        "target": v,
                        "type": edge_data.get("type", "related_to"),
                    }

                    if "rule_id" in edge_data:
                        edge_info["rule_id"] = edge_data["rule_id"]
                        rules_involved.add(edge_data["rule_id"])

                    for key in ["protocol", "port", "sources", "actions", "resources"]:
                        if key in edge_data:
                            edge_info[key] = edge_data[key]

                    edges_in_path.append(edge_info)

                raw_paths.append({
                    "source": source,
                    "target": target,
                    "nodes": path,
                    "edges": edges_in_path,
                    "rules_involved": sorted(list(rules_involved)),
                    "length": len(path) - 1,
                })

    # Canonicalize and deduplicate raw paths into distinct security attack vectors
    return canonicalize_attack_paths(raw_paths, graph)