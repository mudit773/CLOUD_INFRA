"""
Identify choke points in the cloud attack graph.
Generic, topology-based choke point discovery based on actual attack path traversal.
"""

from collections import Counter
from typing import Any, Dict, List
import networkx as nx


def find_choke_points(
    graph: nx.DiGraph,
    attack_paths: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Identify intermediary resources that appear across multiple attack paths.
    Returns empty list if no attack paths exist.
    """
    if not attack_paths:
        return []

    node_counts = Counter()
    total_paths = len(attack_paths)

    for path_dict in attack_paths:
        nodes = path_dict.get("nodes", [])
        # Exclude internet from choke points
        path_nodes = set(n for n in nodes if n != "internet")

        for node in path_nodes:
            node_counts[node] += 1

    choke_points = []
    for node_id, count in node_counts.most_common():
        percentage = round((count / total_paths) * 100, 1) if total_paths > 0 else 0.0
        choke_points.append({
            "resource_id": node_id,
            "path_count": count,
            "path_percentage": percentage,
        })

    return choke_points