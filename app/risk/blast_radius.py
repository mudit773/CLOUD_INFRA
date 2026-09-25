"""
Blast radius calculation module.
"""

from typing import List
import networkx as nx


def calculate_blast_radius(graph: nx.DiGraph, resource_id: str) -> List[str]:
    """
    Given a resource ID, find all downstream reachable resources in the graph.
    """
    if not graph.has_node(resource_id):
        return []

    try:
        descendants = nx.descendants(graph, resource_id)
    except nx.NetworkXError:
        return []

    # Exclude internet from blast radius
    reachable = [d for d in descendants if d != "internet"]
    return sorted(reachable)