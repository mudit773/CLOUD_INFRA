"""
Risk scoring module for cloud infrastructure resources.
"""

from typing import Any, Dict, List

import networkx as nx

from app.graph.nodes import GraphNode
from .blast_radius import calculate_blast_radius


SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 7.0,
    "MEDIUM": 4.0,
    "LOW": 1.0,
    "INFO": 0.0,
}


def score_resource_risk(
    graph: nx.DiGraph,
    resource_id: str,
    entry_points: List[str],
    crown_jewels: List[str],
) -> Dict[str, Any]:
    """
    Calculate risk score for a specific resource based on findings,
    exposure, and reachability.
    """
    if not graph.has_node(resource_id):
        return {
            "resource_id": resource_id,
            "score": 0.0,
            "risk_level": "LOW",
        }

    node_data = graph.nodes[resource_id].get("data")
    findings = node_data.findings if node_data else []

    # Finding severity score
    base_score = 0.0

    for finding in findings:
        sev = finding.get("severity", "INFO").upper()
        base_score += SEVERITY_WEIGHTS.get(sev, 0.0)

    # Multipliers
    is_entry = resource_id in entry_points
    is_crown = resource_id in crown_jewels
    blast_radius = calculate_blast_radius(graph, resource_id)

    multiplier = 1.0

    if is_entry:
        multiplier += 0.5

    if is_crown:
        multiplier += 1.0

    if blast_radius:
        multiplier += min(len(blast_radius) * 0.2, 1.5)

    final_score = round(base_score * multiplier, 2)

    if final_score >= 25.0:
        level = "CRITICAL"
    elif final_score >= 12.0:
        level = "HIGH"
    elif final_score >= 5.0:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "resource_id": resource_id,
        "score": final_score,
        "risk_level": level,
        "is_entry_point": is_entry,
        "is_crown_jewel": is_crown,
        "blast_radius_count": len(blast_radius),
        "blast_radius": blast_radius,
    }


def score_infrastructure_risk(
    graph: nx.DiGraph,
    entry_points: List[str],
    crown_jewels: List[str],
) -> Dict[str, Any]:
    """
    Calculate risk scores across all infrastructure resources.

    Returns the existing per-resource risk_scores structure.
    """
    scores = {}

    for node_id in graph.nodes():
        if node_id == "internet":
            continue

        scores[node_id] = score_resource_risk(
            graph,
            node_id,
            entry_points,
            crown_jewels,
        )

    return scores


def calculate_overall_risk(
    risk_scores: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate the overall infrastructure risk.

    The overall risk is represented by the highest-risk resource.
    This does not modify the existing per-resource risk_scores.
    """

    if not risk_scores:
        return {
            "score": 0.0,
            "risk_level": "LOW",
        }

    highest_risk = max(
        risk_scores.values(),
        key=lambda item: item.get("score", 0.0),
    )

    return {
        "score": highest_risk.get("score", 0.0),
        "risk_level": highest_risk.get("risk_level", "LOW"),
    }