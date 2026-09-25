"""
Main execution pipeline for cloud infrastructure security scanner
and attack graph generator.
"""

from pathlib import Path
import json

from app.parser.json_loader import load_json, parse_infrastructure
from app.security.scanner import (
    get_resources,
    run_resource_rules,
    deduplicate_findings,
    sort_findings,
)
from app.graph.builder import build_graph
from app.attack import (
    find_entry_points,
    find_crown_jewels,
    find_attack_paths,
    find_choke_points,
)
from app.risk import score_infrastructure_risk, calculate_overall_risk


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INPUT_FILE = PROJECT_ROOT / "input" / "infra.json"
GRAPH_OUTPUT_FILE = PROJECT_ROOT / "output" / "graph_output.json"


def export_graph_to_dict(
    graph,
    attack_paths,
    entry_points,
    crown_jewels,
    choke_points,
):
    """Convert the NetworkX graph and attack analysis into JSON data."""

    nodes = []

    for node_id, node_data in graph.nodes(data=True):
        node_obj = node_data.get("data")

        if hasattr(node_obj, "to_dict"):
            nodes.append(node_obj.to_dict())
        else:
            nodes.append({
                "id": node_id,
                **node_data,
            })

    edges = []

    for source, target, edge_data in graph.edges(data=True):
        edge = {
            "source": source,
            "target": target,
        }

        edge.update(edge_data)
        edges.append(edge)

    return {
        "nodes": nodes,
        "edges": edges,
        "entry_points": entry_points,
        "crown_jewels": crown_jewels,
        "attack_paths": attack_paths,
        "choke_points": choke_points,
    }


def save_graph_json(data, output_path):
    """Save graph data as JSON."""

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, default=str)

    print(f"[INFO] Graph JSON written to: {output_path}")


def print_attack_summary(
    entry_points,
    crown_jewels,
    attack_paths,
    choke_points,
    overall_risk=None,
):
    """Print a readable attack-analysis summary."""

    print("\n" + "=" * 60)
    print("SECURITY ATTACK GRAPH SUMMARY")
    print("=" * 60)

    if overall_risk:
        level = overall_risk.get("risk_level", "LOW")
        score = overall_risk.get("score", 0.0)
        print(f"Overall Risk : {level} ({score})")

    print(f"Entry Points : {len(entry_points)}")
    print(f"Crown Jewels : {len(crown_jewels)}")
    print(f"Attack Paths : {len(attack_paths)}")
    print(f"Choke Points : {len(choke_points)}")

    if entry_points:
        print("\nEntry Points:")
        for item in entry_points:
            print(f"  - {item}")

    if crown_jewels:
        print("\nCrown Jewels:")
        for item in crown_jewels:
            print(f"  - {item}")

    if attack_paths:
        print("\nAttack Paths:")
        for index, path in enumerate(attack_paths, start=1):
            nodes = path.get("nodes", [])
            print(f"  {index}. {' -> '.join(nodes)}")

    if choke_points:
        print("\nChoke Points:")
        for item in choke_points:
            print(f"  - {item}")

    print("=" * 60)


def run_pipeline(
    input_path: Path = INPUT_FILE,
    output_path: Path = GRAPH_OUTPUT_FILE,
):
    input_path = Path(input_path)
    output_path = Path(output_path)

    print(f"[INFO] Loading infrastructure from: {input_path}")

    raw_data = load_json(input_path)
    parsed_data = parse_infrastructure(raw_data)

    # Run security rules if findings are not already available
    if not parsed_data.get("findings"):
        print("[INFO] No security findings found in input. Running scanner rules...")

        resources = get_resources(raw_data)

        raw_findings = run_resource_rules(resources)

        findings = sort_findings(
            deduplicate_findings(raw_findings)
        )

        parsed_data["findings"] = findings

    print(
        f"[INFO] Resources: {len(parsed_data['resources'])}, "
        f"Findings: {len(parsed_data['findings'])}"
    )

    # Build NetworkX security attack graph
    print("[INFO] Constructing attack graph...")

    graph = build_graph(parsed_data)

    # Attack path analysis
    print("[INFO] Analyzing entry points, crown jewels, and attack paths...")

    entry_points = find_entry_points(graph)

    crown_jewels = find_crown_jewels(graph)

    attack_paths = find_attack_paths(
        graph,
        entry_points,
        crown_jewels,
    )

    choke_points = find_choke_points(
        graph,
        attack_paths,
    )

    # Risk scoring
    risk_scores = score_infrastructure_risk(
        graph,
        entry_points,
        crown_jewels,
    )

    overall_risk = calculate_overall_risk(risk_scores)

    # Console summary
    print_attack_summary(
        entry_points,
        crown_jewels,
        attack_paths,
        choke_points,
        overall_risk=overall_risk,
    )

    # Export graph
    exported_data = export_graph_to_dict(
        graph,
        attack_paths,
        entry_points,
        crown_jewels,
        choke_points,
    )

    exported_data["risk"] = overall_risk
    exported_data["risk_scores"] = risk_scores

    # Save graph JSON
    save_graph_json(
        exported_data,
        output_path,
    )

    print(
        f"[INFO] Security attack graph saved to:\n"
        f"       {output_path}"
    )

    return exported_data, graph


def main():
    run_pipeline()


if __name__ == "__main__":
    main()