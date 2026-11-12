"""
LLM Service for Automated Infrastructure Remediation.
Connects with local Ollama service (qwen2.5-coder:1.5b) to analyze
attack paths, resource inventory, and choke points extracted from
graph security analysis JSON, generating 2 strict least-privilege remediation options.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Generator, Dict, Any, List, Optional
import requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_TAGS_URL = os.environ.get(
    "OLLAMA_TAGS_URL",
    f"{OLLAMA_URL.rsplit('/api/', 1)[0]}/api/tags",
)
MODEL_NAME = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:1.5b")


def extract_graph_context(json_path: str | Path) -> Dict[str, Any]:
    """
    Parses the graph JSON output (e.g. output/terraform.json or output/graph_output.json)
    to extract:
      1. Detected attack paths
      2. Resource inventory (and details for resources on the attack path)
      3. Identified choke points
    """
    path = Path(json_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Graph JSON file not found at: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    # 1. Identify companion graph_output.json if terraform.json was passed
    graph_data = {}
    companion_path = path.parent / "graph_output.json"
    if "attack_paths" in data and "choke_points" in data:
        graph_data = data
    elif companion_path.exists():
        try:
            with companion_path.open("r", encoding="utf-8") as gf:
                graph_data = json.load(gf)
        except Exception as e:
            print(f"[WARN] Failed to load companion graph JSON: {e}", file=sys.stderr)

    # 2. Extract Attack Paths
    raw_attack_paths = graph_data.get("attack_paths", data.get("attack_paths", []))
    formatted_attack_paths: List[str] = []

    for path_obj in raw_attack_paths:
        if isinstance(path_obj, dict):
            nodes = path_obj.get("nodes", [])
            if nodes:
                path_str = " -> ".join(nodes)
                rules = path_obj.get("rules_involved", [])
                if rules:
                    path_str += f" [Vulnerabilities: {', '.join(rules)}]"
                formatted_attack_paths.append(path_str)
        elif isinstance(path_obj, str):
            formatted_attack_paths.append(path_obj)

    if not formatted_attack_paths and "relationships" in data:
        # Fallback synthesis if relationships exist
        for rel in data.get("relationships", [])[:5]:
            formatted_attack_paths.append(f"{rel.get('source')} -> {rel.get('target')} ({rel.get('type')})")

    # 3. Extract Choke Points
    raw_choke_points = graph_data.get("choke_points", data.get("choke_points", []))
    choke_point_str = ""
    choke_point_list = []

    for cp in raw_choke_points:
        if isinstance(cp, dict):
            res_id = cp.get("resource_id", "Unknown")
            pct = cp.get("path_percentage", 100.0)
            choke_point_list.append(f"{res_id} (Severs {pct}% of paths)")
        elif isinstance(cp, str):
            choke_point_list.append(cp)

    if choke_point_list:
        choke_point_str = choke_point_list[0]
    elif formatted_attack_paths:
        # Pick the second node in the first path as a sensible choke point
        first_path = raw_attack_paths[0] if raw_attack_paths else None
        if isinstance(first_path, dict) and len(first_path.get("nodes", [])) > 1:
            choke_point_str = first_path["nodes"][1]
        else:
            choke_point_str = "Intermediate resource along attack path"
    else:
        choke_point_str = "Resource with open public egress/ingress"

    # 4. Extract Resource Inventory
    resources = data.get("resources", [])
    if not resources and "nodes" in data:
        resources = data.get("nodes", [])

    resource_inventory: List[Dict[str, Any]] = []
    # Identify resources involved in the attack path for focused context
    attack_node_names = set()
    for ap in raw_attack_paths:
        if isinstance(ap, dict):
            attack_node_names.update(ap.get("nodes", []))

    for res in resources:
        if isinstance(res, dict):
            res_id = res.get("id") or res.get("name")
            res_type = res.get("type", "unknown")
            is_relevant = res_id in attack_node_names if attack_node_names else True

            inv_entry = {
                "id": res_id,
                "type": res_type,
                "provider": res.get("provider"),
                "is_attack_node": res_id in attack_node_names,
            }
            if is_relevant and "security" in res:
                sec = res["security"]
                inv_entry["security"] = {
                    k: v for k, v in sec.items()
                    if v and k in ("ingress_rules", "egress_rules", "internet_exposed", "encryption_enabled")
                }
            resource_inventory.append(inv_entry)

    return {
        "attack_chain": formatted_attack_paths,
        "choke_point": choke_point_str,
        "all_choke_points": choke_point_list,
        "resource_inventory": resource_inventory,
        "total_resources": len(resources),
        "risk": graph_data.get("risk", {"score": 0, "risk_level": "UNKNOWN"}),
    }


def build_prompt(attack_chain: List[str], choke_point: str, resource_inventory: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Builds a concise, highly constrained prompt instructing the LLM to output
    EXACTLY 2 least-privilege remediation options.
    """
    inv_summary = ""
    if resource_inventory:
        attack_resources = [r for r in resource_inventory if r.get("is_attack_node")]
        if attack_resources:
            inv_summary = f"\nRelevant Resources on Attack Path:\n{json.dumps(attack_resources[:4], indent=2)}\n"

    prompt = f"""You are a senior DevSecOps engineer.
Analyze this attack path:
{json.dumps(attack_chain, indent=2)}
{inv_summary}
Choke Point to sever:
{choke_point}

Task:
1. Provide EXACTLY 2 distinct least-privilege remediation options (Option 1 and Option 2) to fix this choke point.
2. For each option, include a 1-sentence explanation of the risk reduction and a clean ```terraform code block snippet implementing the fix.
3. Do not include any extra options, commentary, or introductory text.
"""
    return prompt


def generate_remediation_stream(
    attack_chain: List[str],
    choke_point: str,
    resource_inventory: Optional[List[Dict[str, Any]]] = None,
) -> Generator[str, None, None]:
    """
    Sends the attack path and choke point to local Ollama and yields streamed text tokens.
    """
    prompt = build_prompt(attack_chain, choke_point, resource_inventory)

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": True,
        "options": {
            "temperature": 0.2,
            "num_predict": 1024,
            "stop": ["Option 3", "Option 3:", "Task:"]
        }
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=(10, 90))
        response.raise_for_status()

        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                token = chunk.get("response", "")
                yield token

                if chunk.get("done", False):
                    break

    except requests.exceptions.Timeout:
        yield "\n[ERROR] Request timed out. Ollama took too long to respond."
    except requests.exceptions.ConnectionError:
        yield f"\n[ERROR] Could not connect to Ollama at {OLLAMA_URL}. Make sure Ollama is running."
    except Exception as e:
        yield f"\n[ERROR] An unexpected error occurred: {e}"


def generate_remediation(
    attack_chain: List[str],
    choke_point: str,
    resource_inventory: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Sends the attack path to local Ollama and returns the full completed remediation response text.
    """
    chunks = []
    for token in generate_remediation_stream(attack_chain, choke_point, resource_inventory):
        chunks.append(token)
    return "".join(chunks)


def remediate_from_file(json_path: str | Path, stream: bool = False):
    """
    High-level entrypoint: loads graph context from JSON path and generates remediation.
    """
    context = extract_graph_context(json_path)
    attack_chain = context["attack_chain"]
    choke_point = context["choke_point"]
    inventory = context["resource_inventory"]

    if stream:
        return generate_remediation_stream(attack_chain, choke_point, inventory)
    return generate_remediation(attack_chain, choke_point, inventory)


def main():
    parser = argparse.ArgumentParser(description="AI Remediation Service using local Ollama")
    parser.add_argument(
        "json_path",
        nargs="?",
        default="output/terraform.json",
        help="Path to graph JSON or terraform.json (default: output/terraform.json)"
    )
    parser.add_argument(
        "--stream",
        action="store_true",
        default=True,
        help="Stream tokens to stdout in real-time (default: True)"
    )
    args = parser.parse_args()

    print(f"[INFO] Loading infrastructure graph context from: {args.json_path}")
    context = extract_graph_context(args.json_path)

    print("\n--- [Extracted Context] ---")
    print(f"Attack Path(s) : {context['attack_chain']}")
    print(f"Choke Point    : {context['choke_point']}")
    print(f"Total Resources: {context['total_resources']}")
    print("---------------------------\n")

    for token in generate_remediation_stream(
        context["attack_chain"],
        context["choke_point"],
        context["resource_inventory"],
    ):
        sys.stdout.write(token)
        sys.stdout.flush()

    print("\n\n--- [Complete] ---\n")


if __name__ == "__main__":
    main()
