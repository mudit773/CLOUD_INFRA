import os
import sys

sys.path.insert(0, os.path.abspath("."))
import json

from main import main
from app.core.schema_validator import validate_schema

BASE_INPUT = os.path.abspath("./input/terraform")
OUTPUT_DIR = os.path.abspath("./scratch/dataset_outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

items = os.listdir(BASE_INPUT)
datasets = []
for item in items:
    path = os.path.join(BASE_INPUT, item)
    if os.path.isdir(path):
        datasets.append(path)
    elif item.endswith(".tf"):
        datasets.append(path)

print(f"Found {len(datasets)} datasets to test:")
results = []

for ds_path in sorted(datasets):
    name = os.path.basename(ds_path)
    out_tf = os.path.join(OUTPUT_DIR, f"{name}_terraform.json")
    out_graph = os.path.join(OUTPUT_DIR, f"{name}_graph_output.json")

    code = main([
        "-i", ds_path,
        "-o", out_tf,
        "--graph-output", out_graph,
    ])

    if code != 0:
        results.append({"dataset": name, "status": "FAILED", "code": code})
        continue

    with open(out_tf, "r", encoding="utf-8") as f:
        tf_data = json.load(f)

    with open(out_graph, "r", encoding="utf-8") as f:
        graph_data = json.load(f)

    schema_valid = False
    try:
        validate_schema(tf_data)
        schema_valid = True
    except Exception as e:
        schema_valid = False

    res_count = len(tf_data.get("resources", []))
    rel_count = len(tf_data.get("relationships", []))
    findings_count = len(tf_data.get("security_findings", []))
    ep_list = graph_data.get("entry_points", [])
    cj_list = graph_data.get("crown_jewels", [])
    ap_list = graph_data.get("attack_paths", [])
    cp_list = graph_data.get("choke_points", [])

    cj_set = set(cj_list)

    # STRICT ASSERTION FOR EVERY PATH
    all_paths_end_in_cj = True
    invalid_path_targets = []
    for p in ap_list:
        target = p.get("target")
        last_node = p.get("nodes", [])[-1] if p.get("nodes") else None
        if target not in cj_set or last_node not in cj_set:
            all_paths_end_in_cj = False
            invalid_path_targets.append((target, last_node))

    results.append({
        "dataset": name,
        "status": "SUCCESS",
        "schema_valid": schema_valid,
        "resources": res_count,
        "relationships": rel_count,
        "findings": findings_count,
        "entry_points": len(ep_list),
        "crown_jewels": len(cj_list),
        "attack_paths": len(ap_list),
        "choke_points": len(cp_list),
        "all_paths_end_in_cj": all_paths_end_in_cj,
        "invalid_targets": invalid_path_targets,
    })

print("\n" + "=" * 105)
print(f"{'Dataset':<35} | {'Schema':<7} | {'Res':<4} | {'Rel':<4} | {'Find':<4} | {'EP':<3} | {'CJ':<3} | {'AP':<3} | {'CP':<3} | {'Paths End CJ'}")
print("=" * 105)
for r in results:
    if r["status"] == "SUCCESS":
        end_cj_str = "YES" if r["all_paths_end_in_cj"] else f"NO ({len(r['invalid_targets'])})"
        print(f"{r['dataset']:<35} | {'VALID' if r['schema_valid'] else 'INVALID':<7} | {r['resources']:<4} | {r['relationships']:<4} | {r['findings']:<4} | {r['entry_points']:<3} | {r['crown_jewels']:<3} | {r['attack_paths']:<3} | {r['choke_points']:<3} | {end_cj_str}")
    else:
        print(f"{r['dataset']:<35} | FAILED ({r['code']})")
print("=" * 105)
