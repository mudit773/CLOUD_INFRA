import json

def audit_validation_tes():
    tf_path = "scratch/dataset_outputs/validation_tes_terraform.json"
    graph_path = "scratch/dataset_outputs/validation_tes_graph_output.json"

    with open(tf_path, "r", encoding="utf-8") as f:
        tf = json.load(f)
    with open(graph_path, "r", encoding="utf-8") as f:
        g = json.load(f)

    print("=== VALIDATION_TES DETAILED AUDIT ===")
    print("\nRESOURCES:")
    for r in tf["resources"]:
        print(f"  - {r['id']} (type={r['type']})")
        print(f"      references: {r.get('references')}")
        sec = r.get("security", {})
        print(f"      security: internet_exposed={sec.get('internet_exposed')}, public_access={sec.get('public_access')}")

    print("\nRELATIONSHIPS:")
    for rel in tf["relationships"]:
        print(f"  - {rel['source']} -> {rel['target']} (type={rel['type']})")

    print("\nSECURITY FINDINGS:")
    for sf in tf.get("security_findings", []):
        print(f"  - {sf.get('id')}: resource={sf.get('resource')}, rule={sf.get('title')}")

    print("\n14 REPORTED ATTACK PATHS:")
    for idx, p in enumerate(g.get("attack_paths", []), 1):
        print(f"  Path {idx}: {' -> '.join(p['nodes'])}")
        for e in p.get("edges", []):
            print(f"    edge: {e['source']} -> {e['target']} (type={e.get('type')}, rule={e.get('rule_id')})")

audit_validation_tes()
