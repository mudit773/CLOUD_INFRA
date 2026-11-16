"""
End-to-end API test verifying all backend bridge endpoints.
"""
import sys
import json
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_endpoints():
    print("[1] Testing /api/health...")
    r = client.get("/api/health")
    assert r.status_code == 200, f"Health check failed: {r.status_code}"
    health_data = r.json()
    print("    Health status:", health_data.get("status"))
    print("    Ollama connected:", health_data.get("ollama", {}).get("connected"))

    print("\n[2] Testing /api/scan...")
    r = client.post("/api/scan", json={"input_path": "input/terraform/aws_vpc_msk", "output_path": "output/terraform.json"})
    assert r.status_code == 200, f"Scan failed: {r.status_code}, {r.text}"
    scan_data = r.json()
    print("    Scan status:", scan_data.get("status"))

    print("\n[3] Testing /api/graph...")
    r = client.get("/api/graph")
    assert r.status_code == 200, f"Graph fetch failed: {r.status_code}"
    graph_data = r.json()
    summary = graph_data.get("summary", {})
    print(f"    Summary: {summary.get('resources_count')} resources, {summary.get('relationships_count')} relationships, {summary.get('security_findings_count')} findings, Risk: {summary.get('risk_level')}")
    print(f"    Nodes count: {len(graph_data.get('nodes', []))}")
    print(f"    Edges count: {len(graph_data.get('edges', []))}")
    assert len(graph_data.get("nodes", [])) > 0, "No nodes returned"
    assert len(graph_data.get("edges", [])) > 0, "No edges returned"

    print("\n[4] Testing /api/findings...")
    r = client.get("/api/findings")
    assert r.status_code == 200, f"Findings fetch failed: {r.status_code}"
    findings_data = r.json()
    print(f"    Findings count: {len(findings_data.get('findings', []))}")

    print("\n[5] Testing /api/remediate...")
    r = client.get("/api/remediate")
    assert r.status_code == 200, f"Remediate failed: {r.status_code}"
    rem_data = r.json()
    print("    Choke Point:", rem_data.get("choke_point"))
    print("    Remediation Options:", len(rem_data.get("options", [])))
    for opt in rem_data.get("options", []):
        print(f"      - {opt.get('title')}: {len(opt.get('code', ''))} chars code snippet")
    assert len(rem_data.get("options", [])) >= 2, "Expected at least 2 options"

    print("\n ALL ENDPOINTS VERIFIED SUCCESSFULLY!")

if __name__ == "__main__":
    test_endpoints()

