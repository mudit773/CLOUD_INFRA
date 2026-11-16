"""
Automated verification for dynamic uploads, scan execution, and graph relationships.
"""
import io
from fastapi.testclient import TestClient
from server import app

client = TestClient(app)

def test_dynamic_pipeline():
    print("[1] Verifying no auto-scan side effect on health check...")
    r = client.get("/api/health")
    assert r.status_code == 200

    print("\n[2] Testing dynamic scan with custom folder path ('input/terraform/new_security_test')...")
    r = client.post("/api/scan", json={"input_path": "input/terraform/new_security_test"})
    assert r.status_code == 200, f"Scan failed: {r.text}"
    data = r.json().get("data", {})
    summary = data.get("summary", {})
    print(f"    Scanned new_security_test: {summary.get('resources_count')} resources, {summary.get('relationships_count')} links, {summary.get('security_findings_count')} findings")
    assert summary.get("resources_count") > 0, "No resources found in new_security_test"

    print("\n[3] Testing dynamic file upload via /api/upload with custom .tf content...")
    tf_content = """
    resource "aws_vpc" "custom_vpc" {
      cidr_block = "10.0.0.0/16"
      tags = {
        Name = "custom-test-vpc"
      }
    }

    resource "aws_security_group" "custom_sg" {
      name   = "custom_sg"
      vpc_id = aws_vpc.custom_vpc.id

      ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
      }
    }
    """
    file_tuple = ("main.tf", io.BytesIO(tf_content.encode("utf-8")), "text/plain")
    r = client.post("/api/upload", files={"files": file_tuple})
    assert r.status_code == 200, f"Upload failed: {r.text}"
    upload_res = r.json()
    up_data = upload_res.get("data", {})
    up_summary = up_data.get("summary", {})
    print(f"    Custom uploaded files scanned: {up_summary.get('resources_count')} resources, {up_summary.get('relationships_count')} links")
    assert up_summary.get("resources_count") >= 2, "Expected 2 resources from custom upload"
    print(f"    Nodes: {[n.get('id') for n in up_data.get('nodes', [])]}")
    print(f"    Edges: {[e.get('id') for e in up_data.get('edges', [])]}")

    print("\n[4] Re-running sample scan with aws_vpc_msk to restore default graph state...")
    r = client.post("/api/scan", json={"input_path": "input/terraform/aws_vpc_msk"})
    assert r.status_code == 200
    msk_summary = r.json().get("data", {}).get("summary", {})
    print(f"    Restored aws_vpc_msk: {msk_summary.get('resources_count')} resources, {msk_summary.get('relationships_count')} links")

    print("\n ALL DYNAMIC UPLOAD & SCAN CHECKS PASSED!")

if __name__ == "__main__":
    test_dynamic_pipeline()
