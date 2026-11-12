"""
InfraScope Backend API Bridge.
Enables React frontend to trigger analysis pipeline dynamically, fetch graph & security findings,
and generate AI remediations via local Ollama.
"""

import os
import sys
import json
import uuid
import shutil
import zipfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
import requests

from llm_service import (
    extract_graph_context,
    generate_remediation,
    generate_remediation_stream,
    remediate_from_file,
    MODEL_NAME,
    OLLAMA_URL,
    OLLAMA_TAGS_URL,
)

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_FILE = PROJECT_ROOT / "output" / "terraform.json"
DEFAULT_GRAPH_OUTPUT_FILE = PROJECT_ROOT / "output" / "graph_output.json"
UPLOADS_BASE_DIR = PROJECT_ROOT / "input" / "uploads"

app = FastAPI(
    title="InfraScope API Bridge",
    description="Bridge connecting Terraform Graph Security Analyzer, Ollama LLM, and InfraScope React UI",
    version="1.1.0"
)

# Enable CORS for React Frontend (vite default port 5173, 3000, or any localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    input_path: str
    output_path: Optional[str] = "output/terraform.json"


def parse_remediation_options(raw_text: str) -> List[Dict[str, str]]:
    """
    Parses LLM response to extract Option 1 and Option 2 into structured objects.
    """
    options = []
    parts = []
    if "Option 1" in raw_text and "Option 2" in raw_text:
        idx1 = raw_text.find("Option 1")
        idx2 = raw_text.find("Option 2")
        parts = [raw_text[idx1:idx2].strip(), raw_text[idx2:].strip()]
    elif "### Option" in raw_text:
        splits = raw_text.split("### Option")
        parts = ["### Option" + s for s in splits if s.strip()]
    else:
        parts = [raw_text]

    for i, part in enumerate(parts[:2], start=1):
        lines = part.split("\n")
        title = lines[0].strip("#* :") if lines else f"Option {i}"
        
        code = ""
        explanation = ""
        risk_reduction = ""
        
        if "```" in part:
            code_parts = part.split("```")
            if len(code_parts) >= 3:
                code_block = code_parts[1]
                code_lines = code_block.split("\n")
                if code_lines and code_lines[0].lower() in ("terraform", "hcl", "tf"):
                    code = "\n".join(code_lines[1:]).strip()
                else:
                    code = code_block.strip()

        for line in lines:
            line_clean = line.strip()
            if line_clean.lower().startswith("**explanation:**") or line_clean.lower().startswith("explanation:"):
                explanation = line_clean.split(":", 1)[1].strip(" *")
            elif line_clean.lower().startswith("**risk reduction:**") or line_clean.lower().startswith("risk reduction:"):
                risk_reduction = line_clean.split(":", 1)[1].strip(" *")

        if not explanation:
            for line in lines[1:]:
                clean = line.strip()
                if clean and not clean.startswith("```") and not clean.startswith("**Terraform"):
                    explanation = clean.replace("**Explanation:**", "").strip()
                    break

        options.append({
            "option_id": i,
            "title": title or f"Remediation Option {i}",
            "explanation": explanation or "Least-privilege infrastructure patch to sever attack choke point.",
            "code": code,
            "risk_reduction": risk_reduction or "Reduces unauthorized lateral movement and exposure."
        })

    return options


def get_combined_graph_data(
    tf_path: Path = DEFAULT_OUTPUT_FILE,
    graph_path: Path = DEFAULT_GRAPH_OUTPUT_FILE
) -> Dict[str, Any]:
    """
    Reads terraform.json and graph_output.json and formats data for React frontend.
    If no scan output exists, returns an empty initial schema.
    """
    if not tf_path.exists() and not graph_path.exists():
        return {
            "summary": {
                "resources_count": 0,
                "relationships_count": 0,
                "security_findings_count": 0,
                "cloud_provider": "None",
                "region": "us-east-1",
                "terraform_version": "1.x",
                "risk_level": "NONE",
                "risk_score": 0.0,
                "entry_points_count": 0,
                "crown_jewels_count": 0,
                "attack_paths_count": 0,
                "choke_points_count": 0,
            },
            "nodes": [],
            "edges": [],
            "resources": [],
            "relationships": [],
            "findings": [],
            "attack_paths": [],
            "choke_points": [],
            "entry_points": [],
            "crown_jewels": [],
            "metadata": {},
        }

    tf_data = {}
    if tf_path.exists():
        try:
            with tf_path.open("r", encoding="utf-8") as f:
                tf_data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to read {tf_path}: {e}")

    graph_data = {}
    if graph_path.exists():
        try:
            with graph_path.open("r", encoding="utf-8") as f:
                graph_data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to read {graph_path}: {e}")

    resources = tf_data.get("resources", [])
    relationships = tf_data.get("relationships", [])
    findings = tf_data.get("security_findings", []) or graph_data.get("findings", [])

    entry_points = graph_data.get("entry_points", [])
    crown_jewels = graph_data.get("crown_jewels", [])
    attack_paths = graph_data.get("attack_paths", [])
    choke_points = graph_data.get("choke_points", [])
    risk = graph_data.get("risk", {"score": 0.0, "risk_level": "LOW"})
    metadata = tf_data.get("metadata", {})

    # Extract all nodes and edge pairs in attack path
    attack_nodes = set()
    attack_edge_pairs = set()
    for ap in attack_paths:
        if isinstance(ap, dict):
            ns = ap.get("nodes", [])
            attack_nodes.update(ns)
            for i in range(len(ns) - 1):
                attack_edge_pairs.add((ns[i], ns[i+1]))

    # Choke point map
    cp_set = {
        cp.get("resource_id") if isinstance(cp, dict) else cp
        for cp in choke_points
    }
    ep_set = set(entry_points)
    cj_set = set(crown_jewels)

    # Format nodes
    formatted_nodes = []
    seen_nodes = set()

    # 1. First add from resources
    for res in resources:
        res_id = res["id"]
        seen_nodes.add(res_id)
        formatted_nodes.append({
            "id": res_id,
            "name": res.get("name", res_id),
            "type": res.get("type", "unknown"),
            "provider": res.get("provider", "aws"),
            "region": res.get("region"),
            "is_entry_point": res_id in ep_set,
            "is_crown_jewel": res_id in cj_set,
            "is_choke_point": res_id in cp_set,
            "in_attack_path": res_id in attack_nodes,
            "security": res.get("security", {}),
            "attributes": res.get("attributes", {}),
            "source_location": res.get("source_location", {}),
        })

    # 2. Add any graph nodes not in resources (e.g. 'internet')
    for g_node in graph_data.get("nodes", []):
        gid = g_node.get("id") if isinstance(g_node, dict) else g_node
        if gid and gid not in seen_nodes:
            seen_nodes.add(gid)
            formatted_nodes.append({
                "id": gid,
                "name": gid,
                "type": "external" if gid == "internet" else "graph_node",
                "provider": "external" if gid == "internet" else "aws",
                "is_entry_point": gid in ep_set or gid == "internet",
                "is_crown_jewel": gid in cj_set,
                "is_choke_point": gid in cp_set,
                "in_attack_path": gid in attack_nodes,
                "security": {},
                "attributes": {},
            })

    # Format edges combining graph edges and relationships
    formatted_edges = []
    seen_edge_keys = set()

    # Priority to graph edges with rule IDs
    for ge in graph_data.get("edges", []):
        s = ge.get("source")
        t = ge.get("target")
        if s and t:
            edge_key = (s, t)
            seen_edge_keys.add(edge_key)
            formatted_edges.append({
                "id": f"{s}->{t}",
                "source": s,
                "target": t,
                "type": ge.get("type", "CONNECTED_TO"),
                "in_attack_path": (s, t) in attack_edge_pairs,
                "rule_id": ge.get("rule_id"),
                "protocol": ge.get("protocol"),
            })

    # Add any relationships from terraform.json not yet covered
    for rel in relationships:
        s = rel.get("source")
        t = rel.get("target")
        if s and t and (s, t) not in seen_edge_keys:
            seen_edge_keys.add((s, t))
            formatted_edges.append({
                "id": f"{s}->{t}",
                "source": s,
                "target": t,
                "type": rel.get("type", "REFERENCES"),
                "in_attack_path": (s, t) in attack_edge_pairs,
                "rule_id": None,
            })

    # Format findings cleanly
    formatted_findings = []
    for f in findings:
        formatted_findings.append({
            "id": f.get("id") or f.get("rule_id", "FINDING"),
            "severity": f.get("severity", "MEDIUM"),
            "category": f.get("category", "NETWORK_EXPOSURE"),
            "resource": f.get("resource") or f.get("resource_id", "Unknown"),
            "title": f.get("title", "Security Finding"),
            "description": f.get("description", ""),
            "recommendation": f.get("recommendation", "Apply security best practice"),
            "evidence": f.get("evidence", {}),
            "attack_vector": f.get("attack_vector", ""),
        })

    cloud_p = metadata.get("cloud_provider", "AWS")
    if cloud_p:
        cloud_p = cloud_p.upper()

    summary = {
        "resources_count": len(resources),
        "relationships_count": len(formatted_edges),
        "security_findings_count": len(formatted_findings),
        "cloud_provider": cloud_p or "AWS",
        "region": metadata.get("region", "us-east-1"),
        "terraform_version": metadata.get("terraform_version", "1.x"),
        "risk_level": risk.get("risk_level", "LOW"),
        "risk_score": risk.get("score", 0.0),
        "entry_points_count": len(entry_points),
        "crown_jewels_count": len(crown_jewels),
        "attack_paths_count": len(attack_paths),
        "choke_points_count": len(choke_points),
    }

    return {
        "summary": summary,
        "nodes": formatted_nodes,
        "edges": formatted_edges,
        "resources": resources,
        "relationships": relationships,
        "findings": formatted_findings,
        "attack_paths": attack_paths,
        "choke_points": choke_points,
        "entry_points": entry_points,
        "crown_jewels": crown_jewels,
        "metadata": metadata,
    }


def execute_pipeline(input_path: Path, output_path: Path = DEFAULT_OUTPUT_FILE) -> Dict[str, Any]:
    """
    Core function that triggers main.py strictly upon user action.
    """
    if not input_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"Specified Terraform input path does not exist: {input_path}"
        )

    # Ensure output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)
    graph_output_path = output_path.parent / "graph_output.json"

    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        "-i", str(input_path),
        "-o", str(output_path),
        "--graph-output", str(graph_output_path),
        "--summary"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        check=False
    )

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline execution failed: {result.stderr or result.stdout}"
        )

    # Load resulting graph payload
    return get_combined_graph_data(output_path, graph_output_path)


@app.get("/api/health")
def health_check():
    """
    Checks backend readiness and local Ollama connectivity.
    """
    ollama_ready = False
    ollama_models = []
    try:
        r = requests.get(OLLAMA_TAGS_URL, timeout=2)
        if r.status_code == 200:
            ollama_ready = True
            ollama_models = [m.get("name") for m in r.json().get("models", [])]
    except Exception:
        ollama_ready = False

    return {
        "status": "healthy",
        "service": "InfraScope API Bridge",
        "ollama": {
            "connected": ollama_ready,
            "target_model": MODEL_NAME,
            "model_present": any(MODEL_NAME in m for m in ollama_models),
            "available_models": ollama_models,
        },
        "output_available": DEFAULT_OUTPUT_FILE.exists()
    }


@app.post("/api/scan")
def trigger_scan(request: ScanRequest):
    """
    Triggers scan pipeline for a specific user-provided folder or file path.
    Only triggers upon user action.
    """
    if not request.input_path:
        raise HTTPException(status_code=400, detail="input_path is required for scanning.")

    input_path = PROJECT_ROOT / request.input_path
    if not input_path.exists():
        # Check absolute path
        input_path = Path(request.input_path)
        if not input_path.exists():
            raise HTTPException(status_code=400, detail=f"Input path not found: {request.input_path}")

    output_path = PROJECT_ROOT / (request.output_path or "output/terraform.json")
    graph_data = execute_pipeline(input_path, output_path)

    return {
        "status": "success",
        "message": f"Scan completed successfully for: {request.input_path}",
        "data": graph_data
    }


@app.post("/api/upload")
async def upload_and_scan(
    files: Optional[List[UploadFile]] = File(None),
    file: Optional[UploadFile] = File(None),
    folder_path: Optional[str] = Form(None),
    git_url: Optional[str] = Form(None)
):
    """
    Dynamically accepts .tf files, ZIP archive, or folder path from the user,
    saves to an isolated upload session folder, and triggers the analysis pipeline.
    """
    # 1. Handle folder path passed directly
    if folder_path and folder_path.strip():
        resolved_path = PROJECT_ROOT / folder_path.strip()
        if not resolved_path.exists():
            resolved_path = Path(folder_path.strip())
        if not resolved_path.exists():
            raise HTTPException(status_code=400, detail=f"Target folder does not exist: {folder_path}")
        
        # Verify it has .tf files
        tf_files = list(resolved_path.glob("**/*.tf"))
        if not tf_files:
            raise HTTPException(status_code=400, detail=f"No .tf files found in target folder: {folder_path}")

        graph_data = execute_pipeline(resolved_path, DEFAULT_OUTPUT_FILE)
        return {
            "status": "success",
            "message": f"Scan executed on folder: {resolved_path.name}",
            "source_type": "folder",
            "source_name": resolved_path.name,
            "data": graph_data
        }

    # 2. Gather uploaded files
    upload_list = []
    if files:
        upload_list.extend(files)
    if file and file not in upload_list:
        upload_list.append(file)

    if not upload_list:
        raise HTTPException(
            status_code=400,
            detail="No files or valid folder path were provided for upload."
        )

    # Create isolated session directory for this upload
    session_id = f"upload_{uuid.uuid4().hex[:8]}"
    session_dir = UPLOADS_BASE_DIR / session_id
    session_dir.mkdir(parents=True, exist_ok=True)

    scan_target = session_dir

    for upload_item in upload_list:
        if not upload_item.filename:
            continue
        dest_file = session_dir / upload_item.filename
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        with dest_file.open("wb") as buffer:
            shutil.copyfileobj(upload_item.file, buffer)

        # Unpack if zip
        if upload_item.filename.lower().endswith(".zip"):
            extract_dir = session_dir / Path(upload_item.filename).stem
            extract_dir.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest_file, "r") as zip_ref:
                zip_ref.extractall(extract_dir)
            scan_target = extract_dir

    # Check that at least one .tf file exists
    tf_files = list(scan_target.glob("**/*.tf"))
    if not tf_files:
        raise HTTPException(
            status_code=400,
            detail="No Terraform (.tf) files found in the uploaded file(s) or archive."
        )

    # Run user-initiated scan
    graph_data = execute_pipeline(scan_target, DEFAULT_OUTPUT_FILE)

    primary_name = upload_list[0].filename if upload_list else session_id
    return {
        "status": "success",
        "message": f"Successfully analyzed {len(tf_files)} Terraform file(s)",
        "source_type": "upload",
        "source_name": primary_name,
        "data": graph_data
    }


@app.get("/api/graph")
def fetch_graph():
    """
    Returns existing graph nodes, edges, summary metrics, and findings from output JSON.
    Never auto-triggers a scan without user action.
    """
    data = get_combined_graph_data(DEFAULT_OUTPUT_FILE, DEFAULT_GRAPH_OUTPUT_FILE)
    return data


@app.get("/api/findings")
def fetch_findings():
    """
    Returns security findings list and risk summary from existing scan output.
    """
    data = get_combined_graph_data(DEFAULT_OUTPUT_FILE, DEFAULT_GRAPH_OUTPUT_FILE)
    return {
        "summary": data["summary"],
        "findings": data["findings"],
        "risk": data.get("summary", {}).get("risk_level", "NONE")
    }


@app.post("/api/remediate")
@app.get("/api/remediate")
def fetch_remediations(
    json_path: str = Query("output/terraform.json"),
    stream: bool = Query(False)
):
    """
    Invokes llm_service.py to extract attack path, resource inventory, and choke point,
    then generates the 2 strict remediation options via local Ollama.
    """
    target_path = PROJECT_ROOT / json_path
    if not target_path.exists():
        raise HTTPException(
            status_code=400,
            detail="No graph analysis output exists. Please run a scan first from the Upload or Visualize page."
        )

    context = extract_graph_context(target_path)

    if stream:
        def event_generator():
            for chunk in generate_remediation_stream(
                context["attack_chain"],
                context["choke_point"],
                context["resource_inventory"]
            ):
                yield f"data: {json.dumps({'token': chunk})}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    # Non-streaming response
    raw_remediation = remediate_from_file(target_path, stream=False)
    options = parse_remediation_options(raw_remediation)

    return {
        "status": "success",
        "attack_chain": context["attack_chain"],
        "choke_point": context["choke_point"],
        "all_choke_points": context["all_choke_points"],
        "total_resources": context["total_resources"],
        "remediation_markdown": raw_remediation,
        "options": options
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
