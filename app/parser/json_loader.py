"""
JSON loader and parser for cloud infrastructure data.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Union


def load_json(path: Union[str, Path]) -> Dict[str, Any]:
    """Load JSON data from a file path."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Infrastructure JSON must contain a JSON object.")

    return data


def parse_infrastructure(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract normalized resources, relationships, and findings from infrastructure data.
    """
    metadata = data.get("metadata", {})

    resources = data.get("resource")
    if resources is None:
        resources = data.get("resources", [])
    if not isinstance(resources, list):
        resources = []

    valid_resources = [r for r in resources if isinstance(r, dict)]

    relationships = data.get("relationships", [])
    if not isinstance(relationships, list):
        relationships = []
    valid_relationships = [rel for rel in relationships if isinstance(rel, dict)]

    findings = data.get("security_findings", [])
    if not isinstance(findings, list):
        findings = []
    valid_findings = [f for f in findings if isinstance(f, dict)]

    return {
        "metadata": metadata,
        "resources": valid_resources,
        "relationships": valid_relationships,
        "findings": valid_findings,
    }