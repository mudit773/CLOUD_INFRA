"""
Cloud infrastructure security scanner.

Flow:

infra.json
    ↓
Load resources
    ↓
Run rules from rules.py
    ↓
Deduplicate findings
    ↓
Sort by severity
    ↓
Generate summary
    ↓
Save security_findings.json
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from .rules import RESOURCE_RULES


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = PROJECT_ROOT / "input" / "infra.json"
OUTPUT_FILE = PROJECT_ROOT / "output" / "security_findings.json"


# Severity order
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


# ============================================================
# Load Infrastructure
# ============================================================

def load_infrastructure(path: Path) -> Dict[str, Any]:
    """Load normalized infrastructure JSON."""

    if not path.exists():
        raise FileNotFoundError(
            f"Input file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "Infrastructure JSON must contain a JSON object."
        )

    return data


# ============================================================
# Extract Resources
# ============================================================

def get_resources(
    infrastructure: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Extract resources from normalized infrastructure JSON.

    Supports both:
        "resource": [...]
    and:
        "resources": [...]
    """

    resources = infrastructure.get("resource")

    if resources is None:
        resources = infrastructure.get("resources", [])

    if not isinstance(resources, list):
        raise ValueError(
            "The 'resource'/'resources' field must be a list."
        )

    valid_resources = []

    for resource in resources:
        if isinstance(resource, dict):
            valid_resources.append(resource)

    return valid_resources


# ============================================================
# Run Rules
# ============================================================

def run_resource_rules(
    resources: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Run every registered rule against every resource."""

    findings = []

    for resource in resources:

        resource_id = resource.get(
            "id",
            "unknown-resource"
        )

        for rule in RESOURCE_RULES:

            try:
                rule_findings = rule(resource)

                if rule_findings:
                    findings.extend(rule_findings)

            except Exception as error:
                print(
                    f"[WARNING] Rule {rule.__name__} failed "
                    f"for {resource_id}: {error}"
                )

    return findings


# ============================================================
# Deduplicate Findings
# ============================================================

def deduplicate_findings(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Remove duplicate findings.

    Two findings are considered duplicates when they have
    the same rule ID, resource ID, and source location.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding.get("rule_id"),
            finding.get("resource_id"),
            finding.get("source_location"),
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings


# ============================================================
# Sort Findings
# ============================================================

def sort_findings(
    findings: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Sort findings from most severe to least severe."""

    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(
                finding.get("severity", "INFO"),
                99
            ),
            finding.get("rule_id", ""),
            finding.get("resource_id", ""),
        ),
    )


# ============================================================
# Generate Summary
# ============================================================

def generate_summary(
    findings: List[Dict[str, Any]]
) -> Dict[str, int]:
    """Generate severity counts."""

    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(findings),
    }

    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        ).upper()

        if severity == "CRITICAL":
            summary["critical"] += 1

        elif severity == "HIGH":
            summary["high"] += 1

        elif severity == "MEDIUM":
            summary["medium"] += 1

        elif severity == "LOW":
            summary["low"] += 1

        else:
            summary["info"] += 1

    return summary


# ============================================================
# Save Results
# ============================================================

def save_results(
    findings: List[Dict[str, Any]],
    summary: Dict[str, int],
    output_path: Path,
) -> None:
    """Save scanner results to JSON."""

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    result = {
        "scanner": {
            "name": "Cloud Infrastructure Security Scanner",
            "version": "1.0.0",
        },
        "summary": summary,
        "findings": findings,
    }

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=2
        )


# ============================================================
# Print Results
# ============================================================

def print_results(
    findings: List[Dict[str, Any]],
    summary: Dict[str, int],
) -> None:
    """Print a human-readable scan summary."""

    print("\n" + "=" * 60)
    print("        CLOUD SECURITY SCAN RESULTS")
    print("=" * 60)

    print(
        f"\nTotal findings : {summary['total']}"
    )

    print(
        f"CRITICAL       : {summary['critical']}"
    )

    print(
        f"HIGH           : {summary['high']}"
    )

    print(
        f"MEDIUM         : {summary['medium']}"
    )

    print(
        f"LOW            : {summary['low']}"
    )

    print(
        f"INFO           : {summary['info']}"
    )

    print("\n" + "-" * 60)

    for index, finding in enumerate(
        findings,
        start=1
    ):
        print(
            f"\n[{index}] "
            f"{finding['severity']} | "
            f"{finding['rule_id']}"
        )

        print(
            f"    Resource : "
            f"{finding['resource_id']}"
        )

        print(
            f"    Title    : "
            f"{finding['title']}"
        )

        print(
            f"    Location : "
            f"{finding['source_location']}"
        )

        print(
            f"    Fix      : "
            f"{finding['recommendation']}"
        )

    print("\n" + "=" * 60)


# ============================================================
# Main Scanner
# ============================================================

def main() -> None:
    """Main scanner execution."""

    print(
        f"[INFO] Loading infrastructure from:\n"
        f"       {INPUT_FILE}"
    )

    infrastructure = load_infrastructure(
        INPUT_FILE
    )

    resources = get_resources(
        infrastructure
    )

    print(
        f"[INFO] Resources loaded: "
        f"{len(resources)}"
    )

    print(
        f"[INFO] Security rules loaded: "
        f"{len(RESOURCE_RULES)}"
    )

    print(
        "[INFO] Running security scan..."
    )

    findings = run_resource_rules(
        resources
    )

    findings = deduplicate_findings(
        findings
    )

    findings = sort_findings(
        findings
    )

    summary = generate_summary(
        findings
    )

    save_results(
        findings,
        summary,
        OUTPUT_FILE
    )

    print_results(
        findings,
        summary
    )

    print(
        f"\n[INFO] Results saved to:\n"
        f"       {OUTPUT_FILE}"
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    main()