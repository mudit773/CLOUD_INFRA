"""
Data model for security findings.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    source_location: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            rule_id=data.get("rule_id", "UNKNOWN-001"),
            severity=data.get("severity", "MEDIUM"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            resource_id=data.get("resource_id", "unknown"),
            resource_type=data.get("resource_type", "unknown"),
            source_location=data.get("source_location", ""),
            evidence=data.get("evidence", {}) or {},
            recommendation=data.get("recommendation", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "source_location": self.source_location,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }