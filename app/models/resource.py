"""
Data model for infrastructure resources.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class Resource:
    id: str
    type: str
    name: str
    provider: str = "aws"
    region: str = ""
    attributes: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    depends_on: List[str] = field(default_factory=list)
    source_location: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Resource":
        return cls(
            id=data.get("id", "unknown"),
            type=data.get("type", "unknown"),
            name=data.get("name", ""),
            provider=data.get("provider", "aws"),
            region=data.get("region", ""),
            attributes=data.get("attributes", {}) or {},
            tags=data.get("tags", {}) or {},
            security=data.get("security", {}) or {},
            references=data.get("references", []) or [],
            depends_on=data.get("depends_on", []) or [],
            source_location=data.get("source_location", {}) or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "provider": self.provider,
            "region": self.region,
            "attributes": self.attributes,
            "tags": self.tags,
            "security": self.security,
            "references": self.references,
            "depends_on": self.depends_on,
            "source_location": self.source_location,
        }