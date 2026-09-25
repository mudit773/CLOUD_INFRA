"""
Data model for infrastructure relationships.
"""

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Relationship:
    source: str
    target: str
    type: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_location: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Relationship":
        return cls(
            source=data.get("source", ""),
            target=data.get("target", ""),
            type=data.get("type", "related_to"),
            attributes=data.get("attributes", {}) or {},
            source_location=data.get("source_location", {}) or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "attributes": self.attributes,
            "source_location": self.source_location,
        }