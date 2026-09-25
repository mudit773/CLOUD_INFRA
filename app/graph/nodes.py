"""
Representation for security graph nodes.
"""

from typing import Any, Dict, List, Optional


class GraphNode:
    """
    Graph node representation supporting infrastructure resources and special nodes (e.g., Internet).
    Findings are attached to resource nodes rather than creating finding nodes.
    """

    def __init__(
        self,
        node_id: str,
        node_type: str,
        name: Optional[str] = None,
        provider: str = "aws",
        attributes: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, Any]] = None,
        security_config: Optional[Dict[str, Any]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        is_special: bool = False,
    ):
        self.id = node_id
        self.type = node_type
        self.name = name or node_id
        self.provider = provider
        self.attributes = attributes or {}
        self.tags = tags or {}
        self.security_config = security_config or {}
        self.findings = findings or []
        self.is_special = is_special

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Attach a security finding to this node if not already present."""
        rule_id = finding.get("rule_id")
        src_loc = finding.get("source_location")
        # Avoid duplicate findings on the same node
        for existing in self.findings:
            if existing.get("rule_id") == rule_id and existing.get("source_location") == src_loc:
                return
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        """Convert node representation to dictionary format."""
        return {
            "id": self.id,
            "type": self.type,
            "name": self.name,
            "provider": self.provider,
            "attributes": self.attributes,
            "tags": self.tags,
            "security": self.security_config,
            "findings": self.findings,
            "is_special": self.is_special,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GraphNode":
        return cls(
            node_id=data["id"],
            node_type=data.get("type", "unknown"),
            name=data.get("name"),
            provider=data.get("provider", "aws"),
            attributes=data.get("attributes"),
            tags=data.get("tags"),
            security_config=data.get("security"),
            findings=data.get("findings"),
            is_special=data.get("is_special", False),
        )


def create_internet_node() -> GraphNode:
    """Helper to create the special Internet node."""
    return GraphNode(
        node_id="internet",
        node_type="external",
        name="Internet",
        provider="external",
        attributes={"description": "External Internet / Public Network"},
        is_special=True,
    )