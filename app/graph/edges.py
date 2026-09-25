"""
Representation for security graph edges.
"""

from typing import Any, Dict, Optional


class RelationshipType:
    NETWORK_ACCESS = "NETWORK_ACCESS"
    IAM_ACCESS = "IAM_ACCESS"
    RESOURCE_ACCESS = "RESOURCE_ACCESS"
    CONTAINS = "CONTAINS"
    ATTACHED_TO = "ATTACHED_TO"
    ROUTES_TO = "ROUTES_TO"
    EXPOSED_TO = "EXPOSED_TO"
    USES_ROLE = "USES_ROLE"
    BELONGS_TO = "BELONGS_TO"
    DEPLOYED_IN = "DEPLOYED_IN"
    PROTECTED_BY = "PROTECTED_BY"
    CAN_CONNECT = "CAN_CONNECT"
    CAN_REACH = "CAN_REACH"


class GraphEdge:
    """
    Graph edge representation supporting relationship types and detailed metadata.
    """

    def __init__(
        self,
        source: str,
        target: str,
        edge_type: str,
        rule_id: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[Any] = None,
        sources: Optional[Any] = None,
        actions: Optional[Any] = None,
        resources: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.source = source
        self.target = target
        self.type = edge_type
        self.rule_id = rule_id
        self.protocol = protocol
        self.port = port
        self.sources = sources
        self.actions = actions
        self.resources = resources
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "source": self.source,
            "target": self.target,
            "type": self.type,
        }
        if self.rule_id:
            result["rule_id"] = self.rule_id
        if self.protocol:
            result["protocol"] = self.protocol
        if self.port is not None:
            result["port"] = self.port
        if self.sources:
            result["sources"] = self.sources
        if self.actions:
            result["actions"] = self.actions
        if self.resources:
            result["resources"] = self.resources

        for key, value in self.metadata.items():
            if value is not None and key not in result:
                result[key] = value

        return result