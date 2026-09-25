"""Compatibility wrapper for app.security.analyzer."""

from app.security.analyzer import (
    default_security,
    normalize_to_list,
    normalize_principals,
    parse_statement_dict,
    parse_iam_policy_document,
    detect_secrets,
    extract_rule_sources,
    extract_rule_destinations,
    parse_network_rules,
    analyze_security,
)

__all__ = [
    "default_security",
    "normalize_to_list",
    "normalize_principals",
    "parse_statement_dict",
    "parse_iam_policy_document",
    "detect_secrets",
    "extract_rule_sources",
    "extract_rule_destinations",
    "parse_network_rules",
    "analyze_security",
]