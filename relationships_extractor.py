"""Compatibility wrapper for app.core.relationships."""

from app.core.relationships import (
    extract_references,
    clean_dependency_reference,
    build_relationships,
)

__all__ = [
    "extract_references",
    "clean_dependency_reference",
    "build_relationships",
]