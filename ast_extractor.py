"""Compatibility wrapper for app.parser.ast_extractor."""

from app.parser.ast_extractor import (
    clean_value,
    extract_source_locations,
    parse_terraform_directory,
)

__all__ = [
    "clean_value",
    "extract_source_locations",
    "parse_terraform_directory",
]