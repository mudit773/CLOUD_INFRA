"""Compatibility wrapper for app.core.schema_validator."""

from app.core.schema_validator import SchemaValidationError, validate_schema

__all__ = ["validate_schema", "SchemaValidationError"]