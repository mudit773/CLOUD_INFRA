"""Compatibility wrapper for app.core.converter."""

from app.core.converter import (
    clean_terraform_type,
    is_utility_provider,
    detect_cloud_provider,
    is_static_concrete_value,
    detect_metadata_region,
    resolve_resource_region,
    detect_resource_provider,
    get_variable_defaults_and_map,
    get_terraform_version,
    get_provider_versions,
    convert_to_schema,
    save_json,
)

__all__ = [
    "clean_terraform_type",
    "is_utility_provider",
    "detect_cloud_provider",
    "is_static_concrete_value",
    "detect_metadata_region",
    "resolve_resource_region",
    "detect_resource_provider",
    "get_variable_defaults_and_map",
    "get_terraform_version",
    "get_provider_versions",
    "convert_to_schema",
    "save_json",
]