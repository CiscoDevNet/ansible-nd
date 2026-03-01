# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "fastmcp>=2.0",
#     "pyyaml>=6.0",
# ]
# ///
"""
# ND 4.2 OpenAPI Schema MCP Server

Provides efficient, low-token-usage access to Cisco Nexus Dashboard 4.2
OpenAPI specifications. Loads schema files from a configurable directory
and exposes tools to browse, search, and inspect endpoints and schemas.

## Usage

    ND_SCHEMA_DIR=.claude/schemas uv run server.py

## Environment Variables

- `ND_SCHEMA_DIR` - Directory containing OpenAPI JSON/YAML files
  (default: `.claude/schemas` relative to cwd)
"""
from __future__ import annotations

import json
import os
import re
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class EndpointInfo:
    """Compact representation of a single API endpoint operation."""

    path: str
    method: str
    operation_id: str | None
    summary: str | None
    description: str | None
    tags: list[str]
    parameters: list[dict[str, Any]]
    request_body: dict[str, Any] | None
    responses: dict[str, Any]
    source_file: str

    def one_line(self) -> str:
        """Return a compact single-line representation."""
        tag_str = ",".join(self.tags) if self.tags else "-"
        summary_str = self.summary or ""
        if len(summary_str) > 80:
            summary_str = summary_str[:77] + "..."
        return f"{self.method:<7} {self.path:<65} [{tag_str}] {summary_str}"


@dataclass
class SchemaInfo:
    """Compact representation of a component schema."""

    name: str
    schema_type: str | None
    description: str | None
    properties: list[str]
    required: list[str]
    enum_values: list[str]
    full_schema: dict[str, Any]
    source_file: str

    def one_line(self) -> str:
        """Return a compact single-line representation."""
        type_str = self.schema_type or "unknown"
        if self.enum_values:
            vals = ", ".join(str(v) for v in self.enum_values[:5])
            if len(self.enum_values) > 5:
                vals += ", ..."
            return f"{self.name:<45} {type_str:<10} enum: [{vals}]"
        if self.properties:
            props = ", ".join(self.properties[:5])
            if len(self.properties) > 5:
                props += ", ..."
            return f"{self.name:<45} {type_str:<10} ({len(self.properties)} props: {props})"
        return f"{self.name:<45} {type_str:<10}"


# ---------------------------------------------------------------------------
# Schema store
# ---------------------------------------------------------------------------

HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}


class OpenAPISchemaStore:
    """
    # Summary

    Load, merge, and index OpenAPI 3.x schema files for efficient querying.

    ## Raises

    None (errors are logged to stderr and stored for reporting)
    """

    def __init__(self, schema_dir: str) -> None:
        self._schema_dir = schema_dir
        self._endpoints: list[EndpointInfo] = []
        self._endpoints_by_path: dict[str, dict[str, EndpointInfo]] = {}
        self._schemas: dict[str, SchemaInfo] = {}
        self._tags: dict[str, str] = {}
        self._api_info: dict[str, Any] = {}
        self._all_components: dict[str, dict[str, Any]] = {}
        self._loaded_files: list[str] = []
        self._file_stats: dict[str, dict[str, int]] = {}
        self._load_errors: list[str] = []

    def load(self) -> None:
        """
        # Summary

        Load all OpenAPI schema files from the schema directory.

        ## Raises

        None (errors logged to stderr)
        """
        schema_path = Path(self._schema_dir)
        if not schema_path.is_dir():
            msg = f"Schema directory not found: {self._schema_dir}"
            print(msg, file=sys.stderr)
            self._load_errors.append(msg)
            return

        files = sorted(
            f
            for f in schema_path.iterdir()
            if f.suffix.lower() in {".json", ".yaml", ".yml"} and f.is_file()
        )

        if not files:
            msg = f"No schema files found in {self._schema_dir}"
            print(msg, file=sys.stderr)
            self._load_errors.append(msg)
            return

        for filepath in files:
            try:
                self._load_file(filepath)
            except Exception as exc:
                msg = f"Error loading {filepath.name}: {exc}"
                print(msg, file=sys.stderr)
                self._load_errors.append(msg)

        print(
            f"Loaded {len(self._loaded_files)} file(s): "
            f"{len(self._endpoints)} endpoints, "
            f"{len(self._schemas)} schemas",
            file=sys.stderr,
        )

    def _load_file(self, filepath: Path) -> None:
        """
        # Summary

        Parse a single OpenAPI file and merge it into the store.

        ## Raises

        - `yaml.YAMLError` if the file is invalid YAML/JSON
        - `ValueError` if the file does not appear to be an OpenAPI spec
        """
        content = filepath.read_text(encoding="utf-8")

        if filepath.suffix.lower() == ".json":
            spec = json.loads(content)
        else:
            spec = yaml.safe_load(content)

        if not isinstance(spec, dict):
            raise ValueError(f"Expected a dict, got {type(spec).__name__}")

        if "openapi" not in spec and "swagger" not in spec:
            raise ValueError("File does not appear to be an OpenAPI spec (missing 'openapi' or 'swagger' key)")

        filename = filepath.name
        endpoint_count = 0
        schema_count = 0

        # Merge API info (first file wins for title/version)
        if not self._api_info and "info" in spec:
            self._api_info = dict(spec["info"])
        if "servers" in spec and "servers" not in self._api_info:
            self._api_info["servers"] = spec["servers"]

        # Merge tags
        for tag in spec.get("tags", []):
            tag_name = tag.get("name", "")
            if tag_name and tag_name not in self._tags:
                self._tags[tag_name] = tag.get("description", "")

        # Merge components
        components = spec.get("components", {})
        for comp_type, comp_items in components.items():
            if not isinstance(comp_items, dict):
                continue
            if comp_type not in self._all_components:
                self._all_components[comp_type] = {}
            for name, definition in comp_items.items():
                if name in self._all_components[comp_type]:
                    print(
                        f"Warning: {comp_type}/{name} redefined in {filename} "
                        f"(overwriting previous definition)",
                        file=sys.stderr,
                    )
                self._all_components[comp_type][name] = definition

                if comp_type == "schemas":
                    schema_count += 1
                    self._schemas[name] = SchemaInfo(
                        name=name,
                        schema_type=definition.get("type"),
                        description=definition.get("description"),
                        properties=list(definition.get("properties", {}).keys()),
                        required=definition.get("required", []),
                        enum_values=definition.get("enum", []),
                        full_schema=definition,
                        source_file=filename,
                    )

        # Merge paths
        shared_params = []
        for path_str, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters apply to all operations
            shared_params = path_item.get("parameters", [])

            for method in HTTP_METHODS:
                if method not in path_item:
                    continue

                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                # Merge path-level and operation-level parameters
                op_params = list(shared_params) + operation.get("parameters", [])

                ep = EndpointInfo(
                    path=path_str,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    tags=operation.get("tags", []),
                    parameters=op_params,
                    request_body=operation.get("requestBody"),
                    responses=operation.get("responses", {}),
                    source_file=filename,
                )

                self._endpoints.append(ep)

                if path_str not in self._endpoints_by_path:
                    self._endpoints_by_path[path_str] = {}

                if method.upper() in self._endpoints_by_path[path_str]:
                    print(
                        f"Warning: {method.upper()} {path_str} redefined in "
                        f"{filename} (overwriting previous definition)",
                        file=sys.stderr,
                    )

                self._endpoints_by_path[path_str][method.upper()] = ep
                endpoint_count += 1

                # Collect tags discovered in operations
                for tag in operation.get("tags", []):
                    if tag not in self._tags:
                        self._tags[tag] = ""

        self._loaded_files.append(filename)
        self._file_stats[filename] = {
            "endpoints": endpoint_count,
            "schemas": schema_count,
        }

    # ------------------------------------------------------------------
    # $ref resolution
    # ------------------------------------------------------------------

    def resolve_refs(
        self,
        obj: Any,
        max_depth: int = 3,
        _current_depth: int = 0,
        _seen: frozenset[str] | None = None,
    ) -> Any:
        """
        # Summary

        Recursively resolve `$ref` pointers in an OpenAPI object.

        Replaces `{"$ref": "#/components/schemas/Foo"}` with the actual
        definition, up to `max_depth` levels deep. Detects cycles and
        marks them with `_circular: true`.

        ## Raises

        None
        """
        if _seen is None:
            _seen = frozenset()

        if isinstance(obj, dict):
            if "$ref" in obj and len(obj) == 1:
                ref_str = obj["$ref"]

                if not ref_str.startswith("#/"):
                    return obj

                if ref_str in _seen:
                    return {"$ref": ref_str, "_circular": True}

                if _current_depth >= max_depth:
                    return {"$ref": ref_str, "_truncated": True}

                resolved = self._lookup_ref(ref_str)
                if resolved is None:
                    return {"$ref": ref_str, "_unresolved": True}

                new_seen = _seen | frozenset([ref_str])
                return self.resolve_refs(
                    deepcopy(resolved),
                    max_depth=max_depth,
                    _current_depth=_current_depth + 1,
                    _seen=new_seen,
                )

            return {
                k: self.resolve_refs(v, max_depth, _current_depth, _seen)
                for k, v in obj.items()
            }

        if isinstance(obj, list):
            return [
                self.resolve_refs(item, max_depth, _current_depth, _seen)
                for item in obj
            ]

        return obj

    def _lookup_ref(self, ref_str: str) -> dict[str, Any] | None:
        """
        # Summary

        Resolve a JSON Pointer like `#/components/schemas/User`.

        ## Raises

        None (returns None if not found)
        """
        parts = ref_str.lstrip("#/").split("/")

        if len(parts) < 2 or parts[0] != "components":
            return None

        current: Any = self._all_components
        for part in parts[1:]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current if isinstance(current, dict) else None

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def query_list_endpoints(
        self,
        tag: str | None = None,
        path_contains: str | None = None,
        method: str | None = None,
    ) -> str:
        """
        # Summary

        List endpoints with optional filters, returning compact text.

        ## Raises

        None
        """
        results = self._endpoints

        if tag:
            tag_lower = tag.lower()
            results = [ep for ep in results if any(t.lower() == tag_lower for t in ep.tags)]

        if path_contains:
            pc_lower = path_contains.lower()
            results = [ep for ep in results if pc_lower in ep.path.lower()]

        if method:
            method_upper = method.upper()
            results = [ep for ep in results if ep.method == method_upper]

        if not results:
            return "No endpoints found matching the given filters."

        lines = [ep.one_line() for ep in sorted(results, key=lambda e: (e.path, e.method))]
        lines.append(f"\n({len(results)} endpoint{'s' if len(results) != 1 else ''})")
        return "\n".join(lines)

    def query_get_endpoint(self, path: str, method: str, ref_depth: int = 3) -> str:
        """
        # Summary

        Get full details of a specific endpoint with $refs resolved.

        ## Raises

        None
        """
        method_upper = method.upper()
        path_methods = self._endpoints_by_path.get(path)

        if not path_methods or method_upper not in path_methods:
            # Try case-insensitive path match
            for stored_path, methods in self._endpoints_by_path.items():
                if stored_path.lower() == path.lower() and method_upper in methods:
                    path_methods = methods
                    break

        if not path_methods or method_upper not in path_methods:
            return (
                f"Endpoint not found: {method_upper} {path}\n"
                f"Use list_endpoints or search_endpoints to find available paths."
            )

        ep = path_methods[method_upper]

        result = {
            "path": ep.path,
            "method": ep.method,
            "operation_id": ep.operation_id,
            "summary": ep.summary,
            "description": ep.description,
            "tags": ep.tags,
            "parameters": self.resolve_refs(ep.parameters, max_depth=ref_depth),
            "request_body": self.resolve_refs(ep.request_body, max_depth=ref_depth) if ep.request_body else None,
            "responses": self.resolve_refs(ep.responses, max_depth=ref_depth),
            "source_file": ep.source_file,
        }

        return json.dumps(result, indent=2, default=str)

    def query_search_endpoints(self, query: str, max_results: int = 20) -> str:
        """
        # Summary

        Search endpoints by keyword across paths, summaries, descriptions,
        operation IDs, and parameter names.

        ## Raises

        None
        """
        q = query.lower()
        matches: list[EndpointInfo] = []

        for ep in self._endpoints:
            searchable = " ".join(
                filter(
                    None,
                    [
                        ep.path,
                        ep.summary,
                        ep.description,
                        ep.operation_id,
                    ]
                    + [p.get("name", "") for p in ep.parameters],
                )
            ).lower()

            if q in searchable:
                matches.append(ep)

        if not matches:
            return f'No endpoints found matching "{query}".'

        matches.sort(key=lambda e: (e.path, e.method))
        total = len(matches)
        truncated = matches[:max_results]

        lines = [f'Search: "{query}" (showing {len(truncated)} of {total} match{"es" if total != 1 else ""})\n']
        lines.extend(ep.one_line() for ep in truncated)

        if total > max_results:
            lines.append(f"\n... {total - max_results} more results not shown. Narrow your search or increase max_results.")

        return "\n".join(lines)

    def query_list_schemas(self, name_filter: str | None = None) -> str:
        """
        # Summary

        List component schema names with type and property preview.

        ## Raises

        None
        """
        schemas = sorted(self._schemas.values(), key=lambda s: s.name.lower())

        if name_filter:
            nf_lower = name_filter.lower()
            schemas = [s for s in schemas if nf_lower in s.name.lower()]

        if not schemas:
            return "No schemas found matching the given filter."

        lines = [s.one_line() for s in schemas]
        lines.append(f"\n({len(schemas)} schema{'s' if len(schemas) != 1 else ''})")
        return "\n".join(lines)

    def query_get_schema(self, name: str, ref_depth: int = 3) -> str:
        """
        # Summary

        Get a specific schema definition by name with $refs resolved.

        ## Raises

        None
        """
        schema_info = self._schemas.get(name)

        if not schema_info:
            # Try case-insensitive match
            for schema_name, info in self._schemas.items():
                if schema_name.lower() == name.lower():
                    schema_info = info
                    break

        if not schema_info:
            return (
                f'Schema "{name}" not found.\n'
                f"Use list_schemas to see available schema names."
            )

        resolved = self.resolve_refs(schema_info.full_schema, max_depth=ref_depth)

        result = {
            "name": schema_info.name,
            "source_file": schema_info.source_file,
            "schema": resolved,
        }

        return json.dumps(result, indent=2, default=str)

    def query_list_tags(self) -> str:
        """
        # Summary

        List all API tags with descriptions.

        ## Raises

        None
        """
        if not self._tags:
            return "No tags found in loaded schemas."

        lines = []
        for tag_name in sorted(self._tags.keys(), key=str.lower):
            desc = self._tags[tag_name]
            if desc:
                lines.append(f"{tag_name:<35} {desc}")
            else:
                lines.append(tag_name)

        lines.append(f"\n({len(self._tags)} tag{'s' if len(self._tags) != 1 else ''})")
        return "\n".join(lines)

    def query_get_api_info(self) -> str:
        """
        # Summary

        Return API metadata, loaded files, and counts.

        ## Raises

        None
        """
        lines = []

        title = self._api_info.get("title", "Unknown API")
        version = self._api_info.get("version", "unknown")
        lines.append(f"API: {title} v{version}")

        if "servers" in self._api_info:
            servers = self._api_info["servers"]
            if isinstance(servers, list):
                urls = [s.get("url", "") for s in servers if isinstance(s, dict)]
                if urls:
                    lines.append(f"Servers: {', '.join(urls)}")

        desc = self._api_info.get("description")
        if desc:
            short_desc = desc[:200] + "..." if len(desc) > 200 else desc
            lines.append(f"Description: {short_desc}")

        lines.append("")

        if self._loaded_files:
            lines.append(f"Loaded files: {len(self._loaded_files)}")
            for fname in self._loaded_files:
                stats = self._file_stats.get(fname, {})
                ep_count = stats.get("endpoints", 0)
                sc_count = stats.get("schemas", 0)
                lines.append(f"  {fname} ({ep_count} endpoints, {sc_count} schemas)")
        else:
            lines.append("No files loaded.")

        if self._load_errors:
            lines.append("")
            lines.append("Load errors:")
            for err in self._load_errors:
                lines.append(f"  - {err}")

        lines.append("")
        lines.append(f"Total: {len(self._endpoints)} endpoints, {len(self._schemas)} schemas")
        lines.append(f"Tags: {len(self._tags)}")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

schema_dir = os.environ.get("ND_SCHEMA_DIR", ".claude/schemas")
if not os.path.isabs(schema_dir):
    schema_dir = os.path.join(os.getcwd(), schema_dir)

store = OpenAPISchemaStore(schema_dir)
store.load()

mcp = FastMCP(
    name="nd-openapi",
    instructions=(
        "ND OpenAPI schema reference for Cisco Nexus Dashboard 4.2. "
        "Use list_endpoints or search_endpoints to discover endpoints, "
        "then get_endpoint for full details. Use list_schemas and get_schema "
        "for data model definitions. All results have $refs resolved inline."
    ),
)

NO_SCHEMAS_MSG = (
    f"No OpenAPI schemas loaded. Place .json, .yaml, or .yml files in: {schema_dir}"
)


def _check_loaded() -> str | None:
    """Return an error message if no schemas are loaded, else None."""
    if not store._loaded_files:
        return NO_SCHEMAS_MSG
    return None


@mcp.tool()
def list_endpoints(
    tag: str | None = None,
    path_contains: str | None = None,
    method: str | None = None,
) -> str:
    """List API endpoints. Returns compact one-line-per-endpoint format.

    Filters are optional and can be combined:
    - tag: exact tag name match
    - path_contains: substring match in the URL path
    - method: HTTP method (GET, POST, PUT, DELETE, PATCH)
    """
    err = _check_loaded()
    if err:
        return err
    return store.query_list_endpoints(tag=tag, path_contains=path_contains, method=method)


@mcp.tool()
def get_endpoint(
    path: str,
    method: str,
    ref_depth: int = 3,
) -> str:
    """Get full details of a specific API endpoint.

    Returns parameters, request body, and response schemas with $ref
    references resolved inline. Use list_endpoints first to find paths.

    - path: API path (e.g. /api/v1/infra/aaa/localUsers/{loginId})
    - method: HTTP method (GET, POST, PUT, DELETE, PATCH)
    - ref_depth: max $ref resolution depth (0-10, default 3)
    """
    err = _check_loaded()
    if err:
        return err
    return store.query_get_endpoint(path=path, method=method, ref_depth=ref_depth)


@mcp.tool()
def search_endpoints(
    query: str,
    max_results: int = 20,
) -> str:
    """Search endpoints by keyword.

    Case-insensitive search across paths, summaries, descriptions,
    operation IDs, and parameter names.

    - query: search term
    - max_results: maximum results to return (1-100, default 20)
    """
    err = _check_loaded()
    if err:
        return err
    return store.query_search_endpoints(query=query, max_results=max_results)


@mcp.tool()
def list_schemas(
    name_filter: str | None = None,
) -> str:
    """List component/model schema names.

    Returns schema name, type, and property preview in compact format.

    - name_filter: optional substring filter on schema names
    """
    err = _check_loaded()
    if err:
        return err
    return store.query_list_schemas(name_filter=name_filter)


@mcp.tool()
def get_schema(
    name: str,
    ref_depth: int = 3,
) -> str:
    """Get a component/model schema definition by name.

    Returns the full schema with $ref references resolved inline.
    Use list_schemas to find available names.

    - name: schema name (e.g. 'LocalUser')
    - ref_depth: max $ref resolution depth (0-10, default 3)
    """
    err = _check_loaded()
    if err:
        return err
    return store.query_get_schema(name=name, ref_depth=ref_depth)


@mcp.tool()
def list_tags() -> str:
    """List all API tags with descriptions. Tags group related endpoints."""
    err = _check_loaded()
    if err:
        return err
    return store.query_list_tags()


@mcp.tool()
def get_api_info() -> str:
    """Get API metadata: title, version, servers, loaded schema files, and counts."""
    return store.query_get_api_info()


if __name__ == "__main__":
    mcp.run()
