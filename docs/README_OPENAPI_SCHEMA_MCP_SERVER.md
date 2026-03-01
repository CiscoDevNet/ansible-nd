# ND OpenAPI Schema MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that gives Claude Code efficient, low-token access to the Cisco Nexus Dashboard 4.2 OpenAPI specification. Instead of loading thousands of lines of raw schema into context, Claude queries specific endpoints, schemas, and tags on demand.

## Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Python >= 3.11

No other setup is required. The server uses [PEP 723](https://peps.python.org/pep-0723/) inline script metadata, so `uv run` automatically installs the two dependencies (`fastmcp`, `pyyaml`) on first launch.

## Quick Start

1. **Add schema files** to the `.claude/schemas/` directory:

   ```
   .claude/schemas/
     nd-infra-api.yaml
     nd-manage-api.json
     nd-insights-api.yaml
   ```

   Any `.json`, `.yaml`, or `.yml` file containing a valid OpenAPI 3.x (or Swagger 2.x) specification will be loaded. Multiple files are merged automatically.

2. **Start a Claude Code session** from the project root. The server launches automatically via the `.mcp.json` configuration that is already checked into the repository.

3. **Verify** by running `/mcp` in Claude Code. You should see `nd-openapi` listed with 7 tools.

## Configuration

### `.mcp.json` (project root, checked in)

This file registers the MCP server for all team members:

```json
{
    "mcpServers": {
        "nd-openapi": {
            "command": "uv",
            "args": ["run", ".claude/mcp-servers/nd-openapi/server.py"],
            "env": {
                "ND_SCHEMA_DIR": ".claude/schemas"
            }
        }
    }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ND_SCHEMA_DIR` | `.claude/schemas` | Directory containing OpenAPI schema files. Relative paths are resolved from the current working directory. |

To point at a different schema directory, update the `env` block in `.mcp.json` or export the variable before starting Claude Code:

```bash
export ND_SCHEMA_DIR=/path/to/my/schemas
claude
```

## Tools Reference

The server exposes 7 read-only tools. Tools that list or search return **plain text** (compact, one line per item) while tools that retrieve full details return **JSON** with `$ref` references resolved inline.

### `get_api_info`

Returns API metadata, loaded file names with per-file endpoint/schema counts, and totals.

**Parameters:** None

**Example output:**

```
API: Cisco Nexus Dashboard API v4.2.0

Loaded files: 2
  nd-infra-api.yaml (142 endpoints, 67 schemas)
  nd-manage-api.json (89 endpoints, 43 schemas)

Total: 231 endpoints, 110 schemas
Tags: 18
```

---

### `list_tags`

Lists all API tags with their descriptions. Tags group related endpoints (e.g. `infra-aaa`, `manage-sites`).

**Parameters:** None

**Example output:**

```
infra-aaa                           Authentication, Authorization, and Accounting
manage-sites                        Site management

(2 tags)
```

---

### `list_endpoints`

Lists endpoints in compact one-line format. All filters are optional and can be combined.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `tag` | `string` | Filter by exact tag name |
| `path_contains` | `string` | Filter by substring in the URL path |
| `method` | `string` | Filter by HTTP method (GET, POST, PUT, DELETE, PATCH) |

**Example output:**

```
GET     /api/v1/infra/aaa/localUsers                                      [infra-aaa] List local users
POST    /api/v1/infra/aaa/localUsers                                      [infra-aaa] Create a local user
GET     /api/v1/infra/aaa/localUsers/{loginId}                            [infra-aaa] Get a local user by login ID

(3 endpoints)
```

---

### `search_endpoints`

Full-text search across endpoint paths, summaries, descriptions, operation IDs, and parameter names.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `query` | `string` | *(required)* | Case-insensitive search term |
| `max_results` | `int` | `20` | Maximum results to return (1-100) |

**Example output:**

```
Search: "user" (showing 3 of 3 matches)

GET     /api/v1/infra/aaa/localUsers                                      [infra-aaa] List local users
POST    /api/v1/infra/aaa/localUsers                                      [infra-aaa] Create a local user
GET     /api/v1/infra/aaa/localUsers/{loginId}                            [infra-aaa] Get a local user by login ID
```

---

### `get_endpoint`

Returns full details of a single endpoint as JSON, including parameters, request body, and response schemas. All `$ref` pointers are resolved inline to the specified depth.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `path` | `string` | *(required)* | API path (e.g. `/api/v1/infra/aaa/localUsers/{loginId}`) |
| `method` | `string` | *(required)* | HTTP method (GET, POST, PUT, DELETE, PATCH) |
| `ref_depth` | `int` | `3` | Max `$ref` resolution depth (0 = no resolution, max 10) |

Use `list_endpoints` or `search_endpoints` first to discover paths.

---

### `list_schemas`

Lists component/model schema names with their type and a preview of property names.

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `name_filter` | `string` | Optional substring filter on schema names |

**Example output:**

```
LocalUser                                     object     (8 props: loginId, firstName, lastName, email, phone, ...)
LocalUserCreate                               object     (5 props: loginId, password, firstName, lastName, email)
HealthStatus                                  string     enum: [healthy, degraded, critical]
UserRole                                      object     (3 props: roleName, roleId, permissions)

(4 schemas)
```

---

### `get_schema`

Returns a full component/model schema definition as JSON with `$ref` references resolved inline.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `name` | `string` | *(required)* | Schema name (e.g. `LocalUser`). Use `list_schemas` to find names. |
| `ref_depth` | `int` | `3` | Max `$ref` resolution depth (0 = no resolution, max 10) |

## Typical Workflows

### Discovering endpoints for a feature area

```
list_tags                         # See what categories exist
list_endpoints(tag="infra-aaa")   # Browse all endpoints in that category
get_endpoint(path="...", method="POST")  # Get full details for one
```

### Finding an endpoint by keyword

```
search_endpoints(query="backup")  # Find anything related to "backup"
get_endpoint(path="...", method="GET")   # Drill into the result
```

### Understanding a data model

```
list_schemas(name_filter="User")  # Find schemas with "User" in the name
get_schema(name="LocalUser")      # Get the full definition with refs resolved
```

### Controlling output size

For very large or deeply nested schemas, reduce `ref_depth` to limit the amount of inline resolution:

```
get_schema(name="LargeModel", ref_depth=1)  # Shallow view
get_schema(name="LargeModel", ref_depth=0)  # No ref resolution, just $ref pointers
```

## Schema File Requirements

- Must be valid **OpenAPI 3.x** or **Swagger 2.x** JSON/YAML
- Must contain the top-level `openapi` or `swagger` key
- Files are loaded in **alphabetical order** by filename
- File extensions must be `.json`, `.yaml`, or `.yml`

### Multi-File Merging

When multiple schema files are present, they are merged as follows:

| Component | Merge strategy |
|-----------|---------------|
| **Paths** | Union. Same path with different methods are combined. Same path + method in a later file overwrites the earlier one (with a warning to stderr). |
| **Components/Schemas** | Union. Name collisions are won by the later file (with a warning to stderr). |
| **Tags** | Union. First file's description wins for duplicate tag names. |
| **API Info** | Title, version, and servers come from the first file loaded. |

### Error Handling

- Files that fail to parse are skipped with a warning to stderr. Other files continue loading.
- If no schema files are found, all tools return a message indicating the expected directory path.
- The `get_api_info` tool reports any load errors.

## `$ref` Resolution

The server resolves `$ref` pointers (e.g. `{"$ref": "#/components/schemas/UserRole"}`) by replacing them with the actual schema definition inline. This makes tool output self-contained so Claude does not need to make follow-up calls to understand referenced types.

Resolution is controlled by the `ref_depth` parameter:

| Depth | Behavior |
|-------|----------|
| `0` | No resolution. `$ref` pointers are left as-is. |
| `1` | Resolve the first level only. Nested `$ref` pointers remain. |
| `3` (default) | Resolve up to 3 levels deep. Covers most practical schemas. |
| `10` (max) | Deep resolution. Use sparingly on complex schemas. |

When resolution stops (due to depth limit or circular references), the output includes markers:

- `{"$ref": "...", "_truncated": true}` - Depth limit reached
- `{"$ref": "...", "_circular": true}` - Circular reference detected
- `{"$ref": "...", "_unresolved": true}` - Reference target not found

## File Layout

```
.
├── .mcp.json                                  # MCP server registration
├── .claude/
│   ├── schemas/                               # Drop OpenAPI files here
│   │   ├── .gitkeep
│   │   ├── nd-infra-api.yaml                  # (you add these)
│   │   └── nd-manage-api.json                 # (you add these)
│   └── mcp-servers/
│       └── nd-openapi/
│           └── server.py                      # The MCP server (~450 lines)
└── docs/
    └── README_OPENAPI_SCHEMA_MCP_SERVER.md    # This file
```

## Troubleshooting

**Server not appearing in `/mcp`:**
- Ensure you are running Claude Code from the project root (where `.mcp.json` is located)
- Check that `uv` is installed and on your `PATH`
- Restart Claude Code after adding `.mcp.json`

**"No OpenAPI schemas loaded" from all tools:**
- Place at least one `.json`, `.yaml`, or `.yml` OpenAPI file in `.claude/schemas/`
- Run `get_api_info` to see load errors

**Schema file not loading:**
- Verify the file has a top-level `openapi` or `swagger` key
- Check stderr output for parse errors (visible in Claude Code's MCP server logs)

**Running the server manually for debugging:**

```bash
ND_SCHEMA_DIR=.claude/schemas uv run .claude/mcp-servers/nd-openapi/server.py
```

The server prints load diagnostics to stderr on startup, then waits for MCP JSON-RPC messages on stdin.
