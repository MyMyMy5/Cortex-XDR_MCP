# Cortex XDR MCP Server

An MCP (Model Context Protocol) server that connects AI assistants to Palo Alto Networks Cortex XDR/XSIAM, enabling natural-language security investigations, threat hunting, and incident response.

## What It Does

This server exposes 25+ Cortex XDR tools via MCP, allowing AI agents to:

- Investigate incidents and alerts with full event details
- Hunt for IOCs (domains, IPs, hashes) across the data lake
- Analyze process trees and causality chains
- Search file activity, browser connections, and user behavior
- Run XQL queries against the XDR data lake
- Manage incidents (comments, assignments, merges)
- Retrieve endpoint details, vulnerabilities, and asset inventory

All API timestamps are automatically converted from epoch milliseconds to human-readable Israel timezone (IDT/IST) for display, while preserving the original values for programmatic use.

## Available Tools

### Builtin Components (Python)
| Tool | Description |
|------|-------------|
| `get_cases` | Retrieve cases/incidents with filtering and search |
| `get_filtered_endpoints` | List endpoints by status, platform, hostname |
| `get_issues` | Retrieve alerts with full event details |
| `enrich_hash` / `search_ioc` | Hunt for SHA256 hashes and IOCs across telemetry |
| `run_xql_query` | Execute XQL queries against the data lake |

### Custom Components (Python)
| Tool | Description |
|------|-------------|
| `get_incidents` | Retrieve incidents with name-based search |
| `get_alert_details` | Full alert details with all events (no truncation) |
| `get_incident_artifacts` | File and network artifacts for an incident |
| `get_process_tree` | Full causality chain for an alert |
| `search_alerts_by_host` | All alerts on a specific host |
| `search_user_activity` | User alert activity (summary + detail modes) |
| `search_file_activity` | File events (downloads, writes, deletions) |
| `search_browser_activity` | Browser network connections with proxy detection |
| `get_exclusions` | Alert exclusion audit records |
| `merge_cases` | Merge duplicate cases |
| `update_incident_no_resolve` | Add comments, reassign, change severity |
| `analyse_file` | Upload and scan files via WildFire |
| `enrich_hash` | Search for SHA256 across process and file events |
| `search_ioc` | Hunt for domains, IPs, or hashes across all events |

### OpenAPI Components (auto-generated)
| Tool | Description |
|------|-------------|
| `get_filtered_endpoints` | Endpoint inventory with detailed filtering |
| `get_assets` | Asset inventory with filtering |
| `get_asset_by_id` | Single asset details |
| `get_assessment_profile_results` | Security assessment results |
| `get_tenant_info` | Tenant license information |
| `get_vulnerabilities` | CVE/vulnerability data with pagination |

## Quick Start

### Prerequisites
- Python 3.12+
- [Poetry](https://python-poetry.org/) for dependency management
- A Cortex XDR/XSIAM API key ([how to create one](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Get-Started-with-APIs))

### Installation

```bash
git clone https://github.com/MyMyMy5/Cortex-XDR_MCP.git
cd Cortex-XDR_MCP
poetry install
```

### Configuration

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env`:
```
CORTEX_MCP_PAPI_URL=https://api-<your-tenant>.xdr.<region>.paloaltonetworks.com
CORTEX_MCP_PAPI_AUTH_HEADER=<your-api-key>
CORTEX_MCP_PAPI_AUTH_ID=<your-api-key-id>
```

### Running

**stdio mode** (for AI assistant integration):
```bash
python src/main.py
```

**HTTP mode** (for web-based clients):
```bash
MCP_TRANSPORT=streamable-http python src/main.py
```

**Via CLI:**
```bash
python src/cli.py start --api_key_id 1 --api_key_secret "your-key" --server-url "https://api-your-tenant.xdr.us.paloaltonetworks.com"
```

**Via Docker:**
```bash
docker build -t cortex-mcp .
docker run --env-file .env cortex-mcp
```

### MCP Client Configuration

Add to your MCP client config (e.g., `mcp.json`):

```json
{
  "mcpServers": {
    "cortex-mcp": {
      "command": "python",
      "args": ["src/main.py"],
      "cwd": "/path/to/Cortex-XDR_MCP",
      "env": {
        "CORTEX_MCP_PAPI_URL": "https://api-<tenant>.xdr.<region>.paloaltonetworks.com",
        "CORTEX_MCP_PAPI_AUTH_HEADER": "<your-api-key>",
        "CORTEX_MCP_PAPI_AUTH_ID": "<your-api-key-id>"
      }
    }
  }
}
```

## Architecture

```
src/
├── main.py                          # Entry point, server initialization
├── cli.py                           # CLI interface (start, update, version)
├── config/config.py                 # Pydantic settings from env vars
├── pkg/
│   ├── util.py                      # Response formatting, timestamp conversion, pagination
│   ├── client.py                    # PAPI HTTP client
│   └── openapi/                     # OpenAPI spec bundling
├── service/cortex_mcp/server.py     # FastMCP server creation
├── usecase/
│   ├── base_module.py               # Abstract base for all tool modules
│   ├── module_util.py               # Auto-discovery of tool modules
│   ├── fetcher.py                   # API request handler
│   ├── builtin_components/          # Core tools (cases, issues, endpoints, XQL, threat intel)
│   │   └── openapi/                 # OpenAPI specs for auto-generated tools
│   ├── custom_components/           # Extended tools (process trees, file activity, etc.)
│   └── remote_components/           # Remotely managed tools (via update command)
└── entities/                        # Data models, exceptions, sample responses
```

## Extending

You can add custom tools in two ways:

### OpenAPI (no code)
1. Create a YAML file in `src/usecase/custom_components/openapi/`
2. Define the endpoint per [Cortex API docs](https://docs-cortex.paloaltonetworks.com/r/Cortex-Cloud-Platform-APIs/Cortex-Cloud-Platform-APIs)
3. Restart the server — the tool is auto-registered

### Python (custom logic)
1. Create a Python file in `src/usecase/custom_components/`
2. Define a class inheriting from `BaseModule`
3. Implement `register_tools()` and `register_resources()`
4. Restart the server — the module is auto-discovered

See `src/usecase/README.md` for detailed instructions.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CORTEX_MCP_PAPI_URL` | Yes | Cortex API URL |
| `CORTEX_MCP_PAPI_AUTH_HEADER` | Yes | API key |
| `CORTEX_MCP_PAPI_AUTH_ID` | Yes | API key ID |
| `MCP_TRANSPORT` | No | `stdio` (default) or `streamable-http` |
| `MCP_HOST` | No | HTTP host (default: `0.0.0.0`) |
| `MCP_PORT` | No | HTTP port (default: `8080`) |
| `LOG_LEVEL` | No | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |

## License

This project is licensed under the **Palo Alto Networks Cortex Communication Python Files License 1.0**.

Key terms:
- Free to use, modify, and redistribute
- **Must only be used with Palo Alto Networks Cortex XSIAM, Cloud, XDR, and AgentiX products**
- Must include the full license with any distribution
- Must retain all copyright and attribution notices

See [LICENSE](LICENSE) for the full text.
