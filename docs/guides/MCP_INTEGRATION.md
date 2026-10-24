# MCP integration

SQLGuard Ninja ships a [Model Context Protocol](https://modelcontextprotocol.io/) server that
lets MCP-compatible agents check SQL against your policy **before** they run it anywhere.

```bash
python -m pip install "sqlguard-ninja[mcp]"
sqlninja mcp --policy policy.yaml --role support --tenant 42          # stdio transport
```

Built on the official MCP Python SDK (`mcp` 2.x, `MCPServer`). The bundled reference policy
works out of the box: `--policy builtin:retail_saas --role support_analyst --tenant 1`.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `validate_sql` | `sql`, optional `dialect` (`postgres`, `sqlite` or `mysql`) | `decision` (allow/review/deny), findings (rule id, action, message, remediation), `decision_id`, policy revision |
| `explain_policy_decision` | `sql`, optional `dialect` | the decision plus per-finding lineage (base column, JSON path, labels) and how-to-fix hints |
| `inspect_query_cost` | `sql`, optional `dialect` | static cost score, thresholds and factors (no execution plan, no database) |
| `get_policy_capabilities` | — | the tables and columns this identity may use, their access mode (`allow`, `aggregate_only`, `review`), required tenant filter, limits, supported dialects |

No tool accepts a role, a tenant, credentials or a connection string. The server has **no
execution tool** and never connects to a database.

## Security model

* **Identity is server-side.** `--role` and `--tenant` are fixed when the server starts, by
  whoever writes the client configuration. A model cannot choose its own permissions. Extra
  arguments such as `role` are rejected or ignored, and the end-to-end test checks this.
* **Least disclosure.** `get_policy_capabilities` lists only tables and columns the role may
  use. Denied tables and columns are not revealed. Internal finding detail is never returned,
  and with `disclosure: generic` lineage is omitted as well.
* **Limits.** A hard cap of 100,000 characters applies before parsing, the policy's own length
  and AST-size limits still apply, and a per-process rate limit (120 calls per minute by
  default) is enforced. Errors are structured (`{"error": ..., "message": ...}`) and carry no
  stack traces.
* **Fail closed.** A tenant-scoped role started without `--tenant` gets every tenant-table
  query denied.
* The server is a validation service. Running the SQL remains your application's job, with a
  least-privilege, read-only database role and row-level security.

## Client configuration (stdio)

Most MCP clients accept a JSON server definition of this shape. Adapt the command path to
your environment:

```json
{
  "mcpServers": {
    "sqlguard-ninja": {
      "command": "sqlninja",
      "args": ["mcp", "--policy", "/absolute/path/policy.yaml", "--role", "support", "--tenant", "42"]
    }
  }
}
```

One server process serves one identity. To give different users different permissions, start
one server per identity from your trusted configuration. Never let the model write the client
configuration.

## Remote transports

The SDK also supports Streamable HTTP. SQLGuard Ninja does **not** enable it by default,
because a remote endpoint needs authentication that binds each caller to a role and tenant.
If you expose it remotely, put it behind your own authenticated gateway, derive the identity
from the authenticated caller, and keep one identity per server process or route. This setup
is not covered by the test suite.

## Verification

`tests/integration/test_mcp_server.py` starts the real server as a subprocess and connects
with the official SDK's `stdio_client` and `ClientSession`. It checks tool discovery,
allowed and denied validations, a forged `role` argument, and capability listing. It also
unit-tests malformed input, oversized input, unsupported dialects, rate limiting, the
missing-tenant fail-closed path and least disclosure.
