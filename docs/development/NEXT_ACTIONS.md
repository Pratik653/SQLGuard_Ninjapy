# Next actions (development program)

1. Merge the v0.3.0 PR, tag v0.3.0, release, verify PyPI and a fresh install.
2. Phase 3 (v0.3.x or v0.4.0): MCP stdio server with validation-only tools (`validate_sql`, `explain_policy_decision`, `inspect_query_cost`, `get_policy_capabilities`), trusted role and tenant from server config, tested with a real MCP client (the official Python SDK client over stdio).
3. Workstream 1 open items: independent dataset (#6), function/catalog cases (#5).
