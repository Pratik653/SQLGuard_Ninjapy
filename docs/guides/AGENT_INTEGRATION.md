# Agent integration (LangGraph, LangChain, FastAPI, SDK)

## The contract

```
LLM ──SQL──▶ SQLCheckpoint.evaluate(sql, RequestContext) ──▶ authorized? ──▶ executor
                     │                     ▲
                     ▼                     └── built by YOUR auth layer only
              Guard.validate (pure)
```

* **Policy evaluation** (`Guard.validate`) is a pure function of SQL, policy and trusted context.
* **Execution authorization** (`SQLCheckpoint`) applies the enforcement mode and approvals.
* The model can influence only the SQL text. It cannot set the role, the tenant or an approval.

| Mode | DENY | REVIEW | ALLOW |
|---|---|---|---|
| `block` (default) | not run | not run | run |
| `review` | not run | run only with an approval bound to the SQL hash, trace and principal (single use, TTL, no self-approval) | run |
| `audit` | run, recorded `enforced=False` | run, recorded | run |

`rewrite_tenant_filters=True` (off by default) adds missing tenant filters through the AST and
executes the re-validated rewrite. See [POLICY_AS_CODE.md](POLICY_AS_CODE.md).

`max_denied_attempts` (default 5) locks a trace after repeated denials, so a retry loop
cannot grind through rephrasings.

## SDK

```python
from sqlguard_ninja import Guard, Policy
from sqlguard_ninja.integrations import RequestContext, SQLCheckpoint, JsonlAuditSink
from sqlguard_ninja.integrations.executors import sqlite_executor

checkpoint = SQLCheckpoint(Guard(Policy.from_file("policy.yaml")),
                           audit_sink=JsonlAuditSink("audit.jsonl"))
ctx = RequestContext(principal=user.id, role=user.role, tenant_id=user.tenant_id,
                     trace_id=conversation_id)
rows = checkpoint.execute(sql_from_llm, ctx, sqlite_executor(conn))   # raises SQLBlockedError
```

`outcome.agent_message` is safe to return to the model. It explains the reason and never
contains approval tokens or internal detail.

## LangChain

```python
from sqlguard_ninja.integrations.langchain import GuardedSQLTool

tool = GuardedSQLTool(checkpoint=checkpoint, executor=sqlite_executor(conn),
                      context_provider=lambda: current_request_context())
```

The tool's argument schema is `{"query": str}` with `extra="forbid"`. A model that tries to
send `role` or `tenant_id` gets a validation error. Blocked queries return the explanation
as the tool result (`raise_on_block=True` raises instead). See
`examples/langchain/guarded_tool_demo.py`.

## LangGraph

```python
from sqlguard_ninja.integrations.langgraph import (
    CONTEXT_KEY, make_guard_node, make_execute_node, route_after_guard)

g.add_node("guard", make_guard_node(checkpoint))
g.add_node("execute", make_execute_node(checkpoint, executor))
g.add_conditional_edges("guard", route_after_guard(3),
                        {"execute": "execute", "revise": "generate", "end": END})
graph.invoke(state, config={"configurable": {CONTEXT_KEY: request_context}})
```

* The context is read from the **run config**, which nodes cannot modify. It is not read
  from state.
* `make_execute_node` **re-validates**. A node that edits `state["sql"]` or forges
  `state["guard"]["authorized"]` gains nothing (`tests/integration/test_frameworks.py`).

See `examples/langgraph/sql_agent_demo.py` for a deterministic agent that revises after
blocks and is locked out after repeated attempts. `examples/langgraph/real_llm_agent.py`
shows the same tool with a real model. That example is optional and not run in tests.

## FastAPI

```python
from sqlguard_ninja.integrations.fastapi import create_router
app.include_router(create_router(checkpoint, current_context_dependency, executor))
```

`POST /v1/sql/validate` and `POST /v1/sql/query`. Blocked queries return 403. The body schema
forbids extra fields. Authentication is your dependency. The example uses a demo stub.

## Defence in depth (required)

* Execute with a **read-only, least-privilege** database role. The bundled executors open
  read-only sessions (`PRAGMA query_only`, `SET TRANSACTION READ ONLY`). The tests show that
  writes fail at the database even in audit mode.
* Use **row-level security** for tenant isolation, and statement timeouts.
* Static inspection cannot guarantee complete database security.
