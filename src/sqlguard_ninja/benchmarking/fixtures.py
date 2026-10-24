"""Synthetic fixture database for the benchmark schema (SQLite and PostgreSQL).

The data is generated deterministically from a seed. It contains no real personal data:
names, emails, card numbers and identifiers are fabricated and use reserved example
domains and test card ranges.
"""

from __future__ import annotations

import json
import random
import sqlite3
from collections.abc import Iterator
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from sqlguard_ninja.policy.model import Catalog, Policy

DEFAULT_SEED = 20261024

_TYPE_MAP = {
    "sqlite": {
        "int": "INTEGER",
        "text": "TEXT",
        "numeric": "NUMERIC",
        "timestamp": "TEXT",
        "date": "TEXT",
        "boolean": "INTEGER",
        "json": "TEXT",
    },
    "postgres": {
        "int": "BIGINT",
        "text": "TEXT",
        "numeric": "NUMERIC(14,2)",
        "timestamp": "TIMESTAMP",
        "date": "DATE",
        "boolean": "BOOLEAN",
        "json": "JSONB",
    },
    "mysql": {
        "int": "BIGINT",
        "text": "TEXT",
        "numeric": "DECIMAL(14,2)",
        "timestamp": "DATETIME(6)",
        "date": "DATE",
        "boolean": "BOOLEAN",
        "json": "JSON",
    },
}

ROW_COUNTS = {
    "tenants": 3,
    "warehouses": 4,
    "customers": 60,
    "products": 30,
    "orders": 200,
    "order_items": 400,
    "payments": 200,
    "shipments": 180,
    "employees": 40,
    "support_tickets": 80,
}

_FIRST = ["Alex", "Sam", "Robin", "Kim", "Jordan", "Taylor", "Morgan", "Casey", "Avery", "Riley"]
_LAST = ["Example", "Sample", "Testperson", "Placeholder", "Demo", "Fixture", "Synthetic"]
_CITIES = ["Berlin", "Lisbon", "Dubai", "Pune", "Oslo", "Austin", "Lyon", "Kraków"]
_COUNTRIES = ["DE", "PT", "AE", "IN", "NO", "US", "FR", "PL"]


class _DBConnection(Protocol):
    def cursor(self) -> Any: ...
    def commit(self) -> None: ...


def schema_ddl(catalog: Catalog, dialect: str) -> list[str]:
    """CREATE TABLE statements derived from the policy catalog."""
    types = _TYPE_MAP[dialect]
    statements = []
    for name, table in catalog.tables.items():
        cols = []
        for col, spec in table.columns.items():
            sql_type = types.get(spec.type, "TEXT")
            pk = " PRIMARY KEY" if col == "id" else ""
            cols.append(f"{col} {sql_type}{pk}")
        statements.append(f"CREATE TABLE {name} ({', '.join(cols)})")
    return statements


def _rows(seed: int) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    rng = random.Random(seed)
    base = datetime(2026, 1, 1)

    def ts(days: int = 300) -> str:
        return (base + timedelta(minutes=rng.randrange(days * 24 * 60))).isoformat(sep=" ")

    def person() -> str:
        return f"{rng.choice(_FIRST)} {rng.choice(_LAST)}"

    tenants = [
        {"id": i, "name": f"Tenant {i}", "plan": rng.choice(["free", "pro"]), "created_at": ts()}
        for i in range(1, ROW_COUNTS["tenants"] + 1)
    ]
    yield "tenants", tenants
    yield (
        "warehouses",
        [
            {"id": i, "name": f"WH-{i}", "region": rng.choice(["EU", "US", "MEA", "APAC"])}
            for i in range(1, ROW_COUNTS["warehouses"] + 1)
        ],
    )
    customers = []
    for i in range(1, ROW_COUNTS["customers"] + 1):
        k = rng.randrange(len(_CITIES))
        customers.append(
            {
                "id": i,
                "tenant_id": (i % 3) + 1,
                "full_name": person(),
                "email": f"user{i}@example.com",
                "email_domain": "example.com",
                "phone": f"+00 555 {i:04d}",
                "date_of_birth": date(
                    1960 + rng.randrange(40), 1 + rng.randrange(12), 1
                ).isoformat(),
                "country": _COUNTRIES[k],
                "city": _CITIES[k],
                "loyalty_tier": rng.choice(["bronze", "silver", "gold"]),
                "marketing_opt_in": rng.random() < 0.5,
                "created_at": ts(),
                "profile": json.dumps(
                    {
                        "preferences": {"newsletter": rng.random() < 0.5, "language": "en"},
                        "health": {"allergies": rng.choice(["none", "synthetic-allergen"])},
                        "payment": {"card_number": "4111111111111111"},
                    }
                ),
            }
        )
    yield "customers", customers
    products = [
        {
            "id": i,
            "tenant_id": (i % 3) + 1,
            "sku": f"SKU-{i:04d}",
            "name": f"Product {i}",
            "category": rng.choice(["books", "garden", "toys", "tools"]),
            "price": round(rng.uniform(2, 200), 2),
        }
        for i in range(1, ROW_COUNTS["products"] + 1)
    ]
    yield "products", products
    orders = []
    for i in range(1, ROW_COUNTS["orders"] + 1):
        cust = rng.choice(customers)
        orders.append(
            {
                "id": i,
                "tenant_id": cust["tenant_id"],
                "customer_id": cust["id"],
                "status": rng.choice(["new", "paid", "shipped", "delivered", "cancelled"]),
                "total_amount": round(rng.uniform(5, 900), 2),
                "currency": "EUR",
                "created_at": ts(),
                "shipping_address": f"{i} Example Street, {cust['city']}",
            }
        )
    yield "orders", orders
    yield (
        "order_items",
        [
            {
                "id": i,
                "tenant_id": (o := rng.choice(orders))["tenant_id"],
                "order_id": o["id"],
                "product_id": rng.choice(products)["id"],
                "quantity": 1 + rng.randrange(5),
                "unit_price": round(rng.uniform(2, 200), 2),
            }
            for i in range(1, ROW_COUNTS["order_items"] + 1)
        ],
    )
    yield (
        "payments",
        [
            {
                "id": o["id"],
                "tenant_id": o["tenant_id"],
                "order_id": o["id"],
                "card_number": "4111111111111111",  # published test card number
                "card_last4": "1111",
                "card_brand": "visa",
                "iban": "XX00TEST0000000000",
                "amount": o["total_amount"],
                "status": rng.choice(["captured", "refunded", "failed"]),
            }
            for o in orders[: ROW_COUNTS["payments"]]
        ],
    )
    yield (
        "shipments",
        [
            {
                "id": o["id"],
                "tenant_id": o["tenant_id"],
                "order_id": o["id"],
                "warehouse_id": 1 + rng.randrange(ROW_COUNTS["warehouses"]),
                "carrier": rng.choice(["DHL", "UPS", "Aramex"]),
                "tracking_number": f"TRK{o['id']:06d}",
                "status": rng.choice(["in_transit", "delivered", "returned"]),
                "shipped_at": ts(),
                "delivery_address": o["shipping_address"],
            }
            for o in orders[: ROW_COUNTS["shipments"]]
        ],
    )
    yield (
        "employees",
        [
            {
                "id": i,
                "full_name": person(),
                "email": f"employee{i}@example.org",
                "department": rng.choice(["warehouse", "support", "finance", "engineering"]),
                "title": rng.choice(["associate", "lead", "manager"]),
                "salary": round(rng.uniform(30000, 120000), 2),
                "bank_account": f"XX00TEST{i:010d}",
                "national_id": f"TEST-{i:06d}",
                "health_notes": "synthetic",
                "hire_date": date(2015 + rng.randrange(10), 1 + rng.randrange(12), 1).isoformat(),
                "manager_id": None if i <= 3 else 1 + rng.randrange(3),
                "warehouse_id": 1 + rng.randrange(ROW_COUNTS["warehouses"]),
            }
            for i in range(1, ROW_COUNTS["employees"] + 1)
        ],
    )
    yield (
        "support_tickets",
        [
            {
                "id": i,
                "tenant_id": (c := rng.choice(customers))["tenant_id"],
                "customer_id": c["id"],
                "subject": rng.choice(["Late delivery", "Refund", "Login issue"]),
                "body": "Synthetic ticket body.",
                "status": rng.choice(["open", "closed"]),
                "priority": rng.choice(["low", "high"]),
                "created_at": ts(),
            }
            for i in range(1, ROW_COUNTS["support_tickets"] + 1)
        ],
    )


def populate(conn: _DBConnection, policy: Policy, dialect: str, seed: int = DEFAULT_SEED) -> None:
    """Create the schema and load synthetic rows. Values are always bound, never interpolated."""
    marker = "?" if dialect == "sqlite" else "%s"
    cur = conn.cursor()
    for stmt in schema_ddl(policy.catalog, dialect):
        cur.execute(stmt)
    for table, rows in _rows(seed):
        if not rows:
            continue
        columns = list(policy.catalog.tables[table].columns)
        placeholders = ", ".join([marker] * len(columns))
        # Table and column names come from the validated policy catalog, not from input.
        insert = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"  # noqa: S608
        params = [tuple(row.get(c) for c in columns) for row in rows]
        cur.executemany(insert, params)
    conn.commit()


def create_sqlite(
    policy: Policy, path: str | Path = ":memory:", seed: int = DEFAULT_SEED
) -> sqlite3.Connection:
    """Return a SQLite connection with the fixture schema and data loaded.

    The connection may be shared across threads (web servers run handlers in a pool);
    :func:`sqlguard_ninja.integrations.executors.sqlite_executor` serialises access.
    """
    conn = sqlite3.connect(str(path), check_same_thread=False)
    populate(conn, policy, "sqlite", seed)
    return conn
