"""Example queries for the demo, with the decision each one must produce (checked by tests)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Example:
    id: str
    role: str
    title: str
    sql: str
    expect: str  # allow | review | deny
    lesson: str


EXAMPLES: tuple[Example, ...] = (
    # Sales analyst
    Example(
        "sales-revenue",
        "sales_analyst",
        "Monthly revenue",
        "SELECT strftime('%Y-%m', o.created_at) AS month, SUM(o.total_amount) AS revenue\n"
        "FROM orders o\nWHERE o.tenant_id = :tenant_id AND o.status <> 'cancelled'\n"
        "GROUP BY month\nORDER BY month",
        "allow",
        "Aggregates over the caller's own tenant are allowed.",
    ),
    Example(
        "sales-top-products",
        "sales_analyst",
        "Top products by units",
        "SELECT p.name, p.category, SUM(i.quantity) AS units\nFROM order_items i\n"
        "JOIN products p ON p.id = i.product_id AND p.tenant_id = :tenant_id\n"
        "WHERE i.tenant_id = :tenant_id\nGROUP BY p.name, p.category\n"
        "ORDER BY units DESC\nLIMIT 10",
        "allow",
        "Joins are fine when every table is filtered to the tenant.",
    ),
    Example(
        "sales-tiers",
        "sales_analyst",
        "Customers per loyalty tier",
        "SELECT c.loyalty_tier, COUNT(*) AS customers\nFROM customers c\n"
        "WHERE c.tenant_id = :tenant_id\nGROUP BY c.loyalty_tier",
        "allow",
        "Counting customers by an unclassified attribute is allowed.",
    ),
    Example(
        "sales-city-count",
        "sales_analyst",
        "How many cities do we sell to?",
        "SELECT COUNT(DISTINCT c.city) AS cities\nFROM customers c\nWHERE c.tenant_id = :tenant_id",
        "allow",
        "City is aggregate-only for sales: it may be used inside an aggregate.",
    ),
    Example(
        "sales-customers-by-city",
        "sales_analyst",
        "Customers per city",
        "SELECT c.city, COUNT(*) AS customers\nFROM customers c\nWHERE c.tenant_id = :tenant_id\n"
        "GROUP BY c.city",
        "deny",
        "Grouping by city prints every city value, so aggregate-only data is revealed.",
    ),
    Example(
        "sales-emails",
        "sales_analyst",
        "Export customer emails",
        "SELECT c.email FROM customers c WHERE c.tenant_id = :tenant_id",
        "deny",
        "Contact details are not granted to sales.",
    ),
    Example(
        "sales-other-tenant",
        "sales_analyst",
        "Another store group's revenue",
        "SELECT SUM(o.total_amount) AS revenue\nFROM orders o\nWHERE o.tenant_id = 2",
        "deny",
        "Tenant isolation: the filter must use the caller's tenant, not a literal.",
    ),
    # Customer support
    Example(
        "support-orders",
        "customer_support",
        "A customer's recent orders",
        "SELECT o.id, o.status, o.total_amount, o.created_at\nFROM orders o\n"
        "WHERE o.tenant_id = :tenant_id AND o.customer_id = 12\n"
        "ORDER BY o.created_at DESC\nLIMIT 20",
        "allow",
        "Support may look up orders within its tenant.",
    ),
    Example(
        "support-shipments",
        "customer_support",
        "Where is my parcel?",
        "SELECT s.order_id, s.carrier, s.tracking_number, s.status\nFROM shipments s\n"
        "JOIN orders o ON o.id = s.order_id AND o.tenant_id = :tenant_id\n"
        "WHERE s.tenant_id = :tenant_id AND o.customer_id = 12",
        "allow",
        "Contact and tracking data are allowed for support.",
    ),
    Example(
        "support-card-last4",
        "customer_support",
        "Card brand and last four digits",
        "SELECT p.order_id, p.card_brand, p.card_last4, p.amount\nFROM payments p\n"
        "WHERE p.tenant_id = :tenant_id\nLIMIT 20",
        "allow",
        "The safe alternative to card numbers is permitted.",
    ),
    Example(
        "support-card-number",
        "customer_support",
        "Full card numbers",
        "SELECT p.order_id, p.card_number\nFROM payments p\nWHERE p.tenant_id = :tenant_id",
        "deny",
        "Card numbers are PCI data and never available to support.",
    ),
    Example(
        "support-health-json",
        "customer_support",
        "Allergies from the profile JSON",
        "SELECT c.id, c.profile ->> '$.health.allergies' AS allergies\nFROM customers c\n"
        "WHERE c.tenant_id = :tenant_id",
        "deny",
        "Health data inside JSON is classified per field, not per column.",
    ),
    Example(
        "support-or-bypass",
        "customer_support",
        "OR 1 = 1 bypass attempt",
        "SELECT o.id, o.total_amount\nFROM orders o\nWHERE o.tenant_id = :tenant_id OR 1 = 1",
        "deny",
        "An OR around the tenant filter would return every tenant's rows.",
    ),
    Example(
        "support-delete",
        "customer_support",
        "Close old tickets (write)",
        "DELETE FROM support_tickets WHERE status = 'closed'",
        "deny",
        "Only read-only queries are allowed.",
    ),
    # Store manager
    Example(
        "manager-salary-by-dept",
        "store_manager",
        "Average salary by department",
        "SELECT e.department, COUNT(*) AS staff, AVG(e.salary) AS avg_salary\n"
        "FROM employees e\nGROUP BY e.department",
        "allow",
        "Salary is aggregate-only: department averages are allowed.",
    ),
    Example(
        "manager-roster",
        "store_manager",
        "Warehouse staff roster",
        "SELECT e.full_name, e.title, w.name AS warehouse\nFROM employees e\n"
        "JOIN warehouses w ON w.id = e.warehouse_id\nORDER BY w.name, e.full_name",
        "allow",
        "Names and titles are allowed for managers.",
    ),
    Example(
        "manager-shipments",
        "store_manager",
        "Shipments per carrier",
        "SELECT s.carrier, s.status, COUNT(*) AS shipments\nFROM shipments s\n"
        "WHERE s.tenant_id = :tenant_id\nGROUP BY s.carrier, s.status",
        "allow",
        "Operational aggregates within the tenant.",
    ),
    Example(
        "manager-salaries",
        "store_manager",
        "Individual salaries",
        "SELECT e.full_name, e.salary FROM employees e",
        "deny",
        "Listing individual salaries reveals financial data row by row.",
    ),
    Example(
        "manager-national-id",
        "store_manager",
        "National ids via a CTE",
        "WITH staff AS (SELECT e.id, e.national_id FROM employees e)\n"
        "SELECT COUNT(*) AS n FROM staff",
        "deny",
        "Government ids are not granted at all, even inside a CTE.",
    ),
    Example(
        "manager-catalog",
        "store_manager",
        "Peek at the system catalog",
        "SELECT name FROM sqlite_master",
        "deny",
        "System catalogs are not part of any role.",
    ),
)

TENANTS: tuple[dict[str, Any], ...] = (
    {"id": 1, "label": "Store group A"},
    {"id": 2, "label": "Store group B"},
    {"id": 3, "label": "Store group C"},
)

ROLE_LABELS = {
    "sales_analyst": "Sales Analyst",
    "customer_support": "Customer Support",
    "store_manager": "Store Manager",
}

# The same query shown for each tenant to demonstrate isolation.
TENANT_DEMO = (
    "SELECT o.status, COUNT(*) AS orders, ROUND(SUM(o.total_amount), 2) AS revenue\n"
    "FROM orders o\nWHERE o.tenant_id = :tenant_id\nGROUP BY o.status\nORDER BY o.status"
)


def as_dicts() -> list[dict[str, Any]]:
    return [asdict(e) for e in EXAMPLES]
