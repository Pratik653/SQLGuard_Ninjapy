-- Example queries an assistant might generate for the support_analyst role
-- (synthetic retail schema, benchmarks/policies/retail_saas.yaml).
-- Scan with:
--   sqlninja scan examples/sql --policy builtin:retail_saas --role support_analyst --tenant 1 --format sarif

-- Allowed: tenant-scoped order lookup.
SELECT o.id, o.status, o.created_at
FROM orders o
WHERE o.tenant_id = :tenant_id
ORDER BY o.created_at DESC
LIMIT 50;

-- Denied: payment card numbers are not available to support.
SELECT p.order_id, p.card_number
FROM payments p
WHERE p.tenant_id = :tenant_id;

-- Denied: no tenant filter, so rows from every tenant would be returned.
SELECT c.full_name, c.city FROM customers c LIMIT 20;

-- Denied: writes are never permitted.
DELETE FROM support_tickets WHERE status = 'closed';
