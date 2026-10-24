"""Role inheritance with explicit-deny precedence.

A role may ``extends: [parent, ...]``. The effective role is built from its parents, in the
order listed, and then its own settings:

* table grants are unioned; for the same table, columns are unioned (``"*"`` wins),
  ``deny_columns`` are unioned, and ``column_access`` entries override per column;
* label access overrides per label;
* ``limits`` and ``unlisted_label_access`` come from the nearest role that sets them.

**Explicit denies are sticky.** A child can add permissions but cannot undo an inherited
explicit deny: a ``deny`` label, a ``deny`` column-access rule, a ``deny_columns`` entry, or
``tenant_scoped: true``. Trying to do so is a *conflict*, and conflicts are load errors, so
a policy never silently means something other than what it says. Cycles and unknown parents
are errors too.
"""

from __future__ import annotations

from collections.abc import Mapping

from sqlguard_ninja.policy.model import Access, Role, TableGrant


class InheritanceError(ValueError):
    pass


def _merge_grant(
    parent: TableGrant, child: TableGrant, where: str, errors: list[str]
) -> TableGrant:
    if parent.columns == "*" or child.columns == "*":
        columns: object = "*"
    else:
        columns = tuple(dict.fromkeys([*parent.columns, *child.columns]))
    deny_columns = tuple(dict.fromkeys([*parent.deny_columns, *child.deny_columns]))
    access = dict(parent.column_access)
    for col, value in child.column_access.items():
        if access.get(col) is Access.DENY and value is not Access.DENY:
            errors.append(f"{where}: column '{col}' is denied by a parent role")
            continue
        access[col] = value
    for col in parent.deny_columns:
        if child.column_access.get(col, Access.DENY) is not Access.DENY:
            errors.append(f"{where}: column '{col}' is in a parent role's deny_columns")
    return TableGrant.model_validate(
        {"columns": columns, "deny_columns": deny_columns, "column_access": access}
    )


def _merge(parent: Role, child: Role, name: str, errors: list[str]) -> Role:
    tables = dict(parent.tables)
    for tname, grant in child.tables.items():
        tables[tname] = (
            _merge_grant(tables[tname], grant, f"role '{name}' table '{tname}'", errors)
            if tname in tables
            else grant
        )
    labels = dict(parent.labels)
    for label, access in child.labels.items():
        if labels.get(label) is Access.DENY and access is not Access.DENY:
            errors.append(f"role '{name}': label '{label}' is denied by a parent role")
            continue
        labels[label] = access
    explicit = child.model_fields_set
    unlisted = (
        child.unlisted_label_access
        if "unlisted_label_access" in explicit
        else parent.unlisted_label_access
    )
    if (
        "unlisted_label_access" in explicit
        and parent.unlisted_label_access is Access.DENY
        and unlisted is not Access.DENY
        and "unlisted_label_access" in parent.model_fields_set
    ):
        errors.append(f"role '{name}': unlisted_label_access 'deny' is set by a parent role")
        unlisted = Access.DENY
    tenant_scoped = parent.tenant_scoped or child.tenant_scoped
    if parent.tenant_scoped and "tenant_scoped" in explicit and not child.tenant_scoped:
        errors.append(f"role '{name}': cannot drop tenant scoping inherited from a parent role")
    return Role(
        description=child.description or parent.description,
        tables=tables,
        labels=labels,
        unlisted_label_access=unlisted,
        tenant_scoped=tenant_scoped,
        limits=child.limits if child.limits is not None else parent.limits,
    )


def resolve_roles(roles: Mapping[str, Role]) -> dict[str, Role]:
    """Return the effective (flattened) role for every role, or raise InheritanceError."""
    resolved: dict[str, Role] = {}
    errors: list[str] = []

    def visit(name: str, stack: tuple[str, ...]) -> Role:
        if name in resolved:
            return resolved[name]
        if name in stack:
            raise InheritanceError(f"role inheritance cycle: {' -> '.join((*stack, name))}")
        role = roles[name]
        effective: Role | None = None
        for parent in role.extends:
            if parent not in roles:
                errors.append(f"role '{name}': extends unknown role '{parent}'")
                continue
            base = visit(parent, (*stack, name))
            effective = base if effective is None else _merge(effective, base, name, errors)
        result = role if effective is None else _merge(effective, role, name, errors)
        resolved[name] = result.model_copy(update={"extends": role.extends})
        return resolved[name]

    for name in roles:
        visit(name, ())
    if errors:
        raise InheritanceError("; ".join(errors))
    return resolved
