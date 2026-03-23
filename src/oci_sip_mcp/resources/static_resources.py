"""Static resource text."""

POLICY_REFERENCE = """
OCI IAM policy review checklist

1. Prefer named groups or dynamic groups over `any-user` and `any-group`.
2. Prefer compartment scope over tenancy scope.
3. Prefer specific resource types or families over `all-resources`.
4. Prefer `inspect` or `read` over `use` or `manage` when possible.
5. Add `where` conditions when a statement must stay broad.
6. Keep policy-administration permissions limited to a dedicated admin group.
""".strip()
