package policies.authz_test

import rego.v1

import data.policies.authz

# ── helpers ────────────────────────────────────────────────────────────────────
# Role-permission tables injected per test so tests are self-contained.
buyer_perms := {
	"buyer": [
		{"action": "order:create", "resource_type": "order"},
		{"action": "order:read", "resource_type": "order"},
		{"action": "catalog:read", "resource_type": "catalog"},
		{"action": "cart:write", "resource_type": "cart"},
		{"action": "cart:read", "resource_type": "cart"},
		{"action": "payment:initiate", "resource_type": "payment"},
		{"action": "notification:read", "resource_type": "notification"},
		{"action": "chat:send", "resource_type": "chat"},
		{"action": "chat:read", "resource_type": "chat"},
	],
}

admin_perms := {"admin": [{"action": "*", "resource_type": "*"}]}

# ── Test 1: admin wildcard allow ───────────────────────────────────────────────
test_admin_role_wildcard_allow if {
	authz.allow with input as {
		"subject": {"email": "admin@example.com", "roles": ["admin"], "attributes": {"department": "ops"}},
		"action": "user:delete",
		"resource": {"type": "user", "id": "usr-999", "attributes": {}},
	}
		with data.role_permissions as admin_perms
}

# ── Test 2: buyer allowed to create an order by role ──────────────────────────
test_buyer_order_create_allow if {
	authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": ["buyer"], "attributes": {}},
		"action": "order:create",
		"resource": {"type": "order", "id": "", "attributes": {}},
	}
		with data.role_permissions as buyer_perms
}

# ── Test 3: ABAC ownership — owner may read their own order ───────────────────
test_abac_owner_read_allow if {
	authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {}},
		"action": "order:read",
		"resource": {
			"type": "order",
			"id": "ord-123",
			"attributes": {"ownerEmail": "alice@example.com"},
		},
	}
		with data.role_permissions as {}
}

# ── Test 4: buyer role does NOT permit user:delete ────────────────────────────
test_buyer_cannot_delete_user if {
	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": ["buyer"], "attributes": {}},
		"action": "user:delete",
		"resource": {"type": "user", "id": "usr-1", "attributes": {}},
	}
		with data.role_permissions as buyer_perms
}

# ── Test 5: default deny — no roles, no matching attributes ───────────────────
test_default_deny if {
	not authz.allow with input as {
		"subject": {"email": "anon@example.com", "roles": [], "attributes": {}},
		"action": "catalog:write",
		"resource": {"type": "catalog", "id": "cat-1", "attributes": {}},
	}
		with data.role_permissions as {}
}

# ── Test 6: ownership ABAC only covers safe actions, not delete ───────────────
test_abac_owner_cannot_delete_own_order if {
	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {}},
		"action": "order:delete",
		"resource": {
			"type": "order",
			"id": "ord-123",
			"attributes": {"ownerEmail": "alice@example.com"},
		},
	}
		with data.role_permissions as {}
}

# ── Test 7: deny when ownerEmail attribute is missing (empty string) ──────────
test_deny_on_empty_owner_attr if {
	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {}},
		"action": "order:read",
		"resource": {"type": "order", "id": "ord-123", "attributes": {"ownerEmail": ""}},
	}
		with data.role_permissions as {}
}

# ── Test 8: deny when ownerEmail attribute is absent entirely ─────────────────
test_deny_on_absent_owner_attr if {
	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {}},
		"action": "order:read",
		"resource": {"type": "order", "id": "ord-123", "attributes": {}},
	}
		with data.role_permissions as {}
}

# ── Test 9: verified subject may user:read (drives the OPAL propagation demo) ─
test_abac_verified_subject_read_allow if {
	authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {"verified": true}},
		"action": "user:read",
		"resource": {"type": "user", "id": "alice@example.com", "attributes": {}},
	}
		with data.role_permissions as {}
}

# ── Test 10: unverified (or missing attribute) subject is denied user:read ────
test_abac_unverified_subject_read_deny if {
	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {"verified": false}},
		"action": "user:read",
		"resource": {"type": "user", "id": "alice@example.com", "attributes": {}},
	}
		with data.role_permissions as {}

	not authz.allow with input as {
		"subject": {"email": "alice@example.com", "roles": [], "attributes": {}},
		"action": "user:read",
		"resource": {"type": "user", "id": "alice@example.com", "attributes": {}},
	}
		with data.role_permissions as {}
}
