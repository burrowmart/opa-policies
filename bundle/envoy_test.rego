package envoy.authz_test

import rego.v1

import data.envoy.authz

# JWT signature verification itself isn't exercised here (that needs a real
# keypair, minted by opa-policies/demo/gen-keys.js + mint-token.js — covered
# by the live end-to-end demo instead). These tests mock `decoded` — the
# rule that wraps io.jwt.decode_verify — to pin down everything downstream of
# it: route matching, subject resolution from data.users, ownership
# derivation from the path, and delegation to policies.authz.allow.

mock_http(method, path) := {"attributes": {"request": {"http": {
	"method": method,
	"path": path,
	"headers": {"authorization": "Bearer irrelevant-under-mock"},
}}}}

alice_claims := [true, {}, {"email": "alice@example.com", "cognito:groups": ["buyer"]}]

buyer_perms := {"buyer": [
	{"action": "catalog:read", "resource_type": "catalog"},
	{"action": "cart:write", "resource_type": "cart"},
]}

test_verified_user_read_allow if {
	authz.allow with input as mock_http("GET", "/users/bob@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

test_unverified_other_user_read_deny if {
	not authz.allow with input as mock_http("GET", "/users/bob@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": false}}}
}

# Ownership from the path: /users/<email> is keyed by the owner's email, so an
# authenticated user may read their own record even before OPAL marks them
# verified — including the URL-encoded form a real client sends.
test_unverified_self_read_allow if {
	authz.allow with input as mock_http("GET", "/users/alice@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": false}}}

	authz.allow with input as mock_http("GET", "/users/alice%40example.com")
		with authz.decoded as alice_claims
		with data.users as {}
}

# Ownership grants read only — never write/delete of one's own record.
test_self_delete_deny if {
	not authz.allow with input as mock_http("DELETE", "/users/alice@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

test_missing_pip_record_deny if {
	not authz.allow with input as mock_http("GET", "/users/bob@example.com")
		with authz.decoded as alice_claims
		with data.users as {}
}

test_unmatched_route_deny if {
	not authz.allow with input as mock_http("PATCH", "/users/alice@example.com/nickname")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

test_no_auth_header_deny if {
	req := {"attributes": {"request": {"http": {"method": "GET", "path": "/users/alice@example.com", "headers": {}}}}}
	not authz.allow with input as req
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

# The OPAL fetcher's periodic sync — a service principal from
# data.service_permissions, not an admin role. Also pins query-string stripping.
test_service_principal_internal_attributes_allow if {
	authz.allow with input as mock_http("GET", "/internal/attributes?since=2026-08-01T00:00:00Z")
		with authz.decoded as [true, {}, {"email": "svc-opal-fetcher@archtenet.internal", "cognito:groups": []}]
		with data.service_permissions as {"svc-opal-fetcher@archtenet.internal": [{"action": "user:read-attributes", "resource_type": "user"}]}
		with data.users as {}
}

# A buyer must NOT reach the bulk attribute dump — user:read-attributes is a
# distinct privilege from user:read, granted to no human role.
test_buyer_internal_attributes_deny if {
	not authz.allow with input as mock_http("GET", "/internal/attributes")
		with authz.decoded as alice_claims
		with data.role_permissions as buyer_perms
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

# Non-user-service routes resolve through the same shared table: RBAC verbs
# apply per route, so a buyer reads the catalog but cannot write it.
test_buyer_catalog_read_allow if {
	authz.allow with input as mock_http("GET", "/catalog")
		with authz.decoded as alice_claims
		with data.role_permissions as buyer_perms
		with data.users as {}
}

test_buyer_catalog_write_deny if {
	not authz.allow with input as mock_http("POST", "/catalog")
		with authz.decoded as alice_claims
		with data.role_permissions as buyer_perms
		with data.users as {}
}

test_buyer_cart_write_allow if {
	authz.allow with input as mock_http("DELETE", "/cart/items/sku-42")
		with authz.decoded as alice_claims
		with data.role_permissions as buyer_perms
		with data.users as {}
}

# /health is public (probes and external checks carry no identity);
# /metrics stays denied through the sidecar — Prometheus scrapes past it.
test_health_public_allow if {
	req := {"attributes": {"request": {"http": {"method": "GET", "path": "/health", "headers": {}}}}}
	authz.allow with input as req
}

test_metrics_deny if {
	req := {"attributes": {"request": {"http": {"method": "GET", "path": "/metrics", "headers": {}}}}}
	not authz.allow with input as req
}
