package envoy.authz_test

import rego.v1

import data.envoy.authz

# JWT signature verification itself isn't exercised here (that needs a real
# keypair, minted by opa-policies/demo/gen-keys.js + mint-token.js — covered
# by the live end-to-end demo instead). These tests mock `decoded` — the
# rule that wraps io.jwt.decode_verify — to pin down everything downstream of
# it: route matching, subject resolution from data.users, and delegation to
# policies.authz.allow.

mock_http(method, path) := {"attributes": {"request": {"http": {
	"method": method,
	"path": path,
	"headers": {"authorization": "Bearer irrelevant-under-mock"},
}}}}

alice_claims := [true, {}, {"email": "alice@example.com", "cognito:groups": ["buyer"]}]

test_verified_user_read_allow if {
	authz.allow with input as mock_http("GET", "/users/alice@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": true}}}
}

test_unverified_user_read_deny if {
	not authz.allow with input as mock_http("GET", "/users/alice@example.com")
		with authz.decoded as alice_claims
		with data.users as {"alice@example.com": {"attributes": {"verified": false}}}
}

test_missing_pip_record_deny if {
	not authz.allow with input as mock_http("GET", "/users/alice@example.com")
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

test_query_string_stripped_before_route_match if {
	authz.allow with input as mock_http("GET", "/internal/attributes?since=2026-08-01T00:00:00Z")
		with authz.decoded as [true, {}, {"email": "svc-opal-fetcher@archtenet.internal", "cognito:groups": ["admin"]}]
		with data.role_permissions as {"admin": [{"action": "*", "resource_type": "*"}]}
		with data.users as {}
}
