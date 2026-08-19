package envoy.authz

# Bridges Envoy's ext_authz v3 CheckRequest shape (input.attributes.request.http)
# into the {subject, action, resource} contract that policies.authz.allow
# expects (see README.md's "Input schema contract"). This is the ONLY place
# that contract is constructed for the PEP path — every rule in authz.rego
# stays testable/reusable against a plain REST caller too.
#
# OPA's envoy_ext_authz_grpc plugin is configured (see
# platform-infra/k8s/opa/configmap.yaml) with:
#   query: data.envoy.authz.allow
# A plain boolean result is a supported decision shape for that plugin.

import rego.v1

default allow := false

# ── Route table ─────────────────────────────────────────────────────────────
# user-service routes this Envoy sidecar fronts, mapped to the authz.rego
# action vocabulary. Extend this as user-service grows more routes.
route_table := [
	{"method": "GET", "pattern": `^/users$`, "action": "user:read", "resource_type": "user"},
	{"method": "GET", "pattern": `^/users/[^/]+$`, "action": "user:read", "resource_type": "user"},
	{"method": "POST", "pattern": `^/users$`, "action": "user:write", "resource_type": "user"},
	{"method": "PUT", "pattern": `^/users/[^/]+$`, "action": "user:write", "resource_type": "user"},
	{"method": "DELETE", "pattern": `^/users/[^/]+$`, "action": "user:delete", "resource_type": "user"},
	{"method": "GET", "pattern": `^/internal/attributes$`, "action": "user:read", "resource_type": "user"},
	{"method": "GET", "pattern": `^/health$`, "action": "user:read", "resource_type": "user"},
]

http_req := input.attributes.request.http

# Envoy's :path pseudo-header includes the query string; strip it before matching.
path_no_query := split(http_req.path, "?")[0]

matched_route := route if {
	some route in route_table
	route.method == http_req.method
	regex.match(route.pattern, path_no_query)
}

# ── Subject resolution ──────────────────────────────────────────────────────
# The Cloudflare OAuth worker already validated the id_token at the edge
# (see ARCHITECTURE.md "Auth & Authz"); this PEP layer re-verifies the
# signature itself rather than trusting that — same "don't trust headers
# blindly" posture the NestJS JWKS guard already takes, just one hop
# earlier. data.jwks is the bundle's own demo JWKS (opa-policies/demo/gen-keys.js);
# swap for a mirrored Cognito JWKS in production.
auth_header := http_req.headers.authorization

token := trim_prefix(auth_header, "Bearer ")

decoded := io.jwt.decode_verify(token, {
	"cert": json.marshal(data.jwks),
	"iss": "archtenet-demo",
	"aud": "archtenet-demo-clients",
})

claims := decoded[2] if decoded[0]

default subject_roles := []

subject_roles := claims["cognito:groups"] if is_array(claims["cognito:groups"])

# Resolved from data.users (OPAL-pushed), never from the token or the
# caller — that's what makes this a genuine PIP check instead of a
# self-asserted attribute a caller could forge.
default subject_attributes := {}

subject_attributes := data.users[claims.email].attributes if data.users[claims.email].attributes

subject := {
	"email": claims.email,
	"roles": subject_roles,
	"attributes": subject_attributes,
}

resource := {"type": matched_route.resource_type, "id": path_no_query, "attributes": {}}

allow if {
	matched_route
	claims
	data.policies.authz.allow with input as {
		"subject": subject,
		"action": matched_route.action,
		"resource": resource,
	}
}
