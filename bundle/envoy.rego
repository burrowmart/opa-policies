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
# One shared bundle serves every service pod's PEP sidecar (base-service chart
# ships the sidecar unconditionally), so this table maps the union of all
# services' routes onto the authz.rego action vocabulary. Paths are disjoint
# across services except where two services intentionally expose the same
# resource (order-service and order-bff both serve /orders) — those collide
# onto the same action, which is exactly right. An unmatched route is a
# denied route: extend this table when a service grows an endpoint.
route_table := [
	# user-service
	{"method": "GET", "pattern": `^/users$`, "action": "user:read", "resource_type": "user"},
	{"method": "GET", "pattern": `^/users/[^/]+$`, "action": "user:read", "resource_type": "user"},
	{"method": "POST", "pattern": `^/users$`, "action": "user:write", "resource_type": "user"},
	{"method": "PUT", "pattern": `^/users/[^/]+$`, "action": "user:write", "resource_type": "user"},
	{"method": "DELETE", "pattern": `^/users/[^/]+$`, "action": "user:delete", "resource_type": "user"},
	# OPAL's periodic PIP sync — granted to svc-opal-fetcher via
	# data.service_permissions, deliberately NOT plain user:read: the bulk
	# attribute dump is a different privilege than reading one user record.
	{"method": "GET", "pattern": `^/internal/attributes$`, "action": "user:read-attributes", "resource_type": "user"},
	# user-bff — /profile is self-scoped by construction (the BFF resolves the
	# record from the caller's own claims); see resource_attributes below.
	{"method": "GET", "pattern": `^/profile$`, "action": "user:read", "resource_type": "user"},
	# catalog-service + catalog-bff (same /catalog surface)
	{"method": "GET", "pattern": `^/catalog$`, "action": "catalog:read", "resource_type": "catalog"},
	{"method": "GET", "pattern": `^/catalog/[^/]+$`, "action": "catalog:read", "resource_type": "catalog"},
	{"method": "POST", "pattern": `^/catalog$`, "action": "catalog:write", "resource_type": "catalog"},
	{"method": "PUT", "pattern": `^/catalog/[^/]+$`, "action": "catalog:write", "resource_type": "catalog"},
	{"method": "DELETE", "pattern": `^/catalog/[^/]+$`, "action": "catalog:write", "resource_type": "catalog"},
	# order-service + order-bff (same /orders surface)
	{"method": "POST", "pattern": `^/orders$`, "action": "order:create", "resource_type": "order"},
	{"method": "GET", "pattern": `^/orders$`, "action": "order:read", "resource_type": "order"},
	{"method": "GET", "pattern": `^/orders/[^/]+$`, "action": "order:read", "resource_type": "order"},
	# payment-service; payment-bff nests under /orders/<id>/payments
	{"method": "GET", "pattern": `^/payments$`, "action": "payment:read", "resource_type": "payment"},
	{"method": "GET", "pattern": `^/payments/[^/]+$`, "action": "payment:read", "resource_type": "payment"},
	{"method": "GET", "pattern": `^/orders/[^/]+/payments$`, "action": "payment:read", "resource_type": "payment"},
	# notification-service — mark-as-read mutates only the caller's own
	# notification state, so it rides on notification:read (the vocabulary
	# deliberately has no notification:write; fan-out writes happen via
	# RabbitMQ consumers, outside the HTTP/PDP path).
	{"method": "GET", "pattern": `^/notifications$`, "action": "notification:read", "resource_type": "notification"},
	{"method": "GET", "pattern": `^/notifications/unread-count$`, "action": "notification:read", "resource_type": "notification"},
	{"method": "POST", "pattern": `^/notifications/[^/]+/read$`, "action": "notification:read", "resource_type": "notification"},
	# chat-service — the PDP gates the verb; per-conversation membership is
	# enforced service-side (chat-service checkMembership, called by
	# ws-gateway's channel router) because conversation ids are opaque to OPA.
	{"method": "POST", "pattern": `^/conversations/[^/]+/messages$`, "action": "chat:send", "resource_type": "chat"},
	{"method": "GET", "pattern": `^/conversations/[^/]+/messages$`, "action": "chat:read", "resource_type": "chat"},
	{"method": "GET", "pattern": `^/conversations/[^/]+/members/[^/]+$`, "action": "chat:read", "resource_type": "chat"},
	{"method": "PUT", "pattern": `^/conversations/[^/]+/typing/[^/]+$`, "action": "chat:send", "resource_type": "chat"},
	{"method": "GET", "pattern": `^/conversations/[^/]+/typing$`, "action": "chat:read", "resource_type": "chat"},
	{"method": "PUT", "pattern": `^/presence/[^/]+$`, "action": "chat:send", "resource_type": "chat"},
	{"method": "GET", "pattern": `^/presence/[^/]+$`, "action": "chat:read", "resource_type": "chat"},
	# cart-bff (Redis-only cart). Checkout places an order downstream, so it
	# is authorized as order:create — same privilege as POST /orders.
	{"method": "GET", "pattern": `^/cart$`, "action": "cart:read", "resource_type": "cart"},
	{"method": "POST", "pattern": `^/cart/items$`, "action": "cart:write", "resource_type": "cart"},
	{"method": "PATCH", "pattern": `^/cart/items/[^/]+$`, "action": "cart:write", "resource_type": "cart"},
	{"method": "DELETE", "pattern": `^/cart/items/[^/]+$`, "action": "cart:write", "resource_type": "cart"},
	{"method": "DELETE", "pattern": `^/cart$`, "action": "cart:write", "resource_type": "cart"},
	{"method": "POST", "pattern": `^/cart/checkout$`, "action": "order:create", "resource_type": "order"},
	# ws-gateway — a WS ticket opens the notifications channel (chat joins are
	# membership-gated again inside ws-gateway), so it rides on
	# notification:read, which every human role carries.
	{"method": "POST", "pattern": `^/ws/ticket$`, "action": "notification:read", "resource_type": "notification"},
]

http_req := input.attributes.request.http

# Envoy's :path pseudo-header includes the query string; strip it before matching.
path_no_query := split(http_req.path, "?")[0]

matched_route := route if {
	some route in route_table
	route.method == http_req.method
	regex.match(route.pattern, path_no_query)
}

# ── Public routes ───────────────────────────────────────────────────────────
# /health skips PDP delegation entirely: kubelet probes and Prometheus already
# hit the app port directly (see base-service deployment.yaml), an external
# health check has no OPA-recognized identity to present, and the app route is
# @Public() for the same reason. /metrics is deliberately NOT public here — it
# must stay unreachable through the edge; Prometheus scrapes past the sidecar.
allow if {
	http_req.method == "GET"
	path_no_query == "/health"
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

# ── Resource construction ───────────────────────────────────────────────────
# User records are the one resource type whose key IS the owner's email, so
# the PEP can assert ownership straight from the path — that's what lets an
# authenticated user read their own record before OPAL has marked them
# verified. Other resource types (orders, payments, conversations) are keyed
# by opaque ids the PDP has no PIP for; instance-level scoping there is
# enforced service-side.
default resource_attributes := {}

resource_attributes := {"ownerEmail": urlquery.decode(captures[0][1])} if {
	captures := regex.find_all_string_submatch_n(`^/users/([^/]+)$`, path_no_query, 1)
	count(captures) == 1
}

# /profile is self-scoped by construction — user-bff resolves the record from
# the caller's own claims — so the PEP asserts the caller as owner.
resource_attributes := {"ownerEmail": claims.email} if {
	path_no_query == "/profile"
}

resource := {
	"type": matched_route.resource_type,
	"id": path_no_query,
	"attributes": resource_attributes,
}

allow if {
	matched_route
	claims
	data.policies.authz.allow with input as {
		"subject": subject,
		"action": matched_route.action,
		"resource": resource,
	}
}
