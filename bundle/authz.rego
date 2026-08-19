package policies.authz

import rego.v1

# Deny by default — every allow must be explicit.
default allow := false

# ── RBAC ──────────────────────────────────────────────────────────────────────
# Grant when the subject holds a role whose permission table covers this
# action + resource-type pair.  data.role_permissions is pushed by OPAL from
# user-service (keyed by role name).
allow if {
	some role in input.subject.roles
	some perm in data.role_permissions[role]
	action_matches(perm.action, input.action)
	resource_type_matches(perm.resource_type, input.resource.type)
}

# ── ABAC: resource ownership ──────────────────────────────────────────────────
# Grant when the authenticated subject is the owner of the resource.
# user-service sets resource.attributes.ownerEmail at creation time; OPAL
# streams it into OPA data under the user's email key.
# Ownership only confers read/cancel — never write or admin actions.
allow if {
	input.subject.email != ""
	input.resource.attributes.ownerEmail != ""
	input.subject.email == input.resource.attributes.ownerEmail
	input.action in {
		"order:read",
		"order:cancel",
		"payment:read",
		"notification:read",
		"chat:read",
	}
}

# ── ABAC: shared organisational unit (inter-service / B2B) ───────────────────
# Grant catalog/notification read access to subjects in the same department as
# the resource.  Useful for seller-dashboard and support tooling.
allow if {
	input.subject.attributes.department != ""
	input.resource.attributes.department != ""
	input.subject.attributes.department == input.resource.attributes.department
	input.action in {"catalog:read", "notification:read"}
}

# ── ABAC: verified subjects may read user-service ─────────────────────────────
# input.subject.attributes is populated by the caller (see
# envoy.rego / opa-policies/README.md's input contract) from
# data.users[subject.email].attributes, which OPAL streams live from
# user-service's outbox. Flipping "verified" false in user-service and
# waiting for propagation is what the OPAL end-to-end demo exercises.
allow if {
	input.action == "user:read"
	input.subject.attributes.verified == true
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# Wildcard "*" in the permission table matches any concrete value.
action_matches(pattern, _) if pattern == "*"

action_matches(pattern, action) if pattern == action

resource_type_matches(pattern, _) if pattern == "*"

resource_type_matches(pattern, rtype) if pattern == rtype
