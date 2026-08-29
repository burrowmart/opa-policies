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

# ── M2M: service principals ───────────────────────────────────────────────────
# Machine callers (today: the OPAL fetcher's periodic /internal/attributes
# sync) authenticate with a JWT whose email lives under the reserved
# @archtenet.internal domain and carries no roles. Their grants come from
# data.service_permissions — bundle-owned static config like
# role_permissions, keyed by that email. Absence from the table means no
# grants at all, so no subject.type discriminator is needed: a human email
# simply never has an entry, and a service email never appears in
# data.users or holds a Cognito group.
allow if {
	some perm in data.service_permissions[input.subject.email]
	action_matches(perm.action, input.action)
	resource_type_matches(perm.resource_type, input.resource.type)
}

# ── ABAC: resource ownership ──────────────────────────────────────────────────
# Grant when the authenticated subject is the owner of the resource.
# ownerEmail arrives two ways: REST callers set resource.attributes per the
# input contract (README.md), and the Envoy PEP derives it from the path for
# user records (envoy.rego), the one resource type whose key IS the owner's
# email. Ownership only confers read/cancel — never write or admin actions.
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
		"user:read",
	}
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
