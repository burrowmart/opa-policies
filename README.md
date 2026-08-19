# opa-policies

OPA Rego bundle for the Archtenet marketplace backend.  
Deployed as a DaemonSet PDP; every service pod's Envoy PEP sidecar calls it via gRPC ext_authz.

---

## Directory layout

```
bundle/
  .manifest           OPA bundle manifest (revision + roots)
  authz.rego          Policy entrypoint — data.policies.authz.allow
  authz_test.rego     Unit tests (10 cases)
  envoy.rego          Envoy ext_authz bridge — data.envoy.authz.allow (see below)
  envoy_test.rego     Unit tests (6 cases) — mocks JWT verification, see its header comment
  data.json           Static config data.role_permissions is bundle-owned (see below)
  jwks/data.json      Demo JWKS — public half of opa-policies/demo/gen-keys.js's keypair
envoy/
  ext-authz.yaml      Envoy ext_authz filter + cluster reference snippet
demo/
  gen-keys.js          Generates the demo RSA keypair (public -> bundle/jwks/data.json)
  mint-token.js        Signs a demo JWT with that keypair
opal/
  fetcher/             RabbitMQ -> OPAL server bridge (see opal/README.md)
  data-config.template.json   OPAL server's initial/periodic sync source
Makefile              test / build / fmt / check targets
```

---

## Input schema contract

Every NestJS service and every Envoy PEP sidecar **must** send the following JSON
body to OPA's `/v1/data/policies/authz` (REST) or as the `CheckRequest.attributes`
payload (gRPC ext_authz).  This is the hard contract between the policy layer and
the application tier.

```jsonc
{
  "input": {
    // Subject — populated from the Cognito id_token verified by the NestJS JWKS guard.
    "subject": {
      "email": "alice@example.com",          // Cognito email claim; primary OPAL key
      "roles": ["buyer"],                     // Cognito groups or custom:roles claim
      "attributes": {                         // OPAL-pushed user attributes from user-service
        "department": "engineering",
        "plan": "standard",
        "verified": true
      }
    },

    // Action — colon-separated "<service>:<verb>", e.g. "order:create", "catalog:read".
    "action": "order:create",

    // Resource — the target object being accessed.
    "resource": {
      "type": "order",                        // Domain resource type (matches role_permissions)
      "id": "ord-abc123",                     // Opaque resource ID (logged, not policy-evaluated)
      "attributes": {                         // Resource-level attributes for ABAC checks
        "ownerEmail": "alice@example.com",    // Set by the owning service at creation time
        "department": "engineering",          // Optional — enables department-scoped ABAC
        "status": "pending"                   // Informational; not evaluated by current policy
      }
    }
  }
}
```

### Action vocabulary

| Prefix | Verbs |
|---|---|
| `order` | `create`, `read`, `cancel`, `delete` |
| `catalog` | `read`, `write` |
| `cart` | `read`, `write` |
| `payment` | `initiate`, `read` |
| `notification` | `read` |
| `chat` | `send`, `read` |
| `user` | `read`, `delete` |

---

## Policy decisions

### Entrypoint

```
data.policies.authz.allow  →  boolean
```

`false` unless at least one of the three rules below fires.

### Rule priority (all independent OR)

1. **RBAC** — subject holds a role whose `role_permissions` entry covers the
   `(action, resource.type)` pair.  Wildcard `"*"` matches any value.
   `data.role_permissions` is pushed by OPAL from user-service (keyed by role name).

2. **ABAC — ownership** — `subject.email == resource.attributes.ownerEmail` **and**
   `action` is in the safe read/cancel set.  Ownership never grants write or admin.

3. **ABAC — department** — subject and resource share the same `department` attribute
   **and** `action` is `catalog:read` or `notification:read`.

4. **ABAC — verified subject** — `subject.attributes.verified == true` **and**
   `action` is `user:read`. This is the rule the OPAL end-to-end demo flips:
   `subject.attributes` comes from `data.users[subject.email].attributes`,
   which OPAL streams live from user-service's outbox — so un-verifying a
   user in user-service turns this from allow to deny with no redeploy.

---

## Data flow (OPAL integration)

```
user-service (outbox) ──RabbitMQ──► opal/fetcher ──POST /data/config──► OPAL server
                                                                            │ pubsub
                                                                            ▼
                                                          OPAL client (sidecar on OPA DaemonSet pod)
                                                                            │ PUT /v1/data/users/<email>
                                                                            ▼
                                                                           OPA
```

`data.users` is **entirely** OPAL's — nothing in this bundle. That's not a
simplification, it's required: OPA rejects a Data API write to any path an
active bundle declares as one of its `roots` (`400 path ... is owned by
bundle "authz"` — found by testing, not by reading the docs first). Bundle
`roots` only covers `policies`, `envoy`, `role_permissions`, `jwks` —
`role_permissions` is genuinely static config so it stays bundle-owned;
`users` is intentionally left unclaimed so OPAL (both the live outbox push
and its own initial/periodic full-sync against user-service's
`/internal/attributes`) is the only writer. If you add more OPAL-owned data
paths, keep them out of `.manifest`'s `roots` for the same reason.

The bundle itself (policy + static role_permissions) is rebuilt by CI and
published to S3; OPA polls it directly (see `platform-infra/k8s/opa`) — OPAL
never touches policy in this deployment, only the `data.users` data plane.

---

## Local development

### Prerequisites

```bash
# Homebrew (macOS)
brew install opa
# or download directly (replace VERSION and PLATFORM as needed)
# curl -L https://openpolicyagent.org/downloads/latest/opa_darwin_arm64_static -o /usr/local/bin/opa && chmod +x /usr/local/bin/opa
```

Tested with OPA **v1.19.0** (Rego v1).

### Run tests

```bash
make test
```

Expected output — all 16 tests pass (10 in authz_test.rego, 6 in envoy_test.rego):

```
PASS: 16/16
```

### Build the bundle tarball

```bash
make build
# → dist/bundle.tar.gz
```

This tarball is what the CI pipeline publishes to S3.  OPAL fetches it on startup
and subscribes to incremental data-update webhooks thereafter.

---

## Envoy integration

See `envoy/ext-authz.yaml` for the gRPC ext_authz filter snippet.  The base Helm
chart in `platform-infra/helm/base-service` merges this into each service's Envoy
ConfigMap.

Key settings:

| Setting | Value | Rationale |
|---|---|---|
| `failure_mode_allow` | `false` | Fail-closed — PDP crash → DENY |
| `timeout` | `0.5 s` | Keeps p99 latency budget for in-cluster calls |
| `transport_api_version` | `V3` | Matches OPA's ext_authz-v3 gRPC server |
| PDP address | `HOST_IP:9191` | OPA DaemonSet — always one instance per node |

---

## CI publish pipeline

`.github/workflows/ci.yml`: `opa test` (every push/PR) -> `opa build` -> on
push to `main` only, upload `dist/bundle.tar.gz` to S3 via a GitHub
OIDC-assumed role (`terraform.opa_bundle_writer_role_arn` output, trust
policy scoped to `refs/heads/main` — see `platform-infra/terraform/modules/opa-bundle-bucket`).
No webhook/trigger step: the OPA DaemonSet polls the bundle itself
(`platform-infra/k8s/opa/configmap.yaml`'s `bundles.polling`), and OPAL is
data-plane-only in this deployment (see `opal/README.md`) — it never
distributes policy, so a policy publish never needs to notify it.

Repo variables required on this repo: `AWS_OPA_BUNDLE_WRITER_ROLE_ARN`,
`AWS_REGION`, `OPA_BUNDLE_BUCKET` (= `terraform.opa_bundle_bucket_name`).
