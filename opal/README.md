# opal

OPAL is used here for the **data plane only** — live user attributes streamed
into OPA. Policy (Rego + seed `data.json`) is distributed the ordinary OPA way,
by polling the S3 bundle directly (see `platform-infra/k8s/opa/configmap.yaml`);
OPAL never touches policy in this deployment.

```
user-service (outbox) --RabbitMQ--> fetcher/ --POST /data/config--> OPAL server --pubsub--> OPAL client (sidecar on each OPA pod) --PUT /v1/data--> OPA
```

## fetcher/

A small standalone Node process (no NestJS — it's a bridge, not a domain
service). Consumes `user.attributes-changed` off the `domain.events` topic
exchange and relays each event to the OPAL server as an inline `DataUpdate`
(`POST /data/config`, `save_method: PUT`, `dst_path: /users/<email>`). This
is the **live** update path — one event, one push, no polling.

## data-config.template.json

The OPAL server's `OPAL_DATA_CONFIG_SOURCES` — NOT the live path above.
This is what a newly-subscribed OPAL client fetches once at startup (initial
full sync) and what gets re-fetched every 300s as a drift-correction safety
net, both against user-service's `GET /internal/attributes` (bulk, no
`?since`). `__SERVICE_TOKEN__` is substituted with a real admin-role JWT by
the deploy script — see `platform-infra/k8s/opal/README.md` — and the
resulting JSON is stored in a Secret, never committed with a real token.

Why both a live push AND a periodic pull: the live push (via the fetcher) is
what makes the demo's allow->deny transition fast: minted `user.attributes-changed`
events land in `data.users` within one RabbitMQ round-trip. The periodic pull
is defense-in-depth against a fetcher outage or a dropped OPAL pubsub message
— without it, a missed event would silently pin a user's data stale forever.

## Auth

OPAL's own auth model: `OPAL_AUTH_MASTER_TOKEN` on the server is a bearer
credential accepted directly on `POST /data/config` (this is OPAL's own
documented pattern for a trusted first-party data provider, not a shortcut
specific to this repo) — used by both `fetcher/` and, indirectly, whoever
constructs the Secret consumed by `data-config.template.json`'s `__SERVICE_TOKEN__`
(a separate, unrelated JWT — that one authenticates to *user-service* via the
Envoy/OPA `envoy.authz` bridge, not to OPAL).
