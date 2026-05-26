# Credential Constraints

Serverware treats credentials as capabilities, not secrets that agents can hold. A route decides which credential may be injected, which principal may use it, which upstream endpoint may be reached, and which request/response constraints must hold before the credential is released.

The route-level `constraints` array is the shared customization layer. Provider adapters still normalize API-specific facts such as `tweets.write`, `gmail.messages.list`, or `npm.publish`; constraints then apply reusable rules to those facts, the HTTP query, JSON body, rate counters, and response payload.

```json
{
  "id": "x-one-tweet-per-day",
  "type": "rateLimit",
  "max": 1,
  "windowSeconds": 86400,
  "store": "shared",
  "key": {"scope": ["principal", "credential", "route", "operation"]}
}
```

## Execution Order

1. Principal allowlist checks run first: client IP, identity headers, and proxy bearer token.
2. Route matching blocks unknown hosts, ports, paths, and methods.
3. The adapter validates provider-specific credential metadata and classifies the operation.
4. Request constraints validate operation, query, body, and current rate-limit headroom.
5. JIT approval is consumed if required.
6. Stateful request constraints, currently rate limits, are committed immediately before credential injection.
7. The credential is injected and Serverware-only identity headers are stripped.
8. Response constraints validate returned data before adapter redaction and before bytes are released to the agent.

If any step fails, the request or response is blocked. Unknown routes are never proxied.

## Implemented Constraint Types

`operationPolicy`: allow or deny normalized adapter operations. Use this to block writes for one app while allowing reads, or to make a broad route safe even if SDKs choose unexpected endpoints.

`rateLimit`: fixed-window credential use limits keyed by principal, credential, route, operation, credential version, or selected operation fields. Examples: one tweet per day, five Slack posts per hour, ten object-store writes per hour. `store: "local"` keeps the counter in the current process for dev-only throttles. `store: "shared"` commits the counter through the authenticated control-plane endpoint so the quota is atomic across proxy/data-plane replicas.

`queryDateWindow`: bounds query parameters such as `start_time`, `end_time`, or `since` to a maximum lookback. Formats supported: RFC3339, date, epoch seconds, and epoch milliseconds.

`queryNumericBounds`: caps query values such as `max_results`, `per_page`, `limit`, and `maxResults`.

`jsonBody`: enforces JSON request body shape: allowed fields, required fields, denied fields, type checks, string length, numeric bounds, enums, exact values, and array size bounds.

`responseDateWindow`: validates JSON responses before release. It supports nested arrays through dot paths, so `data.created_at` checks every item in a `data` array.

## Common Patterns Already Modeled

The demo policy includes:

- Gmail read access limited to the last 30 days, with page size caps and response `internalDate` validation.
- X recent search limited to seven days, capped at 100 results, with response `created_at` validation.
- X controlled posting limited to one plain-text tweet per day.
- X broad route guarded by an operation allowlist so write operations stay blocked.
- npm publish/dist-tag writes guarded by operation allowlists and per-operation JIT approval.

[policies/credential-limits.examples.json](../policies/credential-limits.examples.json) adds ready-to-adapt examples for Slack posting, GitHub issue listing, Stripe customer read-only access, and bounded object-store writes.

## Production Store Semantics

`rateLimit.store` is enforced. `local` counters are process-local and exist for development throttles or single-instance deployments. `shared` counters use the metadata store, acquire a row lock or SQLite immediate transaction, and update by `counter_key` before credential injection. The Rust gate calls `POST /api/data-plane/rate-limits/consume` when `SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL` is configured; the Python proxy calls the same store directly. If a shared store is requested but unavailable, credential release fails closed with `shared_rate_limit_store_unavailable`.

## Response Validation

Request constraints are not enough. Many APIs can accept a bounded query and still return old or over-broad data through bugs, aliases, pagination cursors, or endpoint drift. Response constraints are therefore first-class and run before redaction. Gmail and X examples both validate response age, and generic REST examples can validate timestamps such as `updated_at` or `created`.
