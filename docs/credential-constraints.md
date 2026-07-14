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

Policy activation is a separate fail-closed gate. Serverware verifies the bundle schema and signature, rejects capabilities that an enforcement runtime cannot implement, and compares the candidate with persisted policy high-water state before making it active. A changed bundle must advance `metadata.sequence`; `rollbackEpoch` cannot decrease; a previously seen policy hash cannot reappear with different monotonic metadata.

For each request:

1. Principal allowlist checks run first: client IP, identity headers, and proxy bearer token.
2. Route matching blocks unknown hosts, ports, paths, and methods.
3. The adapter validates provider-specific credential metadata and classifies the operation.
4. Request constraints validate operation, query, body, time windows, and current rate-limit headroom.
5. A request- and operation-bound JIT approval is consumed if the route requires one.
6. Stateful request constraints, currently rate limits, are committed immediately before credential use.
7. The Rust gate obtains the route's one-credential scoped lease, checks its version, policy generation, and expiry, injects only the selected credential field, and strips Serverware-only identity headers.
8. Immediately before the upstream send, the gate rechecks that the lease and policy snapshot are still current, synchronously submits `data_plane.credential.release_started`, and requires the control plane to acknowledge its durable hash-chain append. If audit is unavailable or rejects the event, the upstream request is not sent.
9. The upstream status selects the success or error response profile. Response size and syntax are checked first; whole-body semantic constraints are then evaluated before field projection and released-header validation. No buffered bytes are released until every applicable check passes.
10. After adapter and constraint projection, the credential-reflection guard scans the final body, content type, and released semantic headers. A match blocks the response.

If any step fails, the request or response is blocked. Unknown routes are never proxied.

For streaming responses, validation and projection happen incrementally. Serverware releases only generated protocol headers, never upstream semantic headers, and applies the reflection guard to projected output as it is written. Because already-released stream prefixes cannot be recalled, credential-bearing opaque streams are rejected at policy admission; see [Response Validation](#response-validation).

## Implemented Constraint Types

`operationPolicy`: allow or deny normalized adapter operations. Use this to block writes for one app while allowing reads, or to make a broad route safe even if SDKs choose unexpected endpoints.

`rateLimit`: fixed-window credential use limits keyed by principal, credential, route, operation, credential version, or selected operation fields. Examples: one tweet per day, five Slack posts per hour, ten object-store writes per hour. `store: "local"` keeps the counter in the current process for dev-only throttles. `store: "shared"` commits the counter through the authenticated control-plane endpoint so the quota is atomic across proxy/data-plane replicas.

`queryDateWindow`: bounds query parameters such as `start_time`, `end_time`, or `since` to a maximum lookback. Formats supported: RFC3339, date, epoch seconds, and epoch milliseconds.

`queryNumericBounds`: caps query values such as `max_results`, `per_page`, `limit`, and `maxResults`.

`requestTimeWindow`: limits credential use by absolute RFC3339 bounds, UTC weekdays, and one or more UTC daily intervals. `timezone` must be `UTC`; daily interval ends are exclusive. Empty bounds, reversed absolute bounds, duplicate weekdays, malformed times, and overlapping intervals are rejected when the policy loads. Runtime parsing also fails closed.

`jsonBody`: enforces JSON request body shape: allowed fields, required fields, denied fields, type checks, string length, numeric bounds, enums, exact values, and array size bounds.

`formBody`: applies the same allowlist, required/denied field, scalar duplicate, type, length, numeric, enum, exact-value, and safe-pattern rules to bounded `application/x-www-form-urlencoded` bodies. Bracketed keys such as `metadata[agent_request_id]` normalize to `metadata.agent_request_id`. Malformed UTF-8, malformed percent encoding, ambiguous duplicate scalar fields, and more than 256 pairs fail closed.

`responseDateWindow`: validates JSON responses before release. It supports nested arrays through dot paths, so `data.created_at` checks every item in a `data` array.

`responseJson`: validates the semantic contract of a buffered JSON success response before release. It can apply to every normalized operation or only named operations, validate the root value or objects selected through explicit item paths, and apply the shared `fieldRule` assertions to every selected item. It validates data; it does not select or redact fields.

## Common Patterns Already Modeled

The demo policy includes:

- Gmail read access limited to the last 30 days, with page size caps and response `internalDate` validation.
- X recent search limited to seven days, capped at 100 results, with response `created_at` validation.
- X controlled posting limited to one plain-text tweet per day.
- X bounded read access covering every explicitly cataloged current GET endpoint while writes, unknown endpoints, and streaming endpoints stay blocked.
- npm publish/dist-tag writes guarded by operation allowlists and per-operation JIT approval.

[policies/credential-limits.examples.json](../policies/credential-limits.examples.json) adds ready-to-adapt examples for Slack posting, GitHub issue listing, Stripe customer read-only access, tokenized PaymentIntent creation with amount caps and hardware-backed JIT approval, and bounded object-store writes. Each provider has a separate credential reference so copying the examples does not imply cross-provider credential reuse.

## X Endpoint Catalog

The X adapter classifies exact path templates from the current [X OpenAPI description](https://docs.x.com/openapi.json). Read operations are grouped into explicit policy names including `tweets.read`, `users.read`, `search.read`, `connections.read`, `directMessages.read`, `bookmarks.read`, `lists.read`, `spaces.read`, `analytics.read`, and the other cataloged families in the adapter schema. A new or changed X endpoint is denied until Serverware's Python classifier, Rust classifier, schema, and tests all recognize it.

`example.x.full_bounded_read` demonstrates the broadest bounded-read profile. It permits the complete current non-streaming GET catalog, subject to the OAuth scopes actually granted to that credential. That includes sensitive private-data families such as bookmarks or direct messages only when both the credential scopes and the route operation policy allow them. Use narrower operation lists for agents that do not need those categories.

Streaming reads are intentionally excluded from that profile because a live stream cannot receive whole-response validation or a final response-proof artifact. An opaque X stream would be credential-bearing and is therefore rejected; supporting it requires a structured, incrementally redacting adapter mode rather than `mode: "stream"`. Controlled writes are separate: the current audited write surface accepts only `POST /2/tweets`, requires `tweets.write`, an explicit JSON body allowlist, and a bounded non-stream response. Delete, follow, direct-message, like, retweet, media-upload, and unknown writes fail closed.

## Composing New Limits

Constraints compose as an intersection: a request must satisfy the principal, endpoint, adapter, every request constraint, any JIT grant, and every response constraint. This supports rules such as "one post per credential and agent per day, only on weekdays, with a 280-character body" without provider-specific scripting.

Policy files are data, not executable code. Unknown constraint types, fields, adapter operations, and extension semantics are rejected instead of ignored. A limitation that cannot be expressed by the typed constraints requires an audited adapter or constraint implementation in both enforcement runtimes, schema admission rules, and parity tests before it can be enabled. This preserves customization without allowing policy text to become an arbitrary-code escape hatch.

## OAuth Credentials

Portal OAuth login stores the provider token response as one encrypted credential secret:

```json
{
  "access_token": "provider-access-token",
  "refresh_token": "provider-refresh-token",
  "token_type": "Bearer",
  "scope": "tweet.read users.read offline.access",
  "expires_at_epoch_ms": 1780000000000
}
```

Policies should inject only the needed field:

```json
{"type": "bearer", "header": "Authorization", "field": "access_token"}
```

Credential `field` selectors are strict dotted object paths such as `access_token` or `nested.token`. Wildcards, array fan-out, empty path components, and non-string selected values fail closed before forwarding the request. The agent never receives the OAuth token JSON or the refresh token.

## Credential Lease Semantics

The Rust gate reports `scoped-recipient-bound-pull/v2`. Each pull names exactly one `(principal, route, credential)` scope and is bound to the active policy hash, measured gate binary digest, recipient key, one-use nonce, and short expiry. The encrypted payload uses the typed `serverware.credentialLeaseEnvelope/v2` envelope. A response containing an unexpected credential, scope, version, field, or duplicated binding is rejected.

Leases are cached only in zeroizing process memory. Cache and renewal work are bounded. A warm lease is renewed in the background before its five-second maximum expiry; a cold or expired lease may require a synchronous broker pull, so background renewal is an availability optimization rather than a security assumption. Lower credential versions and same-version secret or metadata changes are rejected. A higher version atomically replaces the old lease, and a stale request cannot remove that newer entry. Policy activation clears incompatible leases, and the gate rechecks lease currency immediately before the upstream send.

## Policy Rollback Protection

The control plane persists the accepted policy ID, sequence, `rollbackEpoch`, hash, and update time in its metadata store. The Rust gate independently persists its policy high-water record when a high-water path is configured. Startup and reload reject a policy ID change, a decreased rollback epoch, a changed policy whose sequence does not increase, or the reuse of a known hash with different monotonic metadata. Attestation binds the active policy and the control-plane high-water digest.

This prevents an ordinary restart or stale signed bundle from silently re-enabling older access. Production durability still depends on protecting and retaining both high-water stores; restoring an older database and data-plane state together is an external rollback problem that deployment attestation and storage controls must address.

## Production Store Semantics

`rateLimit.store` is enforced. `local` counters are process-local and exist for development throttles or single-instance deployments. `shared` counters use the metadata store, acquire a row lock or SQLite immediate transaction, and update by `counter_key` before credential injection. The Rust gate calls `POST /api/data-plane/rate-limits/consume` when `SERVERWARE_CONTROL_PLANE_RATE_LIMIT_CONSUME_URL` is configured; the Python proxy calls the same store directly. If a shared store is requested but unavailable, credential release fails closed with `shared_rate_limit_store_unavailable`.

## Response Validation

Request constraints are not enough. Many APIs can accept a bounded query and still return old or over-broad data through bugs, aliases, pagination cursors, or endpoint drift. Response constraints are therefore first-class. Gmail and X examples validate response age, and generic REST examples can validate timestamps such as `updated_at` or `created`.

### JSON response contracts

`responseJson` is a whole-body response constraint with this shape:

```json
{
  "id": "typed-results",
  "type": "responseJson",
  "phase": "response",
  "operations": ["widgets.read"],
  "items": ["data"],
  "required": true,
  "fields": {
    "status": {"required": true, "type": "string", "enum": ["ready", "done"]},
    "score": {"type": "number", "min": 0, "max": 1},
    "tags": {"type": "array", "maxItems": 3}
  }
}
```

`phase` is required and must be `response`. `operations` is optional; when present, the constraint runs only for those normalized adapter operations. A matching response without operation context fails closed, while a known non-matching operation skips the constraint.

`items` is an optional, non-empty list of unique explicit dotted paths. Wildcards and empty path segments are not allowed. Without `items`, the response root is validated as one item. With `items`, each resolved array is expanded and every element is validated; a resolved non-array value is validated as one item. The constraint-level `required` controls whether at least one configured item path must exist and defaults to `true`. `required: false` permits all item paths to be absent. A present empty array proves that the item path exists and contains no elements to validate.

`fields` is required and must be a non-empty map of dotted paths, relative to each selected item, to non-empty `fieldRule` objects. Arrays encountered while resolving a field path fan out, and every resolved value must pass. A field rule supports:

- `required`: require that field on every selected item.
- `type`: `string`, `number`, `integer`, `boolean`, `object`, `array`, or `null`. Booleans are not numbers.
- `enum` or `equals`: constrain the exact JSON value.
- `minLength`, `maxLength`, and a bounded safe `pattern`: constrain strings. Patterns use only the anchored form `^<literal-prefix>[<ASCII class>]{min,max}$`; `max` cannot exceed 4096 and a pattern requires `maxLength`.
- `min` and `max`: constrain finite numeric values.
- `minItems` and `maxItems`: constrain arrays.

An absent field is allowed unless its own field rule has `required: true`. `responseJson` does not reject unmentioned siblings, remove fields, or define the release shape. Those are redaction responsibilities of the adapter response profile.

Both the Python policy engine and production Rust gate evaluate `responseJson` against the bounded, parsed upstream success body before applying `allowedFields`. This ordering lets a contract validate a provider field even when that field is not released. API-specific projection then runs, `responseDateWindow` evaluates the canonicalized response where required, structural projection removes unlisted fields, response headers are normalized, and the final credential-reflection guard scans the projected output.

Policy admission rejects `responseJson` with the wrong phase, missing or empty `fields`, invalid or duplicate operation/item paths, wildcard paths, empty or unsupported field rules, unsafe patterns, or inconsistent bounds. Whole-body response constraints cannot be combined with a streaming response mode. At runtime, invalid JSON, missing operation context, absent required items or fields, and any type/value/bound violation block the response with a synthetic `502`; errors use the `response_json_*` family and no upstream body bytes are released.

Validation is not redaction. Every credential-bearing `generic.rest` or `x.v2` response profile using `mode: "json"` must also define a non-empty, unique `allowedFields` projection, including any configured JSON error profile. A `responseJson` constraint never satisfies this requirement. Missing, empty, duplicate, wildcard, or malformed projections reject policy activation; the runtime check independently blocks with `response_allowed_fields_missing` and `502` if an invalid profile reaches response handling.

The bounded object-store write in [policies/credential-limits.examples.json](../policies/credential-limits.examples.json) combines both controls:

```json
{
  "adapter": {
    "type": "generic.rest",
    "config": {
      "response": {
        "mode": "json",
        "maxBodyBytes": 65536,
        "allowedFields": ["ok", "id", "sha256"]
      }
    }
  },
  "constraints": [
    {
      "id": "object-store-response-contract",
      "type": "responseJson",
      "phase": "response",
      "fields": {
        "ok": {"required": true, "type": "boolean", "equals": true},
        "id": {"required": true, "type": "string", "maxLength": 128, "pattern": "^[A-Za-z0-9._-]{1,128}$"},
        "sha256": {"required": true, "type": "string", "maxLength": 71, "pattern": "^sha256:[0-9a-f]{64,64}$"}
      }
    }
  ]
}
```

Here `responseJson` proves that the provider reported success and returned a bounded object ID and SHA-256 digest. `allowedFields` separately guarantees that only those three fields can reach the agent.

Every response profile has an explicit `maxBodyBytes`. A `2xx` status uses the success profile. Redirects are always blocked with `response_redirect_not_allowed`; Serverware never follows or releases an upstream `Location`. A `4xx` or `5xx` status uses the nested `error` profile, and fails closed with `response_error_policy_missing` if that profile is absent. Gmail and npm require bounded JSON error profiles at policy admission. Generic REST and X permit an omitted error profile at admission for compatibility, but an actual error response is still blocked when no profile exists. Other status classes are invalid.

Buffered JSON profiles use non-empty dotted `allowedFields` paths. Each path segment is explicit; empty segments, wildcards, duplicates, and unrecognized shapes are rejected. Projection is structural, so allowing `data.id` does not release sibling fields under `data`. Gmail adds `allowedMessageHeaderNames`: when `payload.headers` is selected, only the named message-header objects are retained, using case-insensitive name matching. Selecting `payload.headers` without a non-empty message-header allowlist, or configuring that allowlist without selecting the field, is rejected.

`allowedHeaders` controls upstream semantic response headers independently for each success or error profile. The only releasable names are `cache-control`, `content-language`, `etag`, `last-modified`, `retry-after`, and `www-authenticate`. Duplicate, malformed, overlong, or unlisted values fail closed or are stripped. Hop-by-hop headers, `set-cookie`, `location`, authentication/session state, upstream content encoding, and upstream content length are never forwarded. Serverware emits a canonical content type and recalculated content length for buffered output.

Credential-bearing `mode: "any"` and opaque `mode: "stream"` responses are rejected at policy admission and again at runtime. Credential-bearing structured streaming modes such as `jsonlStream`, `jsonArrayStream`, `jsonSseStream`, `jsonNestedStream`, `formUrlencodedStream`, and `csvStream` require a non-empty field projection. No streaming mode may configure non-empty `allowedHeaders`, because streaming responses do not release upstream semantic headers. Credential-bearing mutating request streams are also rejected: methods other than `GET`, `HEAD`, and `OPTIONS` must use a bounded request body so malformed or truncated content cannot be discovered after an upstream write has begun.

The final credential-reflection guard runs after adapter and constraint projection. It scans for the injected value and common JSON, URL, Base64, Base64url, and SHA-256 representations across output boundaries. This is a defense in depth control, not general information-flow proof: an intentionally malicious provider could transform a secret into some other allowed semantic value. Narrow endpoint allowlists, structured projections, trusted upstreams, and provider-specific response validation remain required.

Successful buffered responses can carry the separate proxy response runtime proof described in [Security Review](security-review.md#response-and-attestation-proofs). Streaming responses have no final body digest or final proxy response-proof artifact.
