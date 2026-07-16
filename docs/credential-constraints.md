# Credential Constraints

Serverware treats credentials as capabilities, not secrets that agents can hold. A route decides which credential may be injected, which principal may use it, which upstream endpoint may be reached, and which request/response constraints must hold before the credential is released.

The route-level `constraints` array is the shared customization layer. Provider adapters still normalize API-specific facts such as `tweets.write`, `gmail.messages.list`, or `npm.publish`; constraints then apply reusable rules to those facts, the HTTP query, JSON body, rate counters, and response payload.

```json
{
  "id": "x-one-tweet-per-day",
  "type": "rateLimit",
  "max": 1,
  "calendarWindow": "utcDay",
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
4. Request constraints validate operation, path/query/header values, body, time windows, and current rate-limit headroom without mutating quota or grant state. Validated `requestValue` captures are added to the canonical operation before its digest is computed.
5. For an actual proxy request, the release authority atomically reserves every shared rate-limit counter and the exact request- and operation-bound one-use JIT grant. If a required grant is absent, it leaves no quota reservation and creates or reuses a bounded pending approval for the exact canonical request. `/v1/decide` is preview-only and does not create approvals or reserve state.
6. The Rust gate obtains the route's one-credential scoped lease, checks its version, policy generation, and expiry, injects only the selected credential field, and strips Serverware-only identity headers.
7. Immediately before the upstream send, the gate rechecks that the reservation, lease, and policy snapshot are still current, advances the exact release attempt to `dispatching`, synchronously submits `data_plane.credential.release_started`, and requires the control plane to acknowledge its durable hash-chain append. If any dependency is unavailable or rejects the binding, the upstream request is not sent.
8. Completion commits an attempt known to have been forwarded, refunds a proven `not_forwarded` attempt, and conservatively commits an unknown result after dispatch as indeterminate. Attempt, flow, and binding identifiers make these transitions idempotent and prevent a quota or grant from being consumed independently.
9. The upstream status selects the success or error response profile. Response size and syntax are checked first; whole-body semantic constraints are then evaluated before field projection and released-header validation. No buffered bytes are released until every applicable check passes.
10. After adapter and constraint projection, the credential-reflection guard scans the final body, content type, and released semantic headers. A match blocks the response.

If any step fails, the request or response is blocked. Unknown routes are never proxied.

For streaming responses, validation and projection happen incrementally. Serverware releases only generated protocol headers, never upstream semantic headers, and applies the reflection guard to projected output as it is written. Because already-released stream prefixes cannot be recalled, credential-bearing opaque streams are rejected at policy admission; see [Response Validation](#response-validation).

## Implemented Constraint Types

`operationPolicy`: allow or deny normalized adapter operations. Use this to block writes for one app while allowing reads, or to make a broad route safe even if SDKs choose unexpected endpoints.

`rateLimit`: credential use limits keyed by principal, credential, verified provider account, route, operation, credential version, or selected operation fields. A constraint selects exactly one window model. `windowSeconds` defines a rolling fixed window anchored by first use; five Slack posts per 3,600-second assignment window and ten object-store writes per 3,600-second assignment window use that model. `calendarWindow` defines a UTC calendar bucket: `utcDay` is `[00:00 UTC, 00:00 UTC the next day)`, `utcIsoWeek` is `[Monday 00:00 UTC, Monday 00:00 UTC the next ISO week)`, and `utcMonth` is `[the first day 00:00 UTC, the first day 00:00 UTC the next month)`. All starts are inclusive and all ends are exclusive. The X and Stripe examples use `utcDay`, so they reset at 00:00 UTC rather than 24 hours after first use. `providerAccount` derives a stable SHA-256 scope from the signed provider and callback-verified subject, so principal, credential, or credential-version rotation cannot reset an account-wide quota; policy admission and runtime authorization fail closed when that identity is unavailable. `store: "local"` keeps eligible fixed-window counters in the current process for dev-only throttles. `store: "shared"` commits the counter through the authenticated control plane so the quota is atomic across proxy/data-plane replicas; calendar windows require the shared authority.

Every shared quota reservation is bounded by its counted window. A fixed-window reservation cannot dispatch after its rolling window ends, and a calendar reservation created before midnight that has not entered durable dispatch expires and is refunded at 00:00 UTC; the caller must reserve again against the new window. A request that entered dispatch before the boundary remains charged to that earlier window even if completion is reported later, and an unknown post-dispatch result is charged conservatively. Changing the duration of a live fixed-window policy preserves its accumulated count while the requested replacement window remains active. This prevents retry, approval, policy-update, or dispatch latency from moving one reservation between quota windows.

`queryDateWindow`: bounds query parameters such as `start_time`, `end_time`, or `since` to a maximum lookback. Formats supported: RFC3339, date, epoch seconds, and epoch milliseconds.

`queryNumericBounds`: caps query values such as `max_results`, `per_page`, `limit`, and `maxResults`.

`requestTimeWindow`: limits credential use by absolute RFC3339 bounds, UTC weekdays, and one or more UTC daily intervals. `timezone` must be `UTC`; daily interval ends are exclusive. Empty bounds, reversed absolute bounds, duplicate weekdays, malformed times, and overlapping intervals are rejected when the policy loads. Runtime parsing also fails closed.

`requestValue`: constrains one path parameter, query value, or forwarded request header per rule on a `generic.rest` route. Every named value is mandatory and must occur exactly once. A rule selects exactly one predicate family through `predicate.kind`: exact string, string enum, bounded anchored pattern, UTF-8 byte-length range, or finite numeric range. Integer numeric rules accept only canonical signed 64-bit text. At most 16 rules and 32 enum values are allowed; string inputs are capped at 4096 bytes. Pattern rules use the shared non-backtracking bounded grammar and must declare `maxLength`.

```json
{
  "id": "repository-scope",
  "type": "requestValue",
  "rules": [
    {
      "source": "pathParam",
      "name": "owner",
      "predicate": {"kind": "equals", "value": "approved-owner"},
      "capture": "githubOwner"
    },
    {
      "source": "query",
      "name": "state",
      "predicate": {"kind": "enum", "values": ["open", "closed"]}
    }
  ]
}
```

Policy admission proves every `pathParam` appears in every route path template and every query/header name appears in the generic adapter allowlist. Header names must be lower-case. Optional `capture` names cannot collide with adapter operation fields; captures can key shared quotas, bind JIT operation digests, and serve as response-binding sources (`exactString`, or `canonicalInteger` for integer predicates). Predicate failure, missing or repeated values, invalid runtime policy state, and duplicate HTTP request header fields deny before JIT lookup, quota consumption, credential lease release, or injection.

`jsonBody`: enforces JSON request body shape: allowed fields, required fields, denied fields, type checks, string length, numeric bounds, enums, exact values, and array size bounds. Structural allowlisting includes empty objects and arrays, including empty containers nested in arrays, so an unknown key cannot evade the allowlist merely because it has no scalar leaf. An explicitly allowlisted container remains valid and can be constrained with `type: "array"`, `minItems`, and `maxItems`.

`formBody`: applies the same allowlist, required/denied field, scalar duplicate, type, length, numeric, enum, exact-value, and safe-pattern rules to bounded `application/x-www-form-urlencoded` bodies. Bracketed keys such as `metadata[agent_request_id]` normalize to `metadata.agent_request_id`. Malformed UTF-8, malformed percent encoding, ambiguous duplicate scalar fields, and more than 256 pairs fail closed.

For a credential-bearing `generic.rest` route, buffered `bodyMode: "json"` requires a matching request-phase `jsonBody` constraint with a non-empty structural `allowedFields` list, and `bodyMode: "formUrlencoded"` requires the equivalent `formBody` constraint. Credential-bearing `bodyMode: "any"` is rejected because it would let provider-recognized fields bypass typed constraints. The JSON Schema, policy compiler, Python adapter, and Rust gate enforce these rules independently. Unknown sibling fields deny the request before credential lookup or injection; Serverware does not silently strip them after the request digest or JIT approval has been computed. Credentialless routes may still use an explicit `bodyMode: "any"` for intentionally opaque forwarding.

`responseDateWindow`: validates JSON responses before release. It supports nested arrays through dot paths, so `data.created_at` checks every item in a `data` array.

`responseJson`: validates the semantic contract of a buffered JSON success response before release. It can apply to every normalized operation or only named operations, validate the root value or objects selected through explicit item paths, and apply the shared `fieldRule` assertions to every selected item. It validates data; it does not select or redact fields.

`responseBinding`: binds fields captured in the authorized request operation to fields in a buffered JSON success response. It rejects a missing or invalid request source before credential release and rejects a missing, ambiguous, mistyped, or mismatched response field before any upstream response bytes are released.

## Generic Required Request Headers

`generic.rest` routes can require ordinary provider request headers through `adapter.config.request.requiredHeaders`. This is adapter policy, not a route-level `constraint` and not principal identity. A principal's top-level `principals[].requiredHeaders` participates in client authentication and must be visible during HTTPS `CONNECT`; an adapter-required header is checked only after principal and route matching, then forwarded to the upstream provider.

Each required adapter header must:

- use a lower-case HTTP field name and also appear in `request.allowedHeaders`;
- define `type: "string"`, `minLength`, and `maxLength`, with UTF-8 byte length bounded from 1 to 8192;
- optionally use the shared bounded anchored-pattern grammar, with the pattern capped at 256 characters and the header maximum capped at 4096 bytes when a pattern is present;
- avoid hop-by-hop, proxy, Host, Content-Length, Serverware service/identity, and credential-injection headers.

At most 16 headers can be required. Duplicate normalized allowlist names, unsupported rule fields, unsafe patterns, non-forwardable names, and credential-injection collisions reject policy activation. At request time, Python and Rust both return a local denial for a missing or invalid value before JIT consumption or credential injection.

The tokenized Stripe PaymentIntent template uses this contract for provider idempotency:

```json
{
  "allowedHeaders": ["accept", "content-type", "idempotency-key", "user-agent"],
  "requiredHeaders": {
    "idempotency-key": {
      "type": "string",
      "minLength": 1,
      "maxLength": 255,
      "pattern": "^[-A-Za-z0-9._:]{1,255}$"
    }
  }
}
```

The agent must generate a policy-conforming `Idempotency-Key` for each intended PaymentIntent operation. Serverware validates and forwards it; Serverware does not synthesize the key or treat it as client identity.

The example accepts Stripe's documented PaymentIntent state machine, including nonterminal states such as `requires_action`, but it does not expose `client_secret` or next-action payloads and cannot complete customer authentication. The agent must preserve the same idempotency key, stop on a nonterminal state, and hand the PaymentIntent ID and status to an operator-owned checkout/SCA workflow. The route accepts only pre-tokenized `pm_...` identifiers and rejects raw card/source fields; this is neither tokenization nor PCI certification.

## Common Patterns Already Modeled

The demo policy includes:

- Gmail read access limited to the last 30 days, with page size caps and response `internalDate` validation.
- X recent search limited to seven days, capped at 100 results, with response `created_at` validation.
- X controlled posting limited to one plain-text tweet for the demo's single simulated account per UTC calendar day, resetting at 00:00 UTC. The production template and common example key the same limit by the OAuth callback-verified provider subject.
- X bounded read access covering every explicitly cataloged current GET endpoint while writes, unknown endpoints, and streaming endpoints stay blocked.
- npm publish/dist-tag writes guarded by operation allowlists and per-operation JIT approval.

[policies/credential-limits.examples.json](../policies/credential-limits.examples.json) adds ready-to-adapt examples for Slack posting; GitHub issue listing scoped to an exact owner and repository allowlist; Stripe customer access scoped to one exact customer with request/response binding; tokenized PaymentIntent creation with a required bounded idempotency key, amount caps, and hardware-backed JIT approval; and object-store writes scoped to one bucket and bounded key grammar under one assignment-wide shared quota. The bucket/key captures constrain each request but are deliberately not quota dimensions, so changing object names cannot reset the assignment's hourly allowance. Each provider has a separate credential reference so copying the examples does not imply cross-provider credential reuse.

## X Endpoint Catalog

The X adapter classifies exact path templates from the current [X OpenAPI description](https://docs.x.com/openapi.json). Read operations are grouped into explicit policy names including `tweets.read`, `users.read`, `search.read`, `connections.read`, `directMessages.read`, `bookmarks.read`, `lists.read`, `spaces.read`, `analytics.read`, and the other cataloged families in the adapter schema. A new or changed X endpoint is denied until Serverware's Python classifier, Rust classifier, schema, and tests all recognize it.

`example.x.full_bounded_read` demonstrates the broadest bounded-read profile. It permits the complete current non-streaming GET catalog, subject to the OAuth scopes actually granted to that credential. That includes sensitive private-data families such as bookmarks or direct messages only when both the credential scopes and the route operation policy allow them. Use narrower operation lists for agents that do not need those categories.

Streaming reads are intentionally excluded from that profile because a live stream cannot receive whole-response validation or a final response-proof artifact. An opaque X stream would be credential-bearing and is therefore rejected; supporting it requires a structured, incrementally redacting adapter mode rather than `mode: "stream"`. Controlled writes are separate: the current audited write surface accepts only `POST /2/tweets`, requires `tweets.write`, an explicit JSON body allowlist, and a bounded non-stream response. Delete, follow, direct-message, like, retweet, media-upload, and unknown writes fail closed.

## Composing New Limits

Constraints compose as an intersection: a request must satisfy the principal, endpoint, adapter, every request constraint, any JIT grant, and every response constraint. This supports rules such as "one post per verified provider account per UTC calendar day, resetting at 00:00 UTC, only on weekdays, with a 280-character body" without provider-specific scripting. Use `windowSeconds` when the intended rule is instead a rolling duration from first use.

Shared quotas and JIT are enforced as one release decision, not as sequential best-effort counters. For example, a one-tweet-per-UTC-calendar-day route cannot consume the daily slot while discovering that its approval is missing, and a failed pre-dispatch audit cannot permanently burn either control. Calendar quota denial reports the next UTC boundary and a retry interval to that boundary; the daily reset is 00:00 UTC. Approval polling remains independently bounded to one hour.

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

Type-specific rules require an explicit compatible `type` at policy admission. String length or pattern rules require `type: "string"`; numeric bounds require `type: "number"` or `type: "integer"`; item-count bounds require `type: "array"`. Python, Rust, and JSON Schema reject incompatible or untyped combinations instead of conditionally ignoring them at runtime.

An absent field is allowed unless its own field rule has `required: true`. `responseJson` does not reject unmentioned siblings, remove fields, or define the release shape. Those are redaction responsibilities of the adapter response profile.

Both the Python policy engine and production Rust gate evaluate `responseJson` against the bounded, parsed upstream success body before applying `allowedFields`. This ordering lets a contract validate a provider field even when that field is not released. API-specific projection then runs, `responseDateWindow` evaluates the canonicalized response where required, structural projection removes unlisted fields, response headers are normalized, and the final credential-reflection guard scans the projected output.

Policy admission rejects `responseJson` with the wrong phase, missing or empty `fields`, invalid or duplicate operation/item paths, wildcard paths, empty or unsupported field rules, unsafe patterns, type-incompatible rules, or inconsistent bounds. Whole-body response constraints cannot be combined with a streaming response mode. At runtime, invalid JSON, missing operation context, absent required items or fields, and any type/value/bound violation block the response with a synthetic `502`; errors use the `response_json_*` family and no upstream body bytes are released.

### Request-to-response bindings

`responseBinding` proves that selected fields in a successful upstream JSON response agree with the operation that Serverware authorized. It reads only explicitly declared operation, top-level body, and route-parameter sources; it does not evaluate arbitrary request paths and it does not redact the response. For example, the tokenized Stripe PaymentIntent route binds the captured form amount, currency, and payment-method token to Stripe's response:

```json
{
  "id": "payment-intent-response-binding",
  "type": "responseBinding",
  "phase": "response",
  "operations": ["stripe.payment_intents.create"],
  "successStatusCodes": [200],
  "contentTypes": ["application/json"],
  "bindings": [
    {
      "id": "amount",
      "operationField": "amount",
      "responseField": "amount",
      "comparison": "canonicalInteger"
    },
    {
      "id": "currency",
      "operationField": "currency",
      "responseField": "currency",
      "comparison": "exactString"
    },
    {
      "id": "payment-method",
      "operationField": "payment_method",
      "responseField": "payment_method",
      "comparison": "exactString"
    }
  ]
}
```

`phase` is required and must be `response`. `successStatusCodes` explicitly admits 1-8 unique `2xx` statuses; a different success status is a binding failure, not an implicit success. `contentTypes` explicitly admits 1-4 unique lower-case media types and the upstream response must contain exactly one matching `Content-Type`. An absent, duplicate, or different content type fails closed, as does any non-identity `Content-Encoding`. `operations` is optional; when present it is a non-empty, unique list and the constraint applies only to those exact normalized operation names. A matching response without operation context fails closed. Each constraint defines 1-8 bindings. Every binding has exactly `id`, `operationField`, `responseField`, and `comparison`; binding IDs and response fields must be unique.

`operationField` is an exact key lookup in the adapter's flat normalized operation map. Dots in a key are literal: `metadata.agent_request_id` names one flat captured key and does not traverse nested request data. A source must be a string no larger than 4096 UTF-8 bytes.

The general v2 source contract is admitted for `generic.rest` routes with a buffered `json` response capped at 65,536 bytes. `request.operation` defines a required `name` and may declare three bounded source arrays:

- `formFields`: at most 16 unique form keys, available only with `bodyMode: "formUrlencoded"`.
- `jsonFields`: at most 16 unique top-level JSON object keys, available only with `bodyMode: "json"`. Dots are forbidden because `jsonBody` uses dots for structural traversal; nested JSON values cannot be captured as operation sources.
- `pathParams`: at most 16 unique route parameter names. Every name must be an exact, non-repeated `{placeholder}` in every path in `route.match.paths`. If equal-specificity templates can match the same path, each configured source must occupy the same segment position; swapped placeholders are rejected.
- `bodySha256Field`: one operation-field name that receives lowercase `sha256:<64hex>` computed from the exact admitted request entity bytes. It is available only with buffered `bodyMode: "json"` or `"formUrlencoded"`, cannot be named `operation`, and can be compared only with `exactString`.

Form, path, and computed-digest source names must match `[A-Za-z][A-Za-z0-9_.-]{0,127}`; JSON source names use the stricter `[A-Za-z][A-Za-z0-9_-]{0,127}` top-level-key contract. Names must be unique across every source, and `operation` is reserved. A route can therefore use `responseBinding` with any request body mode when its declared sources are compatible: for example, a `bodyMode: "none"` GET can bind `operation` and declared path parameters without inventing a request body. Path and computed-digest sources support `exactString` only.

`npm.registry` has a narrower adapter-specific source contract for `npm.publish`. It permits only captured `packageName`, `packageVersion`, or `tarballIntegrity` fields with `exactString` and rejects any other npm operation. When a signed route enables `npm.publish` response binding, admission requires a buffered JSON success profile capped at 65,536 bytes, status exactly `200` or `201`, content type exactly `application/json`, exact `packageName` and `packageVersion` bindings, and a `responseJson` rule scoped only to `npm.publish` that requires boolean `published` equal to `true`. Python and Rust reject any weaker combination. This mode is for compatible registries whose documented bounded JSON success response explicitly echoes package identity. The public `registry.npmjs.org` template intentionally does not enable response-body binding because the [official npm client](https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/publish.js) ignores the body for ordinary publishes. That template instead binds package, version, integrity, route, credential generation, and operation digest into its one-use hardware-approved request.

JSON capture uses the same strict decoder as request constraints. The request root must be an object and only exact top-level keys are inspected. A JSON string is captured as its exact decoded UTF-8 value, with no trimming or Unicode normalization. A JSON integer is captured as its canonical base-10 string only when it fits signed i64. Booleans, floats, nulls, arrays, objects, out-of-range integers, invalid UTF-8 strings, malformed JSON, duplicate-key JSON, and non-object roots produce no JSON sources. `-0` is rejected by the strict decoder. Form capture likewise requires one unambiguous normalized value for the configured key. These extraction failures do not bypass request validation: ordinary `jsonBody` or `formBody` constraints run before source preflight and preserve their canonical denial.

Policy admission proves every bound form or JSON source is required by the corresponding `formBody` or `jsonBody` constraint. `canonicalInteger` requires `type: "integer"`; `exactString` requires `type: "string"`. Path parameters need no body rule because admission proves the route placeholder and runtime uses the matched route parameters. A computed digest is populated only after the buffered structured body passes its normal request constraints, and it hashes the original entity bytes rather than a parsed or reserialized value. A missing, duplicate, mistyped, oversized, or otherwise invalid source denies the request before request quota reservation, JIT grant consumption, credential lease acquisition, credential injection, or upstream contact.

`responseField` is a unique explicit dotted JSON path, not an operation-map key. Empty components and wildcards are forbidden. The response root and every intermediate node must be JSON objects; arrays are never traversed, even single-element arrays. The final value must be a scalar. This prevents fields from separate array elements from being combined into a false match. Missing paths, arrays, objects, or other non-scalar final values fail closed. The two comparisons are deliberately narrow:

- `exactString` requires the response value to be a JSON string exactly equal to the captured source. There is no trimming, case folding, Unicode normalization, or scalar coercion.
- `canonicalInteger` requires the source string to match `0|-?[1-9][0-9]*` and fit the signed 64-bit range `-9223372036854775808` through `9223372036854775807`. The response must be an equal JSON integer in that range, not a string, boolean, or floating-point value. Leading zeroes, `+`, `-0`, decimal points, and exponents are not canonical.

The validation order is fail closed. Policy admission validates the bounded binding shape, response envelope, required typed sources, route placeholders, and adapter capture contract. At request time the adapter validates and classifies the request, ordinary request-body constraints run first so malformed, duplicate, or mistyped form/JSON fields keep their canonical denial, and then Serverware validates all applicable binding sources before any credential lookup or release state is reserved or consumed. At response time Serverware validates the configured success status and media envelope, then runs `responseBinding` and `responseJson` against the original bounded upstream entity before adapter semantic validation, canonicalization, `responseDateWindow`, structural `allowedFields` projection, released-header checks, and the final credential-reflection guard.

Response binding is considered only for upstream `2xx` responses, and only configured `successStatusCodes` can pass. Redirects are blocked separately, and `4xx`/`5xx` bodies use the bounded error response profile without applying success bindings. An unapproved success status or media type, invalid JSON, missing operation context, a missing object-only response path, a type mismatch, or an unequal value produces a synthetic `502`; the upstream body is replaced and no upstream status, headers, or body bytes are released to the agent. Because binding requires the complete body before release, any route with `responseBinding` is rejected at policy admission when its response mode is streaming, including structured streaming modes. The development mitmproxy transport also forces response buffering in `responseheaders`; non-development deployments use the Rust decision gate.

Binding failures emit value-free evidence: the error family, constraint ID, optional binding ID, raw upstream entity digest, and a SHA-256 evidence digest. The digest commits to the policy hash, request digest, operation digest, raw response-body digest, constraint ID, binding ID, comparison, and result class. Successful bindings emit one value-free evidence digest per binding using the same event material with result `match`. Neither captured request values, observed response values, the response entity, nor the full operation map are included in response audit events. Exact replay of the same attested event material is stable; different request, operation, or response bytes produce different evidence.

Validation is not redaction. Every credential-bearing JSON response profile, including `generic.rest`, `x.v2`, and `npm.registry`, must also define a non-empty, unique `allowedFields` projection, including any configured JSON error profile. A `responseJson` constraint never satisfies this requirement. Missing, empty, duplicate, wildcard, or malformed projections reject policy activation; the runtime check independently blocks with `response_allowed_fields_missing` and `502` if an invalid profile reaches response handling.

The bounded object-store write in [policies/credential-limits.examples.json](../policies/credential-limits.examples.json) combines both controls:

```json
{
  "adapter": {
    "type": "generic.rest",
    "config": {
      "request": {
        "bodyMode": "json",
        "maxBodyBytes": 65536,
        "operation": {
          "name": "object_store.objects.put",
          "bodySha256Field": "requestBodySha256",
          "pathParams": ["artifact_id"]
        }
      },
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
    },
    {
      "id": "object-store-response-binding",
      "type": "responseBinding",
      "phase": "response",
      "operations": ["object_store.objects.put"],
      "successStatusCodes": [200],
      "contentTypes": ["application/json"],
      "bindings": [
        {"id": "artifact-id", "operationField": "artifact_id", "responseField": "id", "comparison": "exactString"},
        {"id": "sha256", "operationField": "requestBodySha256", "responseField": "sha256", "comparison": "exactString"}
      ]
    }
  ]
}
```

Here `responseJson` proves that the provider reported success and returned a bounded object ID and SHA-256-shaped string. `responseBinding` separately proves that the ID equals the matched `{artifact_id}` and that the returned string equals the SHA-256 Serverware computed over the exact admitted request bytes. `allowedFields` guarantees that only those three fields can reach the agent. The digest covers the complete JSON entity, including formatting and every admitted field; it is not a semantic hash of only the decoded `content` string.

Every response profile has an explicit `maxBodyBytes`. A `2xx` status uses the success profile. Redirects are always blocked with `response_redirect_not_allowed`; Serverware never follows or releases an upstream `Location`. A `4xx` or `5xx` status uses the nested `error` profile, and fails closed with `response_error_policy_missing` if that profile is absent. Gmail and npm require bounded JSON error profiles at policy admission. Generic REST and X permit an omitted error profile at admission for compatibility, but an actual error response is still blocked when no profile exists. Other status classes are invalid.

Buffered JSON profiles use non-empty dotted `allowedFields` paths. Each path segment is explicit; empty segments, wildcards, duplicates, and unrecognized shapes are rejected. Projection is structural, so allowing `data.id` does not release sibling fields under `data`. Gmail adds `allowedMessageHeaderNames`: when `payload.headers` is selected, only the named message-header objects are retained, using case-insensitive name matching. Selecting `payload.headers` without a non-empty message-header allowlist, or configuring that allowlist without selecting the field, is rejected.

`allowedHeaders` controls upstream semantic response headers independently for each success or error profile. The only releasable names are `cache-control`, `content-language`, `etag`, `last-modified`, `retry-after`, and `www-authenticate`. Duplicate, malformed, overlong, or unlisted values fail closed or are stripped. Hop-by-hop headers, `set-cookie`, `location`, authentication/session state, upstream content encoding, and upstream content length are never forwarded. Serverware emits a canonical content type and recalculated content length for buffered output.

Credential-bearing `mode: "any"` and opaque `mode: "stream"` responses are rejected at policy admission and again at runtime. Credential-bearing structured streaming modes such as `jsonlStream`, `jsonArrayStream`, `jsonSseStream`, `jsonNestedStream`, `formUrlencodedStream`, and `csvStream` require a non-empty field projection. No streaming mode may configure non-empty `allowedHeaders`, because streaming responses do not release upstream semantic headers. Credential-bearing mutating request streams are also rejected: methods other than `GET`, `HEAD`, and `OPTIONS` must use a bounded request body so malformed or truncated content cannot be discovered after an upstream write has begun.

The final credential-reflection guard runs after adapter and constraint projection. It scans for the injected value and common JSON, URL, Base64, Base64url, and SHA-256 representations across output boundaries. This is a defense in depth control, not general information-flow proof: an intentionally malicious provider could transform a secret into some other allowed semantic value. Narrow endpoint allowlists, structured projections, trusted upstreams, and provider-specific response validation remain required.

Successful buffered responses can carry the separate proxy response runtime proof described in [Security Review](security-review.md#response-and-attestation-proofs). Streaming responses have no final body digest or final proxy response-proof artifact.
