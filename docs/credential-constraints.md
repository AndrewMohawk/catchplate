# Credential Constraints

Serverware treats credentials as capabilities, not secrets that agents can hold. A route decides which credential may be injected, which principal may use it, which upstream endpoint may be reached, and which request/response constraints must hold before the credential is released.

The route-level `constraints` array is the shared customization layer. Provider adapters still normalize API-specific facts such as `tweets.write`, `gmail.messages.list`, or `npm.publish`; constraints then apply reusable rules to those facts, the HTTP query, JSON body, rate counters, and response payload.

## Current Source Status

The current source tree includes the closed conditional adapter model; generic REST credential/no-credential proofs; provider, subject, OAuth client/app, granted-scope, and operation binding; adapter-wide `requestValue`; canonical IPv4/IPv6 and private verified-mTLS selectors; fixed, UTC-calendar, true sliding, and weighted shared budgets; durable traversal page/lifetime/record/byte limits with one-use cursor lineage; nonvacuous response/date/JSON proofs; exact response-envelope and physical-header uniqueness checks; and X recent-search alternate-path isolation. Post-dispatch uncertainty charges count and weight, consumes the input cursor, poisons traversal, and cannot release a continuation cursor. Expired completion and reconciliation converge on the same conservative result, while PostgreSQL lock contention skips only the busy candidate and systemic query cancellation propagates.

These are source contracts and source-reviewed implementations in the current batch, not current execution evidence. No build, interpreter, test, live provider, real PostgreSQL concurrency exercise, or production deployment has run against this source batch. The hardware-only approval path also has a source-level typed HTTP `403` denial when no currently eligible WebAuthn credential exists; that denial does not prove a successful physical YubiKey ceremony.

The production credential transport is the Rust decision gate. It owns the selected upstream socket, validates the complete resolved address set, uses one deterministic pinned address with original-host TLS verification, and performs no alternate-address retry or re-resolution. The legacy Python mitmproxy path is limited to credentialless development traffic: it rejects every credential-bearing route before adapter lookup, credential metadata, JIT, quota, reservation, secret acquisition, or provider dispatch. Python helpers and parity tests remain useful for policy semantics, but they are not a credential-forwarding or Gmail-hydration implementation.

The signed `routes[].match.resolvedCidrs` field optionally restricts DNS results to 1-32 explicit networks. Entries must be unique canonical, host-bit-free IPv4 or IPv6 CIDRs. Omitting the field selects public-only resolution; setting it permits deliberate private or loopback destinations such as an internal service. IPv4-mapped IPv6 space, zone IDs, and CIDRs overlapping known cloud metadata ranges are always rejected and cannot be enabled by policy. The bounded resolve-once and socket-pinning transport contract is documented in the [data-plane README](../data-plane/README.md#rust-decision-gate).

Principal network selectors use the same canonical, host-bit-free IPv4/IPv6 CIDR rules. A `requiredHeaders` identity selector is never a trust anchor by itself: admission requires the principal to bind it to a non-universal trusted source CIDR, a validated proxy bearer credential with its own source restriction, or verified `mtls` evidence. An mTLS principal sets `verifiedByTrustedIngress: true` and may match bounded exact `sanSpiffeIds`, `sanDnsNames`, `sanUris`, `certificateSha256`, `spkiSha256`, and `issuerSpkiSha256`. Every declared mTLS selector is an intersection over private connection evidence supplied by an authenticated TLS terminator; an unverified forwarded certificate header is not mTLS evidence. The Python runtime defines this trusted-ingress interface, but `mitm_addon.py` does not currently populate it. Therefore mTLS-only principals deny until a trusted ingress sets `client_conn.serverware_mtls_verified` and bounded `client_conn.serverware_mtls_evidence`; this is not yet an end-to-end live mTLS attestation claim.

```json
{
  "id": "x-one-tweet-per-day",
  "type": "rateLimit",
  "max": 1,
  "calendarWindow": "utcDay",
  "windowSemantics": "calendarUTC",
  "store": "shared",
  "key": {"scope": ["principal", "credential", "route", "operation"]}
}
```

## Execution Order

Policy activation is a separate fail-closed gate. Serverware verifies the bundle schema and signature, rejects capabilities that an enforcement runtime cannot implement, and compares the candidate with persisted policy high-water state before making it active. A changed bundle must advance `metadata.sequence`; `rollbackEpoch` cannot decrease; a previously seen policy hash cannot reappear with different monotonic metadata.

For each request:

1. Raw request-target admission runs before policy lookup, audit, principal selection, credential metadata, JIT, or quota work. The wire scheme, authority or physical Host, path and query, and first-line form must be bounded ASCII and mutually consistent; DNS is lowercase, the absolute path is explicit, default ports are omitted, percent escapes are canonical, and the parser must preserve the admitted target exactly. The Python development addon uses mitmproxy `RequestData` fields and fails closed when those raw views are unavailable or disagree with normalized fields. Principal allowlist checks then validate canonical client IP, any trusted-ingress header or proxy bearer token, and verified mTLS evidence.
2. Route matching blocks unknown hosts, ports, paths, and methods.
3. Declared discard-only headers and every selector used to establish the selected principal are removed, while the already authenticated principal remains local state. A bounded byte-level preflight requires concrete buffered bytes and rejects missing or unreadable content, duplicate fields, unsupported transfer framing, malformed or inconsistent `Content-Length`, oversized or forbidden bodies, unsupported `Content-Encoding`, and missing/malformed/wrong media types before decoded body access, any adapter parser, or canonicalization. Only an absent encoding or the exact identity encoding is admitted; any non-identity encoding fails closed until a separately bounded decoded-body contract exists. After those checks, decoded access must return the identical buffered bytes, and an exact identity marker is removed before provider admission and canonicalization. The adapter then performs its deterministic request rewrite. Serverware rematches the rewritten method and target to the same signed route, reruns header/profile/request validation, and rejects any reintroduced discarded or identity field. The Python proxy additionally replaces the rewritten query with the single canonical wire serialization defined below. The exact post-rewrite, pre-credential provider-visible method, URL, headers, and body become the canonical request.
4. The adapter classifies that final request, and request constraints validate its operation, path/query/header/body values, time windows, traversal lineage, and current count/weight headroom without mutating durable state. Validated `requestValue` captures and canonical budget weights are added to the canonical operation before its digest is computed.
5. For an actual proxy request, the release authority requires the exact canonical request digest and operation digest even when JIT is disabled. It atomically reserves shared fixed/calendar count limits and, when required, the exact request- and operation-bound one-use JIT grant. The data plane then creates one separately durable policy-state bundle containing every sliding count, weighted sum, and traversal claim for the same attempt, policy hash, request digest, operation digest, and claim-set digest. The policy-state bundle is all-or-none under one SQLite immediate transaction or one PostgreSQL transaction with ordered advisory locks. If either reservation stage fails, the other stage is terminalized as proven not forwarded before any secret is read. Missing, malformed, or mismatched canonical material or either digest denies before any provider effect. If a required grant is absent, the authority leaves no policy-state bundle and creates or reuses a bounded pending approval for the exact canonical request. `/v1/decide` is preview-only and does not create approvals or reserve state.
6. The gate may obtain bounded non-secret credential generation metadata before release, but every JIT or atomic-reservation-controlled scope obtains `DispatchSecret` only with the exact validated reservation identity from step 5. Background renewal for those scopes refreshes generation metadata only. The gate then checks lease version, policy generation, release binding, and expiry before injecting only the selected credential field.
7. Immediately before the upstream send, the gate rechecks that the reservation, lease, and policy snapshot are still current, advances the exact release attempt and the exact durable policy-state bundle to `dispatched`, synchronously submits `data_plane.credential.release_started`, and requires the control plane to acknowledge its durable hash-chain append. The policy-state transition dispatches every child claim in one transaction or none and persists its original dispatch time plus an absolute deadline no later than the release attempt's bounded dispatch deadline. Every reserve, transition, and recovery operation derives the same complete set of attempt, bundle, budget, chain, and cursor resources, acquires PostgreSQL advisory locks in one total sorted order, and only then takes row locks. If the transition result is uncertain, count and weight are charged conservatively and every traversal chain in the bundle is poisoned before the request is denied.
8. A proven pre-dispatch failure aborts the entire policy-state bundle: sliding and weighted reservations are cancelled and any reserved input cursor becomes available again. Every expected child cancellation, cursor restoration, chain update, and bundle transition must affect exactly one row or the transaction fails. After dispatch, transport uncertainty, response preparation denial, release-completion failure, unexpected response-evaluator exception, or response-validation failure uses a distinct indeterminate terminal operation, not the successful response-completion API. Release cleanup and durable cleanup are independent attempts; failure of one never suppresses the other, and combined uncertainty reports both. Count and weight remain charged from the original dispatch time; each traversal input cursor is consumed, its chain is poisoned, and no next cursor is released. Claim-specific failure evidence binds the constraint, lineage, input-cursor commitment, typed reason, and response-body digest. Replays must present the identical evidence.
9. Startup and the bounded request-pruning hook reconcile expired `dispatched` bundles without an external worker. Recovery revalidates the stored release binding against the exact release-authorization attempt, policy, request, operation, principal, route, credential, and credential version. Only an exact terminal `cancelled` plus `not_forwarded` release outcome permits an atomic abort. A forwarded outcome, an indeterminate or nonterminal outcome, an absent release row, a binding mismatch, or corrupt deadline evidence cannot disprove forwarding: recovery atomically charges count/weight from the persisted dispatch time, consumes any input cursor, poisons traversal, and records deterministic indeterminate evidence. No dispatched bundle can wait forever.
10. The upstream status selects the success or error response profile. `responseEnvelope` validates the exact status, media type, and semantic header contract before body interpretation. Response size, syntax, semantic constraints, adapter response checks, and traversal observations are prepared next. Preparation does not commit durable state.
11. The adapter finalizer performs the final projection and released-header transformation. The credential-reflection guard then scans that final body, content type, and released semantic headers. A finalizer error or reflection match terminalizes the dispatched bundle as indeterminate and releases no next cursor.
12. Only after every response check, adapter finalizer, and reflection guard succeeds does the successful completion API atomically commit count/weight children plus each traversal page's exact validated record count, decoded byte count, response digest, and optional next-cursor commitment. A traversal-limit or cursor-collision denial charges count/weight, poisons every traversal chain in the bundle, and returns no partial success.

If any step fails, the request or response is blocked. Unknown routes are never proxied.

For streaming responses, validation and projection happen incrementally. Serverware releases only generated protocol headers, never upstream semantic headers, and applies the reflection guard to projected output as it is written. Because already-released stream prefixes cannot be recalled, credential-bearing opaque streams are rejected at policy admission; see [Response Validation](#response-validation).

## Implemented Constraint Types

`operationPolicy`: allow or deny normalized adapter operations. Any X route admitting `search.read` must use `recentSearchOnly`, only the exact recent-search path family, and the exact non-optional request and response seven-day proofs. `/2/**`, `/2/tweets/search/all`, and alternate path families conflict even if unrelated proofs are present. The checked-in broad X route admits only `tweets.read` and `users.read`; bookmarks, DMs, search, unknown operations, and unsupported streams are excluded.

`rateLimit`: fixed and UTC-calendar operation-count limits keyed by principal, credential, route, operation, credential version, or selected operation fields. A fixed limit uses `windowSeconds` with `windowSemantics: "fixedFromFirstUse"`. A calendar limit uses `calendarWindow` with `windowSemantics: "calendarUTC"`: `utcDay` is `[00:00 UTC, 00:00 UTC the next day)`, `utcIsoWeek` is `[Monday 00:00 UTC, Monday 00:00 UTC the next ISO week)`, and `utcMonth` is `[the first day 00:00 UTC, the first day 00:00 UTC the next month)`. All starts are inclusive and all ends are exclusive. The X and Stripe count examples use `utcDay`, so they reset at 00:00 UTC rather than 24 hours after first use.

`slidingWindowLimit`: a true trailing operation-count interval. It requires the shared store, `windowSeconds`, `windowSemantics: "sliding"`, `measure: "operationCount"`, `reservationMode: "atomicReserveCommitRelease"`, and `onOverflow: "deny"`. The Slack example permits at most five sends in every trailing 3,600 seconds.

`weightedBudget`: a true trailing sum over one canonical non-negative integer request value or adapter operation field. It uses the same explicit sliding/reservation fields with `measure: "weightedCanonicalInteger"` and a closed `weight` declaration: `source`, `field`, `representation: "canonicalNonNegativeInteger"`, bounded `unit`, and per-operation minimum/maximum. The field must already be structurally required and bounded by the typed request profile; policy data cannot contain JSONPath, arithmetic expressions, scripts, floating-point coercion, or provider-supplied post hoc cost code. The PaymentIntent example captures `amount` in cents and limits the sum to 100,000 cents across every trailing 86,400 seconds, in addition to the separate five-operation UTC-day cap. Missing, negative, noncanonical, overflowing, out-of-range, or differently typed weights deny before reservation.

`providerAccount` derives a stable SHA-256 scope from the signed provider and callback-verified subject, so principal, credential, or credential-version rotation cannot reset an account-wide quota; policy admission and runtime authorization fail closed when that identity is unavailable. `store: "local"` keeps only eligible unweighted fixed-window counters in the current process for development throttles. `store: "shared"` commits count and weight state through the authenticated control plane so the limit is atomic across proxy/data-plane replicas. Calendar, sliding, weighted, and traversal limits require the shared authority.

Every shared quota reservation is bounded by its selected window and exact canonical weight. A fixed-window reservation cannot dispatch after its anchored window ends, and a calendar reservation created before midnight that has not entered durable dispatch expires and is refunded at 00:00 UTC; the caller must reserve again against the new window. Sliding admission prunes only committed events at or before `now - windowSeconds`, considers active reservations at their reserved weights, and rejects clock regression rather than silently widening access. A request that entered dispatch before a boundary remains charged even if completion is reported later, and an unknown post-dispatch result is charged conservatively. Changing a live window or weight definition requires a new policy generation while preserving still-relevant committed state. This prevents retry, approval, policy-update, or dispatch latency from moving one reservation between quota models.

`queryDateWindow`: bounds query parameters such as `start_time`, `end_time`, or `since` to a maximum lookback. Every parameter must be an admitted typed adapter query key. X recent search requires both `start_time` and `end_time`, `required: true`, and exactly `rfc3339`; omitting either cannot prove the seven-day boundary.

`queryNumericBounds`: caps query values such as `max_results`, `per_page`, `limit`, and `maxResults`.

`requestTimeWindow`: limits credential use by absolute RFC3339 bounds, UTC weekdays, and one or more UTC daily intervals. `timezone` must be `UTC`; daily interval ends are exclusive. Empty bounds, reversed absolute bounds, duplicate weekdays, malformed times, and overlapping intervals are rejected when the policy loads. Runtime parsing also fails closed.

`requestValue`: constrains one typed `pathParam`, `query`, `header`, `jsonBody`, `formBody`, or `operationField` source. The same rule shape is used by route constraints and `adapter.config.request.valueRules` on `generic.rest`, Gmail, X, and npm routes. The adapter must expose that source for the selected normalized operation, and every named value must occur exactly once. `jsonBody` and `formBody` sources must also be required and typed by the route's structural body constraint; provider adapters may expose only fields in their closed operation grammar. A rule selects exactly one predicate family through `predicate.kind`: exact string, string enum, bounded anchored pattern, UTF-8 byte-length range, or finite numeric range. Integer numeric rules accept only canonical signed 64-bit text. At most 16 rules and 32 enum values are allowed; string inputs are capped at 4096 bytes. Pattern rules use the shared non-backtracking bounded grammar and must declare `maxLength`.

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

Policy admission proves every `pathParam` appears in every route path template, every query/header name appears in the selected adapter operation's exact allowlist, and every body source is compatible with its closed media/body grammar. Header names must be lower-case. Optional `capture` names cannot collide with adapter operation fields; captures can key shared quotas, supply a weighted budget, bind JIT operation digests, and serve as response-binding sources (`exactString`, or `canonicalInteger` for integer predicates). Predicate failure, missing or repeated values, invalid runtime policy state, and duplicate HTTP request header fields deny before JIT lookup, quota reservation, credential lease release, or injection.

`jsonBody`: enforces JSON request body shape: allowed fields, required fields, denied fields, type checks, string length, numeric bounds, enums, exact values, and array size bounds. Structural allowlisting includes empty objects and arrays, including empty containers nested in arrays, so an unknown key cannot evade the allowlist merely because it has no scalar leaf. An explicitly allowlisted container remains valid and can be constrained with `type: "array"`, `minItems`, and `maxItems`.

`formBody`: applies the same allowlist, required/denied field, scalar duplicate, type, length, numeric, enum, exact-value, and safe-pattern rules to bounded `application/x-www-form-urlencoded` bodies. Bracketed keys such as `metadata[agent_request_id]` normalize to `metadata.agent_request_id`. Malformed UTF-8, malformed percent encoding, ambiguous duplicate scalar fields, and more than 256 pairs fail closed.

For a credential-bearing `generic.rest` route, the request and response profiles are both closed. The request must name a bounded normalized `operation`, enumerate allowed headers/query keys/media types, select a typed bounded body mode, and use structural constraints for every structured body. Buffered `bodyMode: "json"` requires a matching request-phase `jsonBody` constraint with a non-empty structural `allowedFields` list, and `bodyMode: "formUrlencoded"` requires the equivalent `formBody` constraint. Credential-bearing `bodyMode: "any"` is rejected because it would let provider-recognized fields bypass typed constraints.

The response must be bounded and structured, define a non-empty projection for every success/error profile, and have an applicable `responseEnvelope`; credential-bearing `mode: "any"` and opaque `mode: "stream"` are rejected. A credential-bearing generic adapter declares `credentialMode: "required"` and an exact `credentialBinding`. A route without `credentialRef` may use an opaque request or response only with `credentialMode: "none"` and a closed `noCredentialProof` asserting that the credential reference is absent, injection is disabled, and authorization/sensitive headers are not forwarded. The checked-in stream demo routes are examples of this explicit credentialless case. Adding a credential reference later makes those profiles invalid rather than silently upgrading them to credential-bearing proxies.

The JSON Schema, policy compiler, Python adapter, and Rust gate enforce these rules independently. Unknown sibling fields deny the request before credential lookup or injection; Serverware does not silently strip them after the request digest or JIT approval has been computed.

Rust request authorization is fully buffered. `bodyMode: "stream"` uses the signed bounded buffer and binds the exact released bytes; it is not request streaming. Structured request-stream modes that would transform bytes (`jsonlStream`, `jsonArrayStream`, `jsonSseStream`, `jsonNestedStream`, `formUrlencodedStream`, and `csvStream`) currently fail closed until their transformations can complete inside the signed `maxBodyBytes` bound before canonicalization. Ordinary proxy and intercepted CONNECT forwarding share the same exact-body digest check. Health reports therefore mark request-body streaming and combined request/response streaming-redaction capabilities unavailable; only independently implemented response-streaming modes are reported available.

`responseDateWindow`: validates JSON responses before release. It supports nested arrays through dot paths, so `data.created_at` checks every item in a `data` array.

`responseJson`: validates the semantic contract of a buffered JSON success response before release. It can apply to every normalized operation or only named operations, validate the root value or objects selected through explicit item paths, and apply the shared `fieldRule` assertions to every selected item. It validates data; it does not select or redact fields.

`responseBinding`: binds fields captured in the authorized request operation to fields in a buffered JSON success response. It rejects a missing or invalid request source before credential release and rejects a missing, ambiguous, mistyped, or mismatched response field before any upstream response bytes are released.

`responseEnvelope`: independently constrains the upstream success envelope. It requires bounded exact `statusCodes`, `bodyPresence` (`required` or `forbidden`), exact lower-case `contentTypes`, explicit `allowedResponseHeaderNames`, and explicit `responseHeaderRules`. The rule-name set must equal the allowed-header set exactly: every allowed header has one bounded value rule, while `required` controls presence only. Every present allowed or required physical header must occur exactly once. Missing required, duplicate, malformed, unruled, disallowed, or nonmatching headers produce a synthetic local `502` before body bytes are released.

`traversalBudget`: bounds a pagination or cursor chain across requests through one closed `traversal` object. `lineage.queryFields` must equal the complete operation-specific set of admitted mutable request-shaping query keys after removing only the exact query cursor; subsets, additions, and the cursor itself deny at admission and runtime. The chain remains bound to principal, route, credential, credential version, and query digest. Continuation cursors are single-use, so replay, cross-lineage use, forks, changed shaping inputs, lifetime/page/record/byte overflow, and ambiguous cursor evidence fail closed.

Traversal reservation and response accounting are one durable state machine. Request admission atomically reserves the next page and marks the supplied cursor in flight. A proven `not_forwarded` result rolls that reservation back. Once dispatch begins, an unknown result conservatively consumes the input cursor and ends the chain. A valid response atomically commits exact body bytes and record count, stores at most one next-cursor digest, and makes that cursor the only legal continuation. A response constraint failure commits the dispatched page conservatively but does not expose or authorize its cursor. Expired and completed chains reject continuations; state-store failure denies rather than falling back to process memory.

## Principal Selector Headers

`principals[].requiredHeaders` is a narrowing selector, never a trust root by itself. A principal using selector headers must also require one of:

- a non-empty canonical `sourceCidrs` set in which every network has a prefix longer than `/0`;
- a verified mTLS identity containing a SPIFFE ID, DNS SAN, URI SAN, certificate SHA-256 pin, or leaf SPKI SHA-256 pin; or
- nonlegacy object-form `proxyAuthorization` whose own canonical `sourceCidrs` set is non-empty and contains no universal network.

`0.0.0.0/0`, `::/0`, a mixture containing either universal network, a bare bearer token, and legacy string-form proxy authorization do not anchor trusted headers. Issuer SPKI evidence may narrow an already verified leaf identity but cannot establish one alone. Forwarded client-certificate headers are ordinary untrusted request fields and never become mTLS evidence; only private evidence populated by the trusted TLS ingress is accepted. Selector headers are removed after principal selection and cannot be forwarded to the provider or reused as adapter evidence.

## Generic Required Request Headers

`generic.rest` routes can require ordinary provider request headers through `adapter.config.request.requiredHeaders`. This is adapter policy, not a route-level `constraint` and not principal identity. A principal's top-level `principals[].requiredHeaders` participates in client authentication and must be visible during HTTPS `CONNECT`; an adapter-required header is checked only after principal and route matching, then forwarded to the upstream provider.

Each required adapter header must:

- use a lower-case HTTP field name and also appear in `request.allowedHeaders`;
- define `type: "string"`, `minLength`, and `maxLength`, with UTF-8 byte length bounded from 1 to 8192;
- optionally use the shared bounded anchored-pattern grammar, with the pattern capped at 256 characters and the header maximum capped at 4096 bytes when a pattern is present;
- avoid hop-by-hop, proxy, Host, Content-Length, Serverware service/identity, and credential-injection headers.

At most 16 headers can be required. Duplicate normalized allowlist names, unsupported rule fields, unsafe patterns, non-forwardable names, and credential-injection collisions reject policy activation. For every principal that can select the route, including every principal selected through `routes[].principals: ["*"]`, policy admission also rejects a provider `allowedHeaders` or `requiredHeaders` name that collides with any principal `requiredHeaders` selector after case folding and underscore-to-hyphen alias normalization. After principal capture, Python and Rust remove the selected principal's selector fields before provider admission, canonicalization, JIT, quota, credential injection, or forwarding; the authenticated principal remains local state. At request time, both runtimes return a local denial for a missing or invalid provider-required value before JIT consumption or credential injection.

The tokenized Stripe PaymentIntent template uses this contract for a provider-visible idempotency header and a Serverware-enforced replay barrier:

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

The agent must generate a policy-conforming `Idempotency-Key` for each intended PaymentIntent operation. Serverware validates and forwards it; Serverware does not synthesize the key or treat it as client identity. The example permits one use of that key per provider account in 86,400 seconds. A proven pre-dispatch cancellation refunds the reservation, but any dispatched or indeterminate attempt consumes it, so this policy is a strict replay barrier rather than transparent Stripe-style retry support.

The example accepts a finite PaymentIntent state-machine contract, including nonterminal states such as `requires_action`, but it does not expose `client_secret` or next-action payloads and cannot complete customer authentication. The agent must not automatically retry a dispatched or uncertain operation through this route; it must stop on a nonterminal or uncertain result and hand the available PaymentIntent identity/status to an operator-owned checkout/SCA workflow. Supporting bounded retries only when both the key and canonical request digest are identical requires a dedicated typed idempotency primitive. The route accepts only pre-tokenized `pm_...` identifiers and rejects raw card/source fields; this is neither tokenization nor PCI certification or live Stripe validation.

## Provider Request Profiles

`routes[].adapter.type` is a discriminator, not an advisory label. The bundle schema conditionally applies exactly one closed adapter schema for `generic.rest`, `gmail.v1`, `x.v2`, or `npm.registry`; an unknown type, missing config, config from another adapter, or unknown config field rejects the whole bundle before semantic admission.

Every `gmail.v1`, `x.v2`, and `npm.registry` adapter has one mandatory closed request object:

```json
{
  "request": {
    "allowedHeaders": [],
    "discardHeaders": [],
    "allowedQueryKeys": [],
    "allowedMediaTypes": [],
    "maxBodyBytes": 0
  }
}
```

The four legacy fields remain required and no unknown sibling fields are accepted. In the post-feature schema, `discardHeaders` is optional only as a compatibility alias for an empty list: omission may normalize only to empty. Admission compares the forwarded header, query, media, and body rules against the provider and operation preset, rejects duplicates and non-lower-case header/media names, and requires the exact body limit. A provider-required non-empty discard must be declared explicitly; the npm schema requires `npm-session`. Additional discard names are permitted only when they pass the global disjointness and reserved-name rules. `discardHeaders` is ordered lexicographically because its exact declaration is part of the canonical authorization contract. The portal should render provider-required entries as immutable and expose any additional safe entries as an advanced policy control.

- Gmail read: seven request headers (`accept`, `accept-encoding`, `content-type`, `user-agent`, and the three supported `x-goog-*` headers), the exact 12 Gmail query keys shown in the checked-in example, no request media types, and zero body bytes.
- X recent search: four standard request headers, the exact 16-key profile for `GET /2/tweets/search/recent`, no request media types, and zero body bytes. `next_token` is the sole continuation field; `pagination_token` is deliberately excluded so traversal accounting cannot be bypassed through an alternate cursor name.
- X bounded read: the same headers, the frozen 55-key union from the current non-streaming GET/OpenAPI catalog, no request media types, and zero body bytes.
- X post: the same headers, no query keys, only `application/json`, and at most 65,536 body bytes. The separate X adapter invariant limits this preset to `POST /2/tweets`.
- npm registry writes: the standard/npm client headers shown in the checked-in example, `npm-session` as the sole discarded header, no query keys, only `application/json`, and at most 16,777,216 body bytes.

OAuth-backed provider profiles declare a closed `credentialBinding` with `credentialType: "oauth2"`, provider, `subjects`, `clientIds`, and `requiredScopes`. X additionally requires `appIds` to equal `credentialBinding.clientIds` byte for byte. These are not display metadata. Admission requires a policy credential with `credentialType: "oauth2"`, the exact provider, a callback-verified `providerSubject`, an `oauthClientId` in `clientIds`, and a stored granted-scope superset. Runtime release revalidates the stored OAuth metadata against the same declaration and the adapter's operation-to-scope table. An app/account/scope mismatch, a static bearer secret masquerading as OAuth, or an operation whose required scope is absent denies before credential release. Gmail and X examples use separate OAuth credentials; static API keys, Basic credentials, cookies, and opaque service tokens remain valid only on routes whose `credentialBinding` declares the matching static provider, subject, and secret class.

The credential lease carries only the non-secret metadata needed to repeat that decision in the data plane: canonical provider aliases, provider/account subject aliases, OAuth client-ID aliases, granted scopes, managed/verified identity flags, and static secret-class aliases. The allowlist deliberately excludes access tokens, refresh tokens, client secrets, passwords, cookies, authorization values, and arbitrary metadata. Static credentials therefore require operator-declared `provider_subject` and `secret_class` values at creation; OAuth records get their subject and client binding only from the verified callback. Missing, contradictory, placeholder, or route-incompatible bindings deny candidate creation or credential release before upstream contact.

The X query catalogs are frozen from the official `https://api.twitter.com/2/openapi.json` document. A provider expansion is denied until the constants, examples, schemas, both runtimes, and tests are deliberately updated.

Python strips identity selectors after principal establishment, applies parser-free body, framing, encoding, and media preflight, and then applies the provider request profile after discard and deterministic adapter rewrite, establishing the exact provider-visible request and operation before credential-version lookup. Generic policy admission rejects `content-encoding` as a forwarded agent header; runtime admission allows only absent or exact identity encoding, enforces every raw-byte limit first, requires decoded access to preserve the raw buffer exactly, and removes the verified identity marker before canonicalization. Python then binds the credential version and already-validated request into the canonical request before JIT/grant handling, quota reservation, secret loading, injection, or upstream contact, and compares the final pre-send request back to that canonical material after excluding only the declared credential injection. Rust performs duplicate, discard-policy, identity-selector, credential-body-policy, and provider-profile admission, applies and revalidates deterministic query rewrites, and canonicalizes the resulting provider query before reservation, DNS resolution, or pinned-client cache access. The legacy shared-JIT compatibility lane uses the rewritten `provider_url` for both availability lookup and final consumption, so a rewrite cannot preview one URL and consume authority for another. Immediately after credential injection, every Rust forwarding path revalidates the active policy, route, principal, credential definition and version, canonical digests, lease scope, and exact injection envelope. Header, bearer, basic, and cookie injection must leave the canonical provider URL unchanged; query injection must yield exactly the canonical pre-credential query followed by one declared pair whose value is the lease-derived secret, with no substituted plan, existing key, duplicate pair, alternate serialization, or extra query. Caller-controlled unknown headers and query keys, ambiguous or invalid `Content-Type`, indeterminate or inconsistent body framing, unsupported content encoding, forbidden bodies, media mismatches, and oversized bodies fail locally. Hop-by-hop headers, `host`, `content-length`, `content-encoding`, proxy authentication, principal selectors, and Serverware service/internal headers are transport or local-auth data: they are stripped, validated, or regenerated by the forwarding pipeline and are not provider allowlist entries. `accept`, `accept-encoding`, `content-type`, `user-agent`, provider-specific headers, and all query keys remain caller policy data.

### Canonical Query Wire

After deterministic rewrite, the Python proxy parses the query with strict percent-escape and UTF-8 handling, rejects duplicate decoded keys, sorts the decoded key/value pairs lexicographically, and serializes them exactly once. The only admitted Python wire form is UTF-8 with RFC 3986 unreserved characters left literal, every other octet percent-encoded with upper-case hexadecimal, spaces encoded as `%20` rather than `+`, and an explicit `=` for every value, including an empty value. The Python request URL is replaced with that serialization before route rematch, request/profile validation, operation classification, constraints, canonical digests, JIT, quota, or atomic reserve. Rust separately reconstructs its deterministic rewritten `provider_url` before the same authorization work and requires the final forwarding consumer to reconstruct that identical URL.

Canonical request v1 and v2 retain their existing sorted `request.query` pair-list field. In Python that is not a lossy decoded summary: the field has one defined serializer, so its digest commits to exactly one provider-visible query octet string without changing either wire shape. Final Python binding reconstructs that exact string from the canonical pair list and requires the provider-bound URL to match byte for byte after accounting only for the policy-declared credential query injection; the injected pair must occur exactly once and its value must equal the credential value loaded for this authorization. Alternate ordering, `+` for space, lower-case or unnecessary percent escapes, malformed escapes, invalid UTF-8, and duplicate decoded keys cannot create a second Python-authorized representation: input is normalized before commitment where safe, otherwise rejected, and any post-commit representation change fails closed before upstream contact.

`discardHeaders` is for bounded SDK metadata that is accepted only so Serverware can remove it. A non-empty declaration selects canonical request v2 and is signed into the request and operation commitments, but each matching field and value is deleted before provider admission, credential/JIT/quota work, audit commitments, request rewriting, injection, and forwarding. The deterministic rewrite is then revalidated and its complete provider-visible result is what v2 binds. Canonical request v1 is the exact legacy wire shape without `discard_headers` and is valid only for a route whose effective discard list is empty. Canonical wire versions are independent of policy-schema compatibility: a pre-feature gate requires the `discardHeaders` policy property to be omitted entirely, not explicitly set to `[]`; both explicit empty and npm's non-empty declaration are post-upgrade policy syntax. Empty-discard routes may use a staged rollout: deploy dual-version control-plane support, then upgrade every compiler and gate while those policies still omit the property, and only then activate explicit empty declarations. npm has no mixed-fleet bridge because upgraded admission requires explicit `["npm-session"]` while a pre-feature gate rejects the property. Before upgrading an active npm route, stop new traffic, drain in-flight requests, pending approvals, one-use grants, and release reservations, disable the route, upgrade every compiler and gate as one coordinated cutover, activate the signed post-feature npm policy, and re-enable traffic only after every component reports that exact policy hash. Rollback likewise requires disabling and draining the route before restoring the complete pre-feature fleet and policy together. The checked-in demo policy contains post-feature declarations and must not be activated in a mixed pre-feature fleet. Mixed canonical shapes and route/version mismatches fail closed.

At most 16 lower-case canonical names are permitted. Discarded names cannot overlap allowed or required provider headers, principal identity headers, credential injection, authentication, cookies, framing, hop-by-hop, conditional, integrity, proxy, Serverware, or reserved provider fields. Python and Rust reject duplicate physical fields before canonicalization, revalidate the active policy, and verify that rewriting cannot reintroduce a discarded field. Audit events persist the closed declared-name/present-name/count record but no raw values or public hashes; without a dedicated audit HMAC key, hashing low-entropy discarded values would enable offline guessing. Every audit URL, for an unrouted denial, routed denial, approval transition, allowed request, or response event, is limited to scheme, authority, and path and omits all query names and values. A separately encrypted, access-controlled approval review may show a redacted query, but that display URL is never reused as an audit URL.

The npm preset's exact `npm-session` exception addresses ordinary npm CLI behavior: independent npm processes generate different session identifiers even when they issue the same package operation. Serverware drops that value, so a first process can receive `428`, an operator can approve the exact semantic operation, and a second ordinary process can consume the one-use grant. Package, version, tarball integrity, npm command, user agent, path, body digest, principal, policy, credential generation, request digest, and operation digest remain bound; the registry must never receive `npm-session`.

The exact npm `11.8.0` public-CLI lane and concurrent one-use contention lane are implemented in the current source, but the current source tree is unbuilt and unexecuted. Those source-only lanes do not relax the mandatory coordinated disable, drain, whole-fleet compiler/gate cutover, exact-policy-hash activation, and equivalent rollback boundary described above.

For Gmail and X reads, `allowedMediaTypes: []` means that no request body is permitted. A bodyless request may still carry one syntactically valid `Content-Type` because common clients add it unconditionally; that compatibility exception never authorizes entity bytes. Duplicate or malformed values still fail closed.

## Common Patterns Already Modeled

[policies/credential-limits.examples.json](../policies/credential-limits.examples.json) is one coherent catalog. Each route intersects endpoint matching, principal selection, adapter admission, request constraints, quota/JIT state, credential injection, and response validation; none of the rows below is an independent advisory example.

| Common policy | Enforced constructs in the example | Important boundary |
| --- | --- | --- |
| Gmail mail from the last 30 days | `gmail.v1` forces the request cutoff, caps `maxResults`, hydrates list results for `internalDate` proof, validates direct message-detail reads against prior validated list evidence, checks response age, and bounds each cursor lineage to three pages, five minutes, 30 records, and 3 MiB. | Query rewriting alone is not the response proof. Equivalent endpoints such as threads, history, attachments, and IMAP remain denied. |
| X read-only | `GET /2/**`, `mode: "readOnly"`, `blockWrites: true`, and `operationPolicy` admit only adapter-classified `tweets.read` and `users.read`. The separate recent-search route requires matching seven-day request and response proofs plus traversal limits. | The broad route does not admit search, bookmarks, DMs, streams, unknown operations, or any write merely because the HTTP method is `GET`. |
| X one post per day | Only `POST /2/tweets` and `tweets.write` are admitted; the JSON body is allowlisted and bounded; `rateLimit` permits one operation per callback-verified provider account per UTC day. | This is a UTC calendar limit, not a rolling 24-hour interval, and the example does not authorize other X write families. |
| npm write with approval on every use | `npm.registry` classifies a closed set of publish, unpublish, dist-tag, token-revocation, and metadata/access writes. `jit.mode: "perOperation"`, `maxUses: 1`, `consumeOn: "forwardStart"`, an operation digest, required user verification, YubiKey/hardware classes, and hardware attestation bind one approval to one forward attempt. | npm prerequisite reads need separate routes. Token creation is denied. Source support for the hardware-only denial path is not evidence that a physical YubiKey ceremony has succeeded. |
| Host, path, method, source IP, header, and mTLS restrictions | Every route has an exact host/port/method/path family; `resolvedCidrs` can constrain destination resolution; principals use canonical `sourceCidrs`, selector `requiredHeaders`, and verified private mTLS evidence; generic routes can require bounded provider-visible headers. | A selector header is not a trust root. mTLS depends on trusted-ingress evidence, and the legacy mitmproxy ingress does not currently populate it. |
| Request and response fields | `requestValue`, `jsonBody`, and `formBody` constrain admitted request values and structure. `responseJson`, `responseDateWindow`, `responseBinding`, `responseEnvelope`, and adapter projection validate and limit the response before release. | `responseJson` validates fields but does not redact siblings; projection belongs to the adapter response profile. Generic nested request capture and polymorphic response unions are unsupported. |
| Monetary, rate, data-volume, and time-window limits | The Stripe PaymentIntent route caps each integer amount, five operations per UTC day, and 100,000 cents per trailing day. Slack demonstrates a true sliding count and UTC weekday/hour gate. Gmail and X traversal budgets cap cumulative validated response bytes as well as pages, records, and lifetime. | `maxBodyBytes` is a per-request bound, not a cumulative budget. Cumulative arbitrary upload/download bytes outside a modeled traversal, floating-point money, exchange-rate conversion, and provider-reported post hoc cost are unsupported. |
| Generic REST credential injection | Separate routes demonstrate bearer, Basic, custom-header, query, and cookie injection with exact credential metadata and closed request/response profiles. | Body injection, multi-fragment credentials, request-dependent signing such as AWS SigV4, client TLS private-key use, and arbitrary templates or scripts are unsupported. |

Additional generic REST routes demonstrate bounded Slack posts, GitHub reads and hardware-approved issue creation, Stripe customer access and tokenized PaymentIntent creation, mTLS-only object-store writes, Google Calendar reads, bounded OpenAI Responses calls, hardware-approved Cloudflare DNS updates, and hardware-approved Twilio SMS. These are structural policy examples, not claims of live-provider compatibility or validation.

The Calendar route proves that the outbound request asks for a bounded recent window, but generic REST cannot validate Calendar's polymorphic `start.date`/`start.dateTime` union against that request. A provider needing that guarantee, provider-side cost reconciliation, nested request-field capture, multipart/XML parsing, or another semantic outside the closed grammar remains denied until a typed adapter and matching Python/Rust enforcement are added.

## npm Wire Contracts

The `npm.registry` adapter uses a closed method, path, and body grammar in both Python and Rust. Unknown or adjacent shapes fail before credential-generation lookup, JIT, quota, release authorization, or upstream contact. The common route models five policy operations:

- `npm.publish`: package-document `PUT` with a canonical attachment and Serverware-derived SHA-512 SRI.
- `npm.unpublish`: revision-bound `PUT /{package}/-rev/{revision}` with matching path/body revision, package identity, a nonempty remaining version map, consistent dist-tags, and no attachment or revision-history payload. Legacy bodyless `DELETE` remains a separately classified admitted form when policy allows it.
- `npm.distTagWrite`: `PUT` accepts the real npm JSON-string version body; `DELETE` must be bodyless.
- `npm.tokenWrite`: only bounded token revocation at `DELETE /-/npm/v1/tokens/token/{token}` is admitted. `POST /-/npm/v1/tokens` is classified as token creation and always fails with `npm_token_creation_denied`; releasing a newly minted token to the requesting agent would violate credential custody.
- `npm.metadataWrite`: bounded package access, profile/team operations, and packument deprecation updates. Team-access deletion accepts only `{"package":"@scope/package"}` matching the path scope. A deprecation packument must bind package/version identity, contain at least one bounded string `deprecated` field, keep every dist-tag pointed at a retained version, and carry no attachment data.

All admitted operations bind the exact request and normalized operation fields into one-use JIT authority. The policy can therefore require a hardware-attested reviewer for every write while preserving distinct review context such as package, version, revision, tag, scope, team, and request-body digest.

Two limits are deliberate. First, npm CLI prerequisite reads such as packument, dist-tag, and token-list fetches need separately configured bounded read routes; the write route does not become a general registry proxy. Second, unpublish and deprecation send a complete replacement packument. Serverware validates the final document and binds its exact bytes to approval, but without a trusted pre-write fetch and comparison it cannot prove that the only delta was one removed version or one deprecation field. Operators should review that full operation digest and use a compatible registry with revision conflict checks; a future stronger profile should perform an authenticated pre-read and exact delta comparison. Package-access, profile, and team `PUT` field semantics also remain operation/body-digest bound unless a narrower typed route is configured.

## X Endpoint Catalog

The X adapter classifies exact path templates from the current [X OpenAPI description](https://docs.x.com/openapi.json). Read operations are grouped into explicit policy names including `tweets.read`, `users.read`, `search.read`, `connections.read`, `directMessages.read`, `bookmarks.read`, `lists.read`, `spaces.read`, `analytics.read`, and the other cataloged families in the adapter schema. A new or changed X endpoint is denied until Serverware's Python classifier, Rust classifier, schema, and tests all recognize it.

`example.x.full_bounded_read` uses `/2/**` as a broad path matcher but admits only the adapter-classified `tweets.read` and `users.read` operations, subject to the OAuth app, callback-verified account, and scopes bound to that credential. Bookmarks, direct messages, and every other read family remain denied by its operation allowlist. Search endpoints match the route path but fail operation admission there, so the same principal and credential can reach search only through `example.x.search.seven_days`. Policy admission rejects a future overlapping route that restores an unconstrained search operation.

Streaming reads are intentionally excluded from that profile because a live stream cannot receive whole-response validation or a final response-proof artifact. An opaque X stream would be credential-bearing and is therefore rejected; supporting it requires a structured, incrementally redacting adapter mode rather than `mode: "stream"`. Controlled writes are separate: the current audited write surface accepts only `POST /2/tweets`, requires `tweets.write`, an explicit JSON body allowlist, and a bounded non-stream response. Delete, follow, direct-message, like, retweet, media-upload, and unknown writes fail closed.

## Composing New Limits

Constraints compose as an intersection: a request must satisfy the principal, endpoint, OAuth/app/account/scope binding where present, adapter, every request constraint, every durable count/weight/traversal reservation, any JIT grant, and every response constraint. This supports rules such as "one post per verified provider account per UTC calendar day, resetting at 00:00 UTC, only on weekdays, with a 280-character body" without provider-specific scripting. Use `rateLimit` plus `windowSemantics: "fixedFromFirstUse"` for a first-use-anchored bucket, `slidingWindowLimit` for a true trailing count, `weightedBudget` for a true trailing sum, and `rateLimit` plus `windowSemantics: "calendarUTC"` for a UTC boundary. These models are intentionally not aliases.

Shared quotas and JIT are enforced as one release decision, not as sequential best-effort counters. The canonical request and operation digests are mandatory reserve inputs whether `jit.required` is true or false; omitting, malforming, or substituting either digest or the canonical request denies before quota state or provider contact, and only the exact binding can reserve and authorize dispatch. For example, a one-tweet-per-UTC-calendar-day route cannot consume the daily slot while discovering that its approval is missing, and a failed pre-dispatch audit cannot permanently burn either control. Calendar quota denial reports the next UTC boundary and a retry interval to that boundary; the daily reset is 00:00 UTC. Approval polling remains independently bounded to one hour.

Uniqueness is a bounded composition, not a separate scripting language. Capture one compiler-proven scalar with `requestValue`, then include that capture in `rateLimit.key.operationFields` with `max: 1`. Always pair an agent-selectable uniqueness key with a coarser provider-account or principal/credential/route quota that bounds how many distinct keys can create durable rows. The PaymentIntent example does this with a provider-account-bound one-use-per-key 86,400-second bucket and an independent five-per-provider-account UTC-day bucket. This is strict uniqueness: after dispatch it denies even an identical retry. Do not put an object ID, repository, recipient, or idempotency value into the only quota key unless policy intentionally grants a fresh allowance for every value.

JIT is likewise closed and bounded. `mode` is `perOperation`, TTL is 1-3,600 seconds, `maxUses` is 1-64, and consumption occurs at `forwardStart`. The binding includes the principal, route, credential and version, policy hash, method, authority, path, canonical query, selected headers, and body digest; operation-specific fields can narrow it further. Hardware attestation implies WebAuthn, required user verification, and only the `yubikey` or `hardware` authenticator classes. An npm, GitHub, Cloudflare, or Twilio example therefore cannot silently fall back to a platform passkey, password, development authenticator, or approval detached from the exact request.

Policy files are data, not executable code. Unknown constraint types, fields, adapter operations, and extension semantics are rejected instead of ignored. A limitation that cannot be expressed by the typed constraints requires an audited adapter or constraint implementation in both enforcement runtimes, schema admission rules, and parity tests before it can be enabled. This preserves customization without allowing policy text to become an arbitrary-code escape hatch.

## Static Credential Injection

The v1 credential envelope has five static injection modes. Each mode is a closed object; fields from another mode reject the bundle.

| Mode | Provider-visible value | Mandatory policy data | Runtime boundary |
| --- | --- | --- | --- |
| `bearer` | One header, normally `Authorization: Bearer <secret>` | Optional safe header, dotted secret `field`, and prefix | Managed OAuth is fixed to `Authorization`, `Bearer `, and `access_token`; static tokens may use another nonreserved header/prefix. |
| `basic` | `Authorization: Basic base64(username:password)` or another safe header | Explicit bounded `username`; optional dotted password `field` | The password is exactly the selected secret string. Runtime code does not infer a username or reinterpret the selected value as another credential object. |
| `header` | One named custom header with optional prefix | Explicit nonreserved `name`; optional `field` and prefix | `Authorization`, cookie, proxy, framing, hop-by-hop, and Serverware headers are forbidden. |
| `query` | One canonical percent-encoded query pair | Explicit key `name`; optional `field` | An existing key, duplicate key, alternate query serialization, control character, or oversized value denies. |
| `cookie` | One `Cookie` pair | Explicit cookie `name`; optional `field` | Agent-supplied `Cookie` collides and denies; the secret must be a nonempty canonical ASCII cookie-octet value. |

All selected secret components are nonempty strings capped at 16,384 UTF-8 bytes and reject C0/DEL controls in the Python parity path. Header values additionally reject outer whitespace; prefixes reject the same controls. Injection happens only after request admission and release authorization, and final pre-send verification permits exactly the declared credential delta. The final response reflection guard scans the raw selected secret and common header, Basic, cookie, URL, JSON, Base64, Base64url, and SHA-256 representations after projection.

A dotted `field` selects one exact object path from an encrypted JSON credential. Wildcards, arrays, missing components, scalar coercion, empty strings, and non-string leaves deny. Omitting `field` means the entire stored secret is the one credential component; it does not enable templates or multi-value expansion.

Body-field credentials, multiple coordinated credential fragments, AWS SigV4 and other request-dependent MAC/signature protocols, OAuth client assertions, HTTP Message Signatures, client TLS private keys, SSH keys, database handshakes, multipart credentials, and provider-specific canonicalization are not static injection modes. Modeling any of them as a header prefix or generic body rewrite would sign or authorize the wrong request. They require a typed adapter or transport implementation that owns canonicalization, key use, nonce/time semantics, post-injection digest verification, response handling, schema admission, and Python/Rust parity. Until that implementation exists, the route is denied.

The schema and Python parity path include the stricter prefix, target, size, cookie-octet, and Basic-selection rules in this source pass. Production activation still requires the Rust gate to mirror those exact value-level checks and error classes; schema admission alone cannot validate encrypted secret bytes. This source batch has not been built or executed.

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

An OAuth policy credential is typed independently from its encrypted token response:

```json
{
  "id": "cred-x",
  "credentialType": "oauth2",
  "provider": "x",
  "providerSubject": "verified-provider-account-id",
  "oauthClientId": "approved-x-app-id",
  "scopes": ["tweet.read", "users.read"],
  "injection": {
    "type": "bearer",
    "header": "Authorization",
    "field": "access_token"
  }
}
```

Provider routes then declare singleton `credentialBinding.subjects` and `credentialBinding.clientIds` arrays plus `credentialBinding.requiredScopes`; X also declares the identical singleton `appIds` array. Schema and semantic admission require the sole subject and client to equal the referenced credential declaration, require the adapter provider to match, and require every admitted operation to have a known required-scope mapping. Credential release proves the encrypted credential is a managed OAuth record whose callback-verified provider, subject, client ID, and complete granted-scope set exactly equal the signed credential declaration. The token response's self-reported `scope` string is not accepted as the only evidence. Account aliases, email addresses, display names, mutable usernames, bearer-token parsing, and agent-supplied headers cannot establish provider subject or app identity.

OAuth bindings are strict intersections. The stored granted-scope set must exactly equal the signed credential declaration; a route may name only the required subset for its admitted operations, and any missing route scope denies. Undeclared extra stored scopes, extra route subjects, and extra route clients deny. Changing app, account, granted scope, credential kind, or provider requires a new credential version and policy generation. Non-OAuth credentials omit the OAuth fields and remain usable with bearer, Basic, header, query, or cookie injection only on routes whose adapter does not require OAuth evidence.

Credential `field` selectors are strict dotted object paths such as `access_token` or `nested.token`. Wildcards, array fan-out, empty path components, and non-string selected values fail closed before forwarding the request. The agent never receives the OAuth token JSON or the refresh token.

## Credential Lease Semantics

The Rust gate reports `scoped-recipient-bound-pull/v2`. Each pull names exactly one `(principal, route, credential)` scope and is bound to the active policy hash, measured gate binary digest, recipient key, one-use nonce, and short expiry. The attested control-plane capability separately identifies the exact dispatch wire tuple. Controlled dispatch uses `serverware.credentialLeaseRequest/v4`, `serverware.credentialLeaseRequestAuthority/v1`, `serverware.credentialLeaseEnvelope/v3`, and `serverware.credentialLeaseSet/v4`, including the `decisionBound` issuance kind. Authority-free Request v3, Envelope v2, and Set v3 remain compatible only for uncontrolled dispatch. A response containing an unexpected protocol version, authority, credential, scope, version, field, or duplicated binding is rejected.

Leases are cached only in zeroizing process memory. Cache and renewal work are bounded. A warm lease is renewed in the background before its five-second maximum expiry; a cold or expired lease may require a synchronous broker pull, so background renewal is an availability optimization rather than a security assumption. Lower credential versions and same-version secret or metadata changes are rejected. A higher version atomically replaces the old lease, and a stale request cannot remove that newer entry. Policy activation clears incompatible leases, and the gate rechecks lease currency immediately before the upstream send.

## Policy Rollback Protection

The control plane persists the accepted policy ID, sequence, `rollbackEpoch`, hash, and update time in its metadata store. Every production writer flocks the same shared policy-volume directory inode beneath root-owned, non-group/world-writable ancestry. Publication and activation bind the full candidate, predecessor, and signed-bundle digests under that lock. Pending and committed publication are distinct. A lost database commit acknowledgement remains ambiguous until recovery re-reads the authoritative committed winner; it is not guessed to be either rollback or success. The Rust gate independently persists its policy high-water record when a high-water path is configured. Startup and reload reject a policy ID change, a decreased rollback epoch, a changed policy whose sequence does not increase, or the reuse of a known hash with different monotonic metadata. Attestation binds the active policy and the control-plane high-water digest.

This prevents an ordinary restart or stale signed bundle from silently re-enabling older access. Production durability still depends on protecting the fixed lock namespace and retaining both persistent high-water/store histories. Replacing that namespace or restoring the database, publication state, and data-plane high-water together is an external rollback problem that deployment attestation and storage controls must address.

### Candidate Policy Safety

A control-plane dry run is advisory and cannot authorize activation. Production
candidate evaluation must use the same pure Rust policy core and the same
immutable ingress facts as the active decision while receiving no credential,
JIT, quota, cache, provider, filesystem, network, RNG, clock, or audit
capability. Candidate results are closed as deny, permit, conditional intent,
or indeterminate; conditional intents are compared but never executed.

Every assigned gate produces a TEE-bound load receipt and contiguous signed
checkpoints over complete integer-only decision, comparability, latency, error,
and drop counters. Missing fleet members, sequence gaps, restarts, active-policy
drift, drops, errors, indeterminate outcomes, incomplete response
comparability, or an active-deny/candidate-permit expansion leave the candidate
non-ready. Expansion requires a separately authenticated approval and pilot.
Activation binds one sealed short-lived readiness root into fresh WebAuthn and
any required two-person approval, then atomically advances the exact predecessor
and policy high-water record. Candidate-generation and shadow-evaluation
components now exist in source, but the signed producer/reducer, independently
trusted custody and generation chain, and atomic authority transaction are still
being integrated. Production activation therefore remains unavailable and must
fail closed until that complete path is integrated and validated. This
source-only policy pass does not claim activation works.

## Production Store Semantics

`rateLimit.store`, `slidingWindowLimit.store`, `weightedBudget.store`, and `traversalBudget.traversal.store` are enforced. `local` counters are process-local and exist only for eligible development fixed-window throttles. Shared fixed/calendar count and JIT state is reserved by the release authority. Sliding count, weighted, and traversal state is reserved by the policy-state bundle store. Each store binds the same attempt, active policy hash, request digest, and operation digest; the bundle additionally binds the canonical complete claim-set digest. Every bundle phase locks all affected budget, chain, and cursor resources in sorted order and applies all child transitions in one transaction. A second replica sees the reservation immediately. If shared state is requested but unavailable, credential release fails closed; it never silently falls back to a local counter.

The phases are intentionally separate:

1. Schema validation checks closed field shapes and bounded declarations.
2. Semantic admission proves adapter support, route overlap safety, typed request/response sources, OAuth bindings, nonvacuous response proofs, and state-model compatibility.
3. Release reservation atomically claims shared fixed/calendar count and JIT authority; policy-state reservation atomically claims every sliding count, weight, and cursor for the same exact request before secret release.
4. A proven pre-dispatch failure aborts the entire policy-state bundle. Dispatch changes every bundle child or none and makes count/weight conservative.
5. An indeterminate post-dispatch terminal operation charges count/weight and poisons every traversal claim with exact claim-specific evidence.
6. Successful response completion is unavailable until envelope, semantic, adapter, finalizer, and reflection checks pass; it then atomically commits traversal records, bytes, and at most one next cursor. A denied completion returns no partial success.

Preview decisions do not mutate this state. Reservation, dispatch, abort, indeterminate terminalization, successful completion, retry, and recovery are idempotent by durable attempt identity and exact evidence digests. Raw cursors are not stored; only SHA-256 cursor commitments are retained.

## Response Validation

Request constraints are not enough. Many APIs can accept a bounded query and still return old or over-broad data through bugs, aliases, pagination cursors, or endpoint drift. Response constraints are therefore first-class. Gmail and X examples validate response age, and generic REST examples can validate timestamps such as `updated_at` or `created`.

### Response envelopes

`responseEnvelope` is independent from request-to-response binding:

```json
{
  "id": "bounded-success-envelope",
  "type": "responseEnvelope",
  "phase": "response",
  "operations": ["widgets.read"],
  "statusCodes": [200],
  "bodyPresence": "required",
  "contentTypes": ["application/json"],
  "allowedResponseHeaderNames": ["cache-control", "content-language"],
  "responseHeaderRules": [
    {
      "name": "content-language",
      "required": true,
      "predicate": {
        "kind": "pattern",
        "pattern": "^[a-z]{2,3}$",
        "maxLength": 3
      }
    },
    {
      "name": "cache-control",
      "required": false,
      "predicate": {
        "kind": "enum",
        "values": ["no-cache", "no-store"]
      }
    }
  ]
}
```

The lists are bounded, non-empty where proof is required, unique, and canonical. Content types are exact lower-case media types without whitespace or parameters unless a future typed media rule explicitly admits them. Header rules contain data-only predicates, never regular-expression engines with backtracking, templates, callbacks, or code. An envelope with no statuses, no content types, an empty rule, an unruled required header, duplicate names, or an unsupported predicate is rejected at policy activation.

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
    "score": {"required": true, "type": "number", "min": 0, "max": 1},
    "tags": {"required": true, "type": "array", "maxItems": 3}
  }
}
```

`phase` is required and must be `response`. `operations` is optional; when present, the constraint runs only for those normalized adapter operations. A matching response without operation context fails closed, while a known non-matching operation skips the constraint.

`items` is an optional, non-empty list of unique explicit dotted paths. Wildcards and empty path segments are not allowed. Without `items`, the response root is validated as one item. With `items`, each resolved array is expanded and every element is validated; a resolved non-array value is validated as one item. The constraint-level `required` controls whether at least one configured item path must exist and defaults to `true`. `required: false` permits all item paths to be absent. A present empty array proves that the item path exists and contains no elements to validate.

`fields` is required and must be a non-empty map of dotted paths, relative to each selected item, to non-empty `fieldRule` objects. Arrays encountered while resolving a field path fan out, and every resolved value must pass. A field rule supports:

- `required`: must be exactly `true`; every proof field is present on every selected item.
- `type`: `string`, `number`, `integer`, `boolean`, `object`, `array`, or `null`. Booleans are not numbers.
- `enum` or `equals`: constrain the exact JSON value.
- `minLength`, `maxLength`, and a bounded safe `pattern`: constrain strings. Patterns use only the anchored form `^<literal-prefix>[<ASCII class>]{min,max}$`; `max` cannot exceed 4096 and a pattern requires `maxLength`.
- `min` and `max`: constrain finite numeric values.
- `minItems` and `maxItems`: constrain arrays.

Every response proof field is explicitly typed, required, and bounded. A string needs `equals`, `enum`, or `maxLength`; a number needs `equals`, `enum`, or both `min` and `max`; an array needs `equals`, `enum`, or `maxItems`; booleans and null require `equals` or `enum`. Type-specific rules require an explicit compatible `type` at policy admission. Python, Rust, and JSON Schema reject optional, unbounded, incompatible, or untyped response assertions instead of conditionally ignoring them at runtime.

An absent configured field always fails. `responseJson` does not reject unmentioned siblings, remove fields, or define the release shape. Those are redaction responsibilities of the adapter response profile. The constraint-level `required` controls only whether a configured `items` path may be absent; it does not make fields inside a present selected item optional.

Both the Python policy engine and production Rust gate evaluate `responseJson` against the bounded, parsed upstream success body before applying `allowedFields`. This ordering lets a contract validate a provider field even when that field is not released. API-specific projection then runs, `responseDateWindow` evaluates the canonicalized response where required, structural projection removes unlisted fields, response headers are normalized, and the final credential-reflection guard scans the projected output.

Policy admission rejects `responseJson` with the wrong phase, missing or empty `fields`, invalid or duplicate operation/item paths, wildcard paths, empty or unsupported field rules, unsafe patterns, type-incompatible rules, or inconsistent bounds. `responseDateWindow` likewise requires at least one explicit date field, one supported format, and a positive bounded age; an empty date proof is invalid. Every response binding/envelope content-type set is non-empty, unique, bounded to 1-4 exact lower-case media types, and checked before body release. Whole-body response constraints cannot be combined with a streaming response mode. At runtime, invalid JSON, missing operation context, absent required items or fields, and any type/value/bound violation block the response with a synthetic `502`; errors use value-free local error families and no upstream body bytes are released.

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

`npm.registry` has a narrower adapter-specific source contract for `npm.publish`. It permits only captured `packageName`, `packageVersion`, or `tarballIntegrity` fields with `exactString` and rejects any other npm operation. When a signed compatible-registry route enables `npm.publish` response binding, admission requires a buffered JSON success profile capped at 65,536 bytes, status exactly `200` or `201`, content type exactly `application/json`, exact `packageName` and `packageVersion` bindings, and a `responseJson` rule scoped only to `npm.publish` that requires boolean `published` equal to `true`. Python and Rust reject any weaker combination. This mode is for compatible registries whose documented bounded JSON success response explicitly echoes package identity. The public `registry.npmjs.org` template instead requires `publishResponseContract: npm-public-registry-receipt-v1` because the [official npm client](https://github.com/npm/cli/blob/latest/workspaces/libnpmpublish/lib/publish.js) ignores the body for ordinary publishes. Its only successful envelope is `200` or `201` with a single valid `application/json` header and a strict object body; `{}` is valid, optional `ok` and `published` values must be boolean `true`, and projection releases only those booleans. Package/version claims are stripped, while the one-use hardware-approved request binds package, version, integrity, route, credential generation, and operation digest.

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
      "credentialMode": "required",
      "credentialBinding": {
        "credentialType": "static",
        "provider": "object-store",
        "subjects": ["object-store-service-account"],
        "secretClass": "customHeader"
      },
      "request": {
        "allowedHeaders": ["accept", "content-type", "user-agent"],
        "allowedQueryKeys": [],
        "allowedMediaTypes": ["application/json"],
        "bodyMode": "json",
        "maxBodyBytes": 65536,
        "allowedFields": ["content", "contentType"],
        "valueRules": [],
        "operation": {
          "name": "object_store.objects.put",
          "bodySha256Field": "requestBodySha256",
          "pathParams": ["artifact_id"]
        }
      },
      "response": {
        "mode": "json",
        "maxBodyBytes": 65536,
        "allowedFields": ["ok", "id", "sha256"],
        "allowedHeaders": [],
        "error": {
          "mode": "json",
          "maxBodyBytes": 65536,
          "allowedFields": ["error", "code", "message"],
          "allowedHeaders": [],
          "onInvalid": "block"
        }
      }
    }
  },
  "constraints": [
    {
      "id": "object-store-response-envelope",
      "type": "responseEnvelope",
      "phase": "response",
      "operations": ["object_store.objects.put"],
      "statusCodes": [200],
      "bodyPresence": "required",
      "contentTypes": ["application/json"],
      "allowedResponseHeaderNames": [],
      "responseHeaderRules": []
    },
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

The final credential-reflection guard runs after the adapter finalizer and its projection. It scans for the injected value and common JSON, URL, Base64, Base64url, and SHA-256 representations across output boundaries. Durable traversal completion occurs only after this guard passes. This is a defense in depth control, not general information-flow proof: an intentionally malicious provider could transform a secret into some other allowed semantic value. Narrow endpoint allowlists, structured projections, trusted upstreams, and provider-specific response validation remain required.

Successful buffered responses can carry the separate proxy response runtime proof described in [Security Review](security-review.md#response-and-attestation-proofs). Streaming responses have no final body digest or final proxy response-proof artifact.
