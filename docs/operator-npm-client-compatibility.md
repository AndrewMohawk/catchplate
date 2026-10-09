# Ordinary npm client compatibility

Status: **specification only; not implemented or verified end to end**. This
2026-10-09 source review did not execute npm, build the gate, start a fixture, or
contact a registry. Existing example/compiler tests are not an npm install or
publish acceptance result.

## User workflow and defaults

1. Save one npm registry credential in Serverware. For the public registry, use
   a granular access token, not the historical example's automation-token label.
   Do not claim the account or token permissions are provider-verified merely
   because a user supplied them.
2. Assign that credential to applications independently: **Install packages** or
   **Publish selected packages**. Select exact packages or explicit scopes;
   install permissions must account for dependency packages without granting
   permission to publish those dependencies.
3. Offer a time window and approval as separate optional restrictions. An
   example window is daily 09:00 inclusive to 17:00 exclusive UTC. A window
   authorizes requests; it does not queue or schedule a publication. Never infer
   weekdays, unpublish, tag management, token management, or account/team writes.
4. Generate ordinary npm configuration: the Serverware application identity and
   token authenticate the proxy; a registry-scoped dummy `_authToken` produces
   the exact upstream Authorization placeholder. The protected npm token stays
   server-side. No response fields, envelopes, or handwritten HTTP adapter are
   part of user setup.

The README's intended flow and the weekday policy differ deliberately. See
[README](../README.md#what-it-controls),
[requirements](operator-workspace-requirements.md), and
[the illustrative policy](../policies/npm-weekday-hours.example.json).
The latter includes broad writes and mandatory hardware approval; it is not a
publish-only preset.

Current [npm token documentation](https://docs.npmjs.com/about-access-tokens/)
states that legacy tokens were removed, describes stage-only tokens, and
announces removal of granular-token direct publication in January 2027. A
direct-publish implementation must state this provider boundary. Stage/promote,
trusted publishing, and interactive provider 2FA are separate workflows, not
capabilities conferred by Serverware's credential replacement or approval.

## Source-backed protocol gaps

| Area | Current source and required change |
| --- | --- |
| Catalog | `CredentialInput` and `create_credential` save generic bearer/header credentials with `provider_id=operator-demo`. `operator_catalog_policy.render` has a typed Gmail branch, not an npm branch. Add a reviewed npm credential/bundle contract; do not relabel a generic rule as npm support. |
| Reads | Rust `npm_operation` and Python `NpmRegistryAdapter` classify writes only. GET/HEAD are unclassified although the npm schema lists `read`. Add bounded package metadata and tarball operations with exact package/origin binding. |
| Request compatibility | `NPM_REGISTRY_REQUEST_HEADERS` and `provider_request_profile` fix the allowed headers, forbid query keys, and admit only JSON bodies up to 16 MiB. Stock pacote metadata requests add three `pacote-*` headers. Cache validators and any read queries need explicit typed treatment, not arbitrary header/query forwarding. |
| Responses | The npm schema allows projected JSON or `headersOnly`, not complete package metadata or tarball bytes. Add whole metadata and bounded binary response contracts. Preserve dynamic version/dependency/dist fields. Initial bounded buffering is a smaller claim than safe streaming. |
| Compression/metadata | npm normally advertises compression. The old profile forwards that offer but the gate rejects encoded responses; its exact response envelope also rejects unlisted metadata such as Date. Reuse reviewed scan-before-discard machinery only through an explicit new typed profile. Handle HTTP compression separately from the gzip bytes of a `.tgz` body. |
| Audit | Default install auditing performs a gzip JSON POST to `/-/npm/v1/security/advisories/bulk`. This operation is unclassified, and `read_request_head_from` invokes the identity-only content-encoding guard before adapter selection. A new adapter alone is insufficient: implement explicitly scoped ingress admission plus bounded compressed/decoded inspection. `--no-audit` is only a separately labelled restricted client profile. |
| Publish | Existing checks bind package, sole version and decoded tarball integrity, but require `dist-tags.latest` and exactly one attachment. Define supported tags and size limits; beta tags and provenance attachments are not automatically supported. The 16-MiB JSON request cap includes Base64 and metadata, so it is not a 16-MiB package allowance. |
| Approval | Legacy npm writes require one-use hardware-attested JIT. Operator mode forbids atomic release authority, while `validate_legacy_release_composition` rejects required JIT. Optional approval needs a separately reviewed operator authority integration; do not weaken legacy admission or advertise an ineffective switch. |

Exact implementation entry points:

- [Catalog DTOs](../serverware/operator_catalog_inputs.py),
  [creation](../serverware/operator_catalog_mutations.py),
  [emitter](../serverware/operator_catalog_policy.py).
- [npm schema](../schemas/adapters/npm.registry.schema.json),
  [Python request profiles](../serverware/policy_bundle.py),
  [Python adapter](../serverware/adapters.py).
- [Rust main](../data-plane/decision-gate-rs/src/main.rs):
  `provider_request_profile`, `validate_provider_request_profile_config`,
  `npm_operation`, `npm_operation_fields`,
  `read_request_head_from`, `validate_identity_request_content_encoding`,
  `validate_legacy_release_composition`, and the response-envelope checks.
- [Typed response pairing](../data-plane/decision-gate-rs/src/buffered_response.rs)
  and [operator runtime admission](../data-plane/decision-gate-rs/src/operator_demo.rs).

Upstream evidence: [registry-scoped npmrc authentication](https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/),
[proxy and CA settings](https://docs.npmjs.com/cli/v11/using-npm/config/),
[pacote's metadata headers](https://raw.githubusercontent.com/npm/cli/v11.8.0/node_modules/pacote/lib/registry.js),
[default compression offer](https://raw.githubusercontent.com/npm/cli/v11.8.0/node_modules/minipass-fetch/lib/request.js),
and [npm's compressed audit request](https://raw.githubusercontent.com/npm/cli/v11.8.0/workspaces/arborist/lib/audit-report.js).

## Minimal implementation slice

Use an additive versioned typed bundle; its final signed/API names require a
contract review before implementation. Leave `npm.registry` behavior unchanged.

- One stored credential may back multiple application grants. Define install
  and publish authority independently, including necessary prerequisite reads,
  and distinguish same-registry dependencies from unsupported Git/URL sources.
- Bind package names, encoded scoped paths, tarball URLs and publication bytes;
  never follow a packument URL or redirect to an unapproved origin. Preserve
  credential-reflection, framing, size, currentness and audit release guards.
- Internally choose the request/response profiles needed by the operation.
  Support ordinary client metadata and gzip audit behavior without global
  parser relaxation. Do not conceal an unsupported operation behind exit zero.
- Ship basic install/publish and time-window acceptance as one complete slice.
  Keep approval, staging, provenance and streaming visibly unavailable until
  each has its own complete authority/protocol verification.

## Bounded private acceptance plan

This is a future authorized run, not an executable runbook. Do not run the
current private ordinary-client checker against a retained/live catalog.

### Fixture and isolation

Adapt the one-shot claim, artifact pinning, catalog setup and audit patterns in
[prepare_operator_catalog_fixture.py](../scripts/prepare_operator_catalog_fixture.py),
[check_operator_catalog.py](../scripts/check_operator_catalog.py), and
[check_operator_ordinary_client.py](../scripts/check_operator_ordinary_client.py).
Their existing API is generic, not a proposed npm API: use the real new DTO
only after its implementation and review, and assert the emitted loaded policy.

[demo_upstream.py](../scripts/demo_upstream.py) currently has illustrative
`/npm/{package}` PUT/POST handlers, not a registry. A focused fixture must add
real package metadata, immutable version storage, scoped/unscoped tarballs,
integrity, publish receipt and audit responses, plus per-method/path counters
and private authorization-digest observations. Use two tiny inert packages,
one depending on the other; reject unexpected paths and operations. Proposed
fixture caps: 32 KiB compressed/128 KiB expanded per tarball, 64 KiB per metadata
document, 16 KiB per audit response, and 128 request observations. No install
scripts, outbound URLs, provider tokens or general registry emulator are needed.

The existing preparer does not create an HTTPS proxy edge or a Node client.
Those are explicit reviewed additions: stock npm must traverse the actual
proxy ingress implementation with verified proxy TLS and the scoped interception
CA, not a management listener or a hand-built CONNECT client. Use an isolated
internal network with no external egress, live mounts or host-published ports.

Pin an immutable source snapshot, gate binary, client and cached images. Existing
file metadata shows Node 24.12.0/npm 11.6.2 and Node 25.5.0/npm 11.8.0; the latter
contains pacote 21.0.4 and npm-registry-fetch 19.1.1. This is availability evidence,
not proof of runtime/container compatibility. No download is required by this plan.

After host/filesystem preflight, use fresh private NVMe scratch, a nonroot client,
read-only source/toolchain mounts, and task-local npm user/global config, cache,
prefix and TMPDIR. Do not repurpose HOME. Proposed client limits: one CPU,
1 GiB RAM, no additional swap, 96 PIDs, 60 seconds per command, 540 seconds inner
and 600 seconds outer aggregate, at most 12 client command invocations, and
256 KiB output per command/2 MiB aggregate. Kill only the job's descendants on
timeout. Consume a durable claim before mutations;
run once, stop at first failure, preserve partial evidence, and do not retry an
uncertain publish. Root must approve final resource/network details.

### Finite operation oracle

| Group | Required outcome, beyond client exit status |
| --- | --- |
| Setup | Create credential/application/grant through the real catalog API, then prove the expected binary and loaded policy. Client config contains only application credentials and a registry-scoped dummy provider token. |
| Cold install | Stock `npm install` from an empty cache obtains both packages' metadata and tarballs; installed files, lockfile and integrity match fixture bytes. Default audit completes against the fixture; no hidden denied prerequisites. |
| Lockfile replay | Stock `npm ci` in a second clean cache installs the same bytes through the proxy using recorded resolved URLs, with no unapproved origin access. |
| Publish then consume | Stock `npm publish` publishes one fresh version. Prove prerequisite metadata GET success, exactly one accepted PUT, decoded package integrity and stored immutable version; install that version from another clean cache. |
| Default library | Exercise the cached pacote manifest/tarball APIs using their standard proxy/CA/auth options, without replacing their transport or constructing HTTP requests by hand. Verify metadata and tarball bytes independently. |
| Denials | Wrong/revoked application token, missing/wrong dummy, wrong package, disallowed write and outside-window publication deny the relevant operation. Count legitimate prerequisite reads separately; require zero unauthorized writes, not an inaccurate zero-total-requests assertion. |
| Evidence | Join each permitted upstream operation to credential generation, policy/request/operation identities and named durable audit events; match released byte/status commitments. Account separately for denials, CONNECTs, mutations and lease caching. Verify drained queues and the persisted chain; do not invent a constant event total before the final protocol is frozen. |

Preserve npm's ordinary headers, retry settings and audit behavior in the
compatibility case; the harness must never automatically restart a failed CLI
command. Any deliberate client setting that removes a standard operation must
be reported as a narrower profile. Capture request inventories and warnings:
[npm's publish implementation](https://raw.githubusercontent.com/npm/cli/v11.8.0/lib/commands/publish.js)
catches metadata-read errors, so exit zero can coexist with a broken read path.

Unit/source regressions should retain the existing exact Rust tests
`tests::npm_encoded_slash_is_authorized_only_for_the_exact_package_capture`,
`tests::npm_session_discard_preserves_semantic_grant_binding_and_forwarding`,
`tests::npm_malformed_operations_precede_credential_jit_quota_and_upstream_access`,
`tests::npm_publish_document_fields_are_approval_bound`, and
`tests::npm_public_registry_receipt_admission_is_exact_and_all_or_nothing`.
Add focused new-mode boundary controls for package/origin/tag scope, compressed
body limits, binary response bounds, header handling and schedule edges. Select
exact affected cases at source freeze; do not sweep the full suite.

[test_npm_weekday_hours_example.py](../scripts/test_npm_weekday_hours_example.py)
only proves example/compiler/time-window behavior.
[npm_publish_companion.js](../scripts/npm_publish_companion.js) is an older fixed
one-use fixture with a loopback proxy and auditing disabled; it is not the stock
operator-client oracle above. A passing private fixture establishes synthetic
client/proxy compatibility only, not real npmjs publication, provider account
verification, or support for every npm/SDK version.
