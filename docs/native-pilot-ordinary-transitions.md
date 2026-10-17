# Ordinary transition composition

The `.380` source batch connects five existing ordinary-service decisions after
the eleven native operational grants. It does not launch services or establish
hardware acceptance. Supervisor coverage is **85/105**, with **20 remaining**;
startup still refuses and production acceptance remains **0/6**.

## Independent policy and fixed sequence

Explicit `catchplate.nativePilotSupervisorCommissioningPolicy/v10` adds only
the literal canonical `ordinaryTransitionsOriginal` to v9's seventeen fields.
The outer 4 MiB policy bound and 77 capability selectors remain unchanged.
Earlier versions retain their original authority and closed field sets.

The fragment has exactly four fields: `apiVersion`
(`catchplate.nativePilotOrdinaryTransitionPolicy/v1`), `dispatch`, `spool` and
`regularAppendCapacity`. It independently selects a nonempty `initialHeadSha256`
for each dispatch role; an `initialTransitionHeadSha256` for DurableRecoveryStore,
Cleanup and CurrentSignatureAuthority; and append capacity from 1 through 32.
These hashes authorize initial chain values. They do not claim prior receipts,
empty storage or a historical transition.

| Service job | Signing authority | Actual inputs required |
| --- | --- | --- |
| 74: dispatch / DurableRecoveryStore | Approved DRS history root | Actual ordinary generation and native CommitRequest originals |
| 75: dispatch / CurrentSignatureAuthority | Approved CSA history root | Same joins for the actual CSA service |
| 76: Head / DurableRecoveryStore | Approved DRS history root | Actual native spool grants, peer, scope and authenticated Cleanup epoch/key |
| 77: Cleanup | Approved Cleanup history root | Actual signed Head and authenticated DRS epoch/key |
| 78: Current / CurrentSignatureAuthority | Approved CSA history root | Actual signed Head and Cleanup and their exact predecessor bindings |

All other fields derive from the authenticated ordinary runtime/history/grant
contexts and complete native input/grant originals. Native results are verified
against the real issuer preparation and signature authority, not merely parsed
as shape-compatible objects. Ordinary and native invocation IDs remain separate
identities; one is not required to equal the other.

## Retained ownership and issuer reuse

The fixed supervisor composer requires the actual retained coordinator and
current opaque job request. It rechecks complete preceding approved inputs,
result signatures and fixed public pins before preparing the next job. It
retains at most 128 MiB and keeps the original startup and grant deadlines.
No generated key, renewed interval, predicted receipt or reconstructed live
owner substitutes for these originals.

The shared pure `native_pilot_service_authority.prepare_input` validates the
existing signed formats and exposes the exact signature message and approved
root. Supplied clocks are checked data, not live ownership. The real signing
wrapper still checks its actual private capability and live pre/post clocks.
Delivery and generation retain their existing producers. Dispatch/Head retain
their 64 KiB result limits; Cleanup/Current retain 128 KiB.

Only completed-owner rechecks extend to service job79,
`install-launch-retrieval`. This is a verified read-only handoff, not an
implemented launch decision or reopened installer. The transition owner closes
before its predecessor owners, only after definite coordinator cleanup.

## Remaining work and evidence

The twenty remaining decisions, launch/bridge/release wiring, executable
supervisor package, independently approved immutable dependencies, provisioning
and connected application allow/deny/cleanup run remain required. Source
coverage is not a readiness percentage. Independent Nitro/KMS, signing,
witness, provider and hardware approval acceptance remain separate.

The immediate next group is ten `install-launch-*` jobs. The existing launch
installer verifies complete bundles, but late closure, encrypted-delivery and
verifier-transport authorizations bind actual C9 Guest13 and need genuine
post-observation issuance. Existing closure and CommitRequest encrypted-delivery
producers are not yet routed through the fixed jobs. Verifier-transport and
other encrypted-delivery producers still need locating or implementing. A
future-guest placeholder, invented ciphertext or pre-start policy literal is
not a substitute. After those launches, service material, bridge, release,
constructed admission, origin observation and shutdown decisions remain.

## Focused verification

Exact source `b0c98be1b5ab602d14cfd3deade95b8c5f832d66` passed **115 focused
Python controls**, grammar and both Make inventories for all twelve changed
Python files, and **61 relative documentation links**, in one run (exit **0**).
The run was 2026-10-01 00:30:06.657986480–00:30:19.323415148 UTC, using Python
3.11.15, cleared environment, CPU 0, isolated user/network namespaces and
`-I -S -B`, under a 120-second limit. No database, application or authority-store
module was imported.

The eight new controls cover closed policy/routing, starting-head and capacity
refusals, authenticated synthetic initial-history epoch projection and tamper
refusals, semantic history hashes, unsigned-only Head projection, independent
signature framing and incomplete-input refusal. They do **not** cover a full
positive eleven-native/five-transition transcript or actual retained-owner,
signing-entrypoint, service or hardware acceptance.

The 85,278,720-byte source archive has SHA256
`543a98d7f469c5267da9b37e3af7fbcb2301a1e3468700e600ccea8925a41af4`.
Archive, source revision, exact harness/command, log, structured result and
verified checksums are retained outside disposable scratch at
`codex-offload/catchplate/engineering-builds/b0c98be1-ordinary-transitions-wrwhMX/`.
Native source, schemas and dependency lock are unchanged from the previously
compiled `03d4075d`; no native/artifact rebuild was repeated. The reused runtime
is still an unpublished engineering candidate. No cloud or paid action ran.
