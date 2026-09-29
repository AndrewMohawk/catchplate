# Measured sequenced audit authorship

Status: source-only, unbuilt, unexecuted and unprovisioned. This connects the
actual queued and synchronous required Rust audit producers to the actual
control-plane audit route. It does not turn an event's contents into independent
proof that an application executed, that a provider acted, or that a response
was delivered. Existing development event/ACK bytes remain distinct.

## Independent permission and actual mTLS

The control-plane cold runner admits `serverware.measuredAuditStartup/v1`
through `SERVERWARE_MEASURED_AUDIT_CONFIG_FD`, after its actual custody owner and
before HTTP serving. The fixed entrypoint supplies
`/run/serverware/authority-trust/measured-audit.json` and the separately pinned
`measured-audit-root-public-key` in that directory. Its root must differ from the
runtime root. An offline holder can use `data_plane_audit_authority.sign_policy`;
neither HTTP intake nor the running control plane accepts the private key.

The signed policy binds the actual control-plane configuration, deployment,
original interval, Nitro roots and at most 32 exact native assignments. Each
assignment binds the actual role-4 boot/key, complete release/policy/config/CA
scope and PCR/EIF/module expectations, plus producer epoch, instance, starting
sequence, predecessor batch, previous assignment and pending-original digest.
Omitted/mismatched production authority refuses. There is no currentness-policy
permission alias or unmeasured UDS fallback.

The new combined native startup profile's `measuredAudit` is the exact seven-field
`nativeMeasuredAuditConfiguration/v1` projection in the [schema](../schemas/measured-data-plane-audit.v1.schema.json).
Its private client key is **not** a file input. The retained enclave-generated
CA issues a fresh clientAuth-only P-256 leaf inside the original CA interval.
The source-fixed URI is `spiffe://serverware.audit/{deploymentId}/{instanceId}`.
Private material moves only into the dedicated audit TLS client; public leaf
and SPKI hashes are retained. It is never attached to the shared service client
or sent to the parent relay. This is not a claim of erasing all TLS-library copies.

The receiver's real TLS context admits the independently assigned native CAs.
Other human APIs may omit a client certificate; the audit route cannot. The
HTTP protocol supplies a private object retaining the actual TLS 1.3 connection
and its peer certificate. Forwarded headers, body certificates, ingress-client
mTLS, configured instance strings and bearer tokens cannot substitute. Every
audit request repeats exact issuer/SAN/leaf/SPKI and original validity checks,
including a reused TLS session. The existing signed response owner still signs
fresh nonce-bound acknowledgements.

## Original signatures and one producer

`native_audit_owner::Owner` serializes the queued flusher, required event posts
and credential-release start audits. A statement has exactly 21 fields and one
of `hello`, `prepare`, `commit`. Its Ed25519 preimage is the ASCII API label plus
NUL plus SHA-256 of sorted compact Python-ASCII statement bytes, including DEL.
This purpose-specific digest preimage preserves the existing native signer's
message bound. Events are exact base64url-encoded original JSON bytes, not
floating-point values re-canonicalized across languages.

The fresh original NSM nonce is SHA-256 of the dedicated
`serverware/native-audit-attestation/v1` NUL-terminated domain, challenge32,
statement hash32 and signature64. The real Native signer checks its actual
boot/key, policy, original process/deadline and CA identity. Receiver verification
replays the genuine role-4 COSE/chain/PCR proof under independently admitted
expectations and joins its key to the actual TLS leaf/SPKI statement fields.

Bounds are 200 events, 1 MiB of event-original bytes, 1.5 MiB signed envelope,
30 seconds per original command, and at most one unresolved batch per epoch.
The signed policy interval is at most 24 hours and cannot renew the original
custody owner. Sequences stop below the signed 64-bit maximum rather than wrap;
exhaustion refuses another batch or restarted producer. The schema is data-only; signature, interval, equality, actual
TLS possession and durable-transition checks remain executable requirements.

## Durable sequence and restart

The actual PostgreSQL audit store adds immutable
`serverware_measured_audit_epochs` (one epoch per deployment/instance) and append-only
`serverware_measured_audit_records`, retaining `admit`, `pending`, and `commit`
originals. It uses the existing audit connection, global chain lock, transaction
and SELECT/INSERT-only runtime ACL; no metadata DML or update/delete grant is
introduced. Bootstrap creates the relation before ACL sealing. Strict runtime
startup requires it; SQLite remains the unchanged development audit profile.

1. `hello` atomically admits the independently assigned producer epoch and exact
   predecessor head. A new assignment must name the previous assignment and
   exact pending digest, or explicit null if none exists.
2. `prepare` durably stores the exact signed envelope before any event append.
   It admits only the next sequence/predecessor and one original for that slot.
3. `commit` names that stored original. Events, collector hash-chain links and
   the producer commit/head record commit together under the same lock.

Only a definite signed receipt advances the sender. Transport uncertainty
retains the exact signed command; retransmission changes only the response nonce,
never the statement/signature/sequence/interval. A 413 cannot split a previously
signed batch. Gaps, alternate originals and partial event history refuse.
Event IDs remain unique within the producer epoch. Existing PostgreSQL collector
sequence numbers are not relabeled as producer sequence evidence.

On restart, a newly signed independent assignment authorizes the exact retained
head and pending original for the same epoch. The source-owned hello receipt
returns that original; the new measured owner commits it using fresh processing
authority. It does not re-sign the old event original or treat its historical
quote/interval as new execution permission. No continuation is inferred from a
timeout, missing row, new boot or a collector-reported head. A mismatch blocks
before serving. Failed hello admission also remains uncertainty requiring an
exact independently authorized successor, not automatic reset.

An existing workload cannot select a fresh epoch UUID to reset this history.
Cross-epoch migration requires a separate future explicit contract. Production
without the measured owner refuses audit use; it cannot revive bearer intake.

The in-memory pre-batch optional queue is not a crash-durable record of every
event the application might generate. Durable custody starts with the actual
pending-store commit; required pre-effect events require the final event commit
ACK before their caller proceeds. A lost pending ACK cannot prove non-storage.
Expired unresolved commands require the explicit continuation path. No history
is pruned, repaired, silently abandoned, or replayed as a new sequence.

This supplies source-level authorship/ordering and transactional continuity,
not independent database rollback prevention, off-host witnessing, physical
key attestation for an ordinary UDS signer, throughput evidence, deployed trust
provisioning, or production acceptance. Native startup, real mTLS and NSM,
PostgreSQL interruption/restart behavior, dependency/build verification and
independent release gates still require their separately authorized validation.
