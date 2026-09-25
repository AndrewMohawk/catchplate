# Controller body result and observer binding

Status: source-implemented admission repairs, unbuilt and unexecuted. A real
controller-owned body runner, live runtime observer and terminal publisher
remain unfinished. [Controller-side stream/output collection](controller-body-output.md)
is now source-implemented but unexecuted. This document does not
authorize verification or provide passing execution evidence.

## Why this contract changed

Tracing the missing result producer found three concrete source blockers:

- The lifecycle used the v11 request encoder for v12 Docker configuration and
  terminal results. That encoder permits only the integer `11`, so ordinary
  exit codes, resource sizes and digest arrays could not pass.
- Observer signature verification serialized a 32-byte digest to a JSON array
  and then required it to be a string. No normal digest could reach signature
  verification.
- The observer's signature did not cover the complete runtime/body claims.
  Comparing a namespace value with the same result's namespace did not supply
  independent observation. Runtime executable/rootfs pins and the two mapping
  inventories also lacked exact joins.

The choice is to repair these actual admission boundaries before introducing a
publisher. A helper that merely fills the required fields cannot replace missing
process observations or an independently authorized observer.

## Separate byte formats

The legacy v11 signature/request encoder is unchanged. The private v12
[lifecycle JSON codec](../data-plane/decision-gate-rs/src/dind_json_v12.rs) admits
exact signed/unsigned 64-bit integers, sorted UTF-16 object keys and ordinary
Serde JSON string escaping. It rejects floating point and bounds output to
16 MiB, nesting to 64 edges and values plus object keys to one million nodes.
It is a purpose-specific integer JSON profile, not general RFC 8785 floating-
point canonicalization. V12 Docker requests, inspection/storage identities,
source/archive metadata and native prepared-manifest comparison use it.

The [shared body contract](../data-plane/decision-gate-rs/src/body_result_v12.rs)
is consumed by both the root lifecycle and plan executor. Original terminal
bytes must fit the existing 4 MiB plan frame and pass a bounded structural scan,
closed typed parsing and exact canonical wire reconstruction. Duplicate or
unknown fields, alternative encodings, floats and an explicit null in place of
an omitted native option are rejected. Wire object keys are sorted; all admitted
keys in this closed schema are ASCII.

The existing terminal digest recipe is preserved: serialize the typed result
in its declared field order with `terminalSha256` zeroed, then SHA-256 those
compact UTF-8 bytes. This digest representation is intentionally distinct from
the sorted-key original wire representation. Do not hash the original terminal
file including its own digest or substitute a differently ordered object.

## Acyclic signed claims

The enclosing body/runtime types remain v12. The embedded observer evidence is
now exactly `serverware/runtime-observer-evidence/v13`; old v12 observer records
are not accepted or silently upgraded. It adds required `runtime_claims_sha256`
and `body_claims_sha256` fields.

```text
actual runtime observations + independently held launch context
  -> explicit runtime-claims digest (no observer or final report digest)
actual body outcome + streams/outputs + static evidence + runtime-claims digest
  -> explicit body-claims digest (no observer or terminal digest)
both digests + actual observer identity/events/mappings
  -> observer canonical digest -> independent observer signature
signed observer + complete runtime claims -> runtime-report digest
complete body result -> existing zero-terminal-field digest -> original wire
```

Both claims projections enumerate their fields explicitly in source. Runtime
claims cover the image, runtime executable/rootfs, source/artifacts, proxy peer,
namespace/cgroup identities, executable mappings, runner identity, inherited
proxy executable and command. Body claims cover version, plan/lane/body/command,
exit status, stdout/stderr/output-manifest digests, both static executable
records, the runtime-claims digest and the optional native inventory digest.
Adding a wire field requires deliberately updating the corresponding projection.

Observer canonical digest calculation retains the typed compact-JSON recipe:
zero `canonical_evidence_sha256` and clear `observer_signature_b64`, retaining
both claims digests and every other observer field. The Ed25519 message is
exactly the bytes `serverware/runtime-observer-evidence/v13`, one NUL byte, then
the raw 32-byte canonical evidence digest. The signature must be exactly 64 bytes
encoded as canonical padded standard Base64, with no whitespace or alternatives.
This framing is explicit; it is neither digest JSON nor a hex string.

The independently pinned observer key/executable policy still authenticates the
signature. Runtime admission recomputes the full claims digest, joins the cgroup
identity to the namespace record, and compares the declared image, executable,
rootfs, runner identity and proxy/command with independently admitted pins.
Both mapping inventories must be nonempty, sorted, nonoverlapping and bounded
to 4096 entries, with exact matching runner intervals and content hashes.
Positional permissions must agree with executable, nonwritable file-backed
mappings; arbitrary four-character permission strings are not accepted.
The body consumer separately recomputes and joins the signed body-claims digest.

The root lifecycle also retains the admitted runner identity from creation,
compares the typed result against that identity and the actual Docker exit,
checks terminal/claims commitments, and preserves the original result bytes.
The executor still performs independent pinned-key verification and static-role,
source/artifact/closure checks. Native selection still requires actual collection
and equality with the [33-file native commitment](native-postgres-controller-consumer.md).
Neither layer synthesizes absent evidence or bypasses cleanup.

## Still required for a genuine producer

The actual create path still invokes the signed payload executable directly.
It does not yet install a controller-owned runner, hand off an independently
held launch context, observe runtime events or publish the terminal file.
The future body owner must preserve the original command rather than injecting a
final plan ID into its signed arguments, which could introduce a commitment
cycle. The lifecycle now subscribes before start, captures bounded separate
stdout/stderr, independently reads the signed output tree and publishes its
manifest under reserved controller filenames. This does not supply the missing
original terminal publisher or observer.

Docker's rotating log is not a complete stream capture. Native combined logs
are not separate stdout/stderr evidence. Generic stream/manifest digests must
now match actual controller capture and collection, not merely be nonzero. Static
measurement must use real retained executable descriptors; runtime acquisition
must own the actual launch, process identity, namespaces, mapping events and
terminal observations. Signing caller-supplied dictionaries is not that owner.

No observer key, policy, runtime, runner image or signed invocation was installed
or reissued. Future deployment must deliberately enroll the new observer contract
and measured binaries; no migration or production acceptance is inferred.
The complete frozen-source preparation and sequential verification gates remain.
