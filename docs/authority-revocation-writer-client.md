# Configured planner-to-writer client

Source `.69` adds a private configured planner client for the existing
[five-original transfer](authority-revocation-writer-transport.md). Before
sending, it derives independent ACK expectations through genuine signature
verification and retained-plan replay. It returns the exact received bytes
only after verifying the [writer ACK](authority-revocation-writer-acknowledgment.md)
against those expectations and the measured writer key. This is unbuilt,
unexecuted source, not a demonstrated service launch, exchange or database
commit. It is not a public purpose or a configured intent/relay producer.

## Measured response public key

Configuration v2 now requires
`roles["planner-writer"]["responseSigningPublicKeyBase64Url"]`. This is the
writer's own public response key, not its existing planner-key alias. It must
be an exact 43-character canonical unpadded base64url encoding of 32 Ed25519
public-key bytes. Both actual measured service admission and artifact
configuration admission construct the key and bind its DER SubjectPublicKeyInfo
SHA-256 digest to the existing `responseSigningSpkiDigest`. The field is
mandatory only for the writer; other roles' closed field sets reject it.

The existing exclusion of verifier, planner, issuer and executor response pins
remains. Writer startup separately binds its descriptor-loaded private key to
that same response pin and rejects its actual launch-identity key. Publishing
the public bytes creates no signer, key candidate or new credential descriptor.
The client never learns its expected key or pin from the response.

The configuration schema identifiers stay v2, with source revision `.69`
providing the cutover. Earlier source-revision configurations are already
rejected; a new-revision writer entry missing this field is rejected too.
Operators must supply the existing dedicated writer signer's public bytes and
regenerate the signed configuration, artifact closure and dependent generation
bindings. No keys have been generated or provisioned here. Transfer v1, private
key custody, database DDL structure, privileges and peer topology are unchanged.

## One owned configuration and original request

`AuthorityProcess._send_revocation_writer_commitments` requires the planner
role, planner process mode and actual `MeasuredConfiguration` type. Main's real
root-signed load and launch admission remain prerequisites. The private method
holds its payload and digest once, bounds the five immutable originals and
captures the full configuration before guarded active-planner and final
generation callbacks. It supplies those values to the fixed client; it accepts
no caller endpoint, key, expected ACK fields, clock, DSN or replacement work.

The client owns the payload again before its callbacks and holds the writer
socket path, service UID/GID, response key/pin and all policy scalars. Writer
peer UID/GID must match the measured planner identity. The exchange timeout and
current control age are each the stricter of the measured planner and writer
values. Timeout admission remains 0.05 through 30 seconds, and skew stays at
the source policy. The actual verifier mapper captures configuration and launch
bindings again, checks their commitment/generation and constructs the pinned
planner/verifier keys and identities. The separate writer key is canonically
decoded and checked against its measured SPKI on the same work allowance.

```text
owned measured configuration + exact original intent/relay/plan/context/history
  -> real key/configuration binding and guarded current clocks
  -> authenticate both controls and replay original plan/context
  -> derive independent scalar19 request expectation
  -> one peer-checked transfer of the same five originals
  -> verify exact returned ACK against held writer key and scalar19
  -> return original signed ACK bytes
```

The independent expectation helper captures the configured identity pair before
key callbacks. It verifies both original controls and their detached-body
commitments, joins the signed historical age triple to measured policy, and
genuinely replays the original plan/context. Record/key digests come from that
replay; intent, relay and history commitments come from their original bytes.
No ACK field, stored request row or previously successful observation supplies
an expectation. Signed historical cutoff and verification times are retained;
the newly sampled clocks do not overwrite them.

## Work, deadlines and meaning of the result

All captures, configuration/key hashes, control verification, genuine
remaining-clamped proof work, request commitments and ACK verification share
the caller's existing allowance. No new work object, database connection or
cached proof token is introduced by this client. Socket framing is not H/B/N
proof work; its guarded callback must leave that meter unchanged.

Current clocks are sampled before local authentication/replay. The separate
transport deadline starts before socket connect and covers one complete
exchange; it does not pretend to bound preceding synchronous proof work.
The actual writer still independently checks current controls, measured policy
and both genuine persistence/reservation replays. It does not accept the
client's local result as authority. The ACK has no fresh timestamp or terminal
execution claim.

A valid reply establishes the pinned writer's signed custody statement for the
independently derived request. It does not prove current roots, execution,
hardware key custody or independently observed database durability. A socket,
deadline or ACK-verification failure can follow a writer commit; the client
returns no success bytes and does not retransmit, regenerate or reconcile.
Historical key resolution and authorized recovery remain separate work.

Configured intent/relay production, the complete public flow, unfinished
WebAuthn/registry gates and production provisioning remain open. Component
fixtures use real cryptography and local replay with modeled socket/clock
observations; source controls bind the private service path without fabricating
admission. This checkpoint adds 30 authored methods: 13 behavioral component
controls and 17 source-linkage controls (six public-key, five expectation and
six client controls). All remain unexecuted under [goal.md](../goal.md).
