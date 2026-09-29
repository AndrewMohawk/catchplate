# Guest ledger exact retrieval

Optional cold `ledgerExactRead: {"apiVersion":"serverware.responseV2.ledgerExactRead/v1"}`
selects a purpose-specific read connection. Missing profile preserves the old
host adapter; explicit null, an absent genuine guest delivery, or a failed guest
connection never falls back to local filesystem access. The independently
admitted full configuration digest binds this explicit selection in both signed
messages, alongside the verified generation, topology and current boot.

State-authority's actual `ImmutableObjectStore` adapter is constructed without
contact or any access to the ledger's private directories. Its generation
install/reconciliation path does not read CAS; the existing inspection/release
operations call the read only after authenticating the protected row's exact
generation, object ID, storage receipt, content digest, length and deadline.
The original canonical locator must match those commitments, but no locator or
arbitrary path crosses the new channel. Ledger's own inspection path continues
to read its own private store.

## Service and identity

The actual final-UID ledger service starts a separate exact-read worker after
acquiring its service lock and before publishing readiness. Using the main RPC
worker would deadlock: ledger inspection calls state-authority, which performs
its own exact inspection read. This new worker serves only exact reads, never
mutations, commands, upstream requests or replay resolution. Its ownership is
retained by the service, checked before every main-service handshake, and joined
on ordinary drop. Existing role lifetime monitors and absolute kill timers
remain in force.

The path is the fixed leaf `ledger-exact-read.sock` in the independently signed
ledger service socket's parent. That parent must already be the exact ledger
UID/shared signed GID with mode `0750`, beneath concrete protected ancestors;
the new socket is `0660`, exact ledger-owned and fresh-only. An existing path is
neither replaced nor unlinked. No CAS, role-key or private state permission is
changed. The existing private state directory remains `0700`. Provisioning
must provide this socket directory separately, not relax a private directory.

Both sides authenticate the actual same-guest socket peer UID/GID and retain
its genuine `SO_PEERPIDFD`, stable kernel process identity and liveness. Each
signature binds both observed process identities. These are PIDFD consistency
checks, not new executable measurements or a substitute for role admission.
Requests use the retained state-authority `linearizable-store` key; replies use
the retained ledger `archive-store` key, under distinct new signature domains.
Inline public bytes must match the independently signed role descriptor and
logical-role assignment; they are not caller-selected authority. This avoids
reopening another UID's role-private public-key credential file. No readiness
record, UID alone, forwarded verdict or claimed PID authorizes a read.

## Exact bytes and allowance

Each canonical frame is at most 16 KiB. A fresh request nonce and the entire
signed request commitment bind the result. The request carries no descriptors;
the result carries exactly one new sealed memfd copy, not a raw-CAS descriptor.
The receiver requires all four immutable seals, zero links, `0400`, CLOEXEC,
offset zero, the exact length and SHA-256, and unchanged held object/peer/socket
originals. The existing 34,603,008-byte object bound is unchanged.

The authority's original current-boot millisecond deadline is carried exactly
as nanoseconds. The service additionally refuses a deadline beyond its original
accepted-connection cap: the minimum of both signed role timeouts and 30 seconds,
bounded by the retained delivery's remaining startup window while startup is
in progress. It never extends an allowance, retries a failed request, reissues
release permission or contacts an upstream source. Receiving committed bytes
does not itself consume or grant public release; the existing state transition
retains that responsibility.

## Unfinished persistence boundary

This source connects only reads of genuinely committed objects. The state
authority already requires a signed ledger `ArtifactCommit` before committing
the exact row, but the actual private-CAS byte producer and its commit caller
are not connected by this patch. The measured-provider flat artifact store is
a different contract and is not aliased to this store. Missing bytes or receipts
refuse; no record, signature, readiness result or persistence success is
fabricated. A real byte producer must durably commit its immutable object and
genuine receipt before the existing authenticated database commit.

No build, test, parser execution or runtime verification accompanies this
source-only checkpoint. It does not establish durable guest storage or a pilot.
