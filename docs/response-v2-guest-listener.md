# Guest response-v2 listener preparation and activation

This source connects fresh privileged socket preparation to the actual custody-router listener and native client. It does not supply the guest cohort launcher, kernel peer inspector, provisioned role secrets, backend, quote authority, or tested guest readiness. The separate [signed guest credential delivery](response-v2-guest-credential-delivery.md) remains mandatory. Source was not built or executed for this increment.

## Explicit cold selection

The protected custody configuration may select this exact closed object:

```json
{"guestListener":{"apiVersion":"serverware.responseV2.guestListener/v1"}}
```

The configuration must also select its independently assigned `guestDeliveryAuthority`, hardware generation profile, `expectedClientUid:65534`, and `expectedSocketGid:65534`. Both the root configuration and signed router topology must name `/run/serverware-response-v2-guest/transaction.sock`. The router UID is the exact signed nonzero UID, distinct from 65534; its signed process GID remains 65519. The original configuration bytes, signed router delivery, generation identity, current guest boot and original absolute BOOTTIME window are retained. No environment fallback or unsigned handoff can select this authority.

The client uses the additive nested `serverware.nativeResponseObservationV2Config/v2`, with mandatory `guestListener` above, the same fixed `socketPath`, and `expectedUid` equal to the signed router UID. All other fields retain the existing native response-v2 contract. Admission follows the actual cold `Pending` encrypted-service-token source, not an incoming version label; outer `nativeStartupConfiguration/v6` produces that source in this checkpoint. Outer native versions 1–5, nested response client v1 and environment-selected host clients preserve their original behavior; v1 rejects `guestListener`, including null. The v6 schema admits either its unchanged nested v1 or this explicit nested v2. An additive outer profile must preserve that actual pending owner and explicitly pair its schema rather than silently promoting a legacy input.

The paired [schema](../schemas/response-v2-guest-listener.v1.schema.json) describes the profile, sealed handoff and native client. Schema conformance is not runtime admission.

## Producer and actual consumer

`PreparedGuestResponseV2Listener::prepare(config_path, delivery_path, delivery_sha256)` is a non-Clone, root-only preparation API for a genuine privileged guest launcher. It independently verifies the existing router delivery signature against the cold delivery authority and retains both original files. It does not read role seeds or claim that generation/TEE verification or service readiness has completed.

Preparation creates only a **fresh** `/run/serverware-response-v2-guest` directory and fixed socket. It never reuses, replaces, prunes or changes ownership of an existing path. The directory is root:65534 mode 0711; the socket is routerUID:65534 mode 0660. Root-owned `/` and `/run` must be non-writable by group/others and traversable by the gate. Other-user execute on the fresh socket-only directory permits the distinct router to traverse it, not list or write it. This directory is not a role-secret container. Neither process receives supplementary groups or a new ACL.

The producer binds an actual `AF_UNIX/SOCK_SEQPACKET` socket, verifies `SO_ACCEPTCONN=0`, and does **not** call `listen()`. `.check()` and `.descriptors()` are preparation-phase methods. The latter permits one borrowed export of the bound socket and sealed handoff memfd; a genuine launcher must retain the owner and explicitly transfer the originals into the router child. Failed owner checks poison further use. No public numeric FD, pathname or handoff document proves this launcher provenance.

The actual router consumer is:

```text
--service custody-router --config CONFIG
--guest-delivery DELIVERY --guest-delivery-sha256 SHA256
--guest-listener-fd FD --guest-listener-handoff-fd FD
```

The paired FDs must be distinct canonical integers outside stdio. They are made close-on-exec before guest generation verification can launch any verifier. These options are forbidden for host mode, other roles, readiness inspection and generation bootstrap/activation.

The router first runs the genuine guest-delivery loader: independent signature, original role credentials/key association, real signed generation and existing TEE verification. It then requires exact equality between that retained owner and handoff commitments. It checks both the filesystem socket inode and kernel socket FD identity separately, fixed bound name, socket type/domain/protocol, non-listening state, sealed metadata and retained ancestor identities. A sealed handoff is consistency data only, not a signed grant or a replacement for those checks.

The same private delivery `Arc` and one-use descriptor owner survive configuration cloning into the real router thread. Activation consumes the slot once. It requires real/effective/saved UID and GID all equal the signed final router IDs, no supplementary groups, zero effective/permitted/inheritable capabilities and `no_new_privs=1`. Only that process calls `listen()`. It rechecks the original allowance afterward and retains the originals through the listener, checking them around acceptance. The existing real runtime construction and readiness path are still required; no synthetic ready result is introduced.

This ordering matters: Linux `unix_listen()` records the caller's current peer credentials, and connection setup copies them. A root-prepared **already-listening** socket would carry the wrong process identity. See [Linux v6.12 AF_UNIX](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/unix/af_unix.c).

The actual final UID/GID 65534 native client, with no supplementary groups, retains and rechecks the fixed path originals around connection. It verifies the socket owner and exact router `SO_PEERCRED` UID/GID. The existing signed hello, generation, TEE, release, role-key and transparency admission then run unchanged. Health probes and subsequent sessions retain this explicit profile; failures never select the host branch.

## Handoff and time

The memfd contains canonical compact sorted-key UTF-8 JSON with no LF, at most 16 KiB, sealed against writes, growth, shrinkage and seal changes. Its closed five fields are `apiVersion`, `binding`, `directory`, `socketPath`, `socketFd`. The closed nine-field binding contains configuration/delivery digests, generation ID/number, guest boot ID, original issued/deadline BOOTTIME decimal strings, and signed router UID/GID. Each identity contains exact `device`, `inode`, `mode`, `uid`, `gid` values.

Activation cannot renew the signed startup window. After existing genuine local startup completion, normal operations retain their existing operation deadlines; the startup grant is not reissued. Neither a handoff nor an FD is permission to create another listener. A partial preparation, failed activation or successful handoff leaves the fresh filesystem objects for explicit launcher lifecycle settlement; this slice deliberately supplies no automatic pruning, restart or cleanup authority.

## Still required for a genuine guest cohort

The launcher must provide the actual privileged preparation, private FD inheritance, final router identity/capability transition and owned lifetime/cleanup. It must also provision the existing signed delivery and real role/backend/quote dependencies. No secret belongs in the image or this socket directory.

The current peer consumer still requires real `SO_PEERPIDFD`, per-packet `SCM_CREDENTIALS`/`SCM_PIDFD`, stable process identity, executable measurement and security labels. The final nondumpable gate prevents an unprivileged cross-UID router from opening its executable under the existing proc path. The separately scoped minimal guest inspection owner is therefore still required; it must use actual kernel socket/PIDFD originals, not a self-claimed executable digest, a role-labelled NSM quote, a relay identity, or synthesized labels. Neither gate nor router receives inspection capabilities from this listener work. Missing UAPI/LSM support remains a refusal, not a successful guest observation.
