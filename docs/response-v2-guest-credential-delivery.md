# Guest-local response-v2 credential delivery

This source adds a protected-file startup profile for the real custody services. It does not provision encrypted secrets, launch the seven-process cohort, create a quote, replace PostgreSQL or attest readiness. No runtime, parser, build or provider verification was performed for this increment.

## Independent authority and originals

The protected cold custody configuration may contain `guestDeliveryAuthority`, using the closed authority definition in [the paired schema](../schemas/response-v2-guest-credential-delivery.v1.schema.json). It assigns an Ed25519 public key and its raw-public-key SHA256 ID specifically to guest delivery. This key must differ from the generation trust root and every runtime role key. Possessing a store-generation signing key does not confer delivery authority. The profile requires the existing `tee-hardware` topology and genuine independently pinned generation verifier; it does not accept trusted-host evidence instead.

An independently authorized provisioner must sign a separate delivery for each service role and actual guest boot. The exact payload binds the original cold configuration hash, authority ID, generation ID/version, role, kernel boot ID, original issued/deadline BOOTTIME nanoseconds, and every delivered file pin. Decimal nanosecond strings avoid lossy JSON number round-trips. Admission requires issued <= current < deadline and an original positive window of at most 600 seconds. The CLI cannot extend this window.

The signature preimage is the UTF-8 string `catchplate.responseV2.guestCredentialDelivery.signature/v1`, one NUL byte, then `custody_protocol::canonical_json_bytes(payload)`: compact sorted-key UTF-8 JSON, without a trailing LF. This is the existing custody codec, not Python ASCII escaping or a new JCS approximation. The signature is canonical unpadded base64url of 64 bytes and uses strict Ed25519 verification. The envelope does not supply its own verifier key.

The config is at most 256 KiB and delivery at most 64 KiB. Both are root-owned regular single-link 0400 or 0444 files. A nonroot consumer therefore needs a readable public 0444 original; this implementation does not chmod or chown it. Each credential original is single-link 0400, owned by the exact signed role UID/GID. Generation/topology/role/key manifests are at most 4 MiB each; roots, public keys and signing seeds are exactly 32 bytes. Paths are absolute normal paths with no symlink components or group/world-writable ancestors. Shared public originals may use the same path only with identical pins and bounds.

The private delivery owner retains descriptors, exact bytes, path/inode/device/ownership/mode/time identities and the actual selected role. Checks compare both held and reopened originals and poison the owner on failure. Seed buffers are zeroizing and omitted from debug output. Key construction derives the actual public key from the retained seed and compares it with the retained public bytes and signed topology key ID/hash. Merely labeling a path with a role is insufficient. The owner is one private `Arc` carried by all configuration clones, including the live service and backend result signer; no incoming JSON can construct it.

## Explicit startup selection

The existing custody binary accepts the paired flags `--guest-delivery PATH --guest-delivery-sha256 sha256:...` alongside its existing `--config` and exactly one startup mode:

- `--bootstrap-generation` or `--activate-generation`: the actual signed state-authority UID/GID and its delivery are required.
- `--service ROLE`: the delivery must name that exact service.
- `--service ROLE --check-readiness`: observes the existing genuine readiness path within the delivered startup window.

A configured guest authority without these originals refuses. A failed guest admission never falls back to systemd credentials or environment timeouts. Existing configs with no authority retain the original host behavior and flags.

Every role receives its own signed provider-generation original, generation public root and exactly its assigned role-key pairs. Only state-authority receives the three bootstrap manifests; the field is required null elsewhere. State-authority uses its actual delivered `linearizable-store` key for generation operations. Existing provider-generation, topology, role and key signatures, generation validity, hardware proof and live backend reconciliation are still checked by the existing consumers. The state-authority engine's generation digest comes from the successfully verified signed generation, not `CATCHPLATE_RESPONSE_V2_PROVIDER_GENERATION_SHA256`. Guest signing does not use `CREDENTIALS_DIRECTORY`; guest generation/readiness reads do not use either systemd/public-credentials directory variable. Guest cgroup observation uses actual `/sys/fs/cgroup`, not an environment replacement.

## One original startup allowance

The same delivery deadline bounds generation-verifier execution, signed generation-operation frames, activation-context creation/admission, startup waits, readiness handshakes/artifact waits and backend startup budgets. A context from another boot, an expired context, or a context extending beyond the delivered deadline cannot serve as guest startup authority. Retained checks surround actual consumers; an elapsed timeout is never treated as readiness. Existing signed process limits may narrow the budget, not renew it.

Only after this service has passed real readiness checks and published its existing signed generation-readiness artifact does its shared owner mark local startup complete. This does not mean the whole generation is ready: the existing independent activation/reconciliation protocol still decides that. Afterward normal service operations retain their original signed request limits and continue checking the retained file/role/boot identity; the startup allowance is not misrepresented as an expiring runtime lease. The implementation does not claim hard real-time cancellation of arbitrary blocking filesystem or kernel work.

## Provisioning and remaining guest work

Delivery-authority assignment, independently authenticated current boot/deadline delivery, role-owned protected files, signed generation manifests, actual verifier/evidence, guest UID/GID separation, local sockets, PostgreSQL, cgroup observation, journals and directory ownership must already be provisioned. No private seed belongs in the EIF, Docker layer, command line or this document. The [offline signing producer](response-v2-guest-delivery-producer.md) emits this exact signed original from independently approved sealed-descriptor inputs; it does not provision secrets, select a fresh guest window, launch services or renew authority.

The profile neither transports host UDS/PID/UID authority across vsock nor relaxes the serving gate's nondumpability. Guest peer measurement, a complete measured cohort launcher and encrypted role-secret provisioning remain separate work. Old journals/history are not reassigned, repaired, pruned or made more accessible. The schema describes structure; it is not a runtime permission or evidence of a booted cohort.
