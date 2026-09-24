# Dedicated writer response-key startup binding

## Status and scope

Source `.66` adds bounded startup loading for a dedicated planner-writer
response key. This is **unbuilt and unexecuted source**, not production key
provisioning, hardware custody, an acknowledgment API or an enabled service
route. Loading the key signs nothing and grants no database or execution
authority.

The actual process stores the key in `writer_response_signing_key`. Its generic
`signing_key` remains `None` for the writer. Existing internal-envelope signing,
runtime responses, launch-identity consumption receipts and public writer
purposes are unchanged. No current path reads the new slot to sign or return a
response.

## Measured identity and original key bytes

The existing measured writer field `responseSigningSpkiDigest` supplies the
response-key identity; no service-configuration field or schema is added.
Both measured topology validation and artifact configuration validation reject
equality with the response pins of verifier, planner, issuer and executor.
The writer's planner-key aliases still identify the planner key used to verify
plans; they are not writer response-key settings.

During writer-specific initialization, the service captures the writer pin,
an immutable tuple of those four other-role pins, and the actual launch public
key handle before reading the writer key descriptor. Subsequent descriptor
or parser callbacks cannot retarget these captured scalar pins through a
configuration alias. This ordering does not claim to precede the constructor's
earlier launch-identity initialization, nor make arbitrary key internals
immutable.

The inert `_signer_from_pem` helper accepts exact immutable bytes from 2 bytes
through 64 KiB. It requires canonical SHA-256 pins and an exact four-tuple,
rejects a reused role pin, parses an unencrypted private PEM with the actual
cryptographic library, and requires Ed25519. Raw private-key bytes are not an
alternative input format. The actual derived public key is serialized as a
44-byte canonical Ed25519 SubjectPublicKeyInfo and hashed; that digest must
match the captured writer response pin. It must also differ from the actual
launch public key's SPKI digest.

The returned object is the genuine parsed private key, not a launch or signing
authority token. Supplied pins and a successful standalone component call do
not establish root-signed configuration or active launch. Startup key loading
is outside request H/B/N accounting; no work object, new allowance, clock,
signature, proof replay or database operation is introduced by this helper.

## Descriptor and role boundaries

Only the writer gains
`SERVERWARE_POLICY_AUTHORITY_PLANNER_WRITER_SIGNING_KEY_FD`. The launcher and
artifact role-manifest inventory require it alongside the existing writer
credentials. The descriptor entrypoint maps it to the writer signing-key
credential named by
`/run/secrets/serverware-authority-planner-writer-signing-key`; the explicit
trusted-host-local path opens the corresponding systemd credential name.
This is not a general service `_PATH` fallback.

Older six-descriptor writer manifests no longer satisfy the exact launch
closure. Deployment requires provisioning the dedicated key and regenerating
and reapproving the credential-set, launch, configuration and generation
bindings together. There is no generated fallback key or compatibility bypass.
No live provisioning or deployment has been performed for this source.

The service requires the FD form, rejects a writer key path, and rejects either
form in other authority roles. Runtime-client admission excludes verifier,
planner and writer signer variables. The writer retains only its existing
writer DSN and planner-only peer topology; no planner read credential is added.

The service descriptor reader duplicates the FD, bounds the read, requires root
ownership and rejects group/other-writable mode bits. That reader alone does
not prove a regular or sealed FD, or membership in the launcher's retained
descriptor set. Exact descriptor inventory, source identity and sealing checks
belong to the upstream launch/entrypoint path. The available host-local path
does not establish HSM, enclave, native stage-zero, independent administration
or production deployment evidence.

The existing writer configuration mapper remains separate: four hashes, two
planner/verifier public-key decodes and the same seven-item persistence owner.
Its request APIs, immutable request custody and genuine two-replay atomic
suffix are unchanged.

## What an acknowledgment still requires

The [immutable request record](authority-revocation-writer-request-storage.md)
is not an ACK. A future closed acknowledgment must bind that exact request,
retained-plan and reserved-execution identities, historical configuration and
the dedicated writer response signer. It must attest custody, not execution,
current roots, capability issuance or a witness result.

Its immutable child record, signing boundary and recovery protocol remain to
be implemented. Creating an ACK after today's atomic owner returns cannot
claim to share that owner's already-completed transaction. Exact stored ACK
bytes may be released only after normal transaction and connection exit;
commit/exit uncertainty requires reconciliation. Exact retries must preserve
the original signed bytes. A separate historical lookup must not masquerade
as fresh authorization or bypass the current action's checks.

Remote ACK verification also needs an independently pinned public-key and
historical key/configuration resolution contract. A public key supplied by an
ACK cannot enroll itself. No ACK payload, purpose, schema, signer operation,
transport framing or public route is added here.

Authored component fixtures use genuine local PEM parsing, key derivation and
serialization with synthetic keys. Bounded source fixtures inspect the actual
service and descriptor wiring without executing extracted functions. Neither
proves service admission, descriptor provenance or production custody; the
fixtures remain unexecuted. Registry closure, the unfinished WebAuthn authority
gates, sealed preparation prerequisites and production signing/witness
provisioning remain open. Follow [goal.md](../goal.md) before any execution.
