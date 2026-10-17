# Cold registration SQL/completion handoff scope

This source-only opt-in configuration extends the existing
[control-plane caller bootstrap](control-plane-registration-execution.md).
It does not deploy a service, admit a release, establish live currentness or
turn an earlier preparation/reservation result into permission to continue.
The current source remains unbuilt and unexecuted.

## Version and field contract

The parent signed `catchplate.signedControlPlaneEnrollmentBootstrap/v3` and
payload `catchplate.controlPlaneEnrollmentBootstrap/v3` remain unchanged and
bounded to 4 MiB. Their `registrationExecution` field may still be null to
disable the caller purpose. Existing nested v1 remains authorizer-only; nested
v2 adds reservation only. Neither is automatically promoted.

The explicit nested `catchplate.controlPlaneRegistrationExecution/v3` is a
closed, twelve-field object. All fields are required and none is nullable:

| Field | Contract |
| --- | --- |
| `schema` | Exactly `catchplate.controlPlaneRegistrationExecution/v3` |
| `executionCallerPrivateKeyFd` | Exactly `203`; unchanged dedicated caller key |
| `currentRootEnrollment` | Exact original `{base64Url, byteCount}`, at most 128 KiB |
| `grantEnrollment` | Exact original `{base64Url, byteCount}`, at most 16 KiB |
| `authorizationEnrollment` | Exact original `{base64Url, byteCount}`, at most 16 KiB |
| `authorizerEndpoint` | Fixed `authorizer.sock` endpoint below |
| `reserverEndpoint` | Fixed `reserver.sock` endpoint below |
| `statePredecessor` | Independent `{sequence, headDigest, nextFence}` reservation precondition |
| `sqlEndpoint` | Fixed `sql.sock` endpoint below |
| `completionEndpoint` | Fixed `completion.sock` endpoint below |
| `currentPending` | Independent `{sequence, headDigest, fence}` for this operation |
| `completionPacketDigest` | Independent canonical `sha256:` plus 64 lowercase hexadecimal digits |

Each endpoint has exactly `socketPath`, `requestTimeoutSeconds`, `listenerUid`
and `listenerGid`. Its path is its named socket beneath
`/run/catchplate/registration-execution/`; timeout is an integer from 1 through
30 seconds; listener UID/GID are exactly `0:0`. These pin the root manager that
activated the listener, not the accepting service process. Paths, peers and
timeouts cannot be selected from a response or overridden through environment
settings. Endpoint identity does not authenticate the returned originals.

Enrollment byte counts are integers of at least two; base64url is canonical
and unpadded at genuine original admission. All digest fields use the canonical
`sha256:` lowercase-hex spelling. Sequence and fence values are exact integers,
not booleans. The source sequence cap is 1024; fences are positive signed-63-bit
integers. `statePredecessor.sequence` may be zero, whereas
`currentPending.sequence` must be positive.

## One independently pinned operation

The [actual nested verifier](../catchplate/control_plane_registration_execution_bootstrap.py)
authenticates the three original enrollments on the parent's existing work and
retains their configuration, generation, caller-purpose and distinct-key joins.
Capacity comes from the genuine current-root enrollment, not the configuration
claim or a received acknowledgment. A genesis predecessor must name that actual
enrollment digest and `nextFence: 1`.

This profile deliberately selects one cold per-operation scope:

- `currentPending.sequence` equals `statePredecessor.sequence + 1`;
- `currentPending.fence` equals `statePredecessor.nextFence`;
- the predecessor must fit enrolled capacity, and the pending sequence must
  be strictly below the enrolled maximum to leave completion capacity.

The pending **head digest** and completion **packet digest** remain independent
root pins. The arithmetic joins do not compute them, prove they are current,
or establish that a packet was issued. They must not be copied from a reserve
acknowledgment, SQL response, completion response or scanned journal. A response
cannot advance this bootstrap's checkpoint or select another operation.
Independent currentness and root-provisioning evidence remain external.

The private material adds `sql_endpoint`, `completion_endpoint`,
`current_pending` and `completion_packet_digest`; each remains `None` for
nested v1/v2. These are ordinary held configuration values, not a successful
verification token. The actual caller composition must still authenticate
the original controls, join the same independently pinned scope, respect its
unchanged lifetime, and enforce its durable delivery/uncertainty rules.

## Delivery and authority boundary

The [early descriptor projection](../catchplate/authority_fd_entrypoint.py)
checks the exact versioned shape, fixed endpoints, scalar bounds and same-launch
sequence/fence relationship before selecting the existing caller-key slot.
It does not replace the child's signature, enrollment or generation checks.
FD203 remains distinct from the enrollment issuer/bootstrap descriptors and
the original signed runtime inventory; collisions still fail closed.

No new descriptor or private purpose is delivered. SQL credentials remain with
the [SQL worker](registration-execution-sql-service.md); the completion private
key and read-role TLS identities remain with the
[completion worker](registration-execution-completion-service.md). This caller profile
does not grant general SQL access, share those keys, activate a public execution
route, finalize a credential, or supply retry permission after uncertainty.
It is not deployment, hardware custody, witness or production-admission evidence.
