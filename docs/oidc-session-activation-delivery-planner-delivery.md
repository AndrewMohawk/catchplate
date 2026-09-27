# Consume-planner cold delivery

This is source-only, unbuilt and unexecuted delivery for the separate
`oidc.session.activation-delivery.consume` planner. It connects the
[root-admitted cold construction](oidc-session-activation-delivery-planner-bootstrap.md)
to a fixed operating-system launch; it does not issue a consume execution grant,
reserve or execute SQL, release a token, or provide a public permission route.

## Originals before private keys

The fixed root entrypoint reads the independent root public key, the original
consume-planner bootstrap and the separate consume-history-v2 custody original.
Actual canonical/signature, configuration, purpose and original-byte joins run
before opening private keys, TLS originals or the journal directory. Completion
history v1 is not relabeled as consume-planning custody. A verifier result from
another caller is never accepted instead of these originals.

`_construction_on_work(work)` samples one actual epoch/monotonic bracket using
source maximum age/skew before trust-original I/O. Admission and subsequent
construction share that work and inherited deadline. The same first three
samples are narrowed to the signed planning policy and both fresh outer launch
expiries; the historical activation planner's expired interval is not used as a
current processing clock. Root delivery and child startup each authenticate the
originals under their own bounded admission call; neither accepts a parent
success token or renews an allowance within that call.

Only protected source-fixed paths are opened, through nonsymlink root-owned
ancestors. Trust files live under
`/run/serverware/oidc-session-activation-delivery-planner-trust` as
`root-public-key.pem`, `bootstrap.json` and `history.json`. Their respective
maximum sizes are 16 KiB, 4 MiB and 8 MiB. Original bytes are retained in sealed
root-owned memfds; all private source files are single-link, root-owned mode
`0400` regular files.

| FD | Fixed original or resource |
| --- | --- |
| 198 | Independent root public key |
| 199 | Root-signed consume-planner bootstrap |
| 200 | Activated Unix stream listener |
| 201 | Separate original consume-history-v2 custody |
| 202 | Historical activation execution-bundle AES key |
| 203 | Historical activation delivery AES key |
| 204 | Dedicated consume-planner Ed25519 signing key |
| 205 | Separate consume-original-journal AES key |
| 206 | Independently pinned private journal directory |

The three AES originals are exactly 32 raw bytes and must differ pairwise.
Their actual SHA-256 digests join the independently signed custody/journal pins.
The actual signing key pair and SPKI join the dedicated planner identity.
`_keys_on_work(material, work)` returns the private local tuple
`(planner_private_key, bundle_key, delivery_key, journal_key)` only after these
checks. No key is serialized into a request, plan, environment value or response.

The fixed key paths are `/run/secrets/serverware-oidc-session-activation-` plus
`bundle-key`, `delivery-key`, `delivery-planner-key` and
`delivery-journal-key`. Shared historical bundle/delivery keys do not transfer
completion or token-release authority to this role.

## Fixed process and resources

The root entrypoint requires one activated listener named
`serverware-oidc-session-activation-delivery-planner`. Its fixed path is
`/run/serverware/oidc-session-activation/delivery-planner.sock`, with filesystem
owner `65501:65532`, mode `0660`; kernel and filesystem socket identities are
separate signed pins. The journal is exactly
`/var/lib/serverware/oidc-session-activation-delivery-planner`, owned by
`65501:65501`, mode `0700`, with signed device/inode and bounded count/quota.
No resource is created, repaired or provisioned by the launcher.

PostgreSQL uses only the admitted fixed TLS files below
`/run/serverware/oidc-session-activation-delivery-planner-tls`: `ca.pem`,
`client.crt` and `client.key`. The two public files are root-owned mode `0444`;
the private TLS key is root-owned mode `0440`, group `65501`, for the dropped
libpq client. Bounded content hashing spends the supplied work allowance;
fixed-path metadata continuity is rechecked afterward. These checks do not
defeat a malicious host administrator.

After checking originals and resources, root delivery permanently drops all
three UID/GID identities to `65501`, clears supplementary groups, and retains
exactly the nine nonstandard descriptors above. The child environment contains
only `PATH`, `LANG`, `TZ`, `LD_LIBRARY_PATH`, `PYTHONDONTWRITEBYTECODE`,
`SERVERWARE_PROCESS_MODE`, and the two fixed root/bootstrap FD variables.
There are no ambient libpq credentials, caller-selected module paths or secret
path overrides. The standalone launcher accepts only fixed `--root-delivery`
and `--run` modes under isolated `/runtime/python/bin/python3`, with protected
installed runtime/source directories.

## One accepted request

The [private service](oidc-session-activation-delivery-planner-service.md)
reauthenticates the sealed originals and constructs the actual reader,
consume-history owner, encrypted journal and retained plan owner. Its original
construction bracket/deadline also bounds idle polling and request processing.
The runner calls `initialize_from_environment()`, then
`require_started().serve_once()`, and always calls `close()` on exit. Only an
idle poll may return `False`; the first accepted connection is terminal,
including malformed input, rejection or uncertain retention/response outcome.
There is no automatic replay, re-signing, token rotation or retry.

The [socket](../ops/systemd/serverware-oidc-session-activation-delivery-planner.socket)
and [service template](../ops/systemd/serverware-oidc-session-activation-delivery-planner.service.in)
are uninstalled deployment inputs. They require independently admitted accounts,
release, originals, keys, TLS/database identity, journal and the state-v7 socket
ACL for UID `65501`. No supplementary state group, state signing key, state
journal or general mutation privilege is granted. The image recipe includes the
fixed standalone launcher; no image was built or service started.

Trusted-host-local custody is not TEE custody, an off-host rollback witness or
atomic action-time authorization. Deadline checks do not preempt a blocked
native/kernel call. A lost response may follow successful encrypted retention.
Consume issuance, reservation, protected SQL, historical recovery, committed
one-use release and the public/portal handoff remain separate work. This source
delivery does not close a production-verification gate.
