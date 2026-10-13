> Publication note: deployment-specific addresses, identities and paths in this document are example placeholders, not a public service or release-verification evidence.

# Native buffered release: original context and temporary JIT refusal

## Status and scope

The Rust source introduced at `38c9689dd97ebb0347f23f356929fb1dea587835` carries the actual
buffered CONNECT request owners into atomic release preparation and reservation.
It does not yet admit a compound native JIT request, authorize sealing or
signing, or commit an atomic pending approval. The first 141-test attempt failed
two source guards; the corrected immutable retry passed all 146 selected tests
as recorded below. Normal compilation and combined CI for that checkpoint also
passed. The separate connection-owner continuation compiled and ran, but its
first attempt failed one binary test. Its corrected focused retry, normal
compilation and subsequent 58-suite CI passed. The normal executable also passed
the separate ordinary guided journey linked below; no native workflow or
deployment acceptance follows.
None of these component results is native workflow acceptance.

The companion Python change at `7013967b` temporarily refuses raw nested JIT
documents at five new-submission/retention boundaries. Its focused component
tests passed as recorded below. Neither change is deployed: the live app
remains `a3899a95` with normal gate `682d66d8…`.

This work follows the separate
[signed preparation retention repair](release-preparation-retention.md).
Retaining a verified prepare response and retaining a real request context are
necessary inputs, not substitutes for purpose-specific native admission.

## Rust: borrow the actual owners, preserve the original clock

`data-plane/decision-gate-rs/src/native_buffered_request.rs` defines private
borrowed context types joined to the actual CONNECT and release paths in
`main.rs`:

- `Context::open` samples the clock before each inner request head is read.
  Its deadline is at most 30 seconds from that opening, clipped by the remaining
  native cohort lifetime and any existing connection deadline. It neither
  resets the persistent keep-alive socket deadline nor reconstructs a fresh
  request window at reserve time.
- `BorrowedRequest` refers to the actual `ConnectAuthentication`, retained
  outer TLS connection/configuration, moved `IncomingRequest`, active snapshot
  and client-request digest. The normal buffered path borrows the writer only
  during the decision; the buffered proof path lends its retained ingress
  separately. These are not deserialized caller verdicts or copied summaries.
- Checks repeat the active snapshot identity, native lifetime, original
  connection deadline, generated TLS configuration/trust identity, completed
  TLS 1.3 handshake, actual peer-certificate evidence, authenticated principal
  and client address. The decision entrance also compares the original method,
  URL, body hash/length/UTF-8 projection and headers before credential metadata
  hydration, header transforms or active proof selection. The existing parsed
  gzip owner for npm audit requests is checked against both the original wire
  bytes and its decoded text.
- `DecisionOriginals` then borrows the trusted pipeline's actual final request,
  route and canonical value as `ReleaseOriginals`. Release checks require those
  same objects and the stable original request fields; a recreated JSON object
  cannot stand in for their ownership.

Native atomic JIT without this buffered context is refused before prepare or
reserve. Direct, preview, streaming and proof-observation compatibility paths
do not manufacture it. The existing non-JIT fallback remains; a genuine
context can only narrow its deadline.

The initial original-context check precedes credential-generation lookup. This
change propagates the original deadline specifically through prepare/reserve;
it does not add per-generation HTTP deadline propagation.

The context is checked before and after preparation and around reservation.
After reserve I/O, the existing shadow-attempt accounting records the actual
committed or unknown outcome before the post-I/O context check, with the
existing cleanup guard retained. A later freshness refusal must not erase an
uncertain outbound attempt or authorize replay. No retry is added.

## Connection-owner continuation — verified components, not native admission

The next source change adds `NativeIngressConnectionV1` in
`native_ingress_connection_v1.rs`, exported through `enclave_runtime_identity_v1`.
Only the retained `Arc<QuotedMutualTlsIngressV1>::open_connection` factory creates
it, from that ingress's exact generated configuration. The object retains the
actual rustls connection and the ingress that created it, with immutable views
only: no arbitrary connection import, replacement, mutable accessor or clone.
Named handshake/read/write/flush/buffered-read/close methods check the creator
process and original ingress lifetime before and after their operation.

The binary's `RetainedProxyIngressTls` now distinguishes imported TLS from this
library-owned connection. Native construction checks the exact generated
configuration/trust association and fails without an imported fallback. Socket
ownership, workload-trust handshake checks and the existing `DeadlineIo` remain
in the binary. Buffered release, ingress attestation, principal preflight and
enrollment/bootstrap callers obtain observations from the same retained owner;
the existing signing entrypoints are unchanged.

This establishes a factory/connection association, not independent quote,
caller or purpose admission, signing permission, readiness or JIT sealing.
Binary controls exercise real rustls over synthetic imported TLS, not a genuine
native owner. Library controls use a synthetic CA and explicitly invalid,
unverified quote bytes to exercise actual factory, connection, process and
lifetime checks. They do not acquire an NSM quote or prove hardware or
native-purpose acceptance. No result from the preceding 146-test build or
combined CI covers this continuation.

The first attempt at `2e520ab37600d0ea8f1f001cf375cee3cdd08a2c` compiled the
library tests in 61.305 seconds and passed all six. Binary test compilation took
401.127 seconds. The initial 149 tests in 31 filters passed; the additional
absolute-deadline control failed a stale raw-error assertion, so the final
control was initially not run. A separate continuation ran that last control
and passed. The first attempt therefore totals **150 binary tests passed and
one failed out of 151**, not a successful run. All five exact-diagnostic,
metadata-only external API probes passed separately. No normal executable was
compiled for this attempt.

The original failure and continuation receipts, including both test ELFs, were
copied from `serverware-native-ingress-rust.8XoRi61t` to the durable private
evidence directory `native-ingress-library-rust.gzjIOVOa/receipts`, with the copy
verified against the originals. All 43 cleanup receipts for that attempt passed.
The independently reviewed test-only correction at `cb1466be` preserves the
10 ms trickle delay and 25 ms absolute cap, and checks the sanitized error, the
same owner's `TimedOut` state and absence of additional progress.

The fresh retry at `cb1466be` passed **all six library tests, all 151 binary
tests in 33 filters, and all five exact-diagnostic API probes**. The library
test artifact was Cargo-fresh, byte-joined to the original `acec6291…` ELF,
and its six tests were actually rerun. Binary test compilation took 220.697
seconds and produced test ELF SHA256
`5e41f61328857ca97f26ee229ea6e6b1b391198980bc31061b271d88e430bfe2`.
The retry source-pin receipt SHA256 is
`1846e42d96961facdba696b3d7e383e4958b10be3a6ab1ae88bfa329ee2efa19`.
Normal compilation at `cb1466be` passed in 227.639 seconds, producing the
41,856,176-byte ELF SHA256
`0908732386fad8f7c89e761665fbda763d3c522b275d6c34ade5322cbaa54b6b`
with 518 recorded compiler inputs. At that compile checkpoint the normal
executable had **not been executed or deployed**. It was subsequently executed
in the isolated ordinary guided journey below, not deployed. All 44 retry cleanup
receipts passed, with zero owned containers remaining; the original retained
cache inputs were unchanged.

The durable retry receipt directory is
`native-ingress-library-rust-retry.qNDpQ9ui/receipts` under the private evidence
root. Its receipt SHA256 values are:

- `tests.json`: `9ec3c7e87d4ee69871cda2f84419ad7d1f1a0cce54147dff221f20d6343d82cb`.
- `libtests.json`: `8da7c84f5f43d80c6c966d34c5fd73f4919328ca712953b1b96b2723b605e117`.
- `api-tests.json`: `8af894307e80bddf89722af464c7f6b927ce8686ead95728a4a3aeb84236124c`.
- `normal.json`: `421da237cfe4e0c39897205fccb457c29828ee5acd25f4b93f9c8041c3da2608`.
- `normal-compiler-inputs.json`: `448d861b8c576627c35e2a7848aac1f4f8f2c75f6378b0fd3b1773ad4b7ea125`.

[CI 38404208827](https://github.com/example/private-deployment)
subsequently passed all 58 suites, 512 Python tests and 145 Node groups, with zero
skips, failures or reported exceptions in 447.976 seconds. Its retained
`ci-38404208827.zgrFniED/quick/result.json` SHA-256 is
`9c47b2f6a9df1c9fceb6b42cf8a9e91a711bc7abcf98a4fda777d0a53ff6e5a6`.
The separate [guided ordinary journey](operator-guided-verification.md#latest-october-13-checkpoint--ordinary-run-with-the-connection-owner-candidate)
passed at documentation-only successor `6cd18577` with this actual `09087323`
normal binary, including UI creation, proxy allow, audit and revocation/denial.
These results do not admit a native caller, private review or protected approval,
and did not change the live deployment. The earlier `3752cb7d` CI result below
remains evidence for its preceding checkpoint only.

## Python: temporary refusal at five boundaries

`serverware/authority_release_private_input.py` rejects any non-`None`
`jit_approval_request` on `release.reserve` or `release.v1.reserve`, even when
`require_jit_grant` is false. Empty objects, false scalars and other non-null
values are not a bypass. Missing or null input retains its existing meaning,
including existing-grant lookup; the guard does not rewrite arguments or admit
an otherwise invalid request.

The fixed error is
`Private JIT release input requires its explicit private profile`.
That profile is not implemented by this guard.

| Boundary | Placement of the refusal |
| --- | --- |
| Installed controlled-writer wrapper in `authority_store/authority_dispatch.py` | After the existing argument marshaling, before dispatch. |
| `authority_service._extract_v9_runtime_input` | After extracting either accepted envelope shape, before returning public typed arguments. |
| `authority_planner.PlannerPersistence.persist` | After existing signed-envelope/payload validation, before retention and opening its SQL connection. |
| `authority_store.executor_v9.complete_authority_planner_transaction` | Checks both the typed request and enclosing measured-plan operation before new plan retention. |
| `authority_store.executor_v9.reserve_authority_execution_envelope` | Checks the exact request before acquiring the lower writer or retaining the execution envelope. |

The upper `ExecutionEnvelopePersistence.reserve` caller can already have opened
a transaction before the lower guard runs. This is not a blanket zero-SQL-contact
claim. Historical typed-request validators, retained reads and committed replay
are unchanged: the refusal protects new submission/retention, not a rewrite or
deletion of historical evidence.

## Verification and remaining work

The Python privacy batch passed **67 tests in seven full suites**, including ten
new refusal controls, with zero failures or skips in 27.733 seconds. All 23
selected source pins were unchanged. The batch used the pinned cached image
with network disabled, two CPUs, 2 GiB memory and 128 PIDs; its cleanup receipt
passed. It exercises synthetic boundary/privacy, historical commitments,
registry, approval/denial and runner controls, not a database service, native
admission or atomic release acceptance. That run did not execute or accept the
entire `test_authority_typed_request_work.py` suite because it then contained an
obsolete registry-failure expectation; its original `notRun` receipt is unchanged.

The retained result is
`jit-release-privacy.Ox3YTfZp/results/result.json` under the private evidence
root, SHA256
`742eaa1b78eb926c8bd48bf7b60c48c4084db0f9711f455dc5d69680cacc2376`.

The separate test-only correction at `4dcf4a5b` replaced that obsolete expectation
with genuine successor refusal before the legacy shared worker, plus an actual
allowed `webauthn.counter.cas` commitment through that worker. All nine groups
in `test_authority_typed_request_work.py` then passed in 2.135 seconds, with zero
skips and all eight selected source pins unchanged; host cleanup completed.
Its separate result is `typed-request-registry.2OJUlMSF/results/result.json`,
SHA256 `c37f02a79ff8685fb46d26efa191598c7ae8f6008c789f1c96339b938816f0f4`.
These are synthetic request/commitment and facade-partition controls, not native
owner or database acceptance, and do not retroactively expand the 67-test run.

The first Rust test build at `38c9689d` compiled. Across its initial run and
continuation, all 141 selected tests were attempted: 139 passed and two stale
source guards failed. The seven new original-context controls and prior 132
tests passed. Five additional behavioral controls passed separately; those
results do not turn the failed 141-test attempt into a passing run.

The approved test/source-guard correction (`main.rs` SHA256 `4e40cc72…`) leaves the
production prefix byte-identical. The full retry at immutable
`72964375a612b7616b4fbbc1f1ac6632cdf62b3e` passed **146 tests in 31 disjoint
filters**, with zero failures or ignored tests. Test compilation took 211.386
seconds. Its test ELF is
`3f0382858ad60be08ee50f25090b42c077e40fc4791edcb2145d0ffd5ed996a4`;
the source-pin receipt SHA256 is
`9bf487494ff7704bbe5fe47231dc239e3c0a9b3b2ef36e2618b28d1f7d08c68f`.
The durable evidence location is
`native-buffered-context-rust-retry.5l8k0KEb/receipts` under the private evidence
root; `tests.json` SHA256 is
`5f99451d16a723d6e543668b079a1443624ffef81b0dab014ff9ed4207ced208`.
The seven new controls use in-memory rustls mutual authentication under a
synthetic CA; their credential/proof metadata is synthetic. They do not create
a genuine native owner or prove native admission.
Normal compilation passed in 234.753 seconds, producing ELF SHA256
`4bfa872918930dce7b11d4b38de2c2a178c290b8f7d90df63f74d319e530752e`
with 517 recorded compiler inputs. The normal executable was not run or
deployed; the 146 tests ran the separate test executable. `normal.json` SHA256
is `3ea870dbc87cd7bcbd0e67217c0cf5347edb4142d1e1502288320d21ae9f4057`,
and `normal-compiler-inputs.json` SHA256 is
`cfa32331f65c6396e1b6394fe31bd99e305991ebf81d266ed3477e06a0b89bf3`.
All 34 build/listing/test container cleanup receipts passed. The original
retained cache/vendor inputs stayed unchanged; the new cache remains reusable.

[CI 38398147094](https://github.com/example/private-deployment)
at `3752cb7d` passed all 58 suites, 512 Python tests and 145 Node groups, with zero
skips in 448.585 seconds. The structural result is
`ci-38398147094.rUE6xJu1/quick/result.json`, SHA256
`89d24baf005850035e98e184e2bc6dc3e00184d2e96042311e63539c48ebc911`.
Artifact `11813962054` has digest
`sha256:22f594a929f651cea114b33252943282416791595a689165ec0a5c5bb0f9d260`.
This is ordinary offline component CI, not Rust execution, rendered-browser,
SDK, native admission or deployment evidence, and predates the connection-owner
continuation above.
The earlier [CI 38391048077](https://github.com/example/private-deployment)
at `dd326cac` passed 57 suites, 502 Python tests and 145 Node groups with zero
skips; its historical receipt remains separate.

The read-only live check at October 13, 12:23:59 UTC found the same four healthy
containers with zero restarts, app source `a3899a95` and gate `682d66d8…`.
TLS-verified console HEAD returned 302 and proxy-health GET returned 200, not
503. These are unauthenticated health/readback observations, not an authenticated
operator, approval or provider workflow, and no deployment occurred.

Still required are purpose-specific compound native admission and sealing,
exact parent-reserve/child-JIT bindings, atomic custody/evidence/pending-row
retention, authenticated private-review opening, and a preservation migration
from the ordinary live owners to the required authority owners. The ordinary
approval UI, expiry/terminal handling, exact-request continuation and actionable
notification source also remain incomplete. Notification delivery or receiver
acknowledgement is not approval authority. Genuine measured end-to-end and
deployment acceptance remains outstanding; no pilot or live change is part of
this checkpoint.
