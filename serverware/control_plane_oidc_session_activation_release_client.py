"""Configured one-use private release handoff on the actual cold owner.

Only public originals and root-configured scope enter this lane. An actual
token-free durable authorization claim precedes its sole socket exchange.
Original response verification and owner continuity gate the raw64 result.
No plaintext journal, private key, new allowance, fallback or retry exists.
"""
from __future__ import annotations

from dataclasses import dataclass
import time

from serverware import control_plane_enrollment_startup as startup
from serverware import control_plane_custody_client as custody
from serverware import control_plane_oidc_session_activation_release_bootstrap as configured
from serverware import control_plane_oidc_session_activation_release_attempt as attempts
from serverware import oidc_session_activation_release_client_authorization as clients
from serverware import oidc_session_activation_release_transport as transport
from serverware import authority_oidc_session_activation_release_response as receiving


authorization, shape, plan = clients.authorization, clients.shape, clients.plan
capture, production, clock = clients.capture, clients.production, clients.clock
delivery, processing = clients.delivery, clients.processing


def _fail(message):
    raise startup.EnrollmentStartupError(message)


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _Held:
    owner: object
    material: object
    binding: object
    custody_owner: object
    release: object
    client_original: bytes
    server_original: bytes
    scope_original: bytes
    root_public_key: object
    scope: dict
    request: tuple
    window: tuple
    deadline_ns: int


def _hold(owner, request_originals, live_window, transport_deadline_ns, work):
    capture._SharedLedger(work)
    material, binding, custody_owner = owner._material, owner._binding, owner._custody
    if material is None or type(binding) is not custody._Binding:
        _fail("release caller requires its actual cold configuration and custody binding")
    release = material.release_client
    if type(release) is not configured._ReleaseClientMaterial:
        _fail("release caller purpose is not independently cold-enabled")
    if (binding.caller_uid, binding.caller_gid) != (clients.CLIENT_UID, clients.CLIENT_GID):
        _fail("release caller differs from its fixed control-plane identity")
    client_original = authorization._original(release.client_authorization_bytes,
        clients.MAX_BYTES, "configured release client authorization")
    server_original = authorization._original(release.server_bootstrap_bytes,
        clients.MAX_SERVER_BOOTSTRAP_BYTES, "configured release server bootstrap")
    scope_original = authorization._original(release.expected_scope_bytes,
        clients.MAX_BYTES, "configured independent release scope")
    root = binding.runtime_root_public_key
    authorization._public(root)
    window = clock._validate(live_window)
    shape._integer(transport_deadline_ns, minimum=1)
    bound = min(transport_deadline_ns, window[4])
    if type(request_originals) is not tuple or len(request_originals) not in (7, 8):
        _fail("release caller requires its exact original raw7 or raw8 request")
    request = request_originals
    for index, raw in enumerate(request):
        if type(raw) is not bytes or not 2 <= len(raw) <= transport.RECOVERY_REQUEST_LIMITS[index]:
            _fail("release caller request exceeds its fixed original field bound")
    # Reserve the complete raw2/header capacity before admission or network I/O.
    total = sum(len(raw) for raw in (*request, client_original, server_original, scope_original))
    total += 8 + 8 * len(request) + transport.RESPONSE_HEADER_BYTES + transport.MAX_RESPONSE_BYTES
    if total > receiving.MAX_ORIGINAL_BYTES:
        _fail("release caller complete original inventory exceeds its aggregate bound")
    work.charge(input_bytes=total)
    # All external byte references, actual owner/key references and supplied
    # clock scalars are held before canonical decoding/hash/native callbacks.
    scope = configured._scope_on_work(scope_original, work)
    request = transport._originals(request, response=False, profile=scope["profile"])
    for observed, expected in ((material.configuration_digest, binding.configuration_digest),
            (scope["configurationDigest"], binding.configuration_digest)):
        plan._same(observed, expected, work, "release caller actual cold configuration")
    return _Held(owner, material, binding, custody_owner, release, client_original,
        server_original, scope_original, root, scope, request, window, bound)


def _request_locked(held, work):
    window = processing._narrow(held.window,
        deadline_epoch_ns=held.binding.attestation_interval[1],
        maximum_lifetime_ns=held.binding.maximum_deadline_ns,
        maximum_clock_skew_ns=held.window[6])
    bound = min(held.deadline_ns, window[4])
    last_epoch, last_monotonic = held.window[0], held.window[2]
    admitted = None

    def identity():
        owner, release = held.owner, held.release
        if (type(owner) is not startup._EnrollmentOwner or owner._release_spent is not True
                or owner._material is not held.material or owner._binding is not held.binding
                or owner._custody is not held.custody_owner or held.material.release_client is not release
                or release.client_authorization_bytes is not held.client_original
                or release.server_bootstrap_bytes is not held.server_original
                or release.expected_scope_bytes is not held.scope_original
                or held.binding.runtime_root_public_key is not held.root_public_key):
            _fail("release caller cold ownership changed during its one exchange")

    def sample(observed):
        nonlocal last_epoch, last_monotonic
        shape._integer(observed, minimum=1)
        monotonic = production._callback(work, time.monotonic_ns)
        shape._integer(monotonic, minimum=1)
        if observed < last_epoch or monotonic < last_monotonic or monotonic >= bound:
            _fail("release caller original processing clocks expired or reversed")
        last_epoch, last_monotonic = observed, monotonic

    def current(epoch_floor=None, monotonic_floor=None):
        nonlocal last_epoch, last_monotonic
        if epoch_floor is not None or monotonic_floor is not None:
            shape._integer(epoch_floor, minimum=1)
            shape._integer(monotonic_floor, minimum=1)
            last_epoch = max(last_epoch, epoch_floor)
            last_monotonic = max(last_monotonic, monotonic_floor)
        capture._SharedLedger(work)
        identity()
        # Fixed metadata continuity only, not _live's unrelated HTTP private-key
        # load. At most four existing sealed descriptors are inspected; none is
        # read, transferred, relaxed or owned by this public-only component.
        work.charge(input_bytes=4096)
        sample(production._callback(work, lambda: startup._continuity(held.owner)))
        sample(clock._check_on_work(window, work=work))
        if admitted is not None:
            sample(admitted.live())
            sample(clock._check_on_work(window, work=work))
        identity()
        return last_epoch

    def receiving_continuity(epoch_floor, monotonic_floor):
        current(epoch_floor, monotonic_floor)
        # Only stricter actual clock floors cross this seam, never permission,
        # policy, a successful result or a replacement processing allowance.
        return last_epoch, last_monotonic

    current()
    admitted = clients._verify_on_work(authorization_bytes=held.client_original,
        server_bootstrap_bytes=held.server_original, root_public_key=held.root_public_key,
        expected_scope=held.scope, live_window=window, transport_deadline_ns=bound, work=work)
    if type(admitted) is not clients._ClientAuthorization:
        _fail("release caller requires actual original client/server admission")
    candidate = clock._validate(admitted.live_window)
    shape._integer(admitted.deadline_ns, minimum=1)
    if (candidate[:3] != window[:3]
            or any(value > prior for prior, value in zip(window[3:], candidate[3:]))
            or admitted.deadline_ns > bound or admitted.deadline_ns > candidate[4]):
        _fail("release caller cannot renew its original processing allowance")
    window, bound = candidate, admitted.deadline_ns
    current()
    endpoint = clients._endpoint(held.scope["endpoint"], work)
    profile = held.scope["profile"]
    request_identity = transport._request_identity_on_work(held.request,
        profile=profile, deadline_ns=bound, work=work, current=current)
    expected_identity = plan._ascii(held.scope["requestIdentity"], work)
    work.charge(input_bytes=len(request_identity) + len(expected_identity))
    if request_identity != expected_identity:
        _fail("release caller exact request differs from its independently configured identity")
    current()
    # The grant digest, not tokens or exchange bytes, keys the irreversible
    # durable slot. Existing or uncertain claims never permit a socket call.
    work.charge(input_bytes=attempts.MAX_CLAIM_IO_BYTES)
    production._callback(work, lambda: custody.ControlPlaneCustodyClient.claim_oidc_session_activation_release(
        held.custody_owner, client_authorization_digest=admitted.authorization_digest,
        request_identity=held.scope["requestIdentity"], profile=profile,
        server_bootstrap_digest=held.scope["serverBootstrapDigest"],
        expected_outcome_digest=held.scope["expectedOutcomeDigest"]))
    current()
    # The actual transport charges this same work and invokes current for every
    # chunk and normal close. Never enclose it in a metrics-stable callback.
    returned = transport._socket_request(endpoint, profile=profile, originals=held.request,
        deadline_ns=bound, work=work, current=current)
    current()
    # Tail-return inside the receiver's final original intent/proof/client and
    # bilateral owner guards; no weaker native suffix follows those checks.
    return receiving._verify_on_work(response_originals=returned, request_originals=held.request,
        client_authorization_bytes=held.client_original, server_bootstrap_bytes=held.server_original,
        root_public_key=held.root_public_key, expected_client_scope=held.scope,
        live_window=window, transport_deadline_ns=bound, work=work, _continuity=receiving_continuity)


def _request_on_owner(owner, *, request_originals, live_window, transport_deadline_ns, work):
    """One configured private handoff, not a public/portal permission endpoint."""
    with startup._LOCK:
        if type(owner) is not startup._EnrollmentOwner:
            _fail("release caller requires the actual cold enrollment owner")
        if owner._release_spent is not False:
            _fail("release caller has already spent its one-use operation")
        # Irreversible even if holding/admission/claim fails before any send.
        # A fresh process also has to pass the independently durable grant claim.
        owner._release_spent = True
        held = _hold(owner, request_originals, live_window, transport_deadline_ns, work)
        return _request_locked(held, work)
