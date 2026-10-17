"""Explicit local root decisions for the first registration's two late scopes.

These records authorize a selected predecessor/pending head; signed history is
not their authority. The independent root supplies an exact protected approval
and original raw10/raw3. The existing admission and packet preparer replay them
before signing. The real control-plane owner repeats original/subject/custody
admission. A record is immutable, linked, one action only, and never renews an
original interval. This is not a current-state discovery or SQL retry service.

The launcher first invokes prepare_directory(), then pins its returned identity
in the explicit local nested bootstrap. Root automation publishes the fixed
reserve filename after grant retention, and the execute filename after genuine
reservation retention. Existing authenticated application actions remain the
only callers of reserve/SQL/completion. Missing decisions refuse, never approve.
"""
from __future__ import annotations

import ctypes
import os
import stat
import time
import select
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from catchplate import authority_local_enrollment_configuration as local
from catchplate import authority_current_root_authorization as roots
from catchplate import authority_successor_execution_packet as packets
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork

io, keys, signer = local.io, local.keys, local.signer
canonical, document, sha = local.canonical, local.document, local.sha
DIRECTORY = "/run/catchplate/registration-contexts"
SCHEMA = "catchplate.authorityTrustedHostLocalRegistrationContext/v1"
SIGNED_SCHEMA = "catchplate.signedAuthorityTrustedHostLocalRegistrationContext/v1"
APPROVAL_SCHEMA = "catchplate.authorityTrustedHostLocalRegistrationContextApproval/v1"
REQUEST_SCHEMA = "catchplate.authorityTrustedHostLocalRegistrationContextRequest/v1"
MAX_CONTEXT, MAX_AGE_NS = 32768, 300_000_000_000
# The protected approval embeds the literal request as a JSON string. Reserve
# worst-case escaping plus the fixed decision wrapper within the existing cap.
MAX_REQUEST = (io.MAX_PUBLIC - 8192) // 2
PURPOSES, STAGES = ("execution", "finalization"), ("reserve", "execute")
_CAPS = frozenset({"bootIdDigest", "issuedAtMonotonicNs", "deadlineMonotonicNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
_FIELDS = frozenset({"schema", "sourceRevision", "purpose", "stage", "configurationDigest", "generationDigest",
    "currentRootEnrollmentSha256", "grantEnrollmentSha256", "authorizationEnrollmentSha256", "callerSpkiDigest",
    "localDigest", "subject", "originalsSha256", "reservationSha256", "scope", "priorContextSha256",
    "completionPacketDigest", "completionAuthorizationDigest"}) | _CAPS
_SUBJECT = frozenset({"localDigest", "userId", "sessionId", "challengeId", "mode", "requestDigest", "operationId"})
_COMMON = frozenset({"payload", "configuration_digest", "generation", "runtime_role_identities",
    "authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"})
_REQUEST_FIELDS = frozenset({"schema", "purpose", "stage", "localDigest", "subject", "directory", "common",
    "originals", "reservationOriginals", "callerPublicKeyBase64Url", "bootIdDigest", "deadlineMonotonicNs",
    "expiresAtUnixNanos", "priorContextOriginal"})


def require(value):
    if not value:
        raise ValueError("local first-registration context refused")


def _development():
    from catchplate import config
    require(not config.PRODUCTION_IMAGE and os.environ.get("CATCHPLATE_RELEASE_CHANNEL") == "dev")


def directory(value):
    require(type(value) is dict and set(value) == {"path", "device", "inode"} and value["path"] == DIRECTORY)
    for name, minimum in (("device", 0), ("inode", 1)):
        require(type(value[name]) is int and minimum <= value[name] < 2**64)
    return value["device"], value["inode"]


def _cold_profile(material, original):
    """After genuine parent admission, prohibit mixing local and later history."""
    from catchplate import control_plane_enrollment_bootstrap as bootstrap
    from catchplate import control_plane_oidc_session_activation_request_issuance_bootstrap as request_planning
    schema = document(original, bootstrap.MAX_BYTES)["schema"]
    request_bound = (schema == bootstrap.V24_SCHEMA
        and type(material.activation_planning) is request_planning._RequestPlanningMaterial
        and material.activation_execution is not None and material.activation_execution.request_bound is True
        and material.consume_execution is not None and material.consume_execution.request_bound is True)
    require((schema == bootstrap.V4_SCHEMA or request_bound)
        and material.execution is not None and material.finalization is not None
        and material.execution.context_directory is not None
        and material.finalization.context_directory == material.execution.context_directory
        and material.registration_history is None and material.finalization_history is None)


def filename(purpose, digest, stage):
    require(purpose in PURPOSES and stage in STAGES)
    roots.shape._digest(digest)
    return purpose + "-" + digest[7:] + "-" + stage + ".json"


def _shape(value, *, draft=False):
    require(type(value) is dict and set(value) == _FIELDS and value["schema"] == SCHEMA
        and value["sourceRevision"] == roots.authority.SOURCE_REVISION
        and value["purpose"] in PURPOSES and value["stage"] in STAGES)
    for name in ("configurationDigest", "generationDigest", "currentRootEnrollmentSha256", "grantEnrollmentSha256",
            "authorizationEnrollmentSha256", "callerSpkiDigest", "localDigest", "bootIdDigest"):
        roots.shape._digest(value[name])
    subject = value["subject"]
    require(type(subject) is dict and set(subject) == _SUBJECT and subject["localDigest"] == value["localDigest"])
    for name in ("requestDigest", "operationId"):
        roots.shape._digest(subject[name])
    for name in ("userId", "challengeId", "mode"):
        require(type(subject[name]) is str and 0 < len(subject[name].encode("utf-8")) <= 4096)
    require(subject["sessionId"] is None or type(subject["sessionId"]) is str
        and 0 < len(subject["sessionId"].encode("utf-8")) <= 4096)
    for first, last in (("issuedAtMonotonicNs", "deadlineMonotonicNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
        require(type(value[first]) is type(value[last]) is int and 0 < value[first] < value[last] < 2**63
            and value[last] - value[first] <= MAX_AGE_NS)
    require(type(value["originalsSha256"]) is list and len(value["originalsSha256"]) == 10)
    for pin in value["originalsSha256"]:
        roots.shape._digest(pin)
    reserve = value["stage"] == "reserve"
    scope = value["scope"]
    require(type(scope) is dict and set(scope) == {"sequence", "headDigest", "nextFence" if reserve else "fence"})
    roots.shape._integer(scope["sequence"], roots.MAX_RECORDS, minimum=0 if reserve else 1)
    roots.shape._digest(scope["headDigest"])
    roots.shape._integer(scope["nextFence" if reserve else "fence"], minimum=1)
    if reserve:
        require(value["reservationSha256"] is value["priorContextSha256"] is value["completionPacketDigest"]
            is value["completionAuthorizationDigest"] is None)
        require(scope["sequence"] != 0 or scope["nextFence"] == 1)
    else:
        require(type(value["reservationSha256"]) is list and len(value["reservationSha256"]) == 3)
        for pin in (*value["reservationSha256"], value["priorContextSha256"]):
            roots.shape._digest(pin)
        for name in ("completionPacketDigest", "completionAuthorizationDigest"):
            if not (draft and value[name] is None):
                roots.shape._digest(value[name])
    return value


def _fresh(value):
    mono, epoch = time.monotonic_ns(), time.time_ns()
    require(value["bootIdDigest"] == local.configuration.launcher._boot_identity_digest()
        and value["issuedAtMonotonicNs"] <= mono < value["deadlineMonotonicNs"]
        and value["issuedAtUnixNanos"] <= epoch < value["expiresAtUnixNanos"])


def _narrow(value, window, bound):
    from catchplate import authority_webauthn_evidence_plan_clock as clock
    expiry = min(window[3], value["expiresAtUnixNanos"])
    result = (window[0], window[1], window[2], expiry,
        min(window[4], window[1] + expiry - window[0]), window[5], window[6])
    return clock._validate(result), min(bound, result[4], value["deadlineMonotonicNs"])


def _read(raw, root, work):
    require(type(raw) is bytes and 2 <= len(raw) <= MAX_CONTEXT)
    envelope = signer.capability.wire._decode_object(raw, work=work, maximum_bytes=MAX_CONTEXT,
        maximum_nodes=4096, maximum_depth=12)
    require(type(envelope) is dict and set(envelope) == {"schema", "payload", "signatureBase64Url"}
        and envelope["schema"] == SIGNED_SCHEMA)
    value = _shape(envelope["payload"])
    signer.codec._canonical(raw, envelope, work)
    signer.capability._signature(root, envelope["signatureBase64Url"], SIGNED_SCHEMA,
        signer.configuration._configuration_wire(value, signer.capture._SharedLedger(work)),
        signer.capture._SharedLedger(work))
    signer.codec._canonical(raw, envelope, work)
    _fresh(value)
    return value


def _record(purpose, originals):
    if purpose == "execution":
        from catchplate import control_plane_registration_execution_records as records
    else:
        from catchplate import control_plane_registration_finalization_records as records
    return records.encode(originals)[0]


def _join(value, common, originals, reserved, caller_public_key, work):
    require(set(common) == _COMMON | {"root_public_key"})
    enrolled = tuple(common[name + "_enrollment_bytes"] for name in ("current_root", "grant", "authorization"))
    held = (*originals, *(reserved or ()), *enrolled)
    work.charge(hashes=len(held) + 1, input_bytes=2 * sum(map(len, held)))
    require(value["configurationDigest"] == common["configuration_digest"]
        and value["generationDigest"] == common["generation"]["digest"]
        and value["localDigest"] == _record(value["purpose"], originals)
        and value["originalsSha256"] == [sha(raw) for raw in originals]
        and value["reservationSha256"] == (None if reserved is None else [sha(raw) for raw in reserved])
        and value["callerSpkiDigest"] == roots.keys._spki_on_work(caller_public_key, work))
    for name, field in (("current_root", "currentRoot"), ("grant", "grant"), ("authorization", "authorization")):
        require(value[field + "EnrollmentSha256"] == sha(common[name + "_enrollment_bytes"]))
    current = roots._admit_enrollment_on_work(enrollment_bytes=common["current_root_enrollment_bytes"],
        root_public_key=common["root_public_key"], work=work)
    scope = value["scope"]
    require(scope["sequence"] < current.payload["maxRecords"])
    if value["stage"] == "reserve" and scope["sequence"] == 0:
        require(scope["headDigest"] == current.enrollment_digest)


def _link(value, prior, prior_raw):
    require(value["stage"] == "execute" and prior["stage"] == "reserve"
        and value["priorContextSha256"] == sha(prior_raw))
    for name in (_FIELDS - {"schema", "stage", "scope", "priorContextSha256", "reservationSha256",
            "completionPacketDigest", "completionAuthorizationDigest"}):
        require(value[name] == prior[name])
    require(value["scope"]["sequence"] == prior["scope"]["sequence"] + 1
        and value["scope"]["fence"] == prior["scope"]["nextFence"])


def _replay(value, common, originals, reserved, work, *, derive=False):
    """Use the real source validators, never a supplied successful carrier."""
    from catchplate import authority_registration_execution_exchange as execution
    from catchplate import authority_registration_finalization_execution_admission as finalization
    window = execution.clock._open_on_work(deadline_epoch_ns=value["expiresAtUnixNanos"],
        maximum_lifetime_ns=execution.evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
        maximum_clock_skew_ns=0, work=work)
    bound = min(window[4], value["deadlineMonotonicNs"])
    if value["stage"] == "reserve":
        if value["purpose"] == "execution":
            from catchplate import authority_registration_execution_response as receiving
            returned = receiving._verify_on_configuration(**common, authorization_bytes=originals[0],
                request_originals=originals[1:4], response_originals=originals[4:8], before_vector_bytes=originals[8],
                deadline_epoch_ns=window[3], transport_deadline_ns=bound, work=work, grant_bytes=originals[9])
            require(returned == originals[9])
        else:
            checked = finalization._admit_on_configuration(**common, authorization_bytes=originals[0],
                originals=originals[1:8], before_vector_bytes=originals[8], grant_bytes=originals[9],
                live_window=window, transport_deadline_ns=bound, work=work)
            checked.live()
        return
    if value["purpose"] == "execution":
        from catchplate import authority_registration_execution_sql_admission as admission
        limits = dict(deadline_epoch_ns=window[3])
    else:
        from catchplate import authority_registration_finalization_sql_admission as admission
        limits = dict(live_window=window)
    scope = value["scope"]
    checked = admission._admit_on_configuration(**common, originals=originals, reservation_originals=reserved,
        expected_pending_sequence=scope["sequence"], expected_pending_head_digest=scope["headDigest"],
        expected_fence=scope["fence"], transport_deadline_ns=bound, work=work, **limits)
    checked.live()
    packet = packets._prepare_on_work(**checked.issue_arguments, live_window=checked.live_window,
        work=work, transport_deadline_ns=checked.deadline_ns)
    for name, actual in (("completionPacketDigest", packet.packet_digest),
            ("completionAuthorizationDigest", checked.issue_arguments["expected_authorization_digest"])):
        require(value[name] == actual or derive and value[name] is None)
        if derive:
            value[name] = actual
    checked.live()


def prepare(raw, *, root_public_key, work):
    """Validate explicit independent scope + complete originals before signing."""
    approval = document(raw, io.MAX_PUBLIC)
    require(set(approval) == {"schema", "directory", "requestOriginal", "requestSha256", "scope",
        "issuedAtMonotonicNs", "issuedAtUnixNanos"} and approval["schema"] == APPROVAL_SCHEMA)
    directory(approval["directory"])
    require(type(approval["requestOriginal"]) is str and approval["requestOriginal"].isascii())
    request_raw = approval["requestOriginal"].encode("ascii")
    require(sha(request_raw) == approval["requestSha256"])
    selected = document(request_raw, MAX_REQUEST)
    require(set(selected) == _REQUEST_FIELDS and selected["schema"] == REQUEST_SCHEMA
        and selected["purpose"] in PURPOSES and selected["stage"] in STAGES
        and selected["directory"] == approval["directory"]
        and type(selected["common"]) is dict and set(selected["common"]) == _COMMON)
    common = dict(selected["common"], root_public_key=root_public_key)
    for name in ("authorization_enrollment_bytes", "current_root_enrollment_bytes", "grant_enrollment_bytes"):
        require(type(common[name]) is str and common[name].isascii())
        common[name] = common[name].encode("ascii")
    for name, count in (("originals", 10), ("reservationOriginals", 3)):
        if name == "reservationOriginals" and selected["stage"] == "reserve":
            require(selected[name] is None)
            continue
        require(type(selected[name]) is list and len(selected[name]) == count
            and all(type(item) is str and item.isascii() for item in selected[name]))
    originals = tuple(item.encode("ascii") for item in selected["originals"])
    reserved = None if selected["reservationOriginals"] is None else tuple(item.encode("ascii") for item in selected["reservationOriginals"])
    caller = Ed25519PublicKey.from_public_bytes(local.configuration._public(selected["callerPublicKeyBase64Url"]))
    value = dict(schema=SCHEMA, sourceRevision=roots.authority.SOURCE_REVISION,
        purpose=selected["purpose"], stage=selected["stage"], localDigest=selected["localDigest"], subject=selected["subject"],
        configurationDigest=common["configuration_digest"], generationDigest=common["generation"]["digest"],
        currentRootEnrollmentSha256=sha(common["current_root_enrollment_bytes"]),
        grantEnrollmentSha256=sha(common["grant_enrollment_bytes"]), authorizationEnrollmentSha256=sha(common["authorization_enrollment_bytes"]),
        callerSpkiDigest=roots.keys._spki_on_work(caller, work), originalsSha256=[sha(item) for item in originals],
        reservationSha256=None if reserved is None else [sha(item) for item in reserved], scope=approval["scope"],
        priorContextSha256=None, completionPacketDigest=None, completionAuthorizationDigest=None,
        bootIdDigest=selected["bootIdDigest"], issuedAtMonotonicNs=approval["issuedAtMonotonicNs"],
        deadlineMonotonicNs=selected["deadlineMonotonicNs"], issuedAtUnixNanos=approval["issuedAtUnixNanos"],
        expiresAtUnixNanos=selected["expiresAtUnixNanos"])
    if value["stage"] == "execute":
        require(type(selected["priorContextOriginal"]) is str and selected["priorContextOriginal"].isascii())
        prior_raw = selected["priorContextOriginal"].encode("ascii")
        prior = _read(prior_raw, root_public_key, work)
        value["priorContextSha256"] = sha(prior_raw)
        # Reuse the ORIGINAL interval, never a second issue time from the later
        # request or operator. The current invocation remains an extra ceiling.
        require(approval["issuedAtMonotonicNs"] == prior["issuedAtMonotonicNs"]
            and approval["issuedAtUnixNanos"] == prior["issuedAtUnixNanos"])
        value.update({name: prior[name] for name in _CAPS})
        require(time.monotonic_ns() < selected["deadlineMonotonicNs"] and time.time_ns() < selected["expiresAtUnixNanos"])
    _shape(value, draft=True)
    _join(value, common, originals, reserved, caller, work)
    # The original caller enrollment must actually enroll this selected key.
    from catchplate import control_plane_registration_execution_bootstrap as execution
    from catchplate import control_plane_registration_finalization_bootstrap as finalization
    module = execution if value["purpose"] == "execution" else finalization
    if value["purpose"] == "execution":
        from catchplate import authority_webauthn_evidence_custody_configuration as mapping
        configured = mapping._capture_on_work(purpose="registration", payload=common["payload"],
            configuration_digest=common["configuration_digest"], generation=common["generation"],
            runtime_role_identities=common["runtime_role_identities"], work=work)
    else:
        configured = finalization.transition._capture_on_work(operation=module.caller.OPERATION,
            payload=common["payload"], configuration_digest=common["configuration_digest"],
            generation=common["generation"], runtime_role_identities=common["runtime_role_identities"], work=work)
    admitted = module.caller._admit_enrollment_on_work(authorization_enrollment_bytes=common["authorization_enrollment_bytes"],
        current_root_enrollment_bytes=common["current_root_enrollment_bytes"], grant_enrollment_bytes=common["grant_enrollment_bytes"],
        root_public_key=root_public_key, configuration_digest=common["configuration_digest"],
        planner_public_key=configured.pins[1], evidence_public_key=configured.pins[4], work=work)
    require(roots.keys._spki_on_work(admitted.caller_public_key, work) == value["callerSpkiDigest"])
    if value["stage"] == "reserve":
        require(selected["priorContextOriginal"] is None)
    else:
        require(type(selected["priorContextOriginal"]) is str and selected["priorContextOriginal"].isascii())
        prior_raw = selected["priorContextOriginal"].encode("ascii")
        _link(value, _read(prior_raw, root_public_key, work), prior_raw)
    _fresh(value)
    _replay(value, common, originals, reserved, work, derive=True)
    _shape(value)
    _fresh(value)
    return dict(directory=approval["directory"], context=value,
        deadline=min(value["deadlineMonotonicNs"], selected["deadlineMonotonicNs"]),
        epochLimit=min(value["expiresAtUnixNanos"], selected["expiresAtUnixNanos"]))


def _open_directory(handles, expected=None):
    parent = None
    for name in ("/", "run", "catchplate", "registration-contexts"):
        with keys._owning():
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            handles.append(fd)
        item = os.fstat(fd)
        require(stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022)
        parent = fd
    info = os.fstat(parent)
    require(stat.S_IMODE(info.st_mode) == 0o750 and info.st_gid == 65532)
    if expected is not None:
        require((info.st_dev, info.st_ino) == directory(expected))
    return parent


def _close(handles):
    while handles:
        fd = handles[-1]
        with keys._owning():
            os.close(fd)
            handles.pop()


class DirectoryCloseUncertain(RuntimeError):
    """Retain the actual descriptor numbers after an indeterminate close."""
    def __init__(self, handles):
        super().__init__("local context directory close is uncertain")
        self.handles, self.owner = handles, self

    def close(self):
        # Retrying an indeterminate close could close a reused descriptor.
        raise RuntimeError("local context directory ownership remains uncertain")


def _close_on_owner(owner):
    require(not owner._registration_context_uncertain)
    try:
        _close(owner._registration_context_handles)
    except BaseException:
        owner._registration_context_uncertain = True
        raise


def prepare_directory():
    """Explicit root launcher action; create absent fixed directory, no adoption."""
    io._process(); _development()
    require(os.environ.get("CATCHPLATE_PROCESS_MODE") == "metadata-bootstrap")
    handles = []
    try:
        parent = None
        for name in ("/", "run", "catchplate"):
            with keys._owning():
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                handles.append(fd)
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022)
            parent = fd
        os.mkdir("registration-contexts", 0o700, dir_fd=parent)
        with keys._owning():
            fd = os.open("registration-contexts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            handles.append(fd)
        require(not os.listdir(fd))
        os.fchown(fd, 0, 65532); os.fchmod(fd, 0o750); os.fsync(fd); os.fsync(parent)
        os.mkdir("requests", 0o700, dir_fd=fd)
        with keys._owning():
            requests = os.open("requests", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            handles.append(requests)
        # Set the exact mode while still the owner; CAP_CHOWN alone is enough
        # for the subsequent deliberate transfer to the application account.
        os.fchmod(requests, 0o700); os.fchown(requests, 65532, 65532); os.fsync(requests); os.fsync(fd)
        info = os.fstat(fd)
        result = dict(path=DIRECTORY, device=info.st_dev, inode=info.st_ino)
        directory(result)
        return result
    finally:
        try:
            _close(handles)
        except BaseException as exc:
            raise DirectoryCloseUncertain(handles) from exc


def _file(handles, selected, name):
    parent = _open_directory(handles, selected)
    with keys._owning():
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        handles.append(fd)
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o440
        and (before.st_uid, before.st_gid, before.st_nlink) == (0, 65532, 1) and 2 <= before.st_size <= MAX_CONTEXT)
    raw = os.pread(fd, MAX_CONTEXT + 1, 0)
    require(len(raw) == before.st_size and io._identity(os.fstat(fd)) == io._identity(before)
        and io._identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == io._identity(before))
    return raw, io._identity(before)


def _check_on_owner(owner):
    """Cheap named-file/original-time checks; never a replacement replay owner."""
    require(not owner._registration_context_uncertain and not owner._registration_context_handles)
    for (_purpose, _digest, _stage), (raw, value, identity, selected) in owner._registration_contexts.items():
        try:
            actual, current = _file(owner._registration_context_handles, selected,
                filename(value["purpose"], value["localDigest"], value["stage"]))
            require(actual == raw and current == identity)
            _fresh(value)
        finally:
            _close_on_owner(owner)


def _selected_scope(owner, purpose, digest):
    """Only previously admitted immutable per-action scope, not a global head."""
    material = getattr(owner._material, purpose)
    if material.context_directory is None:
        return material
    require((purpose, digest, "execute") in owner._registration_contexts)
    _check_on_owner(owner)
    value = owner._registration_contexts[(purpose, digest, "execute")][1]
    fields = dict(current_pending=tuple(value["scope"][name] for name in ("sequence", "headDigest", "fence")),
        completion_packet_digest=value["completionPacketDigest"])
    if purpose == "finalization":
        fields["completion_authorization_digest"] = value["completionAuthorizationDigest"]
    return replace(material, **fields)


def _claim_reservation_on_owner(owner, purpose, digest):
    from catchplate import control_plane_enrollment_startup as startup
    require(type(owner) is startup._EnrollmentOwner and startup.require_started() is owner)
    token = purpose, digest, "reserve"
    require(token in owner._registration_contexts and token not in owner._registration_context_reservations)
    _check_on_owner(owner)
    owner._registration_context_reservations.add(token)


def _request_on_owner(owner, selected, token, common, originals, reserved, subject, deadline, bound, work):
    """Publish actual retained DATA, then wait for the independent fixed input.

    The request is no grant. Root automation must independently select the
    predecessor/pending scope and use the fixed issuer; it cannot copy a receipt
    into an authorization. No timeout extends the calling operation.
    """
    from cryptography.hazmat.primitives import serialization
    from catchplate import control_plane_enrollment_startup as startup
    purpose, digest, stage = token
    material = getattr(owner._material, purpose)
    require(os.geteuid() == os.getegid() == 65532)
    body = dict(schema=REQUEST_SCHEMA,
        purpose=purpose, stage=stage, localDigest=digest, subject=subject, directory=selected,
        common={name: raw.decode("ascii") if type(raw) is bytes else raw for name, raw in common.items() if name != "root_public_key"},
        originals=[raw.decode("ascii") for raw in originals],
        reservationOriginals=None if reserved is None else [raw.decode("ascii") for raw in reserved],
        callerPublicKeyBase64Url=local.spec.strict_base64url_encode(material.caller_public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        bootIdDigest=local.configuration.launcher._boot_identity_digest(), deadlineMonotonicNs=bound,
        expiresAtUnixNanos=deadline,
        priorContextOriginal=None if stage == "reserve" else owner._registration_contexts[(purpose, digest, "reserve")][0].decode("ascii"))
    raw = canonical(body)
    require(len(raw) <= MAX_REQUEST)
    work.charge(input_bytes=len(raw))
    handles = owner._registration_context_handles
    try:
        parent = _open_directory(handles, selected)
        with keys._owning():
            output = os.open("requests", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            handles.append(output)
        info = os.fstat(output)
        require((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (65532, 65532, 0o700))
        name = filename(*token)
        with keys._owning():
            fd = os.open("." + name + ".pending", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=output)
            handles.append(fd)
        offset = 0
        while offset < len(raw):
            require(time.monotonic_ns() < bound and time.time_ns() < deadline)
            count = os.write(fd, raw[offset:offset + 65536]); require(count > 0); offset += count
        os.fchmod(fd, 0o400); os.fsync(fd)
        require(os.pread(fd, len(raw) + 1, 0) == raw)
        if keys._LIBC.renameat2(output, os.fsencode("." + name + ".pending"), output, os.fsencode(name), 1) != 0:
            raise OSError(ctypes.get_errno(), "fixed context request publication refused")
        os.fsync(output)
    finally:
        _close_on_owner(owner)
    while True:
        startup._live(owner, work=work)
        require(time.monotonic_ns() < bound and time.time_ns() < deadline)
        try:
            return _file(handles, selected, filename(*token))
        except FileNotFoundError:
            pass
        finally:
            _close_on_owner(owner)
        select.select([], [], [], min(0.02, max(0, bound - time.monotonic_ns()) / 1e9))


def _admit_on_owner(owner, *, purpose, local_digest, stage, common, originals, reserved, subject,
        deadline_epoch_ns, deadline_ns, work):
    """Caller holds the genuine cold owner lock and repeats subject replay."""
    from catchplate import control_plane_enrollment_startup as startup
    require(type(owner) is startup._EnrollmentOwner and startup.require_started() is owner)
    _development()
    material = getattr(owner._material, purpose)
    require(material.context_directory is not None and local_digest == _record(purpose, originals))
    selected = dict(path=DIRECTORY, device=material.context_directory[0], inode=material.context_directory[1])
    token = purpose, local_digest, stage
    require(not any(key[0] == purpose and key[1] != local_digest for key in owner._registration_contexts)
        and (token in owner._registration_contexts or len(owner._registration_contexts) < 4))
    try:
        if token in owner._registration_contexts:
            raw, identity = _file(owner._registration_context_handles, selected, filename(*token))
        else:
            raw, identity = _request_on_owner(owner, selected, token, common, originals, reserved, subject,
                deadline_epoch_ns, deadline_ns, work)
        value = _read(raw, owner._binding.runtime_root_public_key, work)
        require((value["purpose"], value["localDigest"], value["stage"]) == token and value["subject"] == subject
            and value["expiresAtUnixNanos"] <= owner._binding.attestation_interval[1])
        _join(value, common, originals, reserved, material.caller_public_key, work)
        if stage == "execute":
            prior_raw, prior, _, _ = owner._registration_contexts[(purpose, local_digest, "reserve")]
            _link(value, prior, prior_raw)
        _replay(value, common, originals, reserved, work)
        prior = owner._registration_contexts.get(token)
        require(prior is None or prior == (raw, value, identity, selected))
        owner._registration_contexts[token] = raw, value, identity, selected
        _fresh(value)
        return value
    finally:
        _close_on_owner(owner)


class LocalRegistrationContextIssuer:
    """One actual delegated root signature and fixed no-replace publication."""
    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd):
        self.handles = []
        self.used = self.closed = self.uncertain = False
        io._process(); _development()
        require(os.environ.get("CATCHPLATE_PROCESS_MODE") == "metadata-bootstrap" and approval_fd != signing_key_fd)
        self.pid, self.environment = os.getpid(), tuple(sorted(os.environ.items()))
        self.approval_fd, self.key_fd = approval_fd, signing_key_fd
        self.identity, self.key_identity = io._input(approval_fd, io.MAX_PUBLIC), io._input(signing_key_fd, 32, private=True)
        require(self.identity[:2] != self.key_identity[:2])
        self.raw = io.read_public(approval_fd, io.MAX_PUBLIC)
        require(sha(self.raw) == approval_sha256)
        self.key = io.signing_key(signing_key_fd)
        self.work = _ValidationWork(QueryReadValidationLimits())
        self.selected = prepare(self.raw, root_public_key=self.key.public_key(), work=self.work)
        self.previous = self.selected["context"]["issuedAtMonotonicNs"], self.selected["context"]["issuedAtUnixNanos"]
        self.check()

    def check(self):
        io._process(); _development()
        require(not self.closed and not self.uncertain and os.getpid() == self.pid and tuple(sorted(os.environ.items())) == self.environment
            and io._input(self.approval_fd, io.MAX_PUBLIC) == self.identity
            and io.read_public(self.approval_fd, io.MAX_PUBLIC) == self.raw
            and io._input(self.key_fd, 32, private=True) == self.key_identity)
        _fresh(self.selected["context"])
        now = time.monotonic_ns(), time.time_ns()
        require(all(current >= prior for current, prior in zip(now, self.previous)))
        require(now[0] < self.selected["deadline"] and now[1] < self.selected["epochLimit"])
        self.previous = now

    def run(self):
        require(not self.used)
        self.used = True
        self.check()
        value = self.selected["context"]
        raw = signer._sign(value, SIGNED_SCHEMA, MAX_CONTEXT, self.key, self.key.public_key(), self.work)
        _read(raw, self.key.public_key(), self.work)
        parent = _open_directory(self.handles, self.selected["directory"])
        name = filename(value["purpose"], value["localDigest"], value["stage"])
        pending = "." + name + ".pending"
        with keys._owning():
            fd = os.open(pending, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            self.handles.append(fd)
        offset = 0
        while offset < len(raw):
            self.check()
            count = os.write(fd, raw[offset:]); require(count > 0); offset += count
        os.fchown(fd, 0, 65532); os.fchmod(fd, 0o440); os.fsync(fd)
        require(os.pread(fd, MAX_CONTEXT + 1, 0) == raw)
        self.check()
        if keys._LIBC.renameat2(parent, os.fsencode(pending), parent, os.fsencode(name), 1) != 0:
            raise OSError(ctypes.get_errno(), "fixed local context publication refused")
        os.fsync(parent)
        actual, _ = _file(self.handles, self.selected["directory"], name)
        require(actual == raw)
        self.check()
        self.close()
        _fresh(value)
        require(time.monotonic_ns() < self.selected["deadline"] and time.time_ns() < self.selected["epochLimit"])
        return dict(path=DIRECTORY + "/" + name, sha256=sha(raw))

    def close(self):
        require(not self.uncertain)
        if self.closed:
            return
        try:
            _close(self.handles)
        except BaseException:
            self.uncertain = True
            raise
        self.key = None
        self.closed = True
