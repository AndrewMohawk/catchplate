"""Fixed encrypted consume-plan originals; neither execution nor release proof.

The distinct exact-class storage profile reuses real private-directory custody,
leases, bounded recovery, no-replace publication and poison/continuity checks.
Its fixed codec retains ordinary originals only. Genuine current signature,
state, completed-activation and consumption replay belongs to the plan owner.
No key, directory, budget, replacement lifetime or anti-rollback anchor is made.
"""
from __future__ import annotations

from serverware import authority_oidc_session_activation_delivery_plan as plan
from serverware import authority_oidc_session_activation_journal as storage


contract, state = plan.contract, plan.state
authority, shape, evidence, registration = storage.authority, storage.shape, storage.evidence, storage.registration
SCHEMA = "serverware.oidcSessionActivationDeliveryPrivateOriginals/v1"
DOMAIN = b"serverware.oidcSessionActivationDeliveryJournal/v1\x00"
MAGIC = b"SWODJ001"
NAME_PREFIX = "delivery-"
MAX_ORIGINAL_BYTES, MAX_SCOPE_BYTES = storage.MAX_ORIGINAL_BYTES, storage.MAX_SCOPE_BYTES
MAX_RECORD_BYTES, MAX_RECORDS, MAX_QUOTA_BYTES = storage.MAX_RECORD_BYTES, storage.MAX_RECORDS, storage.MAX_QUOTA_BYTES
MAX_NODES, MAX_DEPTH = storage.MAX_NODES, storage.MAX_DEPTH
SCOPE_FIELDS, READ_INPUT_FIELDS = storage.SCOPE_FIELDS, storage.READ_INPUT_FIELDS
ORIGINAL_FIELDS = frozenset({"schema", "sourceRevision", "request", "scope", "databaseNow",
    "oldTokenBase64Url", "readInputs", "writeProofBase64Url", "planEnvelopeBase64Url",
    "stateEnrollmentBase64Url", "completeRootVectorBase64Url", "headQueryBase64Url",
    "headObservationBase64Url", "activationOriginals", "activationExpectations", "activationScope"})
_ARGUMENT_FIELDS = frozenset({"delivery_id", "session_id", "user_id", "credential_id", "credential_record_id",
    "challenge_id", "old_token_digest", "new_token_digest", "assertion_digest", "businessIntent"})
_ACTIVATION_SCOPE_FIELDS = frozenset({"authorizationDigest", "databaseId", "generationDigest",
    "pendingSequence", "pendingHeadDigest", "fence"})


class DeliveryOriginalJournalError(storage.ActivationOriginalJournalError):
    pass


def _fail(message):
    raise DeliveryOriginalJournalError(message)


def _scope(value):
    return storage._scope(value)


def _activation_frames(values, work):
    """Decode the fixed raw13 transport inventory, not a verified result."""
    response = plan.provenance.response
    maxima = (*response.transport.RESPONSE_LIMITS, plan.activation_plan.contract.MAX_BYTES,
        plan.bundle.MAX_BYTES, response.authorization.MAX_BYTES, response.pending.MAX_RECEIPT_BYTES,
        response.pending.computation.MAX_SNAPSHOT_BYTES, response.admission.caller.MAX_AUTHORIZATION_BYTES,
        response.grants.MAX_GRANT_BYTES, response.admission.caller.MAX_ENROLLMENT_BYTES,
        response.grants.MAX_ENROLLMENT_BYTES)
    if type(values) is not list or len(values) != 13 or len(maxima) != 13:
        _fail("consume retained activation originals require the fixed array13")
    originals = []
    for index, (value, maximum) in enumerate(zip(values, maxima)):
        if index in (1, 2, 3) and type(value) is str and value == "":
            # The existing closed uncertainty frame has empty suffixes. It is
            # still never valid completed provenance for a produced plan.
            work.charge(input_bytes=1)
            originals.append(b"")
        else:
            originals.append(registration._encoded_original(value, maximum, work,
                minimum=1 if index < 4 else 2))
    return plan._activation_originals(tuple(originals), work)


def _typed_request(value, *, operation, handler, arguments, request_digest=None):
    shape._object(value, shape.TYPED_REQUEST_FIELDS, "retained delivery typed request")
    shape._literal(value["schema"], shape.TYPED_REQUEST_SCHEMA)
    shape._literal(value["operation"], operation)
    shape._literal(value["handler"], handler)
    shape._literal(value["operationManifestDigest"], authority.OPERATION_MANIFEST_DIGEST)
    shape._object(value["arguments"], arguments, "retained delivery argument inventory")
    shape._digest(value["operationId"])
    shape._digest(value["requestDigest"])
    if request_digest is not None:
        shape._literal(value["requestDigest"], request_digest)


def _original(value, scope, work):
    """Closed owned storage graph only; AEAD is not semantic authority."""
    owned = storage._Capture(evidence.capture._SharedLedger(work), maximum_bytes=MAX_ORIGINAL_BYTES).visit(value)
    shape._object(owned, ORIGINAL_FIELDS, "consume private originals")
    shape._literal(owned["schema"], SCHEMA)
    shape._literal(owned["sourceRevision"], scope["sourceRevision"])
    request, expected, reads = owned["request"], owned["scope"], owned["readInputs"]
    _typed_request(request, operation=contract.OPERATION, handler="consume_oidc_session_activation_delivery",
        arguments=_ARGUMENT_FIELDS, request_digest=scope["requestDigest"])
    shape._object(expected, state.SCOPE_FIELDS, "retained consume plan scope")
    shape._literal(expected["configurationDigest"], scope["configurationDigest"])
    shape._object(reads, READ_INPUT_FIELDS, "retained consume original read graph")
    shape._literal(reads["schema"], contract.PROOF_DOMAIN)
    for name, count in (("selectedRows", 10), ("beforeProofs", 10), ("readHeads", 7),
            ("queryFrontiers", 7), ("queryReads", 17), ("countedBeforeHeads", 7)):
        if type(reads[name]) is not list or len(reads[name]) != count:
            _fail("consume retained read inventory differs from the fixed source closure")
    for name in ("businessBeforeRoots", "authorizationBeforeRoots"):
        if type(reads[name]) is not list or len(reads[name]) > authority.MAX_QUERY_PROOFS:
            _fail("consume retained primary roots exceed their source inventory bound")
    database_now = registration._utc(owned["databaseNow"], "retained consume database time", work)
    if database_now.isoformat() != owned["databaseNow"]:
        _fail("consume retained database time is not its canonical UTC original")
    storage.delivery._token(registration._encoded_original(owned["oldTokenBase64Url"],
        storage.delivery.TOKEN_BYTES, work, minimum=storage.delivery.TOKEN_BYTES), work)
    registration._encoded_original(owned["writeProofBase64Url"], plan.writes.MAX_WRITE_PROOF_BYTES, work)
    for name, maximum in (("stateEnrollmentBase64Url", state.head.authorization.MAX_ENROLLMENT_BYTES),
            ("completeRootVectorBase64Url", state.vector.MAX_BYTES),
            ("headQueryBase64Url", state.head.MAX_QUERY_BYTES), ("headObservationBase64Url", state.head.MAX_BYTES)):
        registration._encoded_original(owned[name], maximum, work)
    _activation_frames(owned["activationOriginals"], work)
    old_expected = owned["activationExpectations"]
    shape._object(old_expected, frozenset({"request", "scope", "journalDigest"}),
        "retained completed activation expectations")
    _typed_request(old_expected["request"], operation=plan.activation_plan.contract.OPERATION,
        handler="finalize_oidc_browser_session_activation", arguments=storage._ARGUMENT_FIELDS)
    shape._object(old_expected["scope"], storage.PLAN_SCOPE_FIELDS, "retained activation original scope")
    shape._literal(old_expected["scope"]["configurationDigest"], scope["configurationDigest"])
    shape._digest(old_expected["journalDigest"])
    old_scope = owned["activationScope"]
    shape._object(old_scope, _ACTIVATION_SCOPE_FIELDS, "retained activation provenance scope")
    for name in ("authorizationDigest", "generationDigest", "pendingHeadDigest"):
        shape._digest(old_scope[name])
    state.head.authorization._token(old_scope["databaseId"])
    for name in ("pendingSequence", "fence"):
        shape._integer(old_scope[name], minimum=1)
    plan_bytes = registration._encoded_original(owned["planEnvelopeBase64Url"], contract.MAX_BYTES, work)
    envelope = contract._decode_on_work(plan_bytes, envelope=True, work=work)
    payload = envelope["payload"]
    shape._literal(payload["requestDigest"], scope["requestDigest"])
    shape._literal(payload["operationId"], request["operationId"])
    shape._literal(payload["configurationDigest"], scope["configurationDigest"])
    identity = evidence.plan._frame(contract.IDENTITY_DOMAIN, (plan_bytes,), work)
    shape._literal(identity, scope["planDigest"])
    return owned


def _encode_original_on_work(value, *, scope, work):
    held = _scope(scope)
    owned = _original(value, held, work)
    return evidence.capability._wire(owned, evidence.capture._SharedLedger(work), MAX_ORIGINAL_BYTES, MAX_NODES)


def _decode_original_on_work(original_bytes, *, scope, work):
    held = _scope(scope)
    if type(original_bytes) is not bytes or not 2 <= len(original_bytes) <= MAX_ORIGINAL_BYTES:
        _fail("consume private originals exceed the immutable byte bound")
    value = evidence.wire._decode_object(original_bytes, work=work, maximum_bytes=MAX_ORIGINAL_BYTES,
        maximum_nodes=MAX_NODES, maximum_depth=MAX_DEPTH)
    owned = _original(value, held, work)
    evidence.capability._canonical(original_bytes, owned, evidence.capture._SharedLedger(work),
        MAX_ORIGINAL_BYTES, MAX_NODES)
    return owned


class DeliveryOriginalJournal(storage.ActivationOriginalJournal):
    """Distinct fixed encrypted consume custody; not an execution outcome store."""

    __slots__ = ("_base_configuration", "_delivery_configuration")

    def __init__(self, *, directory_fd, expected_device, expected_inode, expected_uid, expected_gid,
            maximum_records, quota_bytes, configuration_digest, journal_key, bundle_key, delivery_key,
            live_window, work, transport_deadline_ns):
        shape._integer(transport_deadline_ns, minimum=1)
        keys = (journal_key, bundle_key, delivery_key)
        if (any(type(key) is not bytes or len(key) != 32 for key in keys)
                or len(set(keys)) != 3):
            _fail("consume journal needs three independently supplied distinct exact32 AES keys")
        # The base retains its exact old seven-field internal storage layout.
        # Its separation slot holds bundle_key; the distinct public-to-private
        # snapshot below retains both historical-purpose keys for owner joins.
        storage.ActivationOriginalJournal.__init__(self, directory_fd=directory_fd,
            expected_device=expected_device, expected_inode=expected_inode, expected_uid=expected_uid,
            expected_gid=expected_gid, maximum_records=maximum_records, quota_bytes=quota_bytes,
            configuration_digest=configuration_digest, journal_key=journal_key, delivery_key=bundle_key,
            live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)
        configured = self._configuration
        self._base_configuration = configured
        self._delivery_configuration = (*configured[:4], delivery_key, *configured[4:])

    def _snapshot_configuration(self):
        configured = storage.ActivationOriginalJournal._snapshot_configuration(self)
        if configured is not self._base_configuration:
            self._io.poison()
            _fail("consume journal configuration changed after construction")
        return self._delivery_configuration

    def append(self, *, scope, original_bytes, live_window, work, transport_deadline_ns):
        shape._integer(transport_deadline_ns, minimum=1)
        return storage.ActivationOriginalJournal.append(self, scope=scope, original_bytes=original_bytes,
            live_window=live_window, work=work, transport_deadline_ns=transport_deadline_ns)

    def read(self, *, scope, live_window, work, transport_deadline_ns):
        shape._integer(transport_deadline_ns, minimum=1)
        return storage.ActivationOriginalJournal.read(self, scope=scope, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)

    def read_bound(self, *, scope, expected_journal_digest, live_window, work, transport_deadline_ns):
        shape._integer(transport_deadline_ns, minimum=1)
        return storage.ActivationOriginalJournal.read_bound(self, scope=scope,
            expected_journal_digest=expected_journal_digest, live_window=live_window,
            work=work, transport_deadline_ns=transport_deadline_ns)
