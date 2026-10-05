"""Inert role pins for JIT original-page custody, not configuration admission.

The measured service supplies its admitted Service6, launch/cohort originals,
retained local signer and (writer only) protected DSN. This mapper repeats
their existing consistency joins; a constructed configuration is not evidence
of that provenance. It opens no clock, socket, descriptor or database and
accepts no role/key/endpoint selection from an incoming page control.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import math

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from serverware import authority_jit_original_persistence as page_persistence
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence as evidence
from serverware import authority_webauthn_evidence_configuration as enabled
from serverware import authority_webauthn_evidence_plan_writer_configuration as database_configuration
from serverware import authority_webauthn_transition_configuration as role_mapping
from serverware import authority_webauthn_transition_custody_configuration as custody


_ROLES = ("planner", "verifier", "planner-writer")
_IDENTITY_FIELDS = ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")
_FIELDS = ("local_role", "planner_identity", "verifier_identity", "planner_public_key",
    "planner_spki_digest", "verifier_public_key", "verifier_spki_digest", "configuration_digest",
    "generation_sequence", "generation_digest", "maximum_age_ns", "maximum_clock_skew_ns",
    "planner_endpoint", "writer_endpoint", "private_key", "persistence")


class JitOriginalConfigurationError(ValueError):
    pass


def _require(condition):
    if not condition:
        raise JitOriginalConfigurationError("JIT original page configuration lost its fixed original selection")


def _validate(values):
    """Fixed shape only: no key callback, clock sample or authority claim."""
    _require(type(values) is tuple and len(values) == len(_FIELDS))
    (role, planner_identity, verifier_identity, planner_key, planner_spki,
        verifier_key, verifier_spki, digest, sequence, generation_digest,
        maximum_age, skew, planner_endpoint, writer_endpoint, private_key, persistence) = values
    _require(type(role) is str and role in _ROLES)
    shape = configuration.capability.shape
    for identity in (planner_identity, verifier_identity):
        _require(type(identity) is tuple and len(identity) == len(_IDENTITY_FIELDS))
        for value in identity:
            shape._digest(value)
    for value in (planner_spki, verifier_spki, digest, generation_digest):
        shape._digest(value)
    _require(planner_spki != verifier_spki and isinstance(planner_key, Ed25519PublicKey)
        and isinstance(verifier_key, Ed25519PublicKey))
    shape._integer(sequence)
    shape._integer(maximum_age, evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(skew, evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS)
    for endpoint in (planner_endpoint, writer_endpoint):
        _require(type(endpoint) is tuple and len(endpoint) == 3)
        path, uid, gid = endpoint
        _require(type(path) is str and 1 <= len(path) <= 107
            and path.startswith("/") and "\x00" not in path)
        _require(len(path.encode("utf-8")) <= 107)
        shape._integer(uid, 0xFFFFFFFF, minimum=1)
        shape._integer(gid, 0xFFFFFFFF, minimum=1)
    if role == "planner-writer":
        _require(private_key is None and type(persistence) is page_persistence.JitOriginalPersistence)
        page_persistence._snapshot(persistence)
    else:
        _require(isinstance(private_key, Ed25519PrivateKey) and persistence is None)
    return values


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _PageConfiguration:
    """Immutable consistency selection; only the measured caller admits it."""

    local_role: str
    planner_identity: tuple
    verifier_identity: tuple
    planner_public_key: object
    planner_spki_digest: str
    verifier_public_key: object
    verifier_spki_digest: str
    configuration_digest: str
    generation_sequence: int
    generation_digest: str
    maximum_age_ns: int
    maximum_clock_skew_ns: int
    planner_endpoint: tuple
    writer_endpoint: tuple
    private_key: object
    persistence: object
    _original: tuple = field(init=False)
    _persistence_original: tuple | None = field(init=False)

    def __post_init__(self):
        values = _validate(tuple(getattr(self, name) for name in _FIELDS))
        object.__setattr__(self, "_original", values)
        object.__setattr__(self, "_persistence_original", None if self.persistence is None
            else page_persistence._snapshot(self.persistence))


def _snapshot(selected):
    """Return the fixed original tuple without recapture or native callbacks."""
    try:
        _require(type(selected) is _PageConfiguration)
        original = selected._original
        _require(type(original) is tuple and len(original) == len(_FIELDS))
        _require(all(getattr(selected, name) is value for name, value in zip(_FIELDS, original, strict=True)))
        _validate(original)
        _require(selected._persistence_original is (None if selected.persistence is None
            else page_persistence._snapshot(selected.persistence)))
        return original
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        if isinstance(exc, JitOriginalConfigurationError):
            raise
        raise JitOriginalConfigurationError("JIT original page configuration snapshot is invalid") from exc


def _from_configuration_on_work(*, local_role, payload, configuration_digest, generation,
        runtime_role_identities, private_key=None, writer_dsn=None, work):
    """Capture actual role originals once on the caller's remaining allowance."""
    try:
        _require(type(local_role) is str and local_role in _ROLES)
        if local_role == "planner-writer":
            _require(private_key is None and type(writer_dsn) is str)
        else:
            _require(isinstance(private_key, Ed25519PrivateKey) and writer_dsn is None)
        owned, launch = configuration._capture_configuration_on_work(payload=payload,
            configuration_digest=configuration_digest, generation=generation, work=work)
        runtime = configuration._capture_runtime_role_identities_on_work(
            runtime_role_identities=runtime_role_identities, owned_payload=owned,
            configuration_digest=configuration_digest, launch=launch, work=work)
        planner, verifier, writer = (role_mapping._role(owned, name) for name in _ROLES)
        enabled._require_enabled_operation(planner, "jit.assertion.issue", work)
        configuration.capability.plan._same(owned["queryManifestDigest"],
            configuration.capability.plan._QUERY_MANIFEST_DIGEST, work,
            "JIT original page query manifest differs from signed configuration")
        shape = configuration.capability.shape
        for role in (planner, verifier, writer):
            for name in ("serviceUid", "serviceGid"):
                shape._integer(role[name], 0xFFFFFFFF, minimum=1)
            shape._integer(role["maximumInternalAgeNs"], minimum=1)
            timeout = role["requestTimeoutSeconds"]
            _require(type(timeout) in (int, float) and math.isfinite(timeout) and 0.05 <= timeout <= 30)
        planner_encoded, planner_spki, planner_measurement, planner_attestation = role_mapping._key_material(
            planner, runtime["roles"]["planner"], work)
        verifier_encoded, verifier_spki, verifier_measurement, verifier_attestation = role_mapping._key_material(
            verifier, runtime["roles"]["verifier"], work)
        planner_session = planner["plannerSessionIdentityDigest"]
        shape._digest(planner_session)
        verifier_session = configuration._frame_text(configuration._VERIFIER_SESSION,
            (configuration_digest, verifier_measurement, verifier_attestation), work)
        planner_identity = (planner_session, planner_measurement, planner_attestation)
        verifier_identity = (verifier_session, verifier_measurement, verifier_attestation)
        maximum_age = min(evidence.authority.VERIFIER_RESPONSE_MAX_AGE_NS,
            planner["maximumInternalAgeNs"], verifier["maximumInternalAgeNs"], writer["maximumInternalAgeNs"])
        sequence, generation_digest = launch["sequence"], launch["digest"]
        planner_path, _planner_timeout, planner_uid, planner_gid = custody._endpoint(verifier, planner, work)
        writer_path, _writer_timeout, writer_uid, writer_gid = custody._endpoint(planner, writer, work)
        planner_endpoint, writer_endpoint = (planner_path, planner_uid, planner_gid), (writer_path, writer_uid, writer_gid)
        database = (None if local_role != "planner-writer" else
            database_configuration._database_from_owned_configuration_on_work(
                owned_payload=owned, writer_dsn=writer_dsn, work=work))
        # All variable settings above are detached scalars/tuples before the
        # first native key callback. Never consult the borrowed graphs again.
        planner_key = configuration._key(planner_encoded, work, expected_spki=planner_spki)
        verifier_key = configuration._key(verifier_encoded, work, expected_spki=verifier_spki)
        custody.wire._distinct_keys(planner_key, verifier_key, work)
        if private_key is not None:
            evidence.keys._pair_on_work(private_key,
                planner_key if local_role == "planner" else verifier_key, work)
        persistence = (None if database is None else page_persistence.JitOriginalPersistence(
            writer_dsn=database[0], connect_timeout_seconds=database[1], database_identity=database[2]))
        return _PageConfiguration(local_role=local_role, planner_identity=planner_identity,
            verifier_identity=verifier_identity, planner_public_key=planner_key,
            planner_spki_digest=planner_spki, verifier_public_key=verifier_key,
            verifier_spki_digest=verifier_spki, configuration_digest=configuration_digest,
            generation_sequence=sequence, generation_digest=generation_digest,
            maximum_age_ns=maximum_age, maximum_clock_skew_ns=evidence.authority.VERIFIER_MAX_CLOCK_SKEW_NS,
            planner_endpoint=planner_endpoint, writer_endpoint=writer_endpoint,
            private_key=private_key, persistence=persistence)
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, JitOriginalConfigurationError):
            raise
        raise JitOriginalConfigurationError("JIT original page configuration capture failed") from exc
