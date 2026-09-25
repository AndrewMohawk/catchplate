"""Explicit dedicated control-plane WebAuthn enrollment authorization policy.

Only the surrounding root-admitted signed configuration grants policy
authority. Absence or null disables this extension; no role, response or
evidence-purpose key is inferred as its issuer. An enabled issuer must target
the explicit registration-evidence signer and remain distinct from every
configured role response/signing pin and enabled evidence/transition key.

The validators own all inputs before genuine raw32 Ed25519/SPKI checks. Role
response pins without a configured public-key field remain independently
admitted role/cohort pins, not keys manufactured by this module. The measured
mapper binds the actual configuration, generation and runtime cohort on the
original caller work and requires the configured registration planner path.
It opens no signer, descriptor, clock, SQL, socket, operation or enrollment.
Standalone validation is for cold configuration loading only, never a fresh
allowance substituted into measured request work.
"""
from __future__ import annotations

from dataclasses import dataclass

from serverware import authority_contract as authority
from serverware import authority_revocation_configuration as configuration
from serverware import authority_webauthn_evidence_policy as evidence_policy
from serverware import authority_webauthn_transition_policy as transition_policy
from serverware.authority_query_read_work import QueryReadValidationLimits, _ValidationWork


FIELD = "webauthnEnrollmentAuthorization"
SCHEMA = "serverware.policyAuthorityWebAuthnEnrollmentAuthorizationPolicy/v1"
OPERATION = "webauthn.registration.evidence.admit"
PURPOSE = "authorize-webauthn-registration"
_FIELDS = frozenset({"schema", "operation", "purpose", "issuerId",
    "signingPublicKeyBase64Url", "signingSpkiDigest", "audienceSigningSpkiDigest",
    "maximumAgeNs", "maximumClockSkewNs"})
_ISSUER_FIRST = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_ISSUER_CHARACTERS = _ISSUER_FIRST | frozenset("._:-")
_ROLES = ("verifier", "planner", "planner-writer", "issuer", "executor")


class WebAuthnEnrollmentPolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True, repr=False, eq=False)
class _EnrollmentSettings:
    """Owned configured inputs, not an enrollment grant or provenance token."""

    policy: dict
    issuer_public_key: object
    generation_sequence: int
    generation_digest: str


def _shape(value):
    shape = configuration.capability.shape
    shape._object(value, _FIELDS, "WebAuthn enrollment authorization policy")
    shape._literal(value["schema"], SCHEMA)
    shape._literal(value["operation"], OPERATION)
    shape._literal(value["purpose"], PURPOSE)
    issuer = value["issuerId"]
    shape._text(issuer, 128)
    if issuer[0] not in _ISSUER_FIRST or any(character not in _ISSUER_CHARACTERS for character in issuer):
        raise WebAuthnEnrollmentPolicyError("enrollment issuer ID is not a bounded ASCII token")
    shape._text(value["signingPublicKeyBase64Url"], 43, minimum=43)
    shape._base64url(value["signingPublicKeyBase64Url"])
    for name in ("signingSpkiDigest", "audienceSigningSpkiDigest"):
        shape._digest(value[name])
    shape._integer(value["maximumAgeNs"], authority.VERIFIER_RESPONSE_MAX_AGE_NS, minimum=1)
    shape._integer(value["maximumClockSkewNs"], authority.VERIFIER_MAX_CLOCK_SKEW_NS)


def _bindings(policy, payload, work):
    """Hold the exact source role/key inventory before any native key callback."""
    shape, plan = configuration.capability.shape, configuration.capability.plan
    roles = payload["roles"]
    shape._object(roles, frozenset(_ROLES), "enrollment configured roles")
    forbidden, role_keys = [], []
    for name in _ROLES:
        role = roles[name]
        if type(role) is not dict:
            raise WebAuthnEnrollmentPolicyError("enrollment role configuration is not an exact object")
        shape._literal(role["processMode"], "policy-authority-" + name)
        shape._digest(role["responseSigningSpkiDigest"])
        forbidden.append(role["responseSigningSpkiDigest"])
        if name in ("verifier", "planner"):
            encoded, spki = role["signingPublicKeyBase64Url"], role["signingSpkiDigest"]
            shape._text(encoded, 43, minimum=43)
            shape._base64url(encoded)
            shape._digest(spki)
            plan._same(spki, role["responseSigningSpkiDigest"], work,
                "enrollment role signing/response pins differ")
            role_keys.append((encoded, spki))
            forbidden.append(spki)
        elif name == "planner-writer":
            for encoded_field, digest_field in (
                    ("responseSigningPublicKeyBase64Url", "responseSigningSpkiDigest"),
                    ("plannerSigningPublicKeyBase64Url", "plannerSigningSpkiDigest")):
                encoded, spki = role[encoded_field], role[digest_field]
                shape._text(encoded, 43, minimum=43)
                shape._base64url(encoded)
                shape._digest(spki)
                role_keys.append((encoded, spki))
                forbidden.append(spki)
    plan._same((roles["planner-writer"]["plannerSigningPublicKeyBase64Url"],
        roles["planner-writer"]["plannerSigningSpkiDigest"]),
        (roles["planner"]["signingPublicKeyBase64Url"], roles["planner"]["signingSpkiDigest"]),
        work, "enrollment planner-writer alias differs from the actual planner key")
    purposes = payload.get(evidence_policy.FIELD)
    evidence_policy._shape(purposes, webauthn=payload["webauthn"])
    registration = purposes["registration"]
    if registration is None:
        raise WebAuthnEnrollmentPolicyError("enrollment authorization requires an explicit registration evidence purpose")
    for slot in ("registration", "installation"):
        if purposes[slot] is not None:
            forbidden.append(purposes[slot]["signingSpkiDigest"])
    transitions = payload.get(transition_policy.FIELD)
    if transition_policy.FIELD in payload:
        transition_policy._shape(transitions, webauthn=payload["webauthn"])
        for slot in ("registration", "stage", "completion"):
            if transitions[slot] is not None:
                forbidden.append(transitions[slot]["signingSpkiDigest"])
    plan._same(policy["audienceSigningSpkiDigest"], registration["signingSpkiDigest"], work,
        "enrollment audience differs from the configured registration evidence signer")
    work.prepare_scan(forbidden)
    if policy["signingSpkiDigest"] in forbidden:
        raise WebAuthnEnrollmentPolicyError("enrollment issuer key is not separate from configured role/evidence/transition keys")
    return tuple(role_keys), purposes, transitions, payload["webauthn"]


def _validate_policy_on_work(value, *, payload, work):
    """Own and validate one enabled extension without admitting its provenance."""
    try:
        ledger = configuration.capability.capture._SharedLedger(work)
        _shape(value)  # Null is disabled, never a valid enabled-policy input.
        if type(payload) is not dict:
            raise WebAuthnEnrollmentPolicyError("enrollment policy requires the exact signed configuration graph")
        owned = configuration._ConfigurationCapture(ledger,
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit({"policy": value, "payload": payload})
        policy, configured = owned["policy"], owned["payload"]
        _shape(policy)
        encoded, spki = policy["signingPublicKeyBase64Url"], policy["signingSpkiDigest"]
        role_keys, purposes, transitions, webauthn = _bindings(policy, configured, work)
        # Every policy, role key/pin and audience scalar is now privately held.
        # Existing genuine validators establish raw32/SPKI correspondence for
        # the comparison keys; no claimed digest bypasses their actual keys.
        for role_encoded, role_spki in role_keys:
            configuration._key(role_encoded, work, expected_spki=role_spki)
        evidence_policy._validate_policy_on_work(purposes, webauthn=webauthn, work=work)
        if transitions is not None:
            transition_policy._validate_policy_on_work(transitions, webauthn=webauthn, work=work)
        public_key = configuration._key(encoded, work, expected_spki=spki)
        return policy, public_key
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEnrollmentPolicyError):
            raise
        raise WebAuthnEnrollmentPolicyError("WebAuthn enrollment authorization policy is invalid") from exc


def validate_policy(value, *, payload):
    """Cold loader validation; null disables and never reconstructs a key."""
    if value is None:
        return None
    # Four actual role/alias keys, two evidence purposes, three transitions
    # and the dedicated issuer use at most ten genuine SPKI SHA operations.
    # Measured requests never enter this standalone allowance constructor.
    work = _ValidationWork(QueryReadValidationLimits(max_hashes=10))
    policy, _ = _validate_policy_on_work(value, payload=payload, work=work)
    return policy


def _capture_on_work(*, payload, configuration_digest, generation, runtime_role_identities, work):
    """Bind actual admitted configuration/cohort and return fixed issuer inputs."""
    try:
        ledger = configuration.capability.capture._SharedLedger(work)
        digest = configuration_digest
        configuration.capability.shape._digest(digest)
        if type(payload) is not dict or type(generation) is not dict:
            raise WebAuthnEnrollmentPolicyError("enrollment configuration requires exact owned JSON inputs")
        configuration.capability.shape._bounded_object(generation, 24, "enrollment launch context")
        # Detach the runtime cohort as well as configuration/launch graphs
        # before the first native configuration commitment or key callback.
        held_payload = configuration._ConfigurationCapture(ledger,
            maximum_bytes=authority.MAX_REQUEST_BYTES).visit(payload)
        held_generation = configuration.capability.capture._JSONCapture(ledger).visit(
            {name: generation[name] for name in configuration._GENERATION_FIELDS})
        held_runtime = configuration.capability.capture._JSONCapture(ledger,
            maximum_bytes=8192).visit(runtime_role_identities)
        owned, launch = configuration._capture_configuration_on_work(payload=held_payload,
            configuration_digest=digest, generation=held_generation, work=work)
        configuration._capture_runtime_role_identities_on_work(runtime_role_identities=held_runtime,
            owned_payload=owned, configuration_digest=digest, launch=launch, work=work)
        if owned.get(FIELD) is None:
            raise WebAuthnEnrollmentPolicyError("WebAuthn enrollment authorization is disabled")
        sequence, generation_digest = launch["sequence"], launch["digest"]
        # Use the existing exact source allowlist/manifest checks. This does
        # not construct a read owner or make any legacy execution gate accept
        # the successor operation; actual configured provenance is upstream.
        from serverware import authority_webauthn_evidence_configuration as read_configuration

        planner = owned["roles"]["planner"]
        configuration.capability.shape._literal(planner["processMode"], "policy-authority-planner")
        read_configuration._require_enabled_operation(planner, OPERATION, work)
        configuration.capability.plan._same(owned["queryManifestDigest"],
            read_configuration.plan._QUERY_MANIFEST_DIGEST, work,
            "enrollment registration planner manifest differs from the source")
        policy, key = _validate_policy_on_work(owned[FIELD], payload=owned, work=work)
        return _EnrollmentSettings(policy, key, sequence, generation_digest)
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        if isinstance(exc, WebAuthnEnrollmentPolicyError):
            raise
        raise WebAuthnEnrollmentPolicyError("WebAuthn enrollment configuration capture failed") from exc
