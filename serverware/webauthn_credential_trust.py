"""Explicit, bounded credential-versus-root classification; no authority or I/O.

The live boundary supplies decoded credential facts, one candidate-root policy
and the explicit development flag. Certificate bytes, private keys, clocks,
configuration, databases and signatures are deliberately absent. A result is
classification data, not verified enrollment, complete withdrawal enumeration,
an authenticated root snapshot, an installation receipt or a capability.

The finite input profile matches the signed trust core's 256 roots, 1024
AAGUIDs per root and 2 MiB aggregate bound. Applying that profile to previously
unbounded legacy descriptors is an explicit fail-closed compatibility tightening;
oversized inputs are never truncated. Digest/UUID spelling and class enums are
not newly imposed here: comparison preserves the existing literal semantics.
"""
from __future__ import annotations

from dataclasses import dataclass


MAX_ROOTS = 256
MAX_ROOT_AAGUIDS = 1024
MAX_INPUT_BYTES = 2 * 1024 * 1024
# Results add only fixed reason/classification labels to retained input text.
# Reserve their bounded overhead instead of rejecting a valid near-limit input
# only after classification. This is not a JSON serialization-size guarantee.
MAX_RESULT_BYTES = MAX_INPUT_BYTES + 128
MIN_SEQUENCE = -(1 << 63)
MAX_SEQUENCE = (1 << 63) - 1
_REASONS = frozenset({
    "development_authenticator", "not_attested", "attestation_root_missing",
    "trust_root_withdrawn", "aaguid_no_longer_trusted", "authenticator_class_changed",
    "trusted_by_current_root",
})


class CredentialTrustError(ValueError):
    pass


def _boolean(value: object, label: str) -> None:
    if type(value) is not bool:
        raise CredentialTrustError(label + " must be an exact boolean")


def _text(value: object, label: str, *, optional: bool = False) -> int:
    if value is None and optional:
        return 0
    if type(value) is not str:
        raise CredentialTrustError(label + " must be exact text")
    if len(value) > MAX_INPUT_BYTES or "\0" in value:
        raise CredentialTrustError(label + " is oversized or contains NUL")
    try:
        size = len(value.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise CredentialTrustError(label + " is not valid Unicode") from exc
    if size > MAX_INPUT_BYTES:
        raise CredentialTrustError(label + " is oversized")
    return size


def _sequence(value: object, label: str) -> int:
    # The SQL history field has no positive CHECK. Preserve nullable signed64
    # metadata (including zero); bundle signature policy imposes its own bound.
    if value is None:
        return 0
    if type(value) is not int or not MIN_SEQUENCE <= value <= MAX_SEQUENCE:
        raise CredentialTrustError(label + " must be a nullable signed64 integer")
    return 8


def _bounded(size: int, *, maximum: int = MAX_INPUT_BYTES) -> None:
    if size > maximum:
        raise CredentialTrustError("credential trust inputs exceed the aggregate byte bound")


@dataclass(frozen=True, slots=True)
class CredentialTrustFacts:
    enrollment_trusted: bool
    authenticator_class: str
    has_development_key: bool
    root_sha256: str | None
    aaguid: str
    enrolled_bundle_digest: str | None
    enrolled_bundle_sequence: int | None

    def __post_init__(self) -> None:
        _facts_size(self)


def _facts_size(value: CredentialTrustFacts) -> int:
    _boolean(value.enrollment_trusted, "enrollment trust")
    _boolean(value.has_development_key, "development key presence")
    size = 2 + _text(value.authenticator_class, "credential class")
    size += _text(value.root_sha256, "credential root", optional=True)
    size += _text(value.aaguid, "credential AAGUID")
    size += _text(value.enrolled_bundle_digest, "enrolled bundle digest", optional=True)
    size += _sequence(value.enrolled_bundle_sequence, "enrolled bundle sequence")
    _bounded(size)
    return size


@dataclass(frozen=True, slots=True)
class RootTrustPolicy:
    id: str
    certificate_sha256: str
    authenticator_class: str | None
    aaguids: tuple[str, ...]
    bundle_digest: str | None
    bundle_sequence: int | None

    def __post_init__(self) -> None:
        _root_size(self)

    def input_size_bytes(self) -> int:
        """Validate and measure this descriptor for incremental edge admission.

        This counts UTF-8 text and fixed-width scalar input, not encoded JSON,
        certificates or authenticated evidence. No caller-supplied size is used.
        """
        try:
            return _root_size(self)
        except AttributeError as exc:
            raise CredentialTrustError("root policy is incomplete") from exc


def _root_size(value: RootTrustPolicy) -> int:
    size = _text(value.id, "root ID") + _text(value.certificate_sha256, "root certificate digest")
    size += _text(value.authenticator_class, "root class", optional=True)
    size += _text(value.bundle_digest, "root bundle digest", optional=True)
    size += _sequence(value.bundle_sequence, "root bundle sequence")
    if type(value.aaguids) is not tuple or len(value.aaguids) > MAX_ROOT_AAGUIDS:
        raise CredentialTrustError("root AAGUIDs must be a bounded exact tuple")
    for item in value.aaguids:
        size += _text(item, "root AAGUID")
        _bounded(size)
    _bounded(size)
    return size


def _copy_root(value: RootTrustPolicy) -> RootTrustPolicy:
    if type(value) is not RootTrustPolicy:
        raise CredentialTrustError("root policy has the wrong type")
    try:
        # No sorting, deduplication or lowercasing of stored policy data.
        return RootTrustPolicy(value.id, value.certificate_sha256, value.authenticator_class,
                               value.aaguids, value.bundle_digest, value.bundle_sequence)
    except AttributeError as exc:
        raise CredentialTrustError("root policy is incomplete") from exc


@dataclass(frozen=True, slots=True)
class CredentialTrustContext:
    roots: tuple[RootTrustPolicy, ...]
    development_enabled: bool

    def __post_init__(self) -> None:
        _boolean(self.development_enabled, "development policy")
        if type(self.roots) is not tuple or len(self.roots) > MAX_ROOTS:
            raise CredentialTrustError("trust roots must be a bounded exact tuple")
        roots = []
        size = 1
        for root in self.roots:
            owned = _copy_root(root)
            size += _root_size(owned)
            _bounded(size)
            roots.append(owned)
        object.__setattr__(self, "roots", tuple(roots))


def _copy_facts(value: CredentialTrustFacts) -> CredentialTrustFacts:
    if type(value) is not CredentialTrustFacts:
        raise CredentialTrustError("credential facts have the wrong type")
    try:
        return CredentialTrustFacts(value.enrollment_trusted, value.authenticator_class,
                                    value.has_development_key, value.root_sha256, value.aaguid,
                                    value.enrolled_bundle_digest, value.enrolled_bundle_sequence)
    except AttributeError as exc:
        raise CredentialTrustError("credential facts are incomplete") from exc


def _copy_context(value: CredentialTrustContext) -> CredentialTrustContext:
    if type(value) is not CredentialTrustContext:
        raise CredentialTrustError("credential trust context has the wrong type")
    try:
        return CredentialTrustContext(value.roots, value.development_enabled)
    except AttributeError as exc:
        raise CredentialTrustError("credential trust context is incomplete") from exc


def _development_exception(facts: CredentialTrustFacts, enabled: bool) -> bool:
    return facts.authenticator_class == "dev" and enabled and facts.has_development_key


def needs_current_roots(facts: CredentialTrustFacts, *, development_enabled: bool) -> bool:
    """Preserve the live wrapper's lazy root load without consulting any roots."""
    owned = _copy_facts(facts)
    _boolean(development_enabled, "development policy")
    return (not _development_exception(owned, development_enabled)
            and owned.enrollment_trusted and bool(owned.root_sha256))


@dataclass(frozen=True, slots=True)
class CredentialTrustStatus:
    """Immutable representation only; direct construction proves no trust."""

    enrollment_trusted: bool
    currently_trusted: bool
    reason: str
    effective_authenticator_class: str
    current_trust_bundle_digest: str | None
    current_trust_bundle_sequence: int | None
    current_trust_root_id: str | None = None
    current_trust_root_sha256: str | None = None

    def __post_init__(self) -> None:
        _boolean(self.enrollment_trusted, "result enrollment trust")
        _boolean(self.currently_trusted, "result current trust")
        if type(self.reason) is not str or self.reason not in _REASONS:
            raise CredentialTrustError("credential trust reason is not closed")
        size = 2 + _text(self.reason, "result reason")
        size += _text(self.effective_authenticator_class, "result class")
        size += _text(self.current_trust_bundle_digest, "result bundle digest", optional=True)
        size += _sequence(self.current_trust_bundle_sequence, "result bundle sequence")
        size += _text(self.current_trust_root_id, "result root ID", optional=True)
        size += _text(self.current_trust_root_sha256, "result root digest", optional=True)
        if self.reason == "trusted_by_current_root":
            if (self.enrollment_trusted is not True or self.currently_trusted is not True
                    or self.current_trust_root_id is None or self.current_trust_root_sha256 is None):
                raise CredentialTrustError("current-root result is incomplete")
        elif self.current_trust_root_id is not None or self.current_trust_root_sha256 is not None:
            raise CredentialTrustError("non-root result contains current-root fields")
        _bounded(size, maximum=MAX_RESULT_BYTES)

    def as_dict(self) -> dict[str, bool | str | int | None]:
        # Revalidate even a deliberately bypassed/mutated frozen dataclass.
        try:
            owned = CredentialTrustStatus(
                self.enrollment_trusted, self.currently_trusted, self.reason,
                self.effective_authenticator_class, self.current_trust_bundle_digest,
                self.current_trust_bundle_sequence, self.current_trust_root_id,
                self.current_trust_root_sha256)
        except AttributeError as exc:
            raise CredentialTrustError("credential trust result is incomplete") from exc
        result = {
            "enrollment_trusted": owned.enrollment_trusted,
            "currently_trusted": owned.currently_trusted,
            "reason": owned.reason,
            "effective_authenticator_class": owned.effective_authenticator_class,
            "current_trust_bundle_digest": owned.current_trust_bundle_digest,
            "current_trust_bundle_sequence": owned.current_trust_bundle_sequence,
        }
        if owned.reason == "trusted_by_current_root":
            result["current_trust_root_id"] = owned.current_trust_root_id
            result["current_trust_root_sha256"] = owned.current_trust_root_sha256
        return result


def classify(facts: CredentialTrustFacts, context: CredentialTrustContext) -> CredentialTrustStatus:
    """Classify owned inputs in the existing branch order, without root authority.

    The first matching certificate digest wins, including when later duplicates
    would permit the credential. AAGUID comparison uses str.lower (not casefold),
    while certificate/class comparison remains literal and case-sensitive.
    """
    owned = _copy_facts(facts)
    policy = _copy_context(context)
    _bounded(_facts_size(owned) + 1 + sum(_root_size(root) for root in policy.roots))
    if _development_exception(owned, policy.development_enabled):
        return CredentialTrustStatus(
            owned.enrollment_trusted, owned.enrollment_trusted,
            "development_authenticator" if owned.enrollment_trusted else "not_attested",
            "dev" if owned.enrollment_trusted else "unknown",
            owned.enrolled_bundle_digest, owned.enrolled_bundle_sequence)
    if not owned.enrollment_trusted:
        return CredentialTrustStatus(False, False, "not_attested", "unknown", None, None)
    if not owned.root_sha256:
        return CredentialTrustStatus(True, False, "attestation_root_missing", "unknown", None, None)
    root = next((item for item in policy.roots if item.certificate_sha256 == owned.root_sha256), None)
    if root is None:
        return CredentialTrustStatus(True, False, "trust_root_withdrawn", "unknown", None, None)
    if root.aaguids and owned.aaguid.lower() not in {item.lower() for item in root.aaguids}:
        return CredentialTrustStatus(True, False, "aaguid_no_longer_trusted", "unknown",
                                     root.bundle_digest, root.bundle_sequence)
    if root.authenticator_class and root.authenticator_class != owned.authenticator_class:
        return CredentialTrustStatus(True, False, "authenticator_class_changed", "unknown",
                                     root.bundle_digest, root.bundle_sequence)
    return CredentialTrustStatus(True, True, "trusted_by_current_root", owned.authenticator_class,
                                 root.bundle_digest, root.bundle_sequence, root.id, root.certificate_sha256)
