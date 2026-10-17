"""Purpose-fixed archive issuance from independently selected retained originals.

This authorizes historical verification for a prospective current scope. It
does not admit a new cohort, advance trust, renew old evidence, or establish
current database/witness truth. The v4 cohort consumer still performs final
archive admission against its genuinely observed and signed current cohort.
"""
from __future__ import annotations

import fcntl
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from scripts.authority import native_pilot_authority_io as io
from catchplate import authority_artifact_spec as spec
from catchplate import authority_attestation_cohort as cohort
from catchplate import authority_historical_archive as history
from catchplate import authority_launcher as launch
from catchplate import authority_local_configuration as configuration
from catchplate.authority_local_artifacts import sha
from catchplate.authority_local_install import _owning
from catchplate.authority_local_limits import LOCAL_SESSION_MAX_NS, LOCAL_SETUP_MAX_NS

SCHEMA = "catchplate.authorityTrustedHostLocalHistoricalArchiveApproval/v1"
PURPOSE = "retain-exact-history-for-current-local-cohort"
DELEGATION = "current-configuration-root-signs-complete-retained-history-v1"
RUNTIME_SCHEMA = "catchplate.authorityRuntimeEvidence/v1"
MAX_APPROVAL = 8192
ORIGINAL_NAMES = ("currentPackage", "currentTrustState", "currentConfiguration",
    "previousPackage", "previousTrustState", "previousConfiguration", "previousRuntimeEvidence")
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "originalSha256",
    "configurationRootPublicKeyBase64Url", "previousConfigurationRootPublicKeyBase64Url",
    "bootIdDigest", "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos",
    "expiresAtUnixNanos", "runtimeValidity"})
canonical = spec.canonical_json_bytes


def require(value):
    if not value:
        raise ValueError("local historical archive issuance refused")


def approval(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = configuration.document(raw, MAX_APPROVAL)
    require(set(value) == FIELDS and value["schema"] == SCHEMA and value["purpose"] == PURPOSE
        and value["rootDelegation"] == DELEGATION and value["bootIdDigest"] == boot)
    spec._require_digest(boot, name="archive issuing boot")
    for name in ("configurationRootPublicKeyBase64Url", "previousConfigurationRootPublicKeyBase64Url"):
        configuration._public(value[name])
    require(type(value["originalSha256"]) is dict and set(value["originalSha256"]) == set(ORIGINAL_NAMES))
    for pin in value["originalSha256"].values():
        spec._require_digest(pin, name="independently selected historical original")
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        require(type(value[name]) is int and 0 < value[name] < 2**63)
    require(type(now_boottime_ns) is type(now_unix_ns) is int
        and value["issuedAtBoottimeNs"] <= now_boottime_ns < value["deadlineBoottimeNs"]
        and value["issuedAtUnixNanos"] <= now_unix_ns < value["expiresAtUnixNanos"]
        and value["deadlineBoottimeNs"] - value["issuedAtBoottimeNs"] <= LOCAL_SETUP_MAX_NS
        and value["expiresAtUnixNanos"] - value["issuedAtUnixNanos"] <= LOCAL_SETUP_MAX_NS)
    interval = value["runtimeValidity"]
    require(type(interval) is dict and set(interval) == {"issuedAtEpochNs", "expiresAtEpochNs"})
    start, end = history._interval(interval["issuedAtEpochNs"], interval["expiresAtEpochNs"])
    require(start == value["issuedAtUnixNanos"] and value["expiresAtUnixNanos"] <= end < 2**63
        and end - start <= LOCAL_SESSION_MAX_NS)
    return value


def _previous(documents, selected):
    """Authenticate complete previous history at its original admission time."""
    runtime = history._object(documents["previousRuntimeEvidence"],
        {"schema", "currentCohort", "historicalArchive"}, "previous runtime evidence")
    require(runtime["schema"] == RUNTIME_SCHEMA)
    archive = runtime["historicalArchive"]
    payload = cohort._envelope(archive, history.SCHEMA, history._PAYLOAD_FIELDS)
    key = Ed25519PublicKey.from_public_bytes(configuration._public(
        selected["previousConfigurationRootPublicKeyBase64Url"]))
    cohort._verify_signature(archive, key)
    archive_start, archive_end = history._interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    prior_cohort = cohort._envelope(runtime["currentCohort"], cohort.SCHEMA, cohort._PAYLOAD_FIELDS)
    cohort_start, cohort_end = history._interval(prior_cohort["issuedAtEpochNs"], prior_cohort["expiresAtEpochNs"])
    statement = documents["previousPackage"]["generation"]
    # Historical lookup uses only this entry's interval. It cannot widen the
    # authority actually granted by the previous runtime's narrower archive.
    start = max(archive_start, cohort_start, history._epoch_ns(statement["validFrom"]))
    end = min(archive_end, cohort_end, history._epoch_ns(statement["validUntil"]))
    history._interval(start, end)
    entry = dict(configurationEnvelope=documents["previousConfiguration"],
        artifactPackage=documents["previousPackage"], artifactTrustState=documents["previousTrustState"],
        configurationRootPublicKeyBase64Url=selected["previousConfigurationRootPublicKeyBase64Url"],
        attestationCohort=runtime["currentCohort"], validFromEpochNs=start, validUntilEpochNs=end,
        configurationDigest=payload["configurationDigest"])
    snapshot = history._entry_snapshot(entry)
    # This is historical evaluation, not a claim that previous evidence is
    # live now. Reuse full signature, entries, interval and selector admission.
    admitted = history._admit_on_startup(original_bytes=canonical(archive), current_snapshot=snapshot,
        current_root_public_key=key, now_epoch_ns=archive_start)
    return entry, admitted, payload["entries"]


def _complete_entries(entry, admitted, originals):
    """Carry every admitted old entry verbatim; append exactly prior-current."""
    require(type(originals) is list and len(admitted.records) == len(originals) + 1
        and len(originals) + 1 <= history.MAX_ENTRIES)
    rows = [(record, original) for record, original in zip(admitted.records[1:], originals)]
    rows.append((admitted.records[0], entry))
    rows.sort(key=lambda row: (row[0].configuration_digest, row[0].planner_receipt_digest))
    selectors = [(record.configuration_digest, record.planner_receipt_digest) for record, _ in rows]
    require(len(set(selectors)) == len(selectors))
    return [original for _, original in rows]


def prepare(raw, originals, *, boot, now_boottime_ns, now_unix_ns):
    """Bounded original-byte validation only; no runtime-owner fabrication."""
    selected = approval(raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    require(type(originals) is dict and set(originals) == set(ORIGINAL_NAMES))
    documents = {}
    for name in ORIGINAL_NAMES:
        require(type(originals[name]) is bytes and 2 <= len(originals[name]) <= history.MAX_BYTES
            and sha(originals[name]) == selected["originalSha256"][name])
        documents[name] = history._canonical_document(originals[name])
        require(type(documents[name]) is dict)
    package, state = documents["currentPackage"], documents["currentTrustState"]
    verified = spec.verify_signed_artifact_package(package, trust_state=state,
        validation_time=history._timestamp_floor(now_unix_ns))
    require(verified.disposition == "CurrentExactRetry")
    interval = selected["runtimeValidity"]
    start, end = interval["issuedAtEpochNs"], interval["expiresAtEpochNs"]
    terminal = spec.verify_signed_artifact_package(package, trust_state=state,
        validation_time=history._timestamp_floor(end - 1))
    require(terminal == verified)
    statement = package["generation"]
    require(history._epoch_ns(statement["validFrom"]) <= start < end <= history._epoch_ns(statement["validUntil"]))
    root_raw = configuration._public(selected["configurationRootPublicKeyBase64Url"])
    root = Ed25519PublicKey.from_public_bytes(root_raw)
    envelope = documents["currentConfiguration"]
    digest = cohort._domain_digest(history.configuration.CONFIG_SCHEMA, canonical(envelope["payload"]))
    service, digest = history._configuration(dict(configurationEnvelope=envelope,
        configurationDigest=digest, artifactPackage=package), history._generation(package, verified), root)
    require(end - start <= cohort._static_configuration(service)[3])
    entry, previous, old_entries = _previous(documents, selected)
    entries = _complete_entries(entry, previous, old_entries)
    payload = dict(schema=history.SCHEMA, purpose=history.PURPOSE,
        sourceRevision=cohort.authority.SOURCE_REVISION, configurationDigest=digest,
        generationDigest=verified.generation_digest, issuedAtEpochNs=start, expiresAtEpochNs=end, entries=entries)
    # Refuse overflow before key access. Never truncate history to fit output.
    require(len(canonical(dict(schema=history.SCHEMA, payload=payload,
        signature=spec.strict_base64url_encode(bytes(64))))) <= history.MAX_BYTES)
    return dict(selected=selected, payload=payload, rootPublic=root_raw)


def _sign_archive(prepared, signer):
    """Existing signature codec; only the owner establishes input custody."""
    require(signer.public_key().public_bytes(serialization.Encoding.Raw,
        serialization.PublicFormat.Raw) == prepared["rootPublic"])
    message = cohort._domain_digest(history.SCHEMA, canonical(prepared["payload"])).encode("ascii")
    signature = signer.sign(message)
    signer.public_key().verify(signature, message)
    raw = canonical(dict(schema=history.SCHEMA, payload=prepared["payload"],
        signature=spec.strict_base64url_encode(signature)))
    require(len(raw) <= history.MAX_BYTES)
    return raw


class LocalHistoricalArchiveIssuer:
    """Own duplicate original FDs only; no process/DB/restart authority token."""
    def __init__(self, *, approval_fd, approval_sha256, signing_key_fd, original_fds):
        io._process()
        self._owned = []
        self._closed, self._used = False, False
        try:
            require(type(original_fds) is dict and set(original_fds) == set(ORIGINAL_NAMES))
            given = {"approval": approval_fd, "key": signing_key_fd, **original_fds}
            require(all(type(fd) is int and fd >= 3 for fd in given.values())
                and len(set(given.values())) == len(given))
            identities, self._fds, self._identities = set(), {}, {}
            for name, fd in given.items():
                maximum = 32 if name == "key" else MAX_APPROVAL if name == "approval" else history.MAX_BYTES
                if name != "key":
                    require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
                identity = io._input(fd, maximum, private=name == "key")
                require(identity[:2] not in identities)
                identities.add(identity[:2])
                with _owning():
                    owned = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
                    self._owned.append(owned)
                require(io._input(owned, maximum, private=name == "key") == identity)
                self._fds[name], self._identities[name] = owned, identity
            self._raw = io.read_public(self._fds["approval"], MAX_APPROVAL)
            require(sha(self._raw) == approval_sha256)
            self._originals = {name: io.read_public(self._fds[name], history.MAX_BYTES) for name in ORIGINAL_NAMES}
            self._pid = os.getpid()
            self._start = launch._process_identity(self._pid)[0]
            self._boot = launch._boot_identity_digest()
            self._last_boot, self._last_epoch = io._clock(), time.time_ns()
            self._prepared = prepare(self._raw, self._originals, boot=self._boot,
                now_boottime_ns=self._last_boot, now_unix_ns=self._last_epoch)
            self.check()
        except BaseException:
            with _owning():
                for fd in reversed(self._owned):
                    os.close(fd)
                self._owned.clear()
                self._closed = True
            raise

    def check(self):
        io._process()
        require(not self._closed and os.getpid() == self._pid
            and launch._process_identity(self._pid)[0] == self._start and launch._boot_identity_digest() == self._boot)
        now_boot, now_epoch = io._clock(), time.time_ns()
        selected = self._prepared["selected"]
        require(self._last_boot <= now_boot < selected["deadlineBoottimeNs"]
            and self._last_epoch <= now_epoch < selected["expiresAtUnixNanos"])
        self._last_boot, self._last_epoch = now_boot, now_epoch
        for name, fd in self._fds.items():
            maximum = 32 if name == "key" else MAX_APPROVAL if name == "approval" else history.MAX_BYTES
            require(io._input(fd, maximum, private=name == "key") == self._identities[name])
            if name != "key":
                require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
                require(io.read_public(fd, maximum) == (self._raw if name == "approval" else self._originals[name]))

    def issue(self):
        self.check()
        require(not self._used)
        self._used = True  # Every later failure is terminal, including uncertain output.
        prepared = prepare(self._raw, self._originals, boot=self._boot,
            now_boottime_ns=io._clock(), now_unix_ns=time.time_ns())
        self.check()
        signer = io.signing_key(self._fds["key"])
        try:
            raw = _sign_archive(prepared, signer)
        finally:
            del signer
        self.check()
        return raw

    def publish(self):
        raw = self.issue()
        io.write_public(raw, deadline_boottime_ns=self._prepared["selected"]["deadlineBoottimeNs"], check=self.check)

    def close(self):
        if self._closed:
            return
        require(os.getpid() == self._pid and launch._process_identity(self._pid)[0] == self._start)
        with _owning():
            for fd in reversed(self._owned):
                os.close(fd)
            self._owned.clear()
            self._closed = True
