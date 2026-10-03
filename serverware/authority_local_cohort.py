"""Observe five parked local services and issue their existing root-signed cohort.

This is a trusted-host, co-located issuer, not independent custody or hardware
attestation. The five approved manifests/certificates must already be issued.
Only the configuration root signs these receipt domains; no service key signs
them. Publication releases actual parked children, not proof of service success.
"""
from __future__ import annotations

import fcntl
import os
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from serverware import authority_attestation_cohort as cohort
from serverware import authority_historical_archive as history
from serverware import authority_local_configuration as configuration
from serverware import authority_local_launch_authorization as pair
from serverware.authority_local_limits import LOCAL_SESSION_MAX_NS, LOCAL_SETUP_MAX_NS

io, spec, launch, stage = pair.io, pair.spec, pair.launch, pair.stage
canonical, document, sha = spec.canonical_json_bytes, configuration.document, pair.sha
SCHEMA = "serverware.authorityTrustedHostLocalCohortApproval/v2"
RUNTIME_SCHEMA = "serverware.authorityTrustedHostLocalCohortApproval/v3"
RETAINED_SCHEMA = "serverware.authorityTrustedHostLocalCohortApproval/v4"
MAX_RUNTIME_NS = LOCAL_SESSION_MAX_NS
PURPOSE = "issue-observed-five-role-local-cohort"
DELEGATION = "configuration-root-signs-five-local-role-receipts-cohort-and-initial-history-v1"
INITIAL_HISTORY = "explicit-empty-first-generation-history"
RETAINED_HISTORY = "explicit-current-root-signed-retained-history-v1"
RETAINED_DELEGATION = "configuration-root-signs-five-local-role-receipts-consumes-retained-history-v1"
RUNTIME_EVIDENCE_SCHEMA = "serverware.authorityRuntimeEvidence/v1"
FIELDS = frozenset({"schema", "purpose", "rootDelegation", "configurationRootPublicKeyBase64Url",
    "serviceConfigurationOriginal", "serviceConfigurationSha256", "roles", "historicalArchiveSelection", "bootIdDigest",
    "issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"})
ROLE_FIELDS = frozenset({"launchApprovalSha256", "observationSha256", "manifestSha256",
    "certificateSha256", "exchangeDirectory"})
ORIGINAL_NAMES = ("launchApproval", "observation", "manifest", "certificate")
CONFIG_NAME = "SERVERWARE_POLICY_AUTHORITY_CONFIG_FD"


def require(value):
    if not value:
        raise ValueError("local five-role cohort refused")


def runtime_interval(value):
    """Prospective local runtime authority, never a renewed issuing window."""
    if value["schema"] == SCHEMA:
        return value["issuedAtUnixNanos"], value["expiresAtUnixNanos"]
    require(value["schema"] in (RUNTIME_SCHEMA, RETAINED_SCHEMA))
    interval = value["runtimeValidity"]
    require(type(interval) is dict and set(interval) == {"issuedAtEpochNs", "expiresAtEpochNs"})
    start, end = interval["issuedAtEpochNs"], interval["expiresAtEpochNs"]
    require(type(start) is type(end) is int and 0 < start < end < 2**63
        and start == value["issuedAtUnixNanos"] and value["expiresAtUnixNanos"] <= end
        and end - start <= MAX_RUNTIME_NS)
    return start, end


def approval(raw, *, boot, now_boottime_ns, now_unix_ns):
    value = document(raw, io.MAX_PUBLIC)
    retained = value.get("schema") == RETAINED_SCHEMA
    require(value.get("schema") in (SCHEMA, RUNTIME_SCHEMA, RETAINED_SCHEMA)
        and set(value) == FIELDS | ({"runtimeValidity"} if value["schema"] != SCHEMA else set())
            | ({"historicalArchiveSha256"} if retained else set())
        and value["purpose"] == PURPOSE
        and value["rootDelegation"] == (RETAINED_DELEGATION if retained else DELEGATION)
        and value["bootIdDigest"] == boot
        and value["historicalArchiveSelection"] == (RETAINED_HISTORY if retained else INITIAL_HISTORY))
    if retained:
        spec._require_digest(value["historicalArchiveSha256"], name="retained historical archive")
    spec._require_digest(boot, name="cohort boot")
    configuration._public(value["configurationRootPublicKeyBase64Url"])
    for name in ("issuedAtBoottimeNs", "deadlineBoottimeNs", "issuedAtUnixNanos", "expiresAtUnixNanos"):
        require(type(value[name]) is int and 0 < value[name] < 2**63)
    require(type(now_boottime_ns) is type(now_unix_ns) is int
        and value["issuedAtBoottimeNs"] <= now_boottime_ns < value["deadlineBoottimeNs"]
        and value["issuedAtUnixNanos"] <= now_unix_ns < value["expiresAtUnixNanos"]
        and value["deadlineBoottimeNs"] - value["issuedAtBoottimeNs"] <= LOCAL_SETUP_MAX_NS
        and value["expiresAtUnixNanos"] - value["issuedAtUnixNanos"] <= LOCAL_SETUP_MAX_NS)
    runtime_interval(value)
    require(type(value["serviceConfigurationOriginal"]) is str and value["serviceConfigurationOriginal"].isascii()
        and sha(value["serviceConfigurationOriginal"].encode("ascii")) == value["serviceConfigurationSha256"])
    document(value["serviceConfigurationOriginal"].encode("ascii"), configuration.MAX_CONFIGURATION)
    require(type(value["roles"]) is dict and set(value["roles"]) == set(cohort.ROLES))
    directories = set()
    for row in value["roles"].values():
        require(type(row) is dict and set(row) == ROLE_FIELDS)
        for name in ORIGINAL_NAMES:
            spec._require_digest(row[name + "Sha256"], name="cohort original")
        directory = row["exchangeDirectory"]
        require(type(directory) is dict and set(directory) == {"device", "inode"}
            and type(directory["device"]) is type(directory["inode"]) is int
            and 0 <= directory["device"] < 2**64 and 0 < directory["inode"] < 2**64)
        directories.add((directory["device"], directory["inode"]))
    require(len(directories) == len(cohort.ROLES))
    return value


def _archive_original(selected, original):
    """Pin bounded canonical bytes only; this is not historical admission."""
    if selected["schema"] != RETAINED_SCHEMA:
        require(original is None)
        return None
    require(type(original) is bytes and 2 <= len(original) <= history.MAX_BYTES
        and sha(original) == selected["historicalArchiveSha256"])
    return history._canonical_document(original)


def _archive_precheck(context, *, now_unix_ns):
    """Authenticate the outer scope before signing, never invent a snapshot."""
    archive = _archive_original(context["selected"], context.get("archiveOriginal"))
    require(archive is not None)
    payload = cohort._envelope(archive, history.SCHEMA, history._PAYLOAD_FIELDS)
    cohort._verify_signature(archive, Ed25519PublicKey.from_public_bytes(context["rootPublic"]))
    start, end = history._interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
    runtime_start, runtime_end = runtime_interval(context["selected"])
    require(payload["purpose"] == history.PURPOSE and payload["sourceRevision"] == cohort.authority.SOURCE_REVISION
        and payload["configurationDigest"] == context["configurationDigest"]
        and payload["generationDigest"] == context["generationDigest"]
        and max(runtime_start, context["generationInterval"][0]) <= start <= now_unix_ns < end
        <= min(runtime_end, context["generationInterval"][1])
        and type(payload["entries"]) is list and len(payload["entries"]) <= history.MAX_ENTRIES)
    return archive


def prepare(raw, originals, *, boot, now_boottime_ns, now_unix_ns, archive_original=None):
    """Authenticate originals; only the owner below supplies live observations."""
    selected = approval(raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    _archive_original(selected, archive_original)
    require(type(originals) is dict and set(originals) == set(cohort.ROLES))
    root_raw = configuration._public(selected["configurationRootPublicKeyBase64Url"])
    root = Ed25519PublicKey.from_public_bytes(root_raw)
    contexts, identities, processes = {}, {}, set()
    common = None
    for role in cohort.ROLES:
        source, pins = originals[role], selected["roles"][role]
        require(type(source) is dict and set(source) == set(ORIGINAL_NAMES))
        require(all(type(source[name]) is bytes and sha(source[name]) == pins[name + "Sha256"] for name in ORIGINAL_NAMES))
        context = pair.prepare(source["launchApproval"], source["observation"], boot=boot,
            now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
        payload, declared = context["payload"], context["selected"]
        require(payload["role"] == role and context["rootPublic"] == root_raw
            and declared["exchangeDirectory"] == pins["exchangeDirectory"])
        for first, last in (("issuedAtBoottimeNs", "deadlineBoottimeNs"), ("issuedAtUnixNanos", "expiresAtUnixNanos")):
            require(declared[first] <= selected[first] < selected[last] <= declared[last])
        process = context["observed"]["process"]
        require(process["pid"] not in processes); processes.add(process["pid"])
        verified = context["verified"]
        # An empty historical archive is an explicit first-generation choice,
        # never an automatic fallback for a later generation or lost history.
        if selected["schema"] != RETAINED_SCHEMA:
            require(verified.generation_sequence == 0 and verified.predecessor_digest is None
                and verified.minimum_rollback_sequence == 0)
        scope = (verified.package_digest, verified.generation_digest, verified.generation_sequence)
        if common is None:
            common = scope
        require(scope == common)
        manifest = document(source["manifest"], pair.LATE_LIMITS["manifest.json"])
        require(set(manifest) == {"schema", "payload", "signature"}
            and manifest["schema"] == launch.LAUNCH_MANIFEST_SCHEMA
            and canonical(manifest["payload"]) == declared["payloadOriginal"].encode("ascii"))
        root.verify(spec.strict_base64url_decode(manifest["signature"], name="launch signature", decoded_size=64),
            launch._domain_digest(launch.LAUNCH_MANIFEST_SCHEMA, canonical(payload)).encode("ascii"))
        certificate = document(source["certificate"], pair.LATE_LIMITS["certificate.json"])
        stage.validate_signed_launch_identity(certificate, request=payload["stageZeroRequest"], **context["kwargs"])
        require(certificate["payload"] == pair.certificate_payload(payload["stageZeroRequest"],
            declared["launchPublicKeyBase64Url"], context["kwargs"]))
        runtime_start, runtime_end = runtime_interval(selected)
        request = payload["stageZeroRequest"]
        require(pair._epoch(request["launch"]["validFrom"]) <= runtime_start < runtime_end
            <= pair._epoch(request["launch"]["validUntil"])
            and runtime_end <= pair._epoch(context["issuer"].not_after))
        identities[role] = (launch._domain_digest(launch.LAUNCH_PAYLOAD_SCHEMA, canonical(payload)),
            stage.stage_zero_request_digest(payload["stageZeroRequest"], **context["kwargs"]))
        contexts[role] = context
    service_raw = selected["serviceConfigurationOriginal"].encode("ascii")
    signed = document(service_raw, configuration.MAX_CONFIGURATION)
    require(set(signed) == {"schema", "payload", "signature"}
        and signed["schema"] == configuration.generator.SERVICE_CONFIGURATION_SCHEMA)
    root.verify(spec.strict_base64url_decode(signed["signature"], name="service signature", decoded_size=64),
        configuration.signature_message("authority-service", signed["payload"]))
    service = signed["payload"]
    verified = contexts[cohort.ROLES[0]]["verified"]
    bundle = verified.package["bundle"]
    payload_schema, config_digest = configuration._validate_payload(service, "authority-service",
        verified.package["generation"], spec.role_binding_digests(bundle["roleManifests"]))
    configuration.generator.genesis_policy.configuration(service.get(configuration.generator.genesis_policy.FIELD),
        root_digest=configuration._spki(selected["configurationRootPublicKeyBase64Url"]))
    require(all(row["responseSigningSpkiDigest"] != configuration._spki(selected["configurationRootPublicKeyBase64Url"])
        for row in service["roles"].values()))
    require(dict(fileDigest=sha(service_raw), payloadDigest=config_digest, payloadSchema=payload_schema,
        role="authority-service") in spec.configuration_payload_bindings(bundle["configurations"]))
    static = cohort._static_configuration(service)
    runtime_start, runtime_end = runtime_interval(selected)
    require(runtime_end - runtime_start <= static[3])
    generation = verified.package["generation"]
    generation_interval = (history._epoch_ns(generation["validFrom"]), history._epoch_ns(generation["validUntil"]))
    require(generation_interval[0] <= runtime_start < runtime_end <= generation_interval[1])
    for context in contexts.values():
        require(context["payload"]["packageVersions"] == service["packageVersions"])
        credentials = {row["name"]: row for row in context["observed"]["credentials"]}
        require(CONFIG_NAME in credentials and credentials[CONFIG_NAME]["sha256"] == sha(service_raw)
            and credentials[CONFIG_NAME]["size"] == len(service_raw))
    context = dict(selected=selected, rootPublic=root_raw, contexts=contexts, identities=identities,
        service=service, serviceOriginal=service_raw, configurationDigest=config_digest,
        static=static, packageDigest=common[0], generationDigest=common[1], generationSequence=common[2],
        generationContext=history._generation(verified.package, verified), generationInterval=generation_interval,
        archiveOriginal=archive_original)
    if selected["schema"] == RETAINED_SCHEMA:
        _archive_precheck(context, now_unix_ns=now_unix_ns)
    return context


def _signed_cohort(context, key, *, now_unix_ns):
    """Existing exact domains; called only after complete original/live admission."""
    require(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == context["rootPublic"])
    selected = context["selected"]
    runtime_start, runtime_end = runtime_interval(selected)
    common = dict(sourceRevision=cohort.authority.SOURCE_REVISION,
        configurationDigest=context["configurationDigest"], generationDigest=context["generationDigest"],
        operationManifestDigest=cohort.authority.OPERATION_MANIFEST_DIGEST, artifactPackageDigest=context["packageDigest"],
        issuedAtEpochNs=runtime_start, expiresAtEpochNs=runtime_end)
    def sign(payload):
        return dict(schema=payload["schema"], payload=payload,
            signature=spec.strict_base64url_encode(key.sign(cohort._domain_digest(payload["schema"], canonical(payload)).encode("ascii"))))
    receipts = []
    for role in cohort.ROLES:
        manifest, request = context["identities"][role]
        process_mode, measurement, response = context["static"][0][role]
        receipts.append(sign(dict(common, schema=cohort.RECEIPT_SCHEMA, role=role, processMode=process_mode,
            launchManifestDigest=manifest, stageZeroRequestDigest=request,
            runtimeClosureDigest=cohort._domain_digest("serverware.policyAuthorityRuntimeClosure/v2",
                manifest.encode("ascii"), canonical(context["service"]["packageVersions"])),
            measurementDigest=measurement, responseSigningSpkiDigest=response, **cohort._LOCAL_CLAIMS)))
    raw = canonical(sign(dict(common, schema=cohort.SCHEMA, roleBindingDigests=context["static"][1], receipts=receipts)))
    require(len(raw) <= cohort.MAX_BYTES)
    for role in cohort.ROLES:
        cohort._verify_cohort_against_scope(held_bytes=raw, held_digest=context["configurationDigest"],
            held_key=key.public_key(), static_configuration=context["static"], generation_sequence=context["generationSequence"],
            generation_digest=context["generationDigest"], package_digest=context["packageDigest"],
            local_binding=(role, *context["identities"][role]), evaluation_epoch_ns=now_unix_ns)
    return raw, canonical(receipts[cohort.ROLES.index("verifier")])


def _signed_runtime_evidence(context, key, *, now_unix_ns):
    """Produce service delivery with initial history or an exact retained archive.

    The owner supplies actual admitted package/launch context. These pure
    signed codec results alone are not evidence of a live process or database.
    """
    selected, generation = context["selected"], context["generationContext"]
    runtime_start, runtime_end = runtime_interval(selected)
    retained = selected["schema"] == RETAINED_SCHEMA
    archive = _archive_precheck(context, now_unix_ns=now_unix_ns) if retained else None
    if not retained:
        _archive_original(selected, context.get("archiveOriginal"))
        require(selected["historicalArchiveSelection"] == INITIAL_HISTORY
            and context["generationSequence"] == generation["sequence"] == 0
            and generation["predecessorDigest"] is None and generation["minimumRollbackSequence"] == 0)
    require(context["generationSequence"] == generation["sequence"]
        and generation["digest"] == context["generationDigest"])
    cohort_raw, verifier_raw = _signed_cohort(context, key, now_unix_ns=now_unix_ns)
    admitted, _, _ = cohort._verify_cohort_against_scope(held_bytes=cohort_raw,
        held_digest=context["configurationDigest"], held_key=key.public_key(),
        static_configuration=context["static"], generation_sequence=context["generationSequence"],
        generation_digest=context["generationDigest"], package_digest=context["packageDigest"],
        local_binding=(cohort.ROLES[0], *context["identities"][cohort.ROLES[0]]), evaluation_epoch_ns=now_unix_ns)
    identities = {}
    for role, raw, digest in admitted.receipts:
        payload = document(raw, cohort.MAX_BYTES)["payload"]
        identities[role] = dict(measurementDigest=payload["measurementDigest"],
            responseSigningSpkiDigest=payload["responseSigningSpkiDigest"], attestationReceiptDigest=digest)
    runtime = dict(schema=history.configuration.RUNTIME_ROLE_IDENTITIES_SCHEMA,
        configurationDigest=context["configurationDigest"], generationSequence=context["generationSequence"],
        generationDigest=context["generationDigest"], cohortDigest=admitted.cohort_digest, roles=identities)
    snapshot = history._HistoricalSnapshot(payload=context["service"], configuration_digest=context["configurationDigest"],
        generation=generation, runtime_role_identities=runtime,
        valid_from_epoch_ns=max(context["generationInterval"][0], admitted.valid_from_epoch_ns),
        valid_until_epoch_ns=min(context["generationInterval"][1], admitted.valid_until_epoch_ns))
    if not retained:
        payload = dict(schema=history.SCHEMA, purpose=history.PURPOSE, sourceRevision=cohort.authority.SOURCE_REVISION,
            configurationDigest=context["configurationDigest"], generationDigest=context["generationDigest"],
            issuedAtEpochNs=runtime_start, expiresAtEpochNs=runtime_end, entries=[])
        archive = dict(schema=history.SCHEMA, payload=payload, signature=spec.strict_base64url_encode(
            key.sign(cohort._domain_digest(history.SCHEMA, canonical(payload)).encode("ascii"))))
    archive_raw = context["archiveOriginal"] if retained else canonical(archive)
    require(canonical(archive) == archive_raw)
    checked = history._admit_on_startup(original_bytes=archive_raw, current_snapshot=snapshot,
        current_root_public_key=key.public_key(), now_epoch_ns=now_unix_ns)
    if not retained:
        require(len(checked.records) == 1)  # Current snapshot only; no invented historical record.
    delivery = canonical(dict(schema=RUNTIME_EVIDENCE_SCHEMA,
        currentCohort=document(cohort_raw, cohort.MAX_BYTES), historicalArchive=archive))
    require(len(delivery) <= pair.LATE_LIMITS["evidence.json"])
    return cohort_raw, verifier_raw, delivery


class LocalCohortError(RuntimeError):
    def __init__(self, owner):
        super().__init__("local cohort refused; partial publication and owner retained")
        self.owner = owner


class LocalCohortIssuer:
    @classmethod
    def open(cls, *, approval_fd, approval_sha256, signing_key_fd, role_inputs, archive_fd=None):
        self = cls()
        self.observers, self.named, self.originals, self.released = {}, [], {}, set()
        self.used = self.issued = self.publication_started = self.closed = self.closing = False
        self.context = self.raw = self.value = self.cohort_raw = self.verifier_raw = self.delivery_raw = None
        self.archive_fd, self.archive_identity, self.archive_raw, self.archive_interval = archive_fd, None, None, None
        self.pid, self.start = os.getpid(), launch._process_identity(os.getpid())[0]
        try:
            io._process()
            require(type(role_inputs) is dict and set(role_inputs) == set(cohort.ROLES))
            require(all(type(row) is dict and set(row) == {"approval_fd", "exchange_directory_fd"} for row in role_inputs.values()))
            fds = [approval_fd, signing_key_fd, *(fd for row in role_inputs.values() for fd in row.values()),
                *([] if archive_fd is None else [archive_fd])]
            require(all(type(fd) is int and 3 <= fd < 2**31 for fd in fds) and len(set(fds)) == len(fds)
                and len({(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in fds}) == len(fds))
            self.fd, self.key_fd = approval_fd, signing_key_fd
            self.source_identity = io._input(self.fd, io.MAX_PUBLIC)
            self.key_identity = io._input(self.key_fd, 32, private=True)
            self.raw = io.read_public(self.fd, io.MAX_PUBLIC)
            require(sha(self.raw) == approval_sha256)
            self.boot = launch._boot_identity_digest()
            self.last_boot, self.last_epoch = io._clock(), time.time_ns()
            self.value = approval(self.raw, boot=self.boot, now_boottime_ns=self.last_boot, now_unix_ns=self.last_epoch)
            require((self.value["schema"] == RETAINED_SCHEMA) == (archive_fd is not None))
            if archive_fd is not None:
                require(fcntl.fcntl(archive_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
                self.archive_identity = io._input(archive_fd, history.MAX_BYTES)
                self.archive_raw = io.read_public(archive_fd, history.MAX_BYTES)
                payload = _archive_original(self.value, self.archive_raw)["payload"]
                self.archive_interval = history._interval(payload["issuedAtEpochNs"], payload["expiresAtEpochNs"])
            for role in cohort.ROLES:
                # The acquisition return/assignment is one ownership transfer;
                # an interrupt cannot strand the observer's real acquired FDs.
                with pair._owning():
                    try:
                        observer = pair.LocalLaunchAuthorizationIssuer.open_observer(**role_inputs[role],
                            approval_sha256=self.value["roles"][role]["launchApprovalSha256"])
                    except pair.LocalLaunchAuthorizationError as error:
                        self.observers[role] = error.owner
                        raise
                    self.observers[role] = observer
                self.originals[role] = dict(launchApproval=observer.raw, observation=observer.observation_raw)
                for purpose in ("manifest", "certificate"):
                    name = purpose + ".json"
                    fd = observer._open(name, directory_fd=observer.directory, nofollow=True)
                    identity = io._input(fd, pair.LATE_LIMITS[name])
                    require(os.fstat(fd).st_nlink == 1)
                    self.named.append((observer.directory, name, fd, identity))
                    self.originals[role][purpose] = io.read_public(fd, pair.LATE_LIMITS[name])
                self._absent(observer.directory)
                self.check()
            self.context = prepare(self.raw, self.originals, boot=self.boot,
                now_boottime_ns=io._clock(), now_unix_ns=time.time_ns(), archive_original=self.archive_raw)
            self.verify_live()
            return self
        except BaseException as error:
            raise LocalCohortError(self) from error

    @staticmethod
    def _absent(directory):
        try:
            os.stat("evidence.json", dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("cohort evidence already exists")

    def check(self):
        io._process()
        require(not self.closed and not self.closing and os.getpid() == self.pid
            and launch._process_identity(self.pid)[0] == self.start and launch._boot_identity_digest() == self.boot)
        now_boot, now_epoch = io._clock(), time.time_ns()
        require(self.last_boot <= now_boot < self.value["deadlineBoottimeNs"]
            and self.last_epoch <= now_epoch < self.value["expiresAtUnixNanos"]
            and io._input(self.fd, io.MAX_PUBLIC) == self.source_identity
            and io._input(self.key_fd, 32, private=True) == self.key_identity)
        self.last_boot, self.last_epoch = now_boot, now_epoch
        self._check_archive()
        for role, observer in self.observers.items():
            observer.check_sources() if role in self.released else observer.check()
        for directory, name, fd, identity in self.named:
            require(io._identity(os.fstat(fd)) == identity
                and io._identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) == identity)

    def _check_archive(self):
        if self.value["schema"] != RETAINED_SCHEMA:
            require(self.archive_fd is self.archive_identity is self.archive_raw is self.archive_interval is None)
            return
        require(fcntl.fcntl(self.archive_fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
            and io._input(self.archive_fd, history.MAX_BYTES) == self.archive_identity
            and io.read_public(self.archive_fd, history.MAX_BYTES) == self.archive_raw
            and sha(self.archive_raw) == self.value["historicalArchiveSha256"])
        require(self.archive_interval[0] <= time.time_ns() < self.archive_interval[1])

    def verify_live(self):
        self.check()
        for role, observer in self.observers.items():
            if role in self.released:
                continue
            observer.verify_live()
            credential = next(row for row in observer.context["observed"]["credentials"] if row["name"] == CONFIG_NAME)
            require(observer._read(observer._child_fd(credential["fd"]), configuration.MAX_CONFIGURATION)
                == self.context["serviceOriginal"])
            self._absent(observer.directory)
            self.check()
        require(io.read_public(self.fd, io.MAX_PUBLIC) == self.raw)

    def issue(self):
        """Retain genuine signed originals while every approved child stays parked.

        The commissioning owner can now bind the database to these exact
        receipts before releasing services. This is one signing attempt, not
        an expiry renewal, and it publishes nothing to an exchange directory.
        """
        try:
            require(not self.used)
            self.used = True
            self.verify_live()
            self.context = prepare(self.raw, self.originals, boot=self.boot,
                now_boottime_ns=io._clock(), now_unix_ns=time.time_ns(), archive_original=self.archive_raw)
            key = io.signing_key(self.key_fd)
            self.cohort_raw, self.verifier_raw, self.delivery_raw = _signed_runtime_evidence(
                self.context, key, now_unix_ns=time.time_ns())
            del key
            self.verify_live()
            self.issued = True
            return self._format_bootstrap_originals()
        except BaseException as error:
            raise LocalCohortError(self) from error

    def bootstrap_originals(self):
        """Return original receipts only while the full cohort remains parked."""
        self.verify_live()
        return self._format_bootstrap_originals()

    def _format_bootstrap_originals(self):
        """Format held originals after the caller's full live verification."""
        require(self.issued and not self.publication_started and not self.released
            and self.cohort_raw is not None and self.delivery_raw is not None)
        signed = document(self.cohort_raw, cohort.MAX_BYTES)
        receipts = {row["payload"]["role"]: canonical(row) for row in signed["payload"]["receipts"]}
        require(set(receipts) == set(cohort.ROLES) and receipts["verifier"] == self.verifier_raw)
        return dict(cohortOriginal=self.cohort_raw, runtimeEvidenceOriginal=self.delivery_raw,
            receiptOriginals=receipts)

    def publish(self):
        """Release the same retained cohort once; never re-sign held originals."""
        try:
            require(not self.publication_started)
            if not self.used:
                self.issue()
            require(self.issued)
            self.publication_started = True
            self.verify_live()
            for role in cohort.ROLES:
                # Earlier recipients may immediately resume. Never demand their
                # parked state again, nor retract an already delivered cohort.
                self.verify_live()
                observer = self.observers[role]
                fd = pair.publish_late_original(observer.directory, "evidence.json", self.delivery_raw,
                    hold=observer._hold, check=self.check, linked=lambda role=role: self.released.add(role))
                self.named.append((observer.directory, "evidence.json", fd, io._identity(os.fstat(fd))))
            self.check()
            return {role: sha(self.delivery_raw) for role in cohort.ROLES}
        except BaseException as error:
            raise LocalCohortError(self) from error

    def verifier_original(self):
        self.check()
        require(self.released == set(cohort.ROLES) and self.verifier_raw is not None)
        return self.verifier_raw

    def close(self):
        if self.closed:
            return
        require(not self.closing and os.getpid() == self.pid and launch._process_identity(self.pid)[0] == self.start)
        self.closing = True
        # Descriptor-only cleanup works after expiry; it never controls children.
        for observer in reversed(tuple(self.observers.values())):
            observer.close()
        self.closed = True
