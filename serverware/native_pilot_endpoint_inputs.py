"""Real remaining endpoint resources for the fixed single-driver native pilot.

Public bytes/pins are independently supplied, not approvals created here. The
retrieval directory must already have been prepared by the existing installer:
inspect actual fs-verity files, or the explicitly selected empty fresh-ledger
directory, never accept its observation JSON instead.
The original cohort window (at most 30 seconds to startup) is never renewed.
Synchronous filesystem work still needs the operator's external watchdog.

Phases are allocation -> actual C9 observations -> independent signed delivery
intake -> independently supplied grants/genesis -> one retained FD handoff.
Only existing spool.initialize_store creates its empty physical storage binding;
no persistence genesis, receipt, history, key, signature or approval is generated.
Native Rust independently admits operational grant signatures/currentness.
"""
from __future__ import annotations

import copy
import fcntl
import os
import stat

from serverware import custody_generation_originals as o
from serverware import native_shadow_guest_delivery as delivery
from serverware import native_shadow_nitro_originals as originals
from serverware import native_shadow_retrieval_artifacts as artifacts
from serverware import native_shadow_retrieval_store as store
from serverware.native_shadow_persistence_inputs import PersistenceInputs
from serverware.native_shadow_trusted_time_inputs import TrustedTimeActivation

p = delivery.p
_TOKEN = object()
_ROLES = ("retrieval", "persistence", "trustedTime")
_WINDOW = ("authorityKeyId", "invocationId", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs")


def _names(fd):
    scan = os.open(".", o.FLAGS | os.O_DIRECTORY, dir_fd=fd)
    try:
        p.require(o.identity(os.fstat(scan)) == o.identity(os.fstat(fd)))
        names = []
        with os.scandir(scan) as entries:
            for entry in entries:
                names.append(entry.name)
                p.require(len(names) <= artifacts.MAX_OBJECTS)
        return sorted(names)
    finally:
        os.close(scan)


class PilotEndpointInputs:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._fds, self._object_files = [], []
        self._persistence = self._trusted_time = self._retrieval = None
        self._closed = self._poisoned = self._delivery_attempted = self._retain_attempted = False
        self._deliveries = self._guests = self._spool_journal = None
        self._assignment_raw = self._assignment_payload = None
        self._transfers = {}

    @classmethod
    def prepare(cls, pilot, *, cold_originals, peer_original, peer_sha256,
                proof_scope_original, proof_scope_sha256, retrieval_manifest_original,
                retrieval_manifest_sha256, object_directory_fd, assignment_original=None):
        from serverware.native_pilot_launch import NativePilotLaunch
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        from serverware.native_shadow_spool_inputs import SpoolInputs
        p.require(cls is PilotEndpointInputs and type(pilot) is NativePilotLaunch)
        pilot._preparing()
        p.require(pilot._endpoint_inputs is None and type(pilot._cohort) is ParkedProofCohort
            and type(pilot._spool) is SpoolInputs and pilot._cohort.endpoint_driver_selected()
            and pilot._cohort.effects_selected() and pilot._spool is pilot._cohort._spool_resources
            and pilot._cohort._external_driver.driver is pilot._driver)
        p.fields(cold_originals, _ROLES)
        value = cls(_TOKEN)
        value._pilot, value._cohort, value._spool = pilot, pilot._cohort, pilot._spool
        value._pid, value._start, value._boot = os.getpid(), originals._start(), originals._boot()
        value._deadline = value._cohort.startup_deadline_boottime_ns()
        value._cold = dict(cold_originals)
        for role in _ROLES:
            cold = delivery.configuration(value._cold[role], value._cohort._config[role + "Configuration"]["sha256"])
            p.require(p.canonical(cold) == p.canonical(value._cohort._cold[role]))
        p.require(p.sha(peer_original) == p.digest(peer_sha256)
            and p.sha(proof_scope_original) == p.digest(proof_scope_sha256))
        value._peer = artifacts._peer(peer_original)
        value._peer_raw, value._peer_sha = peer_original, peer_sha256
        value._scope = artifacts.scope_original(proof_scope_original)
        value._scope_raw, value._scope_sha = proof_scope_original, proof_scope_sha256
        if value._scope.get("api_version") == artifacts.SCOPE_SET_API:
            from serverware import native_pilot_assignment as assignment_profile
            p.require(type(assignment_original) is bytes and 0 < len(assignment_original) <= assignment_profile.MAX_BYTES)
            assignment = assignment_profile.shape(p.document(assignment_original, assignment_profile.MAX_BYTES))
            p.require(assignment_profile.version(assignment) == 2)
            value._assignment_raw = bytes(assignment_original)
            value._assignment_payload = p.canonical(assignment["payload"])
            artifacts.require_assignment_scope(value._scope, value._assignment_payload)
            # This is the exact operator's retained public original, not a new
            # signature verdict. Persistence intake binds its payload hash to
            # actual signed key authorization; Rust verifies full membership.
        value._objects = artifacts.manifest_objects(retrieval_manifest_original, retrieval_manifest_sha256)
        value._retrieval_initialization = artifacts.manifest_initialization(
            retrieval_manifest_original, retrieval_manifest_sha256)
        manifest = p.document(retrieval_manifest_original, artifacts.MAX_MANIFEST)
        p.require(p.decoded(manifest["proofScopeOriginalBase64url"], maximum=16384) == proof_scope_original)
        value._manifest_raw, value._manifest_sha = retrieval_manifest_original, retrieval_manifest_sha256
        # Retain the actual composite before any descriptor/file allocation.
        # A failure fences this pilot slot; it cannot be reconstructed/retried.
        pilot._endpoint_inputs = value
        try:
            value._origin()
            p.require(type(object_directory_fd) is int and object_directory_fd >= 0)
            value._object_directory = fcntl.fcntl(object_directory_fd, fcntl.F_DUPFD_CLOEXEC, 128)
            value._fds.append(value._object_directory)
            info = os.fstat(value._object_directory)
            p.require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0
                and stat.S_IMODE(info.st_mode) == 0o555
                and fcntl.fcntl(value._object_directory, fcntl.F_GETFL) & (os.O_ACCMODE | os.O_PATH) == os.O_RDONLY)
            value._object_directory_id = o.identity(info)
            for locator, raw in value._objects:
                value._origin()
                observation = store._observe(value._object_directory, locator, raw)
                fd = os.open(locator["filename"], o.FLAGS, dir_fd=value._object_directory)
                value._fds.append(fd)
                identity = o.identity(store._file(fd, len(raw)))
                p.require((identity[0], identity[1]) == (observation["device"], observation["inode"])
                    and store._measure(fd) == observation["fsVeritySha256"]
                    and os.pread(fd, len(raw) + 1, 0) == raw)
                value._object_files.append((locator["filename"], fd, identity, observation["fsVeritySha256"]))
            value._check_objects()
            PersistenceInputs.prepare(cohort=value._cohort,
                configuration_raw=value._cold["persistence"],
                configuration_sha256=value._cohort._config["persistenceConfiguration"]["sha256"],
                peer_original=peer_original, peer_sha256=peer_sha256,
                scope_original=proof_scope_original, scope_sha256=proof_scope_sha256,
                startup_deadline_boottime_ns=str(value._deadline), pilot_inputs=value)
            TrustedTimeActivation.prepare(configuration_raw=value._cold["trustedTime"],
                configuration_sha256=value._cohort._config["trustedTimeConfiguration"]["sha256"],
                peer_raw=peer_original, peer_sha256=peer_sha256,
                startup_deadline_boottime_ns=str(value._deadline), pilot_inputs=value)
            value._retrieval = value._spool.prepare_retrieval(configuration_raw=value._cold["retrieval"],
                configuration_sha256=value._cohort._config["retrievalConfiguration"]["sha256"],
                peer_raw=peer_original, peer_sha256=peer_sha256, object_directory_fd=value._object_directory,
                startup_deadline_boottime_ns=str(value._deadline))
            value.check()
            return value
        except BaseException:
            value._poisoned = True
            raise

    def _origin(self):
        p.require(not self._closed and not self._poisoned and os.getpid() == self._pid
            and originals._start() == self._start and originals._boot() == self._boot
            and self._pilot._endpoint_inputs is self and self._pilot._cohort is self._cohort
            and self._pilot._spool is self._spool and o.clock() < self._deadline)
        self._pilot._origin()
        p.require(self._pilot._stage == "resources" and not self._pilot._release_attempted
            and not self._pilot._cleanup_attempted and self._cohort._external_driver.driver is self._pilot._driver)
        self._cohort.check()
        self._spool.check()
        child = self._cohort._external_driver.value
        process = child["driver"]
        p.require((self._peer["uid"], self._peer["gid"]) ==
            (self._cohort._cold["bridge"]["uid"], self._cohort._cold["bridge"]["gid"])
            and (self._peer["pid"], self._peer["startTimeTicks"]) ==
            (process["processId"], process["startTimeTicks"]))
        for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
                ("executableLength", "length"), ("executableSha256", "sha256")):
            p.require(self._peer[target] == child["executable"][source])
        # The retained actual driver supplies these process/executable facts.
        # Supplied cgroup/label expectations still require the real inspector.

    def _check_objects(self):
        self._origin()
        p.require(o.identity(os.fstat(self._object_directory)) == self._object_directory_id
            and not os.get_inheritable(self._object_directory)
            and _names(self._object_directory) == sorted(item[0] for item in self._object_files))
        for name, fd, identity, verity in self._object_files:
            p.require(o.identity(store._file(fd, identity[6])) == identity
                and o.identity(os.stat(name, dir_fd=self._object_directory, follow_symlinks=False)) == identity
                and not os.get_inheritable(fd) and store._measure(fd) == verity)
            self._origin()
        # fs-verity protects the bytes read/compared at preparation; unchanged
        # kernel measurements are not independently signed service authority.

    def check(self):
        self._check_objects()
        p.require(self._persistence is not None and self._trusted_time is not None
            and self._retrieval is not None and self._retrieval is self._spool._retrieval_activation)
        self._persistence.check()
        self._trusted_time.check()
        self._retrieval.check()
        self._origin()

    def activations(self):
        """Actual FD metadata for three independent C9 signatures, not readiness."""
        self.check()
        return {"retrieval": self._retrieval.activation(), "persistence": self._persistence.activation(),
            "trustedTime": self._trusted_time.activation()}

    def _delivery(self, role, raw):
        signed = p.fields(p.document(raw, delivery.MAX_DELIVERY), ("apiVersion", "payload", "signatureBase64url"))
        p.require(signed["apiVersion"] == "serverware.policyCustodyGuestDelivery/v1")
        payload = p.fields(signed["payload"], delivery.FIELDS)
        p.require(payload["configurationSha256"] == self._cohort._config[role + "Configuration"]["sha256"])
        for name in _WINDOW:
            p.require(p.canonical(payload[name]) == p.canonical(self._cohort._window[name]))
        for name in ("serviceRole", "uid", "gid"):
            p.require(p.canonical(payload[name]) == p.canonical(self._cohort._cold[role][name]))
        return delivery._delivery_guest(payload, raw)

    def admit_deliveries(self, *, originals):
        """One intake of actual C9 originals; no signing or startup renewal."""
        self.check()
        p.require(not self._delivery_attempted and not self._retain_attempted)
        self._delivery_attempted = True
        try:
            p.fields(originals, _ROLES)
            guests = {role: self._delivery(role, originals[role]) for role in _ROLES}
            self._persistence.admit_delivery(signed_delivery_original=originals["persistence"])
            self._trusted_time.admit_delivery(signed_delivery_original=originals["trustedTime"])
            self._retrieval.admit_delivery(signed_delivery_original=originals["retrieval"])
            self._spool_journal = self._spool.initialize_store(
                retrieval_delivery_original=originals["retrieval"], proof_scope_original=self._scope_raw)
            self._deliveries, self._guests = dict(originals), guests
            self.check()
            return copy.deepcopy({"guests": guests, "spoolJournal": self._spool_journal})
        except BaseException:
            self._poisoned = True
            raise

    def _grant(self, role, launch_pin):
        launch_raw, signed_raw, grant_raw = self._cohort.activation_originals(role=role, launch_pin=launch_pin)
        p.require(signed_raw == self._deliveries[role])
        launch = p.document(launch_raw, 32768)
        envelope = p.fields(p.document(grant_raw, 65536), ("payload", "signature"))
        grant = envelope["payload"]
        p.require(type(grant) is dict and p.canonical(grant["guest"]) == p.canonical(self._guests[role])
            and p.canonical(grant["expectedPeer"]) == self._peer_raw)
        if role == "trustedTime":
            p.require(grant["apiVersion"] == "serverware.nativeShadowTrustedTimeServiceAssignment/v1"
                and grant["purpose"] == "native-shadow-trusted-time-response"
                and grant["clockBootstrapSha256"] == launch["keyAdmission"]["timeBootstrap"]["sha256"])
        elif role == "retrieval":
            from serverware import native_pilot_native_service_authority as services
            services.grant_shape("retrieval", grant)
            fresh = self._retrieval_initialization == artifacts.FRESH_INITIALIZATION
            p.require(grant["apiVersion"] == "serverware.nativeLedgerSpoolRetrievalGrant/v" + ("4" if fresh else "3")
                and grant["purpose"] == "native-ledger-spool-retrieval"
                and p.decoded(grant["proofScopeOriginalBase64url"], maximum=16384) == self._scope_raw
                and p.canonical(grant["store"]) == p.canonical(self._spool_journal))
        # These two grants are exact pinned originals, not new Python signature
        # verdicts. The native time/retrieval consumers verify their real roots.
        return grant_raw

    def retain(self, *, launch_pins, persistence_configuration_original,
               persistence_configuration_sha256, genesis_original, genesis_sha256,
               journal_original, journal_sha256):
        """Return exactly three genuine transfers; partial failure keeps all owners."""
        self.check()
        p.require(self._deliveries is not None and not self._retain_attempted)
        self._retain_attempted = True
        try:
            p.fields(launch_pins, _ROLES)
            grants = {role: self._grant(role, launch_pins[role]) for role in _ROLES}
            self._persistence.install_genesis(genesis_original=genesis_original, genesis_sha256=genesis_sha256,
                journal_original=journal_original, journal_sha256=journal_sha256)
            self._persistence.admit_service_grant(signed_grant_original=grants["persistence"],
                configuration_original=persistence_configuration_original,
                configuration_sha256=persistence_configuration_sha256,
                assignment_payload_original=self._assignment_payload)
            self._transfers["persistence"] = self._persistence.take_for_launch(
                signed_delivery_sha256=p.sha(self._deliveries["persistence"]),
                service_grant_sha256=p.sha(grants["persistence"]))
            self._transfers["trustedTime"] = self._trusted_time.take_for_cohort(
                cohort=self._cohort, launch_pin=launch_pins["trustedTime"])
            self._transfers["retrieval"] = self._retrieval.take_for_cohort(launch_pin=launch_pins["retrieval"])
            self.check()
            return dict(self._transfers)
        except BaseException:
            self._poisoned = True
            raise

    def require_retired(self):
        """Same-owner cleanup facts, including safe use after cohort FD closure."""
        p.require(os.getpid() == self._pid and originals._start() == self._start
            and originals._boot() == self._boot and self._pilot._endpoint_inputs is self
            and self._pilot._cohort is self._cohort and self._cohort._parent_reaped
            and self._pilot._driver._closed)
        if not self._cohort._closed:
            from serverware.native_shadow_proof_cohort_control import _terminal
            p.require(all(_terminal(fd) for fd, _, _ in self._cohort._parked))
            self._cohort._external_driver.terminal()
        # cohort._closed can only follow its real endpoint/driver cleanup;
        # its PIDFDs and external-driver rights are no longer open in that arm.

    def close(self):
        if self._closed:
            return
        self.require_retired()
        # Cohort closes its installed transfers; a failed partial intake may
        # leave a Persistence transfer only in this actual composite owner.
        for transfer in self._transfers.values():
            transfer.close()
        if self._persistence is not None:
            self._persistence.close()
        if self._trusted_time is not None:
            self._trusted_time.close()
        # Retrieval is owned/closed by the spool, including partial handoffs.
        p.require(self._spool._closed)
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()
        self._closed = True
