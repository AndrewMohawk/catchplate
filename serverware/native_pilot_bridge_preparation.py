"""The conductor's retained initial requests and peer preparation, not approval.

Public shape/binding checks do not create live owners or approve final labels,
configuration generations, external signers, currentness or provider effects.
The actual conductor captures once, rechecks its genuine owners while waiting
for independent approvals, and consumes this preparation before child release.
"""
from __future__ import annotations

import copy
import os

from serverware import native_pilot_bridge_runtime as runtime_profile
from serverware import native_pilot_current_head_profile as head
from serverware import native_pilot_initial_requests as requests_owner
from serverware import native_pilot_initial_requests_profile as requests_profile
from serverware import native_pilot_ordinary_key_profile as key
from serverware import native_pilot_peer_preparation as peers_profile
from serverware import native_pilot_helper_bootstrap_profile as helper_bootstrap
from serverware import native_pilot_service_handshakes as handshakes_profile
from serverware import native_shadow_driver_outgoing as outgoing

p = head.p
API = "serverware.nativePilotBridgePreparation/v1"
HELPER_API = "serverware.nativePilotBridgePreparation/v2"
ADOPTED_API = "serverware.nativePilotBridgePreparation/v3"
MAX_BYTES = 1024 * 1024
FIELDS = ("apiVersion", "driverObservationSha256", "initialTrustRequestsOriginal",
    "ordinaryPeerPreparationOriginal", "nativePeerPreparationOriginal", "gatePeerPreparationOriginal")
PEER_FIELDS = (("ordinaryPeerPreparationOriginal", "ordinary-services"),
    ("nativePeerPreparationOriginal", "native-endpoints"), ("gatePeerPreparationOriginal", "gate"))
WINDOW = ("bootIdBase64url", "timeNamespaceDevice", "timeNamespaceInode",
    "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs", "invocationId")
NATIVE_SIGNERS = {"ledger-append": "commitRequest", "ingress-admission": "ingressAdmission",
    "terminal-append": "terminalAppend", "dispatch-barrier": "dispatchBarrier",
    "active-effect-barrier": "activeEffectBarrier", "active-effect-commit": "activeEffectCommit"}
NATIVE_PROOFS = {"retrieval": "retrieval", "persistence": "persistence", "trusted-time": "trustedTime",
    "generation-install-envelope": "generationInstall"}
ADOPTED_SIGNERS = {**NATIVE_SIGNERS, "publication-reconciliation": "publicationReconciliation"}
_TOKEN = object()
_USED = False


def _raw(value, maximum):
    p.require(type(value) is str and value.isascii() and 0 < len(value) <= maximum)
    return value.encode("ascii")


def _parts(value):
    requests = requests_profile.shape(_raw(value["initialTrustRequestsOriginal"], requests_profile.MAX_BYTES))
    peers = {kind: peers_profile.shape(_raw(value[field], peers_profile.MAX_BYTES)) for field, kind in PEER_FIELDS}
    return requests, peers


def shape(raw):
    """Pure exact data associations; not a provenance or authority verdict."""
    value = p.fields(p.document(raw, MAX_BYTES), FIELDS)
    p.require(value["apiVersion"] in (API, HELPER_API, ADOPTED_API))
    p.digest(value["driverObservationSha256"])
    requests, peers = _parts(value)
    p.require((value["apiVersion"] in (HELPER_API, ADOPTED_API)) == (requests["apiVersion"] == requests_profile.HELPER_API)
        and (value["apiVersion"] == ADOPTED_API) == (peers["native-endpoints"]["apiVersion"] == peers_profile.ADOPTED_API))
    ordinary = peers["ordinary-services"]
    identities = set()
    for kind, item in peers.items():
        p.require(item["ownerKind"] == kind
            and tuple(item[field] for field in WINDOW) == tuple(ordinary[field] for field in WINDOW))
        for row in item["peers"].values():
            identity = (row["processId"], row["startTimeTicks"])
            p.require(identity not in identities)
            identities.add(identity)
    p.require(ordinary["sourceOriginalSha256"] == requests["launchSha256"])
    for field in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"):
        p.require(requests[field] == ordinary[field])
    for _, _, row in requests_profile.iter_requests(requests):
        pending = head.request(row["requestOriginal"].encode("ascii"))
        p.require(pending["deadline"]["domain"] == key._boot(ordinary))
    return copy.deepcopy(value)


def _peer(expected, observed, ids):
    """Bind measured fields and admitted IDs; label/configuration remain policy."""
    p.fields(expected, outgoing._PEER_FIELDS)
    p.fields(ids, ("uid", "gid"))
    p.require(expected["uid"] == ids["uid"] and expected["gid"] == ids["gid"])
    p.require(expected["pid"] == observed["processId"]
        and expected["startTimeTicks"] == observed["startTimeTicks"])
    for target, source in (("executableDevice", "device"), ("executableInode", "inode"),
            ("executableLength", "length"), ("executableSha256", "sha256")):
        p.require(expected[target] == observed["targetExecutable"][source])
    for target, source in (("cgroupPathSha256", "pathSha256"), ("cgroupMountId", "mountId"), ("cgroupInode", "inode")):
        p.require(expected[target] == observed["cgroup"][source])
    p.require(expected["processIdentitySha256"] == peer_identity(
        {name: expected[name] for name in outgoing._PEER_FIELDS if name != "processIdentitySha256"}))


def peer_identity(expected):
    """Exact native v4 digest; a projection, never observation or approval."""
    p.fields(expected, tuple(name for name in outgoing._PEER_FIELDS if name != "processIdentitySha256"))
    parts = []
    for name, width in (("uid", 4), ("gid", 4), ("pid", 4), ("startTimeTicks", 8),
            ("executableDevice", 8), ("executableInode", 8), ("executableLength", 8)):
        parts.append(p.integer(expected[name], maximum=(1 << (width * 8)) - 1).to_bytes(width, "big"))
    p.digest(expected["executableSha256"])
    parts.append(bytes.fromhex(expected["executableSha256"].removeprefix("sha256:")))
    parts.append(p.digest(expected["cgroupPathSha256"]).encode("ascii"))
    for name in ("cgroupMountId", "cgroupInode"):
        parts.append(p.integer(expected[name], maximum=(1 << 64) - 1).to_bytes(8, "big"))
    for name in ("securityLabelSha256", "configurationGenerationSha256"):
        parts.append(p.digest(expected[name]).encode("ascii"))
    return p.framed(b"serverware.policyCustodyPeerProcessIdentity/v4", parts)


def require_runtime(raw, runtime_raw, *, driver_observation_raw, cohort_observation_raw, peer_ids):
    """Additional associations inside the actual approved bridge job only."""
    value = shape(raw)
    requests, peers = _parts(value)
    p.fields(peer_ids, peers_profile.ROLES)
    for kind, roles in peers_profile.ROLES.items():
        if kind == "native-endpoints" and value["apiVersion"] == ADOPTED_API:
            roles = peers_profile.ADOPTED_NATIVE_ROLES
        p.fields(peer_ids[kind], roles)
    runtime = runtime_profile.shape(runtime_raw)
    version = runtime_profile.version(runtime)
    p.require(((version == 10 and value["apiVersion"] == API)
            or (version in (11, 12) and value["apiVersion"] == HELPER_API)
            or (version == 14 and value["apiVersion"] == ADOPTED_API))
        and p.sha(driver_observation_raw) == value["driverObservationSha256"]
        and p.sha(cohort_observation_raw) == peers["native-endpoints"]["sourceOriginalSha256"])
    _peer(runtime["expectedFacadePeer"], peers["gate"]["peers"]["gate"], peer_ids["gate"]["gate"])
    sessions = runtime["serviceSessions"]
    p.require(type(sessions) is list and len(sessions) == len(requests["requests"]))
    pending_rows = {(role, endpoint): row for role, endpoint, row in requests_profile.iter_requests(requests)}
    consumed = set()
    seen = set()
    for session in sessions:
        role = session["serviceRole"]
        p.require(role in requests["requests"] and role not in seen)
        seen.add(role)
        member = runtime["ordinaryInitialHistories"][role]
        _peer(session["expectedPeer"], peers["ordinary-services"]["peers"][role], peer_ids["ordinary-services"][role])
        p.require(type(session["handshakes"]) is list and bool(session["handshakes"]))
        if version in (11, 12, 14) and role == "bounded-cleanup-helper":
            p.require([item["endpointRole"] for item in session["handshakes"]] == list(helper_bootstrap.ROLES))
        for handshake in session["handshakes"]:
            selected_key = (role, handshake["endpointRole"])
            p.require(selected_key in pending_rows and selected_key not in consumed)
            consumed.add(selected_key)
            selected = pending_rows[selected_key]
            p.require(p.sha(member["runtimeOriginal"].encode("ascii")) == selected["runtimeConfigurationSha256"]
                == runtime["expectedServiceConfigurationSha256"][role])
            pending = head.request(selected["requestOriginal"].encode("ascii"))
            request = handshake["request"]
            handshakes_profile.shape(p.canonical(request), service_role=role, endpoint_role=handshake["endpointRole"],
                client_process_identity_sha256=runtime["expectedDriverProcessIdentitySha256"],
                client_configuration_generation_sha256=runtime["expectedDriverConfigurationGenerationSha256"])
            binding = request["expectedCurrentHead"]
            p.fields(binding, ("signedCurrentHead", "exactAttestationSha256"))
            p.require(binding == head.binding(binding["signedCurrentHead"]))
            statement = binding["signedCurrentHead"]["statement"]
            p.require(handshake["endpointRole"] == selected["endpointRole"] == statement["endpointRole"]
                and statement["requestSha256"] == selected["requestSha256"]
                and statement["requestNonceSha256"] == pending["requestNonceSha256"]
                and statement["checkpointSha256"] == selected["checkpointSha256"]
                and pending["requestedAtBoottimeNanos"] <= statement["issuedAtBoottimeNanos"]
                and statement["deadline"] == pending["deadline"] == request["deadline"])
    p.require(consumed == set(pending_rows))
    if version in (11, 12, 14):
        helper = runtime["ordinaryInitialHistories"]["bounded-cleanup-helper"]["runtimeOriginal"].encode("ascii")
        pending = [head.request(row["requestOriginal"].encode("ascii"))
            for (role, _), row in pending_rows.items() if role == "bounded-cleanup-helper"]
        deadline = copy.deepcopy(pending[0]["deadline"])
        deadline["absoluteBoottimeNanos"] = min(row["deadline"]["absoluteBoottimeNanos"] for row in pending)
        helper_bootstrap.require_runtime(p.canonical(runtime["helperBootstrap"]), helper, deadline=deadline)
        p.require(runtime["expectedHelperEndpointRoles"] == list(helper_bootstrap.ROLES))
    for field, discriminator, mapping in (("parentSignerEndpoints", "signerRole", ADOPTED_SIGNERS if version == 14 else NATIVE_SIGNERS),
            ("proofEndpoints", "endpointKind", NATIVE_PROOFS)):
        for endpoint in runtime[field]:
            role = mapping.get(endpoint[discriminator])
            if role is not None:
                _peer(endpoint["expectedPeer"], peers["native-endpoints"]["peers"][role], peer_ids["native-endpoints"][role])
    return runtime


class BridgePreparation:
    def __init__(self, token, pilot):
        p.require(token is _TOKEN)
        self._pilot, self._pid = pilot, os.getpid()
        self._requests = self._raw = None
        self._attempted = self._failed = self._consumed = self._closed = False

    @classmethod
    def claim(cls, pilot):
        global _USED
        from serverware.native_pilot_launch import NativePilotLaunch
        p.require(cls is BridgePreparation and type(pilot) is NativePilotLaunch and not _USED)
        pilot._preparing()
        _USED = True
        return cls(_TOKEN, pilot)

    def _snapshot(self):
        pilot = self._pilot
        pilot._preparing()
        requests_raw = self._requests.original()
        requests = requests_profile.shape(requests_raw)
        adopted = pilot.cohort.adoption_selected()
        p.require(not adopted or requests["apiVersion"] == requests_profile.HELPER_API)
        return p.canonical({"apiVersion": ADOPTED_API if adopted else HELPER_API if requests["apiVersion"] == requests_profile.HELPER_API else API,
            "driverObservationSha256": p.sha(pilot.driver.observation_original()),
            "initialTrustRequestsOriginal": requests_raw.decode("ascii"),
            "ordinaryPeerPreparationOriginal": pilot.ordinary_services.peer_preparation_original().decode("ascii"),
            "nativePeerPreparationOriginal": pilot.cohort.peer_preparation_original().decode("ascii"),
            "gatePeerPreparationOriginal": pilot.driver.peer_preparation_original().decode("ascii")})

    def prepare(self):
        p.require(not self._attempted and not self._closed and os.getpid() == self._pid)
        self._attempted = True
        try:
            self._requests = requests_owner.InitialRequests.prepare(self._pilot)
            self._raw = self._snapshot()
            self.check()
            return self._raw
        except BaseException:
            self._failed = True
            raise

    def check(self):
        try:
            p.require(self._attempted and not self._closed and not self._failed and not self._consumed
                and os.getpid() == self._pid and type(self._raw) is bytes)
            shape(self._raw)
            p.require(self._snapshot() == self._raw)
        except BaseException:
            self._failed = True
            raise

    def consume(self):
        self.check()
        self._requests.consume()
        self._consumed = True  # No further startup snapshot or retry after release.

    def close(self):
        p.require(not self._closed and self._pilot._closed and os.getpid() == self._pid)
        requests_owner.close(self._pilot)
        self._raw = self._requests = None
        self._closed = True
