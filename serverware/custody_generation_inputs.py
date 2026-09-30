"""Fresh real grant memfds/journals and one-shot five-service C9 transfer.

This is the generation-only software profile. Existing business descriptors and
independently approved runtime/scope originals are required, not manufactured.
"""
import ctypes
import fcntl
import os
import socket
import stat
import threading

from cryptography.hazmat.primitives import serialization

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o
from serverware.custody_generation_launch import FiveServiceLaunch

p = g.p
_TOKEN = object()
BASE = "/var/lib/serverware/custody-generation"


def _persistent(fd):
    buffer = ctypes.create_string_buffer(256)
    p.require(ctypes.CDLL(None, use_errno=True).fstatfs(fd, ctypes.byref(buffer)) == 0)
    kind = ctypes.c_long.from_buffer(buffer).value & 0xffffffff
    p.require(kind in {0xef53, 0x58465342, 0x9123683e})  # ext4, XFS, Btrfs; not tmpfs/overlay


class GenerationInputs:
    def __init__(self, token, launcher):
        p.require(token is _TOKEN)
        self._launcher = launcher
        self._roles, self._fds, self._originals = {}, [], []
        self._closed = self._taken = self._released = False
        self._business_owner = None
        self._commitment = launcher._commitment
        self._commitments = {}
        self._spool = launcher._spool
        self._effects = launcher._effects
        self._spools = {}

    @classmethod
    def prepare(cls, launcher, *, business_descriptors):
        p.require(type(launcher) is FiveServiceLaunch and not launcher._commitment)
        return cls._prepare(launcher, business_descriptors=business_descriptors)

    @classmethod
    def _prepare(cls, launcher, *, business_descriptors):
        p.require(cls is GenerationInputs)
        p.require(type(launcher) is FiveServiceLaunch and not launcher._attempted
            and launcher._input_owner is None and threading.current_thread() is threading.main_thread())
        launcher.check(); p.fields(business_descriptors, g.ROLES)
        owner = cls(_TOKEN, launcher)
        launcher._input_owner = owner
        try:
            identities = set()
            for role in g.ROLES:
                configuration, cold, _ = launcher._configurations[role]
                supplied = p.fields(business_descriptors[role], g.BUSINESS[role])
                descriptors = []
                for name in g.BUSINESS[role]:
                    p.require(type(supplied[name]) is int and supplied[name] >= 0)
                    fd = fcntl.fcntl(supplied[name], fcntl.F_DUPFD_CLOEXEC, 70)
                    owner._fds.append(fd); info = os.fstat(fd)
                    if name == "listener":
                        wire = socket.socket(fileno=os.dup(fd))
                        try:
                            p.require(wire.family == socket.AF_UNIX
                                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_SEQPACKET
                                and wire.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
                                and type(wire.getsockname()) is str and wire.getsockname().startswith("/"))
                        finally:
                            wire.close()
                    else:
                        p.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                            and info.st_uid == cold["uid"] and info.st_gid == cold["gid"])
                        _persistent(fd)
                    descriptors.append((name, fd))
                parent = o.directory(f"{BASE}/{role}")
                owner._fds.append(parent)
                info = os.fstat(parent)
                p.require(info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o711)
                fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # No adoption: leftover state from any earlier attempt refuses.
                os.mkdir("generation-journal", 0o700, dir_fd=parent)
                directory = os.open("generation-journal", o.FLAGS | os.O_DIRECTORY, dir_fd=parent)
                owner._fds.append(directory)
                os.fchown(directory, cold["uid"], cold["gid"]); os.fchmod(directory, 0o700)
                _persistent(directory); p.require(o.names(directory) == ())
                os.fsync(directory); os.fsync(parent)
                descriptors.append(("generation-journal", directory))
                grant = os.memfd_create(f"custody-generation-{role}", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
                owner._fds.append(grant)
                # Allocate/fix the real identity before C9 is signed. The public
                # grant is filled later; no file-content hash cycle in C9.
                os.fchown(grant, cold["uid"], cold["gid"]); os.fchmod(grant, 0o400)
                p.require(os.fstat(grant).st_size == 0 and fcntl.fcntl(grant, fcntl.F_GET_SEALS) == 0)
                descriptors.append(("generation-grant", grant))
                if owner._commitment and role in (g.ROLES[0], g.ROLES[3]):
                    from serverware.custody_commitment_inputs import _RoleInputs
                    selected = _RoleInputs.prepare(owner, role, parent, cold)
                    owner._commitments[role] = selected
                    descriptors.extend(selected.descriptors())
                if owner._spool and (role in owner._commitments or owner._effects and role == g.ROLES[1]):
                    from serverware.custody_spool_inputs import RoleInputs
                    selected = RoleInputs.prepare(owner, role, parent, cold)
                    owner._spools[role] = selected
                    descriptors.extend(selected.descriptors())
                entries = [o.activation(name, target, fd) for target, (name, fd) in enumerate(descriptors, 6)]
                for entry in entries:
                    ident = entry["device"], entry["inode"]
                    p.require(ident not in identities); identities.add(ident)
                owner._roles[role] = dict(configuration=configuration, cold=cold, descriptors=descriptors,
                    activation=entries, parent=parent, directory=directory, grant=grant,
                    directory_identity=o.structural(os.fstat(directory)), delivery_attempt=False,
                    grant_attempt=False, delivery=None, guest=None, grant_raw=None, launch=None)
            owner.check(); return owner
        except BaseException:
            owner.close(); raise

    def check(self):
        p.require(not self._closed and threading.current_thread() is threading.main_thread())
        self._launcher.check()
        for original in self._originals:
            original.check()
        for role, item in self._roles.items():
            for entry, (name, fd) in zip(item["activation"], item["descriptors"]):
                p.require(entry == o.activation(name, entry["fd"], fd) and not os.get_inheritable(fd))
            p.require(o.structural(os.fstat(item["directory"])) == item["directory_identity"]
                and o.structural(os.stat("generation-journal", dir_fd=item["parent"], follow_symlinks=False))
                == item["directory_identity"])
            if not self._released:
                p.require(o.names(item["directory"]) == ())
            if item["grant_raw"] is not None:
                p.require(fcntl.fcntl(item["grant"], fcntl.F_GET_SEALS) == o.SEALS
                    and o.read(item["grant"], 65536) == item["grant_raw"])
            else:
                p.require(os.fstat(item["grant"]).st_size == 0 and fcntl.fcntl(item["grant"], fcntl.F_GET_SEALS) == 0)
            if role in self._commitments:
                self._commitments[role].check()
            if role in self._spools:
                self._spools[role].check()

    def activation(self, role):
        self.check(); p.require(role in g.ROLES and not self._taken)
        return [dict(entry) for entry in self._roles[role]["activation"]]

    def directory_identities(self, role):
        self.check(); p.require(role in g.ROLES and not self._taken)
        return {name: o.directory_identity(fd) for name, fd in self._roles[role]["descriptors"]
            if name not in {"listener", "generation-grant", "dispatch-grant", "spool-head-grant", "spool-current-grant", "active-effect-cleanup-grant"}}

    def sign_delivery(self, role, *, approved_payload_original, delivery_authority):
        self.check(); p.require(role in g.ROLES and not self._taken)
        item = self._roles[role]
        p.require(not item["delivery_attempt"]); item["delivery_attempt"] = True
        payload = g.document(approved_payload_original, 65536)
        p.require(payload["invocationId"] == self._launcher._invocation
            and p.ns(payload["issuedAtBoottimeNs"]) >= self._launcher._issued)
        if role in self._spools:
            from serverware.custody_spool_inputs import sign_delivery, sign_effects_delivery
            sign = sign_effects_delivery if self._effects else sign_delivery
        elif role in self._commitments:
            from serverware.native_shadow_commitment_artifacts import sign_service_delivery
            sign = sign_service_delivery
        else:
            sign = g.sign_delivery
        signed, guest = sign(cold_raw=item["configuration"].read(), cold_sha=item["configuration"].sha,
            role=role, payload_raw=approved_payload_original, activation=item["activation"], boot=self._launcher._boot,
            startup=self._launcher._startup, lifetime=self._launcher._lifetime, now=o.clock(), signing_key=delivery_authority)
        runtime_pin = payload["runtimeConfig"]
        runtime = o.Original(runtime_pin["path"], g.MAX_BYTES, sha=runtime_pin["sha256"])
        self._originals.append(runtime)
        runtime_raw = runtime.read(); header = g.document(runtime_raw, g.MAX_BYTES)["runtime"]
        if self._business_owner is not None:
            self._business_owner._require_runtime_peer(header)
        selected = role in self._commitments
        version = 8 if self._effects and role in self._spools else 7 if role in self._spools else 6 if selected else 5
        p.require(header["apiVersion"] == f"serverware.policyCustodyServiceRuntimeConfig/v{version}"
            and header["generationAdmission"] == {"grantFdName": "generation-grant"}
            and (header.get("dispatchAdmission") == {"grantFdName": "dispatch-grant"} if selected else header.get("dispatchAdmission") is None)
            and header["activationDirectoryIdentities"] == self.directory_identities(role))
        listener = socket.socket(fileno=os.dup(item["descriptors"][0][1]))
        try:
            p.require(header["listenerSocketPath"] == listener.getsockname())
        finally:
            listener.close()
        originals = {}
        for entry in payload["credentials"]:
            # Opening/retaining signing seeds is not reading/exporting them.
            # The final-role Rust owner reads and verifies those key originals.
            credential = o.Original(entry["original"]["path"], entry["length"],
                uid=item["cold"]["uid"], gid=item["cold"]["gid"])
            self._originals.append(credential)
            p.require(credential.expected[6] == entry["length"])
            originals[entry["name"]] = credential
        if self._launcher._inspected:
            selected_policy = [entry for entry in payload["credentials"] if entry["name"] == "peer-inspection-policy"]
            p.require(len(selected_policy) == 1 and selected_policy[0]["signing"] is None
                and selected_policy[0]["length"] <= 4096)
            policy_raw = originals["peer-inspection-policy"].read()
            p.require(p.sha(policy_raw) == selected_policy[0]["original"]["sha256"])
            policy = p.fields(g.document(policy_raw, 4096), ("apiVersion", "purpose", "runtimeConfigurationSha256",
                "serviceRole", "uid", "gid", "startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
            p.require(policy == {"apiVersion": "serverware.custodyOrdinaryPeerInspection/v1",
                "purpose": "ordinary-service-peer-inspection", "runtimeConfigurationSha256": runtime.sha,
                "serviceRole": role, "uid": item["cold"]["uid"], "gid": item["cold"]["gid"],
                "startupDeadlineBoottimeNs": str(self._launcher._startup),
                "lifetimeDeadlineBoottimeNs": str(self._launcher._lifetime)})
        history_name = header["authorityHistoryManifestCredential"]
        selected = [entry for entry in payload["credentials"] if entry["name"] == history_name]
        p.require(len(selected) == 1 and selected[0]["signing"] is None)
        history_raw = originals[history_name].read()
        p.require(p.sha(history_raw) == selected[0]["original"]["sha256"])
        delivery = o.publish(f"/etc/serverware/custody-{role}-delivery.json", signed)
        self._originals.append(delivery)
        item.update(delivery=delivery, delivery_raw=signed, guest=guest, runtime=runtime,
            runtime_raw=runtime_raw, history_raw=history_raw)
        self.check(); return signed

    def seal_grant(self, role, *, approved_grant_payload_original, history_root_authority):
        self.check(); p.require(role in g.ROLES and not self._taken)
        item = self._roles[role]
        p.require(item["delivery"] is not None and not item["grant_attempt"])
        item["grant_attempt"] = True
        public = history_root_authority.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p.require(p.encoded(public) != item["cold"]["authority"]["publicKeyBase64url"])
        if role in self._spools:
            from serverware.custody_spool_inputs import sign_generation_grant, sign_effects_generation_grant
            sign = sign_effects_generation_grant if self._effects else sign_generation_grant
        elif role in self._commitments:
            from serverware.native_shadow_commitment_artifacts import sign_service_generation_grant
            sign = sign_service_generation_grant
        else:
            sign = g.sign_grant
        raw = sign(payload_raw=approved_grant_payload_original, guest=item["guest"],
            runtime_raw=item["runtime_raw"], history_raw=item["history_raw"], delivery_raw=item["delivery_raw"],
            signing_key=history_root_authority, now=o.clock())
        offset = 0
        while offset < len(raw):
            count = os.pwrite(item["grant"], raw[offset:], offset); p.require(count > 0); offset += count
        fcntl.fcntl(item["grant"], fcntl.F_ADD_SEALS, o.SEALS)
        p.require(o.read(item["grant"], 65536) == raw and fcntl.fcntl(item["grant"], fcntl.F_GET_SEALS) == o.SEALS)
        item["grant_raw"] = raw
        if role not in self._commitments and role not in self._spools:
            self._publish_launch(role)
        self.check(); return raw

    def seal_dispatch_grant(self, role, *, approved_grant_original, native_grant_original):
        """Consume independent exact signatures; never synthesize a grant."""
        self.check()
        p.require(self._commitment and role in self._commitments and not self._taken)
        selected = self._commitments[role]
        selected.seal(approved_grant_original, native_grant_original)
        if role not in self._spools:
            self._publish_launch(role)
        self.check(); return selected.original()

    def seal_spool_grant(self, role, *, approved_grant_original, native_originals):
        self.check(); p.require(self._spool and role in self._spools and not self._taken)
        if role in self._commitments:
            self._commitments[role].original()
        self._spools[role].seal(approved_grant_original, native_originals)
        self._publish_launch(role)
        self.check(); return self._spools[role].original()

    def _publish_launch(self, role):
        item = self._roles[role]
        p.require(item["launch"] is None and item["grant_raw"] is not None)
        if role in self._commitments:
            self._commitments[role].original()
        if role in self._spools:
            self._spools[role].original()
        launch_value = {"apiVersion": "serverware.custodyOrdinaryServiceGuestLaunch/v1",
            "deliveryConfiguration": {"path": item["configuration"].path, "sha256": item["configuration"].sha},
            "delivery": {"path": item["delivery"].path, "sha256": item["delivery"].sha}}
        if self._launcher._inspected:
            launch_value.update(apiVersion="serverware.custodyOrdinaryServiceGuestLaunch/v2",
                peerInspectionCredential="peer-inspection-policy")
        if role in self._commitments:
            launch_value["apiVersion"] = ("serverware.custodyOrdinaryServiceGuestLaunch/v4"
                if self._launcher._inspected else "serverware.custodyOrdinaryServiceGuestLaunch/v3")
        if role in self._spools:
            p.require(self._launcher._inspected)
            launch_value["apiVersion"] = ("serverware.custodyOrdinaryServiceGuestLaunch/v6"
                if self._effects else "serverware.custodyOrdinaryServiceGuestLaunch/v5")
        launch_raw = g.canonical(launch_value)
        launch = o.publish(f"/etc/serverware/custody-{role}-guest.json", launch_raw)
        self._originals.append(launch); item["launch"] = launch

    def guest_original(self, role):
        self.check(); p.require(role in g.ROLES and self._roles[role]["guest"] is not None)
        return dict(self._roles[role]["guest"])

    def grant_sha256s(self):
        self.check(); p.require(all(item["grant_raw"] is not None for item in self._roles.values()))
        return {role: p.sha(self._roles[role]["grant_raw"]) for role in g.ROLES}

    def transfer(self):
        self.check(); p.require(not self._taken and all(item["launch"] is not None for item in self._roles.values()))
        # The complete signed installation scope must agree across all five
        # independently signed grants, not merely be five valid local grants.
        scopes = [g.document(self._roles[role]["grant_raw"], 65536)["payload"]["scope"] for role in g.ROLES]
        p.require(all(scope == scopes[0] for scope in scopes))
        if self._commitment:
            from serverware.custody_commitment_inputs import _same_cohort
            _same_cohort(self, scopes[0])
        if self._spool:
            from serverware.custody_spool_inputs import _release_current
            _release_current(self)
        self._taken = True
        return GenerationTransfer(_TOKEN, self)

    def close(self):
        if self._closed:
            return
        # Never release a journal/lock/descriptor while its actual child lives.
        self._launcher.close(); self._closed = True
        for original in reversed(self._originals):
            original.close()
        for fd in reversed(self._fds):
            os.close(fd)
        if self._business_owner is not None:
            self._business_owner._close_after_reap()


class GenerationTransfer:
    def __init__(self, token, owner):
        p.require(token is _TOKEN)
        self._owner, self._attempted = owner, False

    def check(self):
        p.require(not self._attempted); self._owner.check()
        if self._owner._commitment:
            from serverware.custody_commitment_inputs import _release_current
            _release_current(self._owner)

    def _prepared(self):
        self.check(); result = {}
        for role in g.ROLES:
            item = self._owner._roles[role]
            notice = {"apiVersion": "serverware.policyCustodyGuestStartup/v1", "deliverySha256": item["delivery"].sha,
                "serviceRole": role, "invocationId": item["guest"]["invocationId"], "phase": "constructed"}
            result[role] = notice, (item["launch"].fd, *(fd for _, fd in item["descriptors"]))
        return result

    def begin_release(self):
        self.check(); self._attempted = True; self._owner._released = True

    def close(self):
        self._owner.close()
