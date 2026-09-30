"""Actual parked software five-service launcher; not the native proof cohort.

Only start() constructs this owner. Public process projections are observations,
not final peer measurements, assignments, IMA evidence or service permissions.
"""
import array
import ctypes
import fcntl
import os
import re
import resource
import select
import signal
import socket
import struct
import threading

from serverware import custody_generation_grants as g
from serverware import custody_generation_originals as o

p = g.p
_TOKEN = object()
CONFIGURATION = "/etc/serverware/custody-generation-five.json"
RELEASE = b"serverware.custodyFiveServiceRelease/v1"
PARKED = b"serverware.custodyFiveServiceParked/v1"
COMMITMENT_CONFIGURATION = "/etc/serverware/custody-commitment-five.json"
SPOOL_CONFIGURATION = "/etc/serverware/custody-spool-five.json"
EFFECTS_CONFIGURATION = "/etc/serverware/custody-effects-five.json"
COMMITMENT_RELEASE = b"serverware.custodyFiveServiceRelease/v2"
COMMITMENT_PARKED = b"serverware.custodyFiveServiceParked/v2"
COMMITMENT_ROLES = (g.ROLES[0], g.ROLES[3])
EFFECTS_ROLES = (g.ROLES[0], g.ROLES[1], g.ROLES[3])


def _packet(channel, maximum, descriptors):
    raw, ancillary, flags, _ = channel.recvmsg(maximum,
        socket.CMSG_SPACE(descriptors * 4) + socket.CMSG_SPACE(12), socket.MSG_CMSG_CLOEXEC)
    rights, credentials = [], []
    try:
        for level, kind, value in ancillary:
            p.require(level == socket.SOL_SOCKET)
            if kind == socket.SCM_RIGHTS:
                p.require(len(value) % 4 == 0)
                received = array.array("i"); received.frombytes(value); rights.extend(received)
            elif kind == socket.SCM_CREDENTIALS:
                p.require(len(value) == 12); credentials.append(struct.unpack("3i", value))
            else:
                raise ValueError("unexpected five-service ancillary data")
        p.require(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) and len(credentials) == 1
            and len(rights) == descriptors and 0 < len(raw) <= maximum)
        return raw, rights, credentials[0]
    except BaseException:
        for fd in rights:
            os.close(fd)
        raise


def _park(channel, executable, parent, role, startup, inspected, commitment, spool, effects):
    """Same fork child performs the fixed exec; no future PID prediction."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        p.require(libc.prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        p.require(libc.prctl(4, 0, 0, 0, 0) == 0)
        channel_copy = fcntl.fcntl(channel.fileno(), fcntl.F_DUPFD_CLOEXEC, 256)
        executable_copy = fcntl.fcntl(executable, fcntl.F_DUPFD_CLOEXEC, 256)
        os.dup2(channel_copy, 3, inheritable=True); os.dup2(executable_copy, 5, inheritable=False)
        limit = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        p.require(256 < limit <= 1_048_576)
        os.closerange(4, 5); os.closerange(6, limit)
        # Replace inherited stdio with fixed /dev/null; never leak operator keys.
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        for target in (0, 1, 2):
            os.dup2(null, target)
        if null > 5:
            os.close(null)
        wire = socket.socket(fileno=3)
        parked = COMMITMENT_PARKED if commitment else PARKED
        release = COMMITMENT_RELEASE if commitment else RELEASE
        p.require(wire.send(parked) == len(parked))
        poll = select.poll(); poll.register(3, select.POLLIN)
        remaining = startup - o.clock(); p.require(remaining > 0)
        p.require(poll.poll((remaining + 999_999) // 1_000_000) and o.clock() < startup)
        selected = commitment and role in COMMITMENT_ROLES
        effect_selected = effects and role in EFFECTS_ROLES
        count = 1 + len(g.BUSINESS[role]) + 2 + (2 if selected else 0) + (2 if effect_selected or selected and spool else 0)
        raw, rights, peer = _packet(wire, len(release), count)
        p.require(raw == release and peer == (parent, 0, 0) and os.getppid() == parent)
        safe = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 256) for fd in rights]
        for fd in rights:
            os.close(fd)
        for target, fd in zip((4, *range(6, 6 + count - 1)), safe):
            os.dup2(fd, target, inheritable=True)
        os.closerange(6 + count - 1, limit)
        p.require(o.clock() < startup and os.getppid() == parent)
        if effect_selected:
            p.require(inspected)
            selector = "--guest-c9-effects-inspected"
        elif selected and spool:
            p.require(inspected)
            selector = "--guest-c9-spool-inspected"
        elif selected:
            selector = "--guest-c9-commitment-inspected" if inspected else "--guest-c9-commitment"
        else:
            selector = "--guest-c9-generation-inspected" if inspected else "--guest-c9-generation"
        os.execve(5, [f"/usr/local/bin/serverware-policy-custody-{role}", selector], {})
    except BaseException:
        os._exit(1)


class FiveServiceStartError(ValueError):
    """Startup failed and its single cleanup attempt did not complete."""

    launch: "FiveServiceLaunch"
    startup_error: BaseException
    cleanup_error: BaseException

    def __init__(self, launch: "FiveServiceLaunch", startup_error: BaseException, cleanup_error: BaseException):
        super().__init__("five service start failed; cleanup uncertain; owner retained")
        self.launch = launch
        self.startup_error = startup_error
        self.cleanup_error = cleanup_error


class FiveServiceLaunch:
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._children, self._originals = {}, []
        self._attempted = self._closed = self._failed = False
        self._stop = threading.Event(); self._input_owner = None
        self._business_resources = None
        self._thread = self._transfer = None
        self._listening = threading.Event(); self._bridge_attempted = False

    @classmethod
    def start(cls):
        return cls._start(False)

    @classmethod
    def start_commitment(cls):
        """A separate fixed protected profile, never an argument to release."""
        return cls._start(True)

    @classmethod
    def start_spool(cls):
        """Fixed inspected two-role shared-spool successor."""
        return cls._start(True, spool=True)

    @classmethod
    def start_effects(cls):
        """Fixed inspected DRS/Cleanup/Current effects successor."""
        return cls._start(True, spool=True, effects=True)

    @classmethod
    def _start(cls, commitment, spool=False, effects=False):
        p.require(cls is FiveServiceLaunch and type(commitment) is bool and type(spool) is bool
            and type(effects) is bool and (not spool or commitment) and (not effects or spool))
        p.require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and threading.current_thread() is threading.main_thread())
        # Fixed kernel-owned self link is intentional, not a supplied ancestor.
        tasks = os.open("/proc/self/task", o.FLAGS | os.O_DIRECTORY)
        try:
            p.require(len(o.names(tasks)) == 1)  # no Python fork from a threaded operator
        finally:
            os.close(tasks)
        owner = cls(_TOKEN)
        try:
            owner._pid = os.getpid(); owner._start = o.native._start(); owner._boot = o.native._boot()
            original = o.Original(EFFECTS_CONFIGURATION if effects else SPOOL_CONFIGURATION if spool else COMMITMENT_CONFIGURATION if commitment else CONFIGURATION, 65536)
            owner._originals.append(original)
            cold = p.fields(g.document(original.read(), 65536), ("apiVersion", "bootIdBase64url",
                "timeNamespaceDevice", "timeNamespaceInode", "startupDeadlineBoottimeNs",
                "lifetimeDeadlineBoottimeNs", "invocationId", "services"))
            versions = ("serverware.custodyFiveServiceLaunch/v3", "serverware.custodyFiveServiceLaunch/v4") if commitment else (
                "serverware.custodyFiveServiceLaunch/v1", "serverware.custodyFiveServiceLaunch/v2")
            if spool:
                versions = ("serverware.custodyFiveServiceLaunch/v5", "serverware.custodyFiveServiceLaunch/v5")
            if effects:
                versions = ("serverware.custodyFiveServiceLaunch/v6", "serverware.custodyFiveServiceLaunch/v6")
            p.require(cold["apiVersion"] in versions
                and (cold["bootIdBase64url"], cold["timeNamespaceDevice"], cold["timeNamespaceInode"]) == owner._boot
                and type(cold["invocationId"]) is str and re.fullmatch(r"[0-9a-f]{32}", cold["invocationId"])
                and cold["invocationId"] != "0" * 32)
            # Only the protected cold original selects inspection. Neither an
            # environment variable nor a release argument can switch modes.
            owner._inspected = cold["apiVersion"] == versions[1]
            owner._commitment = commitment
            owner._spool = spool
            owner._effects = effects
            owner._startup = p.ns(cold["startupDeadlineBoottimeNs"])
            owner._lifetime = p.ns(cold["lifetimeDeadlineBoottimeNs"])
            owner._issued = o.clock(); owner._invocation = cold["invocationId"]
            p.require(owner._issued < owner._startup <= owner._lifetime
                and owner._startup - owner._issued <= 30_000_000_000)
            services = p.fields(cold["services"], g.ROLES)
            owner._configurations = {}; identities = set(); uids = set(); gids = set()
            # Admit the entire fixed inventory before forking any child.
            for role in g.ROLES:
                spec = p.fields(services[role], ("executableSha256", "deliveryConfiguration"))
                g.c9._pin(spec["deliveryConfiguration"])
                configuration = o.Original(spec["deliveryConfiguration"]["path"], 65536,
                    sha=spec["deliveryConfiguration"]["sha256"])
                owner._originals.append(configuration)
                config = g.configuration(configuration.read(), configuration.sha, role)
                p.require(config["uid"] not in uids and config["gid"] not in gids)
                uids.add(config["uid"]); gids.add(config["gid"])
                executable = o.Original(f"/usr/local/bin/serverware-policy-custody-{role}", 256 * 1024 * 1024,
                    mode=0o755, sha=p.digest(spec["executableSha256"]))
                owner._originals.append(executable)
                # Real fs-verity immutability of the retained executable, not a
                # caller flag or content-hash assertion of IMA/verity evidence.
                flags = array.array("L", [0]); p.require(flags.itemsize == 8)
                fcntl.ioctl(executable.fd, 0x80086601, flags, True)
                p.require(flags[0] & 0x100000 and os.pread(executable.fd, 4, 0) == b"\x7fELF")
                ident = o.structural(os.fstat(executable.fd))[:2]
                p.require(ident not in identities); identities.add(ident)
                owner._configurations[role] = (configuration, config, executable)
            for role in g.ROLES:
                parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
                parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                child.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                pid = os.fork()
                if pid == 0:
                    _park(child, owner._configurations[role][2].fd, owner._pid, role, owner._startup,
                        owner._inspected, owner._commitment, owner._spool, owner._effects)
                    os._exit(1)
                child.close()
                try:
                    pidfd = os.pidfd_open(pid, 0)
                except BaseException:
                    # Closing the only parent channel aborts the parked child;
                    # reap this actual fork child, never signal a guessed PID.
                    parent.close(); os.waitpid(pid, 0); raise
                owner._children[role] = dict(pid=pid, pidfd=pidfd, start=None, channel=parent,
                    phase="parked", reaped=False)
                _, start = o.process(pid); owner._children[role]["start"] = start
                poll = select.poll(); poll.register(parent, select.POLLIN)
                remaining = owner._startup - o.clock(); p.require(remaining > 0)
                p.require(poll.poll((remaining + 999_999) // 1_000_000) and o.clock() < owner._startup)
                parked = COMMITMENT_PARKED if owner._commitment else PARKED
                raw, _, peer = _packet(parent, len(parked), 0)
                p.require(raw == parked and peer == (pid, 0, 0))
                o.live(pidfd, pid, start, owner._pid)
                parent.setblocking(False)
            owner.check()
            owner._thread = threading.Thread(target=owner._watch, name="custody-five-lifetime", daemon=True)
            owner._thread.start()
            return owner
        except BaseException as startup_error:
            try:
                owner.close()
            except BaseException as cleanup_error:
                # Preserve this actual partial owner and both failures. The
                # caller must not mistake retention for permission to retry.
                raise FiveServiceStartError(owner, startup_error, cleanup_error) from cleanup_error
            raise

    def check(self):
        p.require(not self._closed and not self._failed and os.getpid() == self._pid
            and o.native._start() == self._start and o.native._boot() == self._boot
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0) and o.clock() < self._lifetime)
        for original in self._originals:
            original.check()
        if self._business_resources is not None:
            self._business_resources._check_resources()
        for item in self._children.values():
            o.live(item["pidfd"], item["pid"], item["start"], self._pid)
            if item["phase"] != "constructed":
                p.require(o.clock() < self._startup)

    def parked_originals(self):
        self.check(); p.require(not self._attempted)
        result = {}
        for role, item in self._children.items():
            executable = self._configurations[role][2]
            info, pidfd = os.fstat(executable.fd), os.fstat(item["pidfd"])
            result[role] = dict(processId=item["pid"], startTimeTicks=item["start"], pidfdInode=pidfd.st_ino,
                executable=dict(device=info.st_dev, inode=info.st_ino, length=info.st_size, sha256=executable.sha))
        return result

    def release(self, transfer):
        from serverware.custody_generation_inputs import GenerationTransfer
        self.check(); p.require(threading.current_thread() is threading.main_thread()
            and type(transfer) is GenerationTransfer and transfer._owner._launcher is self
            and not self._attempted)
        transfer.check(); prepared = transfer._prepared()
        p.require(transfer._owner._commitment == self._commitment and transfer._owner._spool == self._spool
            and transfer._owner._effects == self._effects)
        p.require(tuple(prepared) == g.ROLES)
        self._attempted = True; self._transfer = transfer
        # Irreversible before the first possible send. A failed/unknown release
        # cannot be retried and cannot return descriptor ownership to a caller.
        transfer.begin_release()
        try:
            for role in g.ROLES:
                item = self._children[role]
                item["expected_notice"] = prepared[role][0]
                item["phase"] = "released"
                fds = array.array("i", prepared[role][1])
                release = COMMITMENT_RELEASE if self._commitment else RELEASE
                p.require(item["channel"].sendmsg([release], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)]) == len(release))
        except BaseException:
            self._failed = True; self._stop.set(); raise

    def constructed(self):
        self.check()
        return all(item["phase"] == "constructed" for item in self._children.values())

    def release_proof_cohort(self, cohort, *, release_original, transfers):
        """Release the actual bridge only after all five final-role listens.

        This is transport ordering, not a readiness/installation assertion. The
        native cohort still independently admits every supplied signed launch.
        Unknown release remains irreversible in both actual owners.
        """
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        self.check()
        p.require(type(cohort) is ParkedProofCohort and self._inspected and self._attempted
            and not self._bridge_attempted and threading.current_thread() is threading.main_thread())
        self._bridge_attempted = True
        try:
            cohort.check()
            p.require(not cohort.endpoint_driver_selected())
            if self._spool:
                from serverware.custody_spool_inputs import _require_native_release
                _require_native_release(self, cohort, transfers)
            elif self._commitment:
                p.require(cohort.commitment_selected())
                from serverware.custody_commitment_inputs import _require_native_release
                _require_native_release(self, cohort, transfers)
            bridge = cohort.bridge_original()
            # Parked identity provides PID/start and the retained executable
            # only. Final UID/cgroup/label/IMA are NOT manufactured here; the
            # independent root workers measure the actual post-exec peer.
            for role in g.ROLES:
                runtime = self._input_owner._roles[role]["runtime_raw"]
                expected = g.document(runtime, g.MAX_BYTES)["runtime"]["expectedPeer"]
                p.require(expected["pid"] == bridge["processId"]
                    and expected["startTimeTicks"] == bridge["startTimeTicks"]
                    and expected["executableDevice"] == bridge["executable"]["device"]
                    and expected["executableInode"] == bridge["executable"]["inode"]
                    and expected["executableLength"] == bridge["executable"]["length"]
                    and expected["executableSha256"] == bridge["executable"]["sha256"])
            while not self._listening.is_set():
                self.check(); cohort.check()
                remaining = self._startup - o.clock(); p.require(remaining > 0)
                self._listening.wait(min(0.01, remaining / 1_000_000_000))
            self.check(); cohort.check()
            p.require(o.clock() < self._startup and all(item["phase"] in {"listening", "constructed"}
                for item in self._children.values()))
            if self._commitment:
                from serverware.custody_commitment_inputs import _release_current
                _release_current(self._input_owner)
            if self._spool:
                from serverware.custody_spool_inputs import _release_current
                _release_current(self._input_owner)
            # Exact native release retains its own original deadlines and
            # purpose checks; this method cannot renew or replace them.
            return cohort.release(release_original=release_original, transfers=transfers)
        except BaseException:
            self._failed = True; self._stop.set(); raise

    def release_endpoint_cohort(self, cohort, *, driver, inputs, release_original, transfers):
        """All five real final-role listens precede ten-endpoint release.

        The bridge identity comes from the retained measured DriverBootstrap,
        never from a parked endpoint or a caller-projected process record.
        """
        from serverware.native_shadow_proof_cohort_control import ParkedProofCohort
        from serverware.native_shadow_driver_bootstrap import DriverBootstrap
        from serverware.native_shadow_driver_inputs import OperationalInputs
        self.check()
        p.require(type(cohort) is ParkedProofCohort and type(driver) is DriverBootstrap
            and type(inputs) is OperationalInputs and self._effects and self._inspected and self._attempted
            and not self._bridge_attempted and threading.current_thread() is threading.main_thread())
        self._bridge_attempted = True
        try:
            cohort.check(); driver.check(); inputs.check()
            p.require(cohort.endpoint_driver_selected() and cohort._external_driver.driver is driver
                and inputs._driver is driver and driver._prepared_inputs is inputs)
            from serverware.custody_spool_inputs import _require_endpoint_release, _release_current
            _require_endpoint_release(self, cohort, driver, inputs, transfers)
            measured = cohort._external_driver.value
            for role in g.ROLES:
                expected = g.document(self._input_owner._roles[role]["runtime_raw"], g.MAX_BYTES)["runtime"]["expectedPeer"]
                p.require(expected["pid"] == measured["driver"]["processId"]
                    and expected["startTimeTicks"] == measured["driver"]["startTimeTicks"]
                    and expected["executableDevice"] == measured["executable"]["device"]
                    and expected["executableInode"] == measured["executable"]["inode"]
                    and expected["executableLength"] == measured["executable"]["length"]
                    and expected["executableSha256"] == measured["executable"]["sha256"]
                    and (expected["uid"], expected["gid"]) == (driver._config["uid"], driver._config["gid"]))
            while not self._listening.is_set():
                self.check(); cohort.check(); inputs.check()
                remaining = self._startup - o.clock(); p.require(remaining > 0)
                self._listening.wait(min(0.01, remaining / 1_000_000_000))
            self.check(); cohort.check(); inputs.check()
            p.require(o.clock() < self._startup and all(item["phase"] in {"listening", "constructed"}
                for item in self._children.values()))
            from serverware.custody_commitment_inputs import _release_current as commitment_current
            commitment_current(self._input_owner); _release_current(self._input_owner)
            cohort._authorize_endpoint_release(self, driver, inputs)
            return cohort.release(release_original=release_original, transfers=transfers)
        except BaseException:
            self._failed = True; self._stop.set(); raise

    def _watch(self):
        try:
            while not self._stop.is_set():
                self.check()
                for role, item in self._children.items():
                    poll = select.poll(); poll.register(item["channel"], select.POLLIN)
                    events = poll.poll(0)
                    if events:
                        allowed = {"released", "listening"} if self._inspected else {"released"}
                        p.require(item["phase"] in allowed and events[0][1] == select.POLLIN)
                        raw, _, peer = _packet(item["channel"], 4096, 0)
                        config = self._configurations[role][1]
                        p.require(peer == (item["pid"], config["uid"], config["gid"]))
                        o.live(item["pidfd"], item["pid"], item["start"], self._pid)
                        expected = dict(item["expected_notice"])
                        if self._inspected and item["phase"] == "released":
                            expected.update(apiVersion="serverware.custodyOrdinaryListening/v1", phase="final-role-listening")
                            p.require(g.document(raw, 4096) == expected)
                            item["phase"] = "listening"
                            if all(child["phase"] in {"listening", "constructed"} for child in self._children.values()):
                                self._listening.set()
                        else:
                            p.require(g.document(raw, 4096) == expected)
                            item["phase"] = "constructed"
                deadline = min(self._lifetime, self._startup if not all(
                    item["phase"] == "constructed" for item in self._children.values()) else self._lifetime)
                self._stop.wait(min(0.01, max(0, deadline - o.clock()) / 1_000_000_000))
        except BaseException:
            self._failed = True
        finally:
            self._terminate()

    def _terminate(self):
        # Only retained actual child PIDFDs, never externally supplied PID data.
        for item in self._children.values():
            if not item["reaped"]:
                try:
                    signal.pidfd_send_signal(item["pidfd"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for item in self._children.values():
            if not item["reaped"]:
                os.waitid(os.P_PIDFD, item["pidfd"], os.WEXITED)
                item["reaped"] = True

    def close(self):
        if self._closed:
            return
        p.require(os.getpid() == getattr(self, "_pid", os.getpid())
            and threading.current_thread() is threading.main_thread())
        self._stop.set()
        if self._thread is not None and self._thread.ident is not None:
            self._thread.join()
        else:
            self._terminate()
        p.require(all(item["reaped"] for item in self._children.values()))
        self._closed = True
        for item in self._children.values():
            item["channel"].close(); os.close(item["pidfd"])
        for original in reversed(self._originals):
            original.close()
        # Public partial files are evidence: no unlink, repair, or restart.
