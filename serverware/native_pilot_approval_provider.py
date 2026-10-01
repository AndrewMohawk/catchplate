"""Actual independently configured provider for the fixed commissioning caller.

Only a separately provisioned protected delegation policy authorizes candidate
derivation. This process has no signing keys, installer or child launcher. The
eight fresh current-head decisions arrive as complete protected input/approval
pairs from a second authenticated peer; they are never inferred from history.
Completion receipts acknowledge validated public transcripts, not a live pilot.
"""
from __future__ import annotations

import os
import threading
import time

from scripts import native_pilot_runtime_artifacts as artifacts
from scripts.authority import native_pilot_authority_io as public_io
from serverware import native_pilot_approval_current_heads as heads
from serverware import native_pilot_approval_policy as policy
from serverware import native_pilot_genesis_execution_protocol as cold_wire
from serverware import native_pilot_genesis_parent_control_io as ownership
from serverware import native_pilot_genesis_rendezvous_profile as rendezvous
from serverware import native_pilot_lifecycle_approval_wire as wire
from serverware import native_shadow_nitro_originals as originals
from serverware.native_pilot_approval_transcript import CandidateTranscript
from serverware.native_pilot_genesis_authority import _SelfRuntime
from serverware.native_pilot_genesis_installer_process import SealedRequest
from serverware.native_pilot_lifecycle import _Protected
from serverware.native_pilot_supervisor_approval_channel import ApprovalChannel, ApprovalPeer

p = policy.p
INPUTS = ("policy", "supervisor_inventory", "recipe", "conductor_inventory", "authority_inventory")
FIELDS = tuple(name + suffix for name in INPUTS for suffix in ("_fd", "_sha256")) + (
    "approval_socket_fd", "current_head_socket_fd")
_TOKEN, _USED, _LIVE = object(), False, None


def _approval(stage, pending, input_raw):
    """Exact existing serializers. The real caller must authorize BEFORE use."""
    p.require(type(input_raw) is bytes and 0 < len(input_raw) <= wire.MAX_REQUEST)
    digest = p.sha(input_raw)
    if stage == "rendezvous":
        ticket = rendezvous.verify_request(pending)
        raw = p.canonical(dict(apiVersion=rendezvous.APPROVAL_API,
            requestSha256=p.sha(pending), inputSha256=digest,
            **{name: ticket[name] for name in rendezvous.PINS + rendezvous.BOUNDS}))
        rendezvous.approval(raw, request_raw=pending, input_sha256=digest)
    elif stage == "cold":
        ticket = p.document(pending, cold_wire.MAX_REQUEST)
        p.require(ticket["apiVersion"] == cold_wire.HANDOFF_REQUEST_API)
        raw = p.canonical(dict(apiVersion=cold_wire.HANDOFF_APPROVAL_API,
            requestSha256=p.sha(pending), inputSha256=digest,
            **{name: ticket[name] for name in ("sequence", "job", "deadlineBoottimeNs")}))
        cold_wire.approval(raw, request_raw=pending, input_sha256=digest)
    else:
        p.require(stage == "adopted" and pending["job"] not in heads.JOB_NAMES)
        ticket, job, _ = policy._adopted_pending(pending)
        p.require(job.family != "current-head")
        profile = policy.adopted.profile
        raw = p.canonical({name: profile.APPROVAL_API if name == "apiVersion" else
            digest if name == "inputSha256" else ticket[name] for name in profile.APPROVAL_FIELDS})
    return raw


class ApprovalProviderError(ValueError):
    def __init__(self, owner):
        super().__init__("independent approval provider refused; actual owner retained")
        self.owner = owner


class ApprovalProvider:
    """One real installed process retaining protected inputs and both channels."""
    def __init__(self, token):
        p.require(token is _TOKEN)
        self._pid, self._start, self._boot = os.getpid(), originals._start(), originals._boot()
        self._last, self._wall = originals._clock(), time.time_ns()
        self._sources, self._outgoing = [], []
        self._runtime = self._peer = self._heads = self._prepared = self._transcript = None
        self._active_caps = self._transport_caps = None
        self._running = self._used = self._failed = self._closed = self._close_attempted = False
        self._complete = False
        self.stage, self.approvals, self.completions = "opening", 0, 0

    def _acquire(self, slot, factory, **kwargs):
        with ownership.owning():
            try:
                value = factory(**kwargs)
            except BaseException as error:
                if getattr(error, "owner", None) is not None:
                    setattr(self, slot, error.owner)
                raise
            setattr(self, slot, value)
        return value

    @classmethod
    def open(cls, **supplied):
        global _USED, _LIVE
        p.require(cls is ApprovalProvider and not _USED and _LIVE is None)
        _USED = True
        owner = cls(_TOKEN)
        _LIVE = owner
        try:
            public_io._process()
            p.fields(supplied, FIELDS)
            descriptors = [supplied[name] for name in FIELDS if name.endswith("_fd")]
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in descriptors)
                and len(set(descriptors)) == len(descriptors))
            bounds = (policy.MAX_POLICY, artifacts.MAX_MANIFEST_BYTES, policy.lifecycle.measured.MAX_RECIPE,
                artifacts.MAX_MANIFEST_BYTES, artifacts.MAX_MANIFEST_BYTES)
            held = {name: _Protected(owner._sources, supplied[name + "_fd"], maximum,
                supplied[name + "_sha256"]) for name, maximum in zip(INPUTS, bounds, strict=True)}
            p.require(len({item.identity[:2] for item in owner._sources}) == len(owner._sources))
            owner._runtime = _SelfRuntime()  # Retain partial admission before it can acquire FDs.
            owner._runtime.admit(held["supervisor_inventory"].fd, held["supervisor_inventory"].digest)
            owner._prepared = policy.prepare(held["policy"].raw,
                **{name + "_original": held[name].raw for name in INPUTS if name != "policy"},
                boot=owner._boot, now_boottime_ns=originals._clock(), now_unix_ns=time.time_ns())
            owner._transcript = CandidateTranscript(owner._prepared["bootstrap_configuration"])
            caps = owner._prepared
            listener = caps["_listener"]
            # Before bootstrap delivery the lifecycle knows only its listener
            # originals, not this independently tighter policy/recipe window.
            # Preserve that outer header. Our callback still bounds every wait
            # and response by the narrower decision policy and active input.
            owner._transport_caps = dict(deadline=p.ns(listener["window"]["lifetimeDeadlineBoottimeNs"]),
                epochLimit=listener["expiresAtUnixNanos"])
            for slot, name, kind, expected in (("_peer", "approval_socket_fd", ApprovalPeer, caps["peer"]),
                    ("_heads", "current_head_socket_fd", ApprovalChannel, caps["currentHeadPeer"])):
                factory = kind.open_lifecycle if kind is ApprovalPeer else kind.open_current_heads
                transport = owner._transport_caps if kind is ApprovalPeer else caps
                owner._acquire(slot, factory, fd=supplied[name],
                    **{"peer_" + field: expected[field] for field in ("pid", "uid", "gid")},
                    deadline_boottime_ns=transport["deadline"], expires_at_unix_ns=transport["epochLimit"],
                    check=owner.check, **({"completions": True} if kind is ApprovalPeer else {}))
                p.require(getattr(owner, slot).peer_identity() == expected)
            owner.check(full=True)
            return owner
        except BaseException as error:
            owner._failed = True
            raise ApprovalProviderError(owner) from error

    def _origin(self):
        p.require(type(self) is ApprovalProvider and _LIVE is self and not self._closed
            and (self._pid, self._start, self._boot) == (os.getpid(), originals._start(), originals._boot())
            and threading.current_thread() is threading.main_thread()
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))

    def check(self, *, full=False):
        # Channel callbacks deliberately do not recursively check channels.
        self._origin()
        p.require(not self._failed and not self._close_attempted and self._prepared is not None)
        for held in self._sources:
            (held.check if full else held.check_identity)()
        self._runtime.check()
        now, wall = originals._clock(), time.time_ns()
        caps = self._prepared
        deadline, expiry = caps["deadline"], caps["epochLimit"]
        if self._active_caps is not None:
            deadline = min(deadline, self._active_caps["deadline"])
            expiry = min(expiry, self._active_caps["epochLimit"])
        p.require(self._last <= now < deadline and self._wall <= wall < expiry)
        self._last, self._wall = now, wall

    def _clocks(self):
        self.check()
        return dict(boot=self._boot, now_boottime_ns=self._last, now_unix_ns=self._wall)

    def _authorize(self, stage, pending, selection=None):
        self.check(full=True)
        peer = self._peer.peer_identity()
        clocks = self._clocks()
        if stage == "adopted" and pending["job"] in heads.JOB_NAMES:
            caps = policy.admit_external(self._prepared, pending, peer=peer, **clocks)
        else:
            caps = policy.authorize(self._prepared, stage, pending, selection=selection, peer=peer, **clocks)
        return caps

    def _head_pair(self, pending):
        caps = self._authorize("adopted", pending)
        inner = heads.pending_bounds(pending)
        self._active_caps = {name: min(caps[name], inner[name]) for name in ("deadline", "epochLimit")}
        p.require(self._heads.peer_identity() == self._prepared["currentHeadPeer"])
        received = self._heads.exchange_current_head(pending,
            deadline_boottime_ns=self._active_caps["deadline"],
            expires_at_unix_ns=self._active_caps["epochLimit"], check=self.check)
        # The channel owns incoming originals even if acquisition is interrupted.
        pair = received.resume_kwargs()
        held = {name: _Protected(self._sources, pair[name + "_fd"], maximum, pair[name + "_sha256"])
            for name, maximum in (("input", heads.MAX_INPUT), ("approval", heads.MAX_APPROVAL))}
        p.require(held["input"].identity[:2] != held["approval"].identity[:2])
        selection = heads.selection(pending, held["input"].raw, held["approval"].raw, **self._clocks())
        candidate = self._transcript.prepare("adopted", pending, selection, **self._clocks())
        checked = heads.require_candidate(candidate, held["input"].raw, held["approval"].raw,
            pending=pending, **self._clocks())
        caps = self._authorize("adopted", pending)
        self._active_caps = {name: min(caps[name], checked[name], self._active_caps[name])
            for name in ("deadline", "epochLimit")}
        for value in held.values(): value.check()
        return candidate, {name + suffix: value.fd if suffix == "_fd" else value.digest
            for name, value in held.items() for suffix in ("_fd", "_sha256")}

    def _delegated_pair(self, stage, pending):
        job = (p.document(pending, wire.MAX_REQUEST)["job"] if stage == "cold" else
            pending["job"] if stage == "adopted" else None)
        selection = policy.selection(self._prepared, stage, job, pending)
        caps = self._authorize(stage, pending, selection)
        self._active_caps = caps
        candidate = self._transcript.prepare(stage, pending, selection, **self._clocks())
        caps = self._authorize(stage, pending, selection)  # Recheck AFTER composition, before approval.
        self._active_caps = {name: min(caps[name], candidate[name]) for name in ("deadline", "epochLimit")}
        self.check(full=True)
        approved = dict(candidate["originals"])
        if stage != "bootstrap":
            approved["approval"] = _approval(stage, pending, approved["input"])
        result = {}
        for name, raw in approved.items():
            with ownership.owning():
                try:
                    sealed = SealedRequest.open(raw)
                except BaseException as error:
                    if getattr(error, "owner", None) is not None:
                        self._outgoing.append(error.owner)
                    raise
                self._outgoing.append(sealed)
            sealed.check()
            result.update({name + "_fd": sealed.fd, name + "_sha256": sealed.digest})
        self._authorize(stage, pending, selection)
        self.check()
        return candidate, result

    def run(self):
        try:
            self.check(full=True)
            p.require(not self._used and not self._running)
            self._used = self._running = True
            while not self._transcript.done:
                self.stage = self._transcript.next_stage
                caps = self._transport_caps
                if self.stage.endswith("-completion"):
                    stage, raw = self._peer.receive_completion(deadline_boottime_ns=caps["deadline"],
                        expires_at_unix_ns=caps["epochLimit"], check=self.check)
                    p.require(self.stage == stage + "-completion")
                    self._transcript.complete(stage, raw, **self._clocks())
                    self.check(full=True)
                    self._peer.acknowledge_completion()
                    self.completions += 1
                    if stage == "cold": self._active_caps = None
                    continue
                stage, pending = self._peer.receive_lifecycle(deadline_boottime_ns=caps["deadline"],
                    expires_at_unix_ns=caps["epochLimit"], check=self.check)
                p.require(stage == self.stage)
                candidate, reply = (self._head_pair(pending) if stage == "adopted"
                    and pending["job"] in heads.JOB_NAMES else self._delegated_pair(stage, pending))
                self.check(full=True)
                self._peer.respond_lifecycle(**reply)
                self._transcript.accept(candidate["originals"])
                self.approvals += 1
                # The peer acknowledged FD delivery. Retire this process's
                # actual sealed handles, not the peer's execution or custody.
                while self._outgoing:
                    self._outgoing[-1].close()
                    self._outgoing.pop()
                # Keep the final action's narrower bounds through its actual
                # completion receipt, but not across the cold-core handoff.
                if not self._transcript.next_stage.endswith("-completion"):
                    self._active_caps = None
            p.require(self.approvals == len(wire.ORDER) == 244 and self.completions == 2)
            self.check(full=True)
            self._runtime.check(installed=True)
            self.check()  # The installed-runtime read must finish inside the final action's caps.
            self._complete = True
            self.stage = "complete-public-transcript"
        except BaseException as error:
            self._failed = True
            raise ApprovalProviderError(self) from error
        finally:
            self._running = False

    def close(self):
        if self._closed: return
        try:
            self._origin()
            p.require(not self._running and not self._close_attempted)
            self._close_attempted = True
            with ownership.owning():
                for sealed in reversed(self._outgoing): sealed.close()
                for held in reversed(self._sources): held.close()
                for channel in (self._heads, self._peer):
                    if channel is not None: channel.close()
                if self._runtime is not None: self._runtime.close()
                self._closed = True
        except BaseException as error:
            self._failed = True
            raise ApprovalProviderError(self) from error
