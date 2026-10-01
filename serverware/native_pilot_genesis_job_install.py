"""Install one independently approved cold66 input/approval pair.

The literal JobRequest/Approval/Reply v2 remain unchanged. A fourth protected
original, the actual caller-pinned Execution/v2 configuration, supplies the
original boot/window and UNIX ceiling absent from the request wire. The parent
must join that configuration and request to its retained cold process. This
installer does not create approval or authenticate producer semantics; the
actual executor still checks predecessors, signatures and narrower grant caps.
"""
from __future__ import annotations

import os

from serverware import native_pilot_genesis_authority_channel as channel
from serverware import native_pilot_genesis_execution_protocol as wire
from serverware import native_pilot_genesis_jobs as jobs
from serverware import native_pilot_genesis_parent_control_io as io
from serverware import native_pilot_genesis_rendezvous_install as writer

p, g = wire.p, wire.g
MAX_CONFIGURATION, MAX_REQUEST, MAX_APPROVAL = 4096, wire.MAX_REQUEST - 1, 8192
CATALOGUE = jobs.catalogue(handoff=True)
MAX_INPUT = max(job.maximum for job in CATALOGUE)
REQUEST_FIELDS = ("apiVersion", "sequence", "job", "deadlineBoottimeNs", "observation", "previousResult")
_TOKEN, _USED = object(), False


def context(raw, *, boot, now_boottime_ns, now_unix_ns):
    """Original lifecycle bounds, not another startup admission or renewal."""
    value = p.fields(g.document(raw, MAX_CONFIGURATION),
        ("apiVersion", "window", "expiresAtUnixNanos", "coreHandoff"))
    p.require(value["apiVersion"] == wire.HANDOFF_CONFIGURATION_API)
    peer = p.fields(value["coreHandoff"], ("peerPid", "peerUid", "peerGid"))
    p.integer(peer["peerPid"], minimum=2, maximum=(1 << 31) - 1)
    p.require(type(peer["peerUid"]) is int and type(peer["peerGid"]) is int
        and peer["peerUid"] == peer["peerGid"] == 0)
    window = p.fields(value["window"], wire.endpoints.WINDOW)
    p.require(p.decoded(window["bootIdBase64url"], size=16) != bytes(16))
    p.integer(window["timeNamespaceDevice"], minimum=0, maximum=p.MAX_U64)
    p.integer(window["timeNamespaceInode"], maximum=p.MAX_U64)
    p.require(tuple(window[name] for name in wire.endpoints.WINDOW[:3]) == boot)
    wire.endpoints.parent._invocation(window["invocationId"])
    issued, startup, lifetime = (p.ns(window[name]) for name in wire.endpoints.WINDOW[3:6])
    expiry = p.integer(value["expiresAtUnixNanos"], maximum=p.MAX_I64)
    p.integer(now_boottime_ns, maximum=p.MAX_U64); p.integer(now_unix_ns, maximum=p.MAX_I64)
    p.require(issued < startup <= lifetime and startup - issued <= 30_000_000_000
        and issued < lifetime - wire.RESERVE and issued <= now_boottime_ns < lifetime
        and now_unix_ns < expiry)
    return value


def request(raw, configuration, *, now_boottime_ns):
    value = p.fields(p.document(raw, MAX_REQUEST), REQUEST_FIELDS)
    p.require(value["apiVersion"] == wire.HANDOFF_REQUEST_API)
    sequence = p.integer(value["sequence"], maximum=len(CATALOGUE))
    selected = CATALOGUE[sequence - 1]
    p.require(value["job"] == selected.name)
    observed = value["observation"]
    p.require(type(observed) is dict and set(observed).issubset((*jobs.OBSERVATIONS, "core.observation"))
        and all(type(original) is str and original.isascii() and 0 < len(original) <= wire.MAX_REQUEST
            for original in observed.values()))
    previous = value["previousResult"]
    if sequence == 1:
        p.require(previous is None)
    else:
        p.fields(previous, ("job", "resultOriginal", "resultSha256"))
        p.require(previous["job"] == CATALOGUE[sequence - 2].name
            and type(previous["resultOriginal"]) is str and previous["resultOriginal"].isascii()
            and 0 < len(previous["resultOriginal"]) <= wire.MAX_REQUEST
            and p.sha(previous["resultOriginal"].encode("ascii")) == p.digest(previous["resultSha256"]))
    window = configuration["window"]
    startup, lifetime = (p.ns(window[name]) for name in ("startupDeadlineBoottimeNs", "lifetimeDeadlineBoottimeNs"))
    # Exactly GenesisExecution._ceiling before optional stricter core bounds.
    upper = lifetime if selected.name in ("cleanup", "handoff-cold-core") else lifetime - wire.RESERVE if (
        selected.name in ("coordinator-finish", "acquire-cold-core")) else min(startup, lifetime - wire.RESERVE)
    deadline = p.ns(value["deadlineBoottimeNs"])
    p.require(now_boottime_ns < deadline <= upper)
    return value, selected, deadline


def prepare_input(request_raw, input_raw, approval_raw, configuration_raw, *, request_sha256,
                  input_sha256, approval_sha256, configuration_sha256, boot, now_boottime_ns, now_unix_ns):
    """Pure fixed association checks; no live-owner or approval verdict."""
    for raw, maximum, digest in ((configuration_raw, MAX_CONFIGURATION, configuration_sha256),
            (request_raw, MAX_REQUEST, request_sha256), (approval_raw, MAX_APPROVAL, approval_sha256)):
        p.require(type(raw) is bytes and 0 < len(raw) <= maximum and p.sha(raw) == p.digest(digest))
    configuration = context(configuration_raw, boot=boot, now_boottime_ns=now_boottime_ns, now_unix_ns=now_unix_ns)
    ticket, selected, deadline = request(request_raw, configuration, now_boottime_ns=now_boottime_ns)
    p.require(type(input_raw) is bytes and 0 < len(input_raw) <= selected.maximum
        and p.sha(input_raw) == p.digest(input_sha256))
    # Public framing only: some unsigned ordinary inputs legitimately carry
    # native u64 metadata. Larger issuer envelopes use the existing i64 codec.
    # Neither branch authenticates the selected producer or embedded originals.
    if len(input_raw) <= g.MAX_BYTES:
        g.document(input_raw, min(selected.maximum, g.MAX_BYTES))
    else:
        p.document(input_raw, selected.maximum)
    wire.approval(approval_raw, request_raw=request_raw, input_sha256=input_sha256)
    result = dict(apiVersion=channel.HANDOFF_REPLY_API, sequence=ticket["sequence"], job=selected.name,
        requestSha256=request_sha256, inputSha256=input_sha256, approvalSha256=approval_sha256)
    channel.reply(p.canonical(result), request_raw)
    return dict(deadline=deadline, epochLimit=configuration["expiresAtUnixNanos"],
        paths=channel.paths(selected.name, handoff=True), maximum=selected.maximum, reply=result)


class InstallationError(ValueError):
    def __init__(self, owner):
        super().__init__("cold job installation refused; partial files and actual owner retained")
        self.owner = owner


class GenesisJobInstallation(writer.GenesisRendezvousInstallation):
    """Same protected publisher and sticky close; only fixed cold66 paths."""
    def __init__(self, token):
        p.require(token is _TOKEN)
        super().__init__(writer._TOKEN)
        self._publication_paths = ()

    def _retain(self, fd, maximum, digest):
        # Retain partial constructor state too. PublicInput's own failed close
        # must not become an unreachable descriptor or a second close attempt.
        with io.owning():
            source = io.PublicInput.__new__(io.PublicInput)
            source.fd = None
            self._sources.append(source)
            try:
                source.__init__(fd, maximum, digest)
            except BaseException:
                if source.fd is not None:
                    self._close_uncertain = True
                raise
        return source

    @classmethod
    def install(cls, *, request_fd, request_sha256, input_fd, input_sha256,
                approval_fd, approval_sha256, configuration_fd, configuration_sha256):
        global _USED
        p.require(cls is GenesisJobInstallation and not _USED)
        _USED = True
        owner = cls(_TOKEN)
        try:
            owner._clock()
            descriptors = (configuration_fd, request_fd, input_fd, approval_fd)
            p.require(all(type(fd) is int and 3 <= fd < (1 << 31) for fd in descriptors)
                and len(set(descriptors)) == 4)
            configuration_source = owner._retain(configuration_fd, MAX_CONFIGURATION, configuration_sha256)
            owner._clock()
            original = context(configuration_source.raw, boot=owner._boot,
                now_boottime_ns=owner._previous, now_unix_ns=owner._wall)
            owner._deadline = p.ns(original["window"]["lifetimeDeadlineBoottimeNs"])
            owner._expiry = original["expiresAtUnixNanos"]
            owner._clock()
            request_source = owner._retain(request_fd, MAX_REQUEST, request_sha256)
            owner._clock()
            _, selected, owner._deadline = request(request_source.raw, original, now_boottime_ns=owner._previous)
            owner._clock()
            input_source = owner._retain(input_fd, selected.maximum, input_sha256)
            owner._clock()
            approval_source = owner._retain(approval_fd, MAX_APPROVAL, approval_sha256)
            owner._clock()
            p.require(len({source.identity[:2] for source in owner._sources}) == 4)
            prepared = prepare_input(request_source.raw, input_source.raw, approval_source.raw, configuration_source.raw,
                request_sha256=request_sha256, input_sha256=input_sha256, approval_sha256=approval_sha256,
                configuration_sha256=configuration_sha256, boot=owner._boot,
                now_boottime_ns=owner._previous, now_unix_ns=owner._wall)
            p.require(prepared["deadline"] == owner._deadline and prepared["epochLimit"] == owner._expiry)
            owner._publication_paths = prepared["paths"]
            owner._clock()
            owner.open()
            root = owner._roots[owner._paths[-1]][0]
            for path in owner._publication_paths:
                owner.check()
                try:
                    os.stat(path.rsplit("/", 1)[1], dir_fd=root, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise ValueError("cold job destination exists")
            owner._publish(owner._publication_paths[0], input_source.raw, selected.maximum, input_sha256)
            owner._publish(owner._publication_paths[1], approval_source.raw, MAX_APPROVAL, approval_sha256)
            owner.check()
            owner._reply = prepared["reply"]
            owner._clock()
            return owner
        except BaseException as error:
            owner._failed = True
            raise InstallationError(owner) from error
