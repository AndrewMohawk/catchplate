"""One fixed parent-to-independent-issuer-to-management-to-bridge exchange.

The relay is not a verifier or a generation owner. The independent issuer
verifies the real measured statement; the separately authorized native/DRS
owners verify its signed result and perform initialization. No retries,
response-selected URLs, private keys, or caller-supplied times.
"""
import errno
import ipaddress
import select
import socket
import time
import urllib.parse
import urllib.request

from serverware import custody_generation_originals as o
from serverware import native_generation_origin_profile as profile
from serverware import native_shadow_nitro_profile as p
from serverware import http_client

PATH = "/v1/native-generation-origin"
CONFIG = "/etc/serverware/native-generation-origin-relay.json"


class Configuration:
    @classmethod
    def open(cls):
        owner = cls(); owner.original = o.Original(CONFIG, 8192)
        try:
            owner.raw = owner.original.read()
            owner.value = p.fields(p.document(owner.raw, 8192), ("apiVersion", "issuerIp", "issuerPort", "managementUrl", "managementToken"))
            value = owner.value
            p.require(value["apiVersion"] == "serverware.nativeGenerationOriginRelay/v1")
            address = ipaddress.ip_address(value["issuerIp"])
            p.require(str(address) == value["issuerIp"] and not address.is_unspecified and not address.is_multicast)
            p.integer(value["issuerPort"], minimum=1024, maximum=65535)
            url = urllib.parse.urlsplit(value["managementUrl"])
            p.require(url.scheme == "http" and url.hostname in {"decision-gate-rs", "localhost", "127.0.0.1", "::1"}
                and url.port == 9091 and url.path == PATH and not url.query and not url.fragment
                and url.username is None and url.password is None)
            token = value["managementToken"]
            p.require(type(token) is str and token.isascii() and 1 <= len(token) <= 4096
                and all(32 < ord(c) < 127 for c in token))
            owner.family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            return owner
        except BaseException:
            owner.close(); raise

    def check(self):
        p.require(self.original.read() == self.raw and p.canonical(self.value) == self.raw)

    def close(self):
        self.original.close()


def deliver(owner, *, deadline_boottime_ns=None):
    from serverware.native_shadow_spool_inputs import SpoolInputs
    p.require(type(owner) is SpoolInputs and owner._delivery_attempted)
    config = owner._relay; config.check()
    head = p.document(owner._head, 65536)["payload"]
    scope, key_pin = head["scope"], head["originVerifier"]
    # This is the one observation's original transport budget, not a renewal
    # of any independently signed grant, generation or cohort lifetime.
    now_boottime = o.clock()
    deadline = min(now_boottime + 30_000_000_000, scope["expiresAtBoottimeNanos"], owner._cohort._lifetime)
    if deadline_boottime_ns is not None:
        p.require(type(deadline_boottime_ns) is int
            and now_boottime < deadline_boottime_ns <= owner._cohort._lifetime)
        # The caller may reserve original lifetime for cleanup, never extend
        # this observation's transport budget or any independently held scope.
        deadline = min(deadline, deadline_boottime_ns)
    previous_wall = 0

    def check(expires=None):
        nonlocal previous_wall
        owner.check(preparation=False)
        now = time.time_ns()
        p.require(previous_wall <= now and o.clock() < deadline)
        previous_wall = now
        if expires is not None:
            p.require(now < expires)
        return now

    def wait(channel, event, expires=None):
        check(expires); poll = select.poll(); poll.register(channel.fileno(), event)
        for _, observed in poll.poll(10):
            p.require(not observed & (select.POLLERR | select.POLLNVAL))
        check(expires)

    def read(channel, length, expires=None):
        raw = bytearray()
        while len(raw) < length:
            check(expires)
            try:
                part = channel.recv(length - len(raw)); p.require(bool(part)); raw.extend(part)
            except (BlockingIOError, InterruptedError):
                wait(channel, select.POLLIN, expires)
        check(expires); return bytes(raw)

    def frame(channel, tag, expires=None):
        header = read(channel, 12, expires)
        p.require(header[:8] == tag)
        count = int.from_bytes(header[8:], "big"); p.require(1 <= count <= profile.MAX_FRAME)
        raw = read(channel, count, expires); p.document(raw, profile.MAX_FRAME)
        return raw

    check()
    with socket.socket(config.family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) as channel:
        code = channel.connect_ex((config.value["issuerIp"], config.value["issuerPort"]))
        p.require(code in (0, errno.EINPROGRESS, errno.EWOULDBLOCK))
        if code != 0:
            while True:
                wait(channel, select.POLLOUT)
                _, ready, _ = select.select([], [channel], [], 0)
                if ready:
                    p.require(channel.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0); break
        p.require(channel.getpeername()[:2] == (config.value["issuerIp"], config.value["issuerPort"]))
        challenge = p.fields(p.document(frame(channel, profile.CHALLENGE_TAG), profile.MAX_FRAME), ("payload", "signature"))
        payload = p.fields(challenge["payload"], ("apiVersion", "request", "expiresAtUnixNanos", "signingKeyId"))
        request = p.fields(payload["request"], profile.REQUEST_FIELDS)
        expires = p.integer(payload["expiresAtUnixNanos"])
        now = check(expires); key = profile.key_live(key_pin, now)
        p.require(payload["apiVersion"] == "serverware.nativeGenerationOriginChallenge/v1"
            and payload["signingKeyId"] == key_pin["keyId"]
            and request["apiVersion"] == "serverware.nativeGenerationOriginRequest/v1"
            and p.integer(request["issuedAtEpochNs"]) <= now < request["expiresAtEpochNs"] == expires
            and expires - request["issuedAtEpochNs"] <= 30_000_000_000
            and request["issuedAtEpochNs"] >= key_pin["notBeforeUnixNanos"] and expires <= key_pin["notAfterUnixNanos"]
            and request["contextSha256"] == p.sha(p.canonical(scope))
            and request["assignmentPayloadSha256"] == scope["assignmentPayloadSha256"] and request["generationId"] == scope["generationId"])
        p.digest(request["policyHash"]); p.decoded(request["challenge"], size=32)
        key.verify(p.decoded(challenge["signature"], size=64), p.preimage(profile.CHALLENGE_DOMAIN, payload))
        request_raw = p.canonical(request); p.require(len(request_raw) <= 4096)
        outbound = urllib.request.Request(config.value["managementUrl"], data=request_raw, method="POST",
            headers={"Accept": "application/json", "Accept-Encoding": "identity", "Content-Type": "application/json",
                     "X-Serverware-Data-Plane-Token": config.value["managementToken"]})
        remaining = min(deadline - o.clock(), expires - check(expires)) / 1_000_000_000
        response = http_client.request_bytes(outbound, timeout=remaining, max_bytes=profile.MAX_EVIDENCE,
            deadline=http_client.HttpDeadline(time.monotonic() + remaining), require_https=False,
            expected_statuses=(200,), expected_content_types=("application/json",))
        check(expires)
        evidence = p.fields(p.document(response.body, profile.MAX_EVIDENCE), ("statement", "signature", "nativeKeyEvidence"))
        statement = p.fields(evidence["statement"], profile.STATEMENT_FIELDS)
        p.require(statement["request"] == request and statement["apiVersion"] == profile.STATEMENT)
        wire = profile.EVIDENCE_TAG + len(response.body).to_bytes(4, "big") + response.body
        offset = 0
        while offset < len(wire):
            check(expires)
            try:
                count = channel.send(wire[offset:], socket.MSG_NOSIGNAL); p.require(count > 0); offset += count
            except (BlockingIOError, InterruptedError):
                wait(channel, select.POLLOUT, expires)
        original = frame(channel, profile.ANCHOR_TAG, expires)
        envelope = p.fields(p.document(original, profile.MAX_FRAME), ("payload", "signature"))
        result = p.fields(envelope["payload"], profile.ORIGIN_FIELDS)
        now = check(expires); profile.key_live(key_pin, now)
        p.require(result["apiVersion"] == "serverware.nativeGenerationOrigin/v1" and result["purpose"] == "native-installed-generation-origin"
            and result["request"] == request and result["evidenceOriginal"] == response.body.decode("ascii")
            and result["signingKeyId"] == key_pin["keyId"] and result["signingKeySpkiSha256"] == key_pin["keySpkiSha256"]
            and request["issuedAtEpochNs"] <= p.integer(result["issuedAtUnixNanos"]) <= now < result["expiresAtUnixNanos"] == expires)
        key.verify(p.decoded(envelope["signature"], size=64), p.preimage(profile.ORIGIN_DOMAIN, result))
        # Require exact response completion, not a request half-close. No
        # second frame or response-selected continuation is accepted.
        while True:
            check(expires)
            try:
                p.require(channel.recv(1) == b""); break
            except (BlockingIOError, InterruptedError):
                wait(channel, select.POLLIN, expires)
        # One seqpacket send. EAGAIN/partial/lost delivery is unknown and may
        # not cause a new issuer challenge, management contact, or resend.
        check(expires)
        p.require(owner._local.send(original, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL) == len(original))
        check(expires)
        return {"apiVersion": "serverware.nativeGenerationOriginHandoff/v1", "okForAction": False,
            "automaticRetryAllowed": False, "originSha256": p.sha(original)}
