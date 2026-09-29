"""Cold audit authority and actual TLS-bound HTTP admission; no bearer alias."""
import os
import ssl
import threading
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from serverware import data_plane_audit_authority as wire
from serverware import oauth_application_owner as originals
from serverware import authority_contract

CONFIG_ENVIRONMENT = "SERVERWARE_MEASURED_AUDIT_CONFIG_FD"
_PID, _LOCK = os.getpid(), threading.RLock()
_state, _owner, _environment_pin = "new", None, None


def _environment():
    return (os.environ.get("SERVERWARE_RELEASE_CHANNEL","dev").strip().lower(),
        tuple(sorted((k,v) for k,v in os.environ.items() if k.startswith("SERVERWARE_MEASURED_AUDIT_"))))


class _Cold:
    def check(self):
        from serverware import control_plane_custody_startup as startup
        from serverware import control_plane_custody_client as custody
        with _LOCK:
            try:
                wire.require(os.getpid()==_PID and _state=="started" and self is _owner and not self.poisoned
                    and _environment()==_environment_pin and startup.require_started() is self.custody
                    and custody._snapshot(self.custody) is self.binding)
                now, mono = custody._receipt_now(self.binding), time.monotonic_ns()
                wire.require(self.now<=now<self.expires and self.mono<=mono<self.deadline)
                for item in self.originals: item.check()
                self.now,self.mono=now,mono
                return now
            except BaseException:
                self.poisoned=True
                raise


def initialize_from_environment():
    global _state,_owner,_environment_pin
    from serverware import control_plane_custody_startup as startup
    from serverware import control_plane_custody_client as custody
    with _LOCK:
        wire.require(os.getpid()==_PID and _state=="new")
        _environment_pin=_environment()
        if _environment_pin[0] in originals._DEVELOPMENT and not _environment_pin[1]:
            _state="disabled"; return
        _state="admitting"
        try:
            actual=startup.require_started(); binding=custody._snapshot(actual)
            wire.require(set(dict(_environment_pin[1]))=={CONFIG_ENVIRONMENT})
            text=os.environ[CONFIG_ENVIRONMENT]; wire.require(text.isascii() and text.isdecimal() and str(int(text))==text)
            fd=originals._fd(int(text)); wire.require(fd in binding.inherited_descriptors)
            config=originals._Original(fd,3*1024*1024); value=wire.document(config.raw,3*1024*1024)
            wire.require(set(value)=={"schema","sourceRevision","configurationDigest","authorityRootFd","authorityRootSha256","authorization"}
                and value["schema"]==wire.STARTUP_SCHEMA and value["sourceRevision"]==authority_contract.SOURCE_REVISION
                and value["configurationDigest"]==binding.configuration_digest)
            root_fd=originals._fd(value["authorityRootFd"]); wire.require(root_fd!=fd and root_fd in binding.inherited_descriptors)
            root_original=originals._Original(root_fd,4096)
            wire.require(wire.sha256(root_original.raw)==value["authorityRootSha256"])
            root=serialization.load_pem_public_key(root_original.raw)
            wire.require(isinstance(root,Ed25519PublicKey) and root.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)==root_original.raw
                and root.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)!=binding.runtime_root_public_key.public_bytes(
                    serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo))
            envelope=value["authorization"]
            wire.require(type(envelope) is dict and set(envelope)=={"schema","payload","signatureBase64Url"}
                and envelope["schema"]=="serverware.signedMeasuredAuditAuthorityPolicy/v1")
            policy=wire.policy(envelope["payload"],root)
            root.verify(wire.common.encoded(envelope["signatureBase64Url"],64),wire.POLICY_SCHEMA.encode("ascii")+b"\0"+wire.canonical(policy))
            now,mono=custody._receipt_now(binding),time.monotonic_ns()
            wire.require(policy["sourceRevision"]==authority_contract.SOURCE_REVISION and policy["configurationDigest"]==binding.configuration_digest
                and policy["issuedAtEpochNs"]<=now<policy["expiresAtEpochNs"])
            owner=_Cold(); owner.custody,owner.binding,owner.originals=actual,binding,(config,root_original)
            owner.policy,owner.poisoned=policy,False; owner.now,owner.mono=now,mono
            owner.expires=min(policy["expiresAtEpochNs"],binding.attestation_interval[1]); owner.deadline=mono+owner.expires-now
            _owner,_state=owner,"started"; owner.check()
        except BaseException:
            _state="poisoned"; raise


def selected():
    with _LOCK:
        wire.require(os.getpid()==_PID)
        current=_environment()
        if _state=="new" and current[0] in originals._DEVELOPMENT and not current[1]: return False
        wire.require(current==_environment_pin)
        if _state=="disabled": return False
        wire.require(_state=="started"); _owner.check(); return True


def close():
    global _state
    with _LOCK:
        wire.require(os.getpid()==_PID)
        if _owner is not None: _owner.poisoned=True
        _state="closed"


def configure_tls(context):
    if not selected(): return
    wire.require(isinstance(context,ssl.SSLContext),"measured audit requires actual control-plane TLS")
    context.minimum_version=ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cadata="".join(item["workloadCaCertificatePem"] for item in _owner.policy["assignments"]))
    # Non-audit human APIs still allow clients without certificates. An audit
    # request requires this verified real peer object, never forwarded headers.
    context.verify_mode=ssl.CERT_OPTIONAL
    _owner.check()


class _Peer:
    def __init__(self,transport):
        self.transport=transport; self.tls=transport.get_extra_info("ssl_object")
        wire.require(self.tls is not None and self.tls.version()=="TLSv1.3")
        self.original=self.tls.getpeercert(binary_form=True)
        wire.require(type(self.original) is bytes and 0<len(self.original)<=16*1024)
        self.check()
    def check(self):
        wire.require(os.getpid()==_PID and not self.transport.is_closing()
            and self.transport.get_extra_info("ssl_object") is self.tls
            and self.tls.version()=="TLSv1.3" and self.tls.getpeercert(binary_form=True)==self.original)


def peer_from_transport(transport):
    # Called only by the actual protocol owner, not from HTTP certificate fields.
    if not selected() or transport.get_extra_info("ssl_object") is None: return None
    tls=transport.get_extra_info("ssl_object")
    return None if not tls.getpeercert(binary_form=True) else _Peer(transport)


class _Request:
    def __init__(self,raw,peer):
        wire.require(selected() and type(peer) is _Peer); peer.check()
        self.owner,self.peer,self.raw=_owner,peer,bytes(raw)
        now=self.owner.check(); self.started=time.monotonic_ns()
        value=wire.envelope(self.raw); self.statement=value["statement"]
        candidates=[item for item in self.owner.policy["assignments"] if wire.sha256(wire.canonical(item))==self.statement["assignmentSha256"]]
        wire.require(len(candidates)==1); self.assignment=candidates[0]
        wire.verify(self.raw,self.owner.policy,self.assignment,peer.original,now)
        self.expires=self.statement["expiresAtEpochNs"]
        self.deadline=min(self.owner.deadline,self.started+min(30_000_000_000,self.expires-now))
        self.check()
    def check(self):
        now=self.owner.check(); self.peer.check()
        wire.require(self.started<=time.monotonic_ns()<self.deadline and self.statement["issuedAtEpochNs"]<=now<self.expires)
    def remaining_ms(self):
        self.check(); return max(1,(self.deadline-time.monotonic_ns())//1_000_000)
    def validate_events(self,raw):
        from serverware.app import DataPlaneAuditBatch, _validate_data_plane_audit_batch
        value=wire.event_document(raw)
        batch=DataPlaneAuditBatch.model_validate(value)
        _validate_data_plane_audit_batch(batch)
        return [item.model_dump(by_alias=True) for item in batch.events]


async def intake(request):
    from serverware import data_plane_audit_store
    wire.require(selected() and not request.scope.get("query_string") and request.headers.get("content-type")=="application/json")
    raw=bytearray()
    async for block in request.stream():
        wire.require(len(raw)+len(block)<=wire.MAX_ENVELOPE); raw.extend(block)
    owner=_Request(bytes(raw),request.scope.get("serverware.measured_audit_peer"))
    return data_plane_audit_store.transact(owner)
