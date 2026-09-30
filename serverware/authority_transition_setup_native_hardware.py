"""Real protected reservation and consume CAS over original native evidence."""
import hashlib
from dataclasses import dataclass
from datetime import timezone
from types import MappingProxyType
from serverware import authority_setup_native_hardware as p
from serverware import authority_transition_core as core, authority_transition_quota as q
from serverware import authority_transition_setup_native_enrollment as issued
from serverware import authority_transition_setup_native_canary as prior
from serverware import authority_transition_credential_currentness as currentness
from serverware import authority_transition_webauthn as assertion
from serverware import authority_transition_oauth_activation as hardware


@dataclass(frozen=True,slots=True)
class Kernel:
    operation:str
    permits_empty_mutation:bool=False

    @property
    def handler(self): return "serverware_policy_authority_"+self.operation.replace(".","_").replace("-","_")
    @property
    def program_id(self): return core.transition_program_id(self.operation,self.handler)

    def queries(self,*,arguments,database_now,request_digest):
        p.require(self.operation==p.COMPLETE); return self._queries(arguments,request_digest,None)

    def queries_with_evidence(self,*,arguments,database_now,request_digest,evidence):
        p.require(self.operation==p.PREPARE); return self._queries(arguments,request_digest,evidence)

    def _queries(self,arguments,request_digest,evidence):
        v=p.arguments(self.operation,arguments,typed=True); a=p.runtime.association(v["association_original"])
        sid,cid=a["session_id"],a["canary_id"]
        enrolled=p.original(v["enrollment_original"],p.enrollment.MAX_ROW_BYTES); i=p.enrollment.intent(enrolled["intent_original"])
        exact=lambda name,table,key:q._query(operation=self.operation,name=name,table=table,key=key)
        query=[exact("slot",p.TABLE,{"session_id":sid}),exact("association",p.runtime.canary.TABLE,{"session_id":sid}),
            exact("setup","setup_sessions",{"id":sid}),exact("continuation",p.enrollment.candidate.TABLE,{"session_id":sid}),
            exact("enrollment",p.enrollment.TABLE,{"session_id":sid}),exact("installation",p.ca.TABLE,{"session_id":sid}),
            exact("runtime",p.runtime.TABLE,{"session_id":sid}),exact("credential","credentials",{"id":i["credentialId"]}),
            exact("generation","credential_generations",{"credential_id":i["credentialId"]}),
            currentness.root_query(self.operation,i["credentialId"],i["credentialVersion"]),
            exact("high","policy_high_water",{"scope":"active"}),exact("publication","policy_publications",{"policy_hash":a["policy_hash"]}),
            exact("artifact","policy_candidate_artifacts",{"artifact_envelope_digest":core.SelectedRowFieldReference(
                p.enrollment.candidate.TABLE,{"session_id":sid},"artifact_envelope_digest")}),
            exact("association_audit","metadata_audit_outbox",{"id":q._audit_identity(p.runtime.canary.RECORD,a["request_digest"])}),
            q._role_query(self.operation,"owner",v["actor_id"]),q._audit_query(self.operation,request_digest)]
        for codec,name in ((p.runtime,"runtime_original"),(p.enrollment,"enrollment_original"),(p.ca,"installation_original")):
            row=p.original(v[name],p.MAX_ROW_BYTES)
            query.append(exact(name+"_audit","metadata_audit_outbox",{"id":q._audit_identity(codec.COMPLETE,row["complete_request_digest"])}))
        for table in (p.runtime.canary.activation.PREPARATION_TABLE,p.runtime.canary.activation.READY_TABLE,p.runtime.canary.activation.HEAD_TABLE,
                "policy_canary_heads","policy_canary_assignments"):
            query.append(exact(table,table,{"canary_id":cid}))
        query.append(core.BoundedQuery(query_id=core.query_program_id(self.operation,"finalizations",p.runtime.canary.activation.FINALIZATION_TABLE),
            table=p.runtime.canary.activation.FINALIZATION_TABLE,predicates=(core.QueryPredicate("policy_hash","eq",a["policy_hash"]),),
            order_by=(core.QueryOrder("canary_id"),),maximum_rows=2,proof_primitive="bounded-limit-plus-one",work_units=2))
        if evidence is not None:
            for name,table,field in (("request_key","webauthn_credentials","credentialRecordId"),("challenge","webauthn_challenges","challengeId")):
                p.enrollment.setup.text(evidence.get(field),1024); query.append(exact(name,table,{"id":evidence[field]}))
            query.extend(assertion._trust_queries(self.operation,work=None))
        else:
            query.append(exact("prepare_audit","metadata_audit_outbox",{"id":core.SelectedRowFieldReference(p.TABLE,{"session_id":sid},"prepare_audit_id")}))
        return tuple(query)

    def transition(self,context):
        v=p.arguments(self.operation,context.arguments,typed=True); a=p.runtime.association(v["association_original"])
        sid,now=a["session_id"],q._database_epoch_ns(context.database_now)
        row=lambda table,key:prior._row(context,table,key)
        p.require(p.runtime.canary.row_original(row(p.runtime.canary.TABLE,{"session_id":sid})).decode("ascii")==v["association_original"])
        audit,_=prior._completed_audit(context,q._audit_identity(p.runtime.canary.RECORD,a["request_digest"]),p.runtime.canary.RECORD,a["request_digest"],session=sid)
        p.require(audit["event_digest"]==a["audit_event_digest"])
        for codec,name in ((p.runtime,"runtime_original"),(p.enrollment,"enrollment_original"),(p.ca,"installation_original")):
            actual=row(codec.TABLE,{"session_id":sid})
            p.require(codec.row_original(actual).decode("ascii")==v[name])
            prior._completed_audit(context,q._audit_identity(codec.COMPLETE,actual["complete_request_digest"]),codec.COMPLETE,actual["complete_request_digest"],session=sid)
        enrolled=row(p.enrollment.TABLE,{"session_id":sid}); i=p.enrollment.intent(enrolled["intent_original"])
        issued._current(context,v,i)
        view=prior._PublicationRows(context)
        p.require(len(view.matching(p.runtime.canary.activation.FINALIZATION_TABLE,policy_hash=a["policy_hash"]))==1)
        committed=prior.native.committed_policy(view,row("policy_high_water",{"scope":"active"}),row("policy_publications",{"policy_hash":a["policy_hash"]}))
        p.require(committed is not None and committed["finalization_digest"]==a["finalization_sha256"])
        runtime=row(p.runtime.TABLE,{"session_id":sid}); before=p.runtime.prepared(runtime["attempt_original"])
        installation=row(p.ca.TABLE,{"session_id":sid})
        grant=p.enrollment.setup.document(p.enrollment.original(installation["installation_original"],p.ca.installation.MAX_BYTES),p.ca.installation.MAX_BYTES)["payload"]
        scope=p.original(v["scope_original"],32768)
        p.require(runtime["scope_original"]==v["scope_original"] and before["issuedAtEpochNs"]<=now<before["expiresAtEpochNs"])
        selected=context.exact(p.TABLE,{"session_id":sid}); stamp=context.database_now.astimezone(timezone.utc).isoformat(); mutations=[]
        inputs=p.canonical({name:v[name] for name in p.INPUT_FIELDS}).decode("ascii")
        if self.operation==p.PREPARE:
            p.require(not selected["present"] and context.verified_webauthn_evidence is not None)
            evidence=context.verified_webauthn_evidence
            hardware._hardware(row("webauthn_credentials",{"id":evidence["credentialRecordId"]}),v["credential_policy"])
            challenge=row("webauthn_challenges",{"id":evidence["challengeId"]})
            mutations.extend(assertion._assertion_mutations(context,{"actor_id":v["actor_id"]}))
            nonce=hashlib.sha256(b"serverware/setup-native-hardware-challenge/v1\0"+
                p.enrollment.original(challenge["challenge"],64)+bytes.fromhex(context.request_digest[7:])).digest()
            attempt={"apiVersion":p.ATTEMPT,"attemptId":core.deterministic_uuid(operation=self.operation,request_digest=context.request_digest,
                purpose="native-setup-hardware"),"sessionId":sid,"ownerId":v["actor_id"],"nonce":p.enrollment.encoded(nonce),
                "policyHash":a["policy_hash"],"principalId":scope["principalId"],"routeId":scope["routeId"],"credentialId":scope["credentialId"],
                "credentialVersion":scope["credentialVersion"],"issuedAtEpochNs":now,"expiresAtEpochNs":min(now+v["maximum_attempt_nanos"],
                    before["expiresAtEpochNs"],i["expiresAtEpochNs"],grant["expiresAtEpochNs"],p.enrollment.setup.epoch(row("setup_sessions",{"id":sid})["expires_at"]))}
            for name,field in (("associationSha256","association_original"),("runtimeSha256","runtime_original"),("enrollmentSha256","enrollment_original"),
                    ("installationSha256","installation_original"),("scopeSha256","scope_original")):
                attempt[name]=p.sha256(v[field].encode("ascii"))
            text=p.canonical(attempt).decode("ascii"); p.prepared(text)
            record={"session_id":sid,"revision":0,"phase":"hardware_outcome_unknown","owner_id":v["actor_id"],"inputs_original":inputs,
                "attempt_original":text,"attempt_sha256":p.sha256(text.encode("ascii")),"prepare_request_digest":context.request_digest,
                "prepare_audit_id":q._audit_identity(self.operation,context.request_digest),"evidence_original":None,"hardware_receipt_original":None,
                "proxy_receipt_original":None,"result_original":None,"complete_request_digest":None,"configuration_digest":v["control_plane_configuration_digest"],
                "created_at":stamp,"completed_at":None}
        else:
            record=q._row(selected,"original native hardware reservation"); p.row_original(record)
            p.require(record["phase"]=="hardware_outcome_unknown" and record["inputs_original"]==inputs and record["attempt_original"]==v["attempt_original"])
            attempt=p.prepared(record["attempt_original"]); p.require(attempt["issuedAtEpochNs"]<=now<attempt["expiresAtEpochNs"])
            prior._completed_audit(context,record["prepare_audit_id"],p.PREPARE,record["prepare_request_digest"],session=sid)
            record={**record,"revision":1,"phase":"hardware_proxy_verified","evidence_original":v["evidence_original"],
                "hardware_receipt_original":v["hardware_receipt_original"],"proxy_receipt_original":v["proxy_receipt_original"],
                "result_original":p.canonical(p.projection(v["attempt_original"],v["evidence_original"],v["hardware_receipt_original"],v["proxy_receipt_original"])).decode("ascii"),
                "complete_request_digest":context.request_digest,"completed_at":stamp}
        raw=p.row_original(record); mutations.append(core.mutation(operation=self.operation,selected=selected,row=record))
        audits,digest,replay=q._audit_mutations(context,event_type=self.operation,actor_type="admin",actor_id=v["actor_id"],
            event={"schema":"serverware.setupNativeHardwareAudit/v1","sessionId":sid,"requestDigest":context.request_digest,"attemptSha256":record["attempt_sha256"]})
        p.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations)+audits,result={"ok":True,"operation":self.operation,"requestDigest":context.request_digest,
            "auditEventDigest":digest,"idempotentReplay":False,"hardwareOriginal":raw.decode("ascii")},work_units=4096)


KERNELS=MappingProxyType({op:Kernel(op) for op in p.OPERATIONS})
