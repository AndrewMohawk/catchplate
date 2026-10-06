"""Final challenge, distinct hardware reviewer, audit-gated native Setup CAS."""
import hashlib
import time
from dataclasses import dataclass
from datetime import datetime,timezone
from types import MappingProxyType
from serverware import authority_setup_native_final as p
from serverware import authority_transition_setup_native_hardware as source
from serverware import authority_transition_core as core,authority_transition_quota as q
from serverware import authority_transition_webauthn as assertion
from serverware import authority_setup_bind_credential as binding
from serverware import authority_transition_setup_bind_credential as binding_kernel


def _static_history(context,session,continuation):
    """Use the complete authenticated population, never a truncated SQL page."""
    population=context.present_rows("setup_session_events")
    maximum=binding_kernel._maximum(context.setup_bind_credential_maximum_events)
    p.require(len(population)<maximum,"Static final settlement event capacity is exhausted")
    events=[item["row"] for item in population if item["row"]["session_id"]==session["id"]]
    p.require(type(session["revision"]) is int and 1<=session["revision"]<2**63-1
        and len(events)==session["revision"]+1,
        "Static final settlement requires the exact retained revision history")
    events.sort(key=lambda event:event["sequence"])
    phase,stamp=None,None
    for sequence,event in enumerate(events,1):
        p.require(set(event)==binding.EVENT_FIELDS and type(event["sequence"]) is int
            and event["sequence"]==sequence and event["audit_status"]=="audited"
            and event["audited_at"] is not None and event["audit_event_hash"] is not None
            and all(event[name] is None for name in ("audit_claim_id","audit_claimed_at","audit_last_error")))
        binding.identifier(event["id"]);binding.digest(event["audit_event_hash"])
        current=binding.epoch(event["created_at"])
        p.require((stamp is None or stamp<=current) and current<=binding.epoch(event["audited_at"])
            <=q._database_epoch_ns(context.database_now))
        document=p.original(event["event_json"],binding.MAX_EVENT_BYTES)
        p.require(set(document)=={"version","setup_session_id","transition","from_phase","to_phase","binding_updates","evidence_digests","details"}
            and document["version"]=="serverware.setupTransition/v1" and document["setup_session_id"]==session["id"]
            and document["transition"]==event["transition"] and document["from_phase"]==phase
            and event["payload_digest"]==p.sha256(event["event_json"].encode("ascii")))
        if sequence==1:
            p.require(event["transition"]=="create" and document["to_phase"]=="created"
                and event["created_at"]==session["created_at"])
        phase,stamp=document["to_phase"],current
    retained=p.original(continuation["request_original"],p.enrollment.candidate.MAX_ARGUMENT_BYTES)["request"]
    final=events[-1];document=p.original(final["event_json"],binding.MAX_EVENT_BYTES)
    p.require(final["id"]==retained["credentialBindingEventId"] and final["transition"]=="bind_credential"
        and final["created_at"]==session["updated_at"] and phase==session["phase"]=="credential_activated"
        and document["details"]["authorityOperation"]==binding.OPERATION
        and document["details"]["setupPostSha256"]==p.sha256(p.enrollment.setup.row_original(session)))
    return len(events)+1


@dataclass(frozen=True,slots=True)
class Kernel:
    operation:str
    permits_empty_mutation:bool=False

    @property
    def handler(self):return "serverware_policy_authority_"+self.operation.replace(".","_").replace("-","_")
    @property
    def program_id(self):return core.transition_program_id(self.operation,self.handler)

    def queries(self,*,arguments,database_now,request_digest):
        p.require(self.operation==p.SETTLE); return self._queries(arguments,request_digest,None)

    def queries_with_evidence(self,*,arguments,database_now,request_digest,evidence):
        p.require(self.operation in p.ASSERTION_OPERATIONS); return self._queries(arguments,request_digest,evidence)

    def _queries(self,arguments,request_digest,evidence):
        v=p.arguments(self.operation,arguments,typed=True); old,prior=p.source(v["hardware_original"]); sid=old["session_id"]
        queries=source.source_queries(self.operation,prior,request_digest)
        exact=lambda name,table,key:q._query(operation=self.operation,name=name,table=table,key=key)
        queries.extend((exact("final",p.TABLE,{"session_id":sid}),
            exact("hardware_audit","metadata_audit_outbox",{"id":q._audit_identity(p.hardware.COMPLETE,old["complete_request_digest"])})))
        if self.operation!=p.PREPARE:queries.append(q._role_query(self.operation,"reviewer",v["actor_id"]))
        if self.operation!=p.PREPARE:
            queries.append(exact("prepare_audit","metadata_audit_outbox",{"id":core.SelectedRowFieldReference(p.TABLE,{"session_id":sid},"prepare_audit_id")}))
        if self.operation==p.SETTLE:
            event_id=core.deterministic_uuid(operation=self.operation,request_digest=request_digest,purpose="native-setup-final-event")
            queries.append(exact("final_setup_event","setup_session_events",{"id":event_id}))
            if p.static_continuation(v) is not None:
                queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation,"complete_population","setup_session_events"),
                    table="setup_session_events",predicates=(),order_by=(core.QueryOrder("id"),),
                    maximum_rows=binding.MAX_EVENTS+1,page_size=binding.MAX_EVENTS,
                    proof_primitive="bounded-limit-plus-one",work_units=binding.MAX_EVENTS+1))
            else:
                queries.append(core.BoundedQuery(query_id=core.query_program_id(self.operation,"setup_events","setup_session_events"),
                    table="setup_session_events",predicates=(core.QueryPredicate("session_id","eq",sid),),order_by=(core.QueryOrder("sequence"),),
                    maximum_rows=5,proof_primitive="bounded-limit-plus-one",work_units=5,page_size=4))
            queries.extend((exact("complete_audit","metadata_audit_outbox",{"id":core.SelectedRowFieldReference(p.TABLE,{"session_id":sid},"complete_audit_id")}),
                exact("review_key","webauthn_credentials",{"id":core.SelectedRowFieldReference(p.TABLE,{"session_id":sid},"reviewer_credential_id")})))
        if evidence is not None:
            for name,table,field in (("request_key","webauthn_credentials","credentialRecordId"),("challenge","webauthn_challenges","challengeId")):
                p.enrollment.setup.text(evidence.get(field),1024); queries.append(exact(name,table,{"id":evidence[field]}))
        queries.extend(assertion._trust_queries(self.operation,work=None)); return tuple(queries)

    def transition(self,context):
        v=p.arguments(self.operation,context.arguments,typed=True); old,prior=p.source(v["hardware_original"])
        sid,now,scope,before,grant,intent=source.current_sources(context,prior)
        row=lambda table,key:source.prior._row(context,table,key)
        p.require(p.hardware.row_original(row(p.hardware.TABLE,{"session_id":sid})).decode("ascii")==v["hardware_original"])
        source.prior._completed_audit(context,q._audit_identity(p.hardware.COMPLETE,old["complete_request_digest"]),
            p.hardware.COMPLETE,old["complete_request_digest"],session=sid)
        selection=context.exact(p.TABLE,{"session_id":sid}); stamp=context.database_now.astimezone(timezone.utc).isoformat(); mutations=[]
        if self.operation in p.ASSERTION_OPERATIONS:
            evidence=context.verified_webauthn_evidence; p.require(evidence is not None)
            key=row("webauthn_credentials",{"id":evidence["credentialRecordId"]})
            source.hardware._hardware(key,v["credential_policy"])
            mutations.extend(assertion._assertion_mutations(context,{"actor_id":v["actor_id"]}))
        if self.operation==p.PREPARE:
            p.require(not selection["present"] and v["actor_id"]==old["owner_id"])
            challenge=row("webauthn_challenges",{"id":evidence["challengeId"]})
            nonce=hashlib.sha256(b"serverware/setup-native-final-challenge/v1\0"+p.enrollment.original(challenge["challenge"],64)
                +bytes.fromhex(context.request_digest[7:])).digest()
            hardware_attempt=p.hardware.prepared(old["attempt_original"])
            expires=min(now+v["maximum_final_nanos"],hardware_attempt["expiresAtEpochNs"],before["expiresAtEpochNs"],intent["expiresAtEpochNs"],grant["expiresAtEpochNs"],
                *(p.hardware.receipt(old[field],role)["payload"]["expiresAtEpochNs"] for field,role in
                    (("hardware_receipt_original",p.hardware.ROLES[0]),("proxy_receipt_original",p.hardware.ROLES[1]))))
            c={"apiVersion":p.CHALLENGE,"challengeId":core.deterministic_uuid(operation=self.operation,request_digest=context.request_digest,purpose="native-final"),
                "sessionId":sid,"ownerId":old["owner_id"],"hardwareSha256":p.sha256(v["hardware_original"].encode("ascii")),"policyHash":intent["policyHash"],
                "configurationSha256":v["control_plane_configuration_digest"],"nonce":p.enrollment.encoded(nonce),"issuedAtEpochNs":now,
                "expiresAtEpochNs":expires,"resultScope":p.SCOPE,"hostAssociationTrust":"trusted-host-local"}
            text=p.canonical(c).decode("ascii");p.challenge(text)
            record={"session_id":sid,"revision":0,"phase":"final_outcome_unknown","owner_id":old["owner_id"],"reviewer_id":None,"reviewer_credential_id":None,"review_trust_original":None,
                "hardware_original":v["hardware_original"],"challenge_original":text,"challenge_sha256":p.sha256(text.encode("ascii")),"receipt_original":None,
                "prepare_request_digest":context.request_digest,"prepare_audit_id":q._audit_identity(self.operation,context.request_digest),
                "complete_request_digest":None,"complete_audit_id":None,"settle_request_digest":None,"configuration_digest":v["control_plane_configuration_digest"],
                "created_at":stamp,"completed_at":None,"settled_at":None}
        else:
            record=q._row(selection,"retained native final challenge");p.row_original(record)
            p.require(record["hardware_original"]==v["hardware_original"] and record["challenge_original"]==v["challenge_original"])
            c=p.challenge(record["challenge_original"]);p.require(c["issuedAtEpochNs"]<=now<c["expiresAtEpochNs"])
            source.prior._completed_audit(context,record["prepare_audit_id"],p.PREPARE,record["prepare_request_digest"],session=sid)
            p.require(v["actor_id"]!=record["owner_id"])
            q._require_role(context,subject_id=v["actor_id"],required_role="attestation_reviewer")
            if self.operation==p.COMPLETE:
                p.require(record["revision"]==0)
                record={**record,"revision":1,"phase":"native_completion_pending_audit","reviewer_id":v["actor_id"],"reviewer_credential_id":evidence["credentialRecordId"],
                    "review_trust_original":p.canonical({name:evidence[name] for name in ("trustHighWaterDigest","metadataPublicationSequence","credentialPolicyDigest")}).decode("ascii"),
                    "receipt_original":v["receipt_original"],"complete_request_digest":context.request_digest,
                    "complete_audit_id":q._audit_identity(self.operation,context.request_digest),"completed_at":stamp}
            else:
                p.require(record["revision"]==1 and record["reviewer_id"]==v["actor_id"] and record["receipt_original"]==v["receipt_original"])
                key=row("webauthn_credentials",{"id":record["reviewer_credential_id"]})
                p.require(key["user_id"]==record["reviewer_id"])
                source.hardware._hardware(key,v["credential_policy"])
                assertion._assertion_trust(context,key,p.original(record["review_trust_original"],4096),work=None)
                source.prior._completed_audit(context,record["complete_audit_id"],p.COMPLETE,record["complete_request_digest"],session=sid)
                selected=context.exact("setup_sessions",{"id":sid});session=q._row(selected,"original Setup")
                continuation=row(p.enrollment.candidate.TABLE,{"session_id":sid})
                retained=p.original(continuation["request_original"],p.enrollment.candidate.MAX_ARGUMENT_BYTES)
                if set(retained["request"])==p.enrollment.candidate.STATIC_REQUEST_FIELDS:
                    p.require(p.static_continuation(v)==continuation
                        and p.enrollment.candidate.row_original(continuation).decode("ascii")==v["continuation_original"])
                    next_sequence=_static_history(context,session,continuation)
                else:
                    p.require(p.static_continuation(v) is None and session["revision"]==3)
                    events=context.present_rows("setup_session_events")
                    p.require(len(events)==4 and {event["row"]["sequence"] for event in events}=={1,2,3,4}
                        and all(event["row"]["session_id"]==sid and event["row"]["audit_status"]=="audited" for event in events))
                    next_sequence=5
                # No legacy receipt columns are populated with native receipts.
                session={**session,"revision":session["revision"]+1,"phase":"native_scoped_complete","status":"complete","updated_at":stamp,"terminal_at":stamp}
                mutations.append(core.mutation(operation=self.operation,selected=selected,row=session))
                event_id=core.deterministic_uuid(operation=self.operation,request_digest=context.request_digest,purpose="native-setup-final-event")
                event_selected=context.exact("setup_session_events",{"id":event_id});p.require(not event_selected["present"])
                document={"version":"serverware.setupTransition/v1","setup_session_id":sid,"transition":"native_scoped_complete",
                    "from_phase":"credential_activated","to_phase":"native_scoped_complete","binding_updates":{},
                    "evidence_digests":[p.sha256(record["receipt_original"].encode("ascii"))],"details":{
                        "authorityOperation":self.operation,"authorityRequestDigest":context.request_digest,
                        "setupPostSha256":p.sha256(p.enrollment.setup.row_original(session)),"nativeFinalChallengeSha256":record["challenge_sha256"],
                        "resultScope":p.SCOPE,"hostAssociationTrust":"trusted-host-local","measuredHost":False,"proxyReady":False}}
                original=p.canonical(document);p.require(len(original)<=p.enrollment.setup.MAX_EVENT_BYTES)
                event={"id":event_id,"session_id":sid,"sequence":next_sequence,"transition":"native_scoped_complete","actor_id":v["actor_id"],
                    "payload_digest":p.sha256(original),"event_json":original.decode("ascii"),"created_at":stamp,"audit_status":"pending",
                    "audit_claim_id":None,"audit_claimed_at":None,"audit_attempts":0,"audited_at":None,"audit_event_hash":None,"audit_last_error":None}
                mutations.append(core.mutation(operation=self.operation,selected=event_selected,row=event))
                record={**record,"revision":2,"phase":"native_scoped_complete","settle_request_digest":context.request_digest,"settled_at":stamp}
        raw=p.row_original(record);mutations.append(core.mutation(operation=self.operation,selected=selection,row=record))
        audits,digest,replay=q._audit_mutations(context,event_type=self.operation,actor_type="admin",actor_id=v["actor_id"],
            event={"schema":"serverware.setupNativeFinalAudit/v1","sessionId":sid,"requestDigest":context.request_digest,"challengeSha256":record["challenge_sha256"]})
        p.require(not replay)
        return core.KernelTransition(mutations=tuple(mutations)+audits,result={"ok":True,"operation":self.operation,"requestDigest":context.request_digest,
            "auditEventDigest":digest,"idempotentReplay":False,"finalOriginal":raw.decode("ascii")},work_units=4096)


def verify_static_settle_plan(*,payload,arguments,maximum_events,deadline_ns,now_epoch_ns,work):
    """Replay the literal authenticated proposal, not a new DB/time observation."""
    from serverware import authority_audit_capacity as capacity
    from serverware import authority_challenge_retention as retention
    from serverware.authority_query_read_work import _ValidationWork
    from serverware.authority_query_reads import _CopyBudget

    p.require(type(work) is _ValidationWork and type(payload) is dict and type(arguments) is dict)
    maximum=binding_kernel._maximum(maximum_events)
    core.require_integer(deadline_ns,"original static settlement deadline",minimum=1,maximum=2**63-1)
    core.require_integer(now_epoch_ns,"current static settlement verifier time",minimum=1,maximum=2**63-1)
    expires=None
    def check():
        current=time.time_ns()
        p.require(time.monotonic_ns()<deadline_ns and now_epoch_ns<=current
            and (expires is None or current<expires))
    def equal(left,right):
        work.prepare_encoding(left);work.prepare_encoding(right)
        p.require(p.canonical(left)==p.canonical(right),"Static final settlement differs from its original source effects")
    check()
    owned=_CopyBudget(work).copy({"payload":payload,"arguments":arguments})
    plan=owned["payload"];values=p.arguments(p.SETTLE,owned["arguments"],typed="businessIntent" in owned["arguments"])
    continuation=p.static_continuation(values);p.require(continuation is not None)
    before=p.original(continuation["setup_original"],p.enrollment.setup.MAX_ROW_BYTES)
    typed,measured,projection=plan["typedRequest"],plan["measuredPlan"],plan["authorizationProjection"]
    p.require(typed["operation"]==measured["operation"]==p.SETTLE and plan["webauthnEvidence"] is None)
    equal(p.arguments(p.SETTLE,typed["arguments"],typed=True),values)
    request_digest=p.request_digest(p.SETTLE,values)
    p.require(typed["requestDigest"]==measured["requestDigest"]==request_digest and measured["deadlineMonotonicNs"]==deadline_ns)
    expires=measured["deadlineEpochNs"];core.require_integer(expires,"signed static settlement expiry",minimum=1,maximum=2**63-1)
    selected,mutations=plan["selectedBusinessRows"],plan["mutationPlan"]
    work.prepare_scan(mutations)
    updates=[item for item in mutations if item["table"]=="setup_sessions"]
    p.require(len(updates)==1 and updates[0]["key"]=={"id":before["id"]}
        and updates[0]["operation"]=="UPDATE" and type(updates[0]["row"]) is dict)
    proposed=updates[0]["row"];p.enrollment.setup.row_original(proposed)
    stamp=proposed["updated_at"];cutoff=p.enrollment.setup.epoch(stamp)
    challenge=p.challenge(values["challenge_original"])
    p.require(challenge["issuedAtEpochNs"]<=projection["createdAtEpochNs"]<=cutoff<=now_epoch_ns
        and now_epoch_ns<expires==projection["expiresAtEpochNs"]<=challenge["expiresAtEpochNs"])
    check()
    roots=plan["rootTransition"]
    binding_kernel.require_complete_populations(selected_rows=selected,
        before_roots=tuple(roots["businessBeforeRoots"])+tuple(roots["authorizationBeforeRoots"]),
        work=work,deadline_ns=deadline_ns,maximum_events=maximum)
    context=core.KernelContext(p.SETTLE,typed["arguments"],tuple(selected),datetime.fromisoformat(stamp),request_digest,
        setup_bind_credential_maximum_events=maximum)
    kernel=Kernel(p.SETTLE);transition=kernel.transition(context)
    expanded=retention.expand_mutations(context,transition.mutations,work=work)
    expected=capacity._finalize_capacity(context,expanded,work=work)
    expected=sorted(expected,key=lambda item:(item["table"],item["keyDigest"],item["operation"]))
    equal(mutations,expected);equal(plan["expectedResult"],transition.result)
    queries=capacity.add_capacity_query(p.SETTLE,kernel.queries(arguments=typed["arguments"],
        database_now=context.database_now,request_digest=request_digest))
    p.require(measured["workUnits"]==capacity.transition_work_units(operation=p.SETTLE,
        query_work_units=sum(query.work_units for query in queries),kernel_work_units=transition.work_units,mutations=tuple(expected)))
    check()


KERNELS=MappingProxyType({op:Kernel(op) for op in p.OPERATIONS})
