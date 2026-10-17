"""Additive v2 initial-provisioning DDL; never upgrade an existing namespace."""

DDL = r"""
ALTER TABLE catchplate_rbac_witness.records
 ADD COLUMN recovery_original text CHECK (pg_catalog.octet_length(recovery_original)<=16384),
 ADD COLUMN recovery_sha256 text UNIQUE,
 ADD COLUMN recovery_id text UNIQUE,
 ADD CHECK ((recovery_original IS NULL)=(recovery_sha256 IS NULL)
   AND (recovery_original IS NULL)=(recovery_id IS NULL)
   AND (recovery_original IS NULL OR completion_original IS NOT NULL));

CREATE FUNCTION catchplate_rbac_witness.recovery_head(p_enrollment text)
RETURNS TABLE(enrollment_original text,head_original text,head_sha256 text,pending_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
BEGIN
 IF session_user<>'catchplate_rbac_witness_writer' THEN RAISE EXCEPTION 'RBAC recovery role'; END IF;
 RETURN QUERY SELECT e.enrollment_original,e.head_original,e.head_sha256,e.pending_sha256
 FROM catchplate_rbac_witness.enrollments e WHERE e.enrollment_sha256=p_enrollment FOR UPDATE;
END $body$;

CREATE FUNCTION catchplate_rbac_witness.recover_complete(p_enrollment text,p_intent text,p_authorization text,p_original text,p_head text)
RETURNS TABLE(completion_original text,completion_sha256 text,recovery_original text,recovery_sha256 text,recovery_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE e catchplate_rbac_witness.enrollments%ROWTYPE; r catchplate_rbac_witness.records%ROWTYPE;
 a jsonb; g jsonb; c jsonb; original_intent jsonb; h text; hh text; ah text;
BEGIN
 IF session_user<>'catchplate_rbac_witness_writer'
   OR (pg_catalog.octet_length(p_authorization) BETWEEN 1 AND 16384) IS NOT TRUE
   OR (pg_catalog.octet_length(p_original) BETWEEN 1 AND 8388608) IS NOT TRUE
   OR (pg_catalog.octet_length(p_head) BETWEEN 1 AND 16384) IS NOT TRUE THEN RAISE EXCEPTION 'RBAC recovery originals'; END IF;
 SELECT * INTO STRICT e FROM catchplate_rbac_witness.enrollments WHERE enrollment_sha256=p_enrollment FOR UPDATE;
 SELECT * INTO STRICT r FROM catchplate_rbac_witness.records WHERE intent_sha256=p_intent AND enrollment_sha256=p_enrollment FOR UPDATE;
 a:=p_authorization::jsonb; g:=a->'payload'; c:=p_original::jsonb; original_intent:=r.intent_original::jsonb;
 h:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_original,'UTF8')),'hex');
 hh:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_head,'UTF8')),'hex');
 ah:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_authorization,'UTF8')),'hex');
 -- Signature/current-role admission is performed by the genuinely launched
 -- verifier; this fixed procedure independently closes the durable CAS scope.
 IF e.enrollment_original::jsonb->'payload'->>'schema' IS DISTINCT FROM 'catchplate.rbacWitnessEnrollment/v2'
   OR a->>'schema' IS DISTINCT FROM 'catchplate.signedRbacWitnessRecoveryAuthorization/v1'
   OR g->>'schema' IS DISTINCT FROM 'catchplate.rbacWitnessRecoveryAuthorization/v1'
   OR g->>'purpose' IS DISTINCT FROM 'complete-known-commit'
   OR (g->>'recoveryId' ~ '^sha256:[0-9a-f]{64}$') IS NOT TRUE
   OR g->>'databaseId' IS DISTINCT FROM e.database_id
   OR g->>'deploymentId' IS DISTINCT FROM e.enrollment_original::jsonb->'payload'->>'deploymentId'
   OR g->>'enrollmentSha256' IS DISTINCT FROM p_enrollment OR g->>'intentSha256' IS DISTINCT FROM p_intent
   OR g->>'requestSha256' IS DISTINCT FROM r.request_sha256
   OR g->>'capabilityId' IS DISTINCT FROM original_intent->>'capabilityId'
   OR g->>'planSha256' IS DISTINCT FROM original_intent->>'planSha256'
   OR g->>'beforeHeadSha256' IS DISTINCT FROM original_intent->>'beforeHeadSha256'
   OR g->>'afterHeadSha256' IS DISTINCT FROM hh OR p_head::jsonb IS DISTINCT FROM original_intent->'afterHead'
   OR ((g->>'issuedAtEpochNs')::numeric <= EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000000000
       AND EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000000000 < (g->>'expiresAtEpochNs')::numeric
       AND (g->>'expiresAtEpochNs')::numeric-(g->>'issuedAtEpochNs')::numeric BETWEEN 1 AND 300000000000) IS NOT TRUE
   OR (SELECT pg_catalog.array_agg(k ORDER BY k) FROM pg_catalog.jsonb_object_keys(c) k) IS DISTINCT FROM
     ARRAY['enrollmentSha256','intentSha256','requestSha256','resultBase64Url','resultSha256','schema','writerReceipt','writerReceiptSha256']::text[]
   OR c->>'schema' IS DISTINCT FROM 'catchplate.rbacWitnessCompletion/v1'
   OR c->>'enrollmentSha256' IS DISTINCT FROM p_enrollment OR c->>'intentSha256' IS DISTINCT FROM p_intent
   OR c->>'requestSha256' IS DISTINCT FROM r.request_sha256
   OR c->>'writerReceiptSha256' IS DISTINCT FROM g->>'writerReceiptSha256'
   OR c->>'resultSha256' IS DISTINCT FROM g->>'resultSha256'
 THEN RAISE EXCEPTION 'RBAC recovery scope or current permission differs'; END IF;
 IF r.completion_original IS NOT NULL THEN
   IF r.completion_original IS DISTINCT FROM p_original OR r.completion_sha256 IS DISTINCT FROM h
      OR e.head_sha256 IS DISTINCT FROM hh OR e.pending_sha256 IS NOT NULL
   THEN RAISE EXCEPTION 'RBAC recovery terminal original differs'; END IF;
   RETURN QUERY SELECT r.completion_original,r.completion_sha256,r.recovery_original,r.recovery_sha256,r.recovery_id; RETURN;
 END IF;
 IF e.pending_sha256 IS DISTINCT FROM p_intent OR e.head_sha256 IS DISTINCT FROM original_intent->>'beforeHeadSha256'
   OR r.recovery_original IS NOT NULL THEN RAISE EXCEPTION 'RBAC recovery pending predecessor differs'; END IF;
 UPDATE catchplate_rbac_witness.records SET completion_original=p_original,completion_sha256=h,
   recovery_original=p_authorization,recovery_sha256=ah,recovery_id=g->>'recoveryId' WHERE intent_sha256=p_intent;
 UPDATE catchplate_rbac_witness.enrollments SET head_original=p_head,head_sha256=hh,pending_sha256=NULL
 WHERE enrollment_sha256=p_enrollment;
 SELECT * INTO STRICT r FROM catchplate_rbac_witness.records WHERE intent_sha256=p_intent;
 RETURN QUERY SELECT r.completion_original,r.completion_sha256,r.recovery_original,r.recovery_sha256,r.recovery_id;
END $body$;
ALTER FUNCTION catchplate_rbac_witness.recovery_head(text) OWNER TO catchplate_rbac_witness_owner;
ALTER FUNCTION catchplate_rbac_witness.recover_complete(text,text,text,text,text) OWNER TO catchplate_rbac_witness_owner;
REVOKE ALL ON FUNCTION catchplate_rbac_witness.recovery_head(text),catchplate_rbac_witness.recover_complete(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION catchplate_rbac_witness.recovery_head(text),catchplate_rbac_witness.recover_complete(text,text,text,text,text)
 TO catchplate_rbac_witness_writer;
"""
