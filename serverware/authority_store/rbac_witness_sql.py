"""Fixed-purpose independent RBAC witness DDL; never runtime bootstrap.

An independent operator installs this on the separately enrolled PostgreSQL
cluster. Application roles receive only fixed EXECUTE privileges, not table
DML, schema ownership, arbitrary SQL, enrollment creation or reset.
"""

SCHEMA = "serverware_rbac_witness"
READER = "serverware_rbac_witness_reader"
WRITER = "serverware_rbac_witness_writer"
OWNER = "serverware_rbac_witness_owner"

DDL = r"""
DO $roles$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='serverware_rbac_witness_owner') THEN
    CREATE ROLE serverware_rbac_witness_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='serverware_rbac_witness_reader') THEN
    CREATE ROLE serverware_rbac_witness_reader LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname='serverware_rbac_witness_writer') THEN
    CREATE ROLE serverware_rbac_witness_writer LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
  END IF;
END $roles$;
DO $database$ BEGIN
 EXECUTE pg_catalog.format('REVOKE CREATE,TEMPORARY ON DATABASE %I FROM PUBLIC,serverware_rbac_witness_reader,serverware_rbac_witness_writer',pg_catalog.current_database());
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='public') THEN
   REVOKE CREATE ON SCHEMA public FROM PUBLIC,serverware_rbac_witness_reader,serverware_rbac_witness_writer;
 END IF;
END $database$;
CREATE SCHEMA IF NOT EXISTS serverware_rbac_witness AUTHORIZATION serverware_rbac_witness_owner;
REVOKE ALL ON SCHEMA serverware_rbac_witness FROM PUBLIC;
CREATE TABLE IF NOT EXISTS serverware_rbac_witness.enrollments (
  enrollment_sha256 text PRIMARY KEY,
  database_id text NOT NULL UNIQUE,
  enrollment_original text NOT NULL CHECK (pg_catalog.octet_length(enrollment_original)<=65536),
  head_original text NOT NULL CHECK (pg_catalog.octet_length(head_original)<=16384),
  head_sha256 text NOT NULL,
  pending_sha256 text,
  record_count bigint NOT NULL DEFAULT 0 CHECK (record_count>=0),
  maximum_records bigint NOT NULL CHECK (maximum_records BETWEEN 2 AND 4096)
);
CREATE TABLE IF NOT EXISTS serverware_rbac_witness.records (
  intent_sha256 text PRIMARY KEY,
  enrollment_sha256 text NOT NULL REFERENCES serverware_rbac_witness.enrollments(enrollment_sha256),
  request_sha256 text NOT NULL,
  intent_original text NOT NULL CHECK (pg_catalog.octet_length(intent_original)<=8388608),
  completion_original text CHECK (pg_catalog.octet_length(completion_original)<=8388608),
  completion_sha256 text,
  UNIQUE(enrollment_sha256,request_sha256),
  CHECK ((completion_original IS NULL)=(completion_sha256 IS NULL))
);
ALTER TABLE serverware_rbac_witness.enrollments OWNER TO serverware_rbac_witness_owner;
ALTER TABLE serverware_rbac_witness.records OWNER TO serverware_rbac_witness_owner;
REVOKE ALL ON ALL TABLES IN SCHEMA serverware_rbac_witness FROM PUBLIC,serverware_rbac_witness_reader,serverware_rbac_witness_writer;

CREATE OR REPLACE FUNCTION serverware_rbac_witness.identity()
RETURNS TABLE (cluster_id text, database_name text, role_name text, tls boolean, tls_version text, client_dn text, client_serial text, issuer_dn text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT (pg_catalog.pg_control_system()).system_identifier::text, pg_catalog.current_database()::text, session_user::text,
   ssl, version, client_dn, client_serial::text, issuer_dn
 FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()
$body$;

CREATE OR REPLACE FUNCTION serverware_rbac_witness.read_head(p_enrollment text)
RETURNS TABLE(enrollment_original text,head_original text,head_sha256 text,pending_sha256 text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT e.enrollment_original,e.head_original,e.head_sha256,e.pending_sha256
 FROM serverware_rbac_witness.enrollments e WHERE e.enrollment_sha256=p_enrollment
 FOR SHARE
$body$;

CREATE OR REPLACE FUNCTION serverware_rbac_witness.read_record(p_enrollment text,p_request text)
RETURNS TABLE(intent_sha256 text,intent_original text,completion_original text,completion_sha256 text)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $body$
 SELECT r.intent_sha256,r.intent_original,r.completion_original,r.completion_sha256
 FROM serverware_rbac_witness.records r
 WHERE r.enrollment_sha256=p_enrollment AND r.request_sha256=p_request
$body$;

CREATE OR REPLACE FUNCTION serverware_rbac_witness.reserve(p_enrollment text,p_original text)
RETURNS TABLE(intent_sha256 text,intent_original text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE e serverware_rbac_witness.enrollments%ROWTYPE; v jsonb; h text;
BEGIN
 IF session_user<>'serverware_rbac_witness_writer' OR (pg_catalog.octet_length(p_original) BETWEEN 1 AND 8388608) IS NOT TRUE THEN
   RAISE EXCEPTION 'RBAC witness reserve role or original bound';
 END IF;
 v:=p_original::jsonb;
 IF (SELECT pg_catalog.array_agg(k ORDER BY k) FROM pg_catalog.jsonb_object_keys(v) k) IS DISTINCT FROM
    ARRAY['afterHead','beforeHead','beforeHeadSha256','capabilityId','enrollmentSha256','expiresAtEpochNs','planSha256','requestSha256','schema']::text[]
    OR v->>'schema' IS DISTINCT FROM 'serverware.rbacWitnessIntent/v1'
    OR v->>'enrollmentSha256' IS DISTINCT FROM p_enrollment THEN RAISE EXCEPTION 'RBAC witness intent profile'; END IF;
 SELECT * INTO STRICT e FROM serverware_rbac_witness.enrollments WHERE enrollment_sha256=p_enrollment FOR UPDATE;
 IF e.pending_sha256 IS NOT NULL OR e.record_count>=e.maximum_records THEN
   RAISE EXCEPTION 'RBAC witness pending or exhausted';
 END IF;
 IF v->>'beforeHeadSha256' IS DISTINCT FROM e.head_sha256 OR v->'beforeHead' IS DISTINCT FROM e.head_original::jsonb
    OR (v->'afterHead'->>'sequence')::bigint IS DISTINCT FROM (e.head_original::jsonb->>'sequence')::bigint+1
    OR v->'afterHead'->>'previousHeadSha256' IS DISTINCT FROM e.head_sha256
    OR (v->'afterHead'->'state'->>'generation')::bigint IS DISTINCT FROM (e.head_original::jsonb->'state'->>'generation')::bigint+1
    OR v->'afterHead'->>'enrollmentSha256' IS DISTINCT FROM p_enrollment
    OR v->'afterHead'->>'schema' IS DISTINCT FROM 'serverware.rbacWitnessHead/v1'
    OR ((v->>'expiresAtEpochNs')::numeric <= (e.enrollment_original::jsonb->'payload'->>'expiresAtEpochNs')::numeric
        AND EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000000000 < (v->>'expiresAtEpochNs')::numeric) IS NOT TRUE THEN
   RAISE EXCEPTION 'RBAC witness predecessor or original deadline differs';
 END IF;
 h:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_original,'UTF8')),'hex');
 INSERT INTO serverware_rbac_witness.records(intent_sha256,enrollment_sha256,request_sha256,intent_original)
 VALUES(h,p_enrollment,v->>'requestSha256',p_original);
 UPDATE serverware_rbac_witness.enrollments SET pending_sha256=h,record_count=record_count+1 WHERE enrollment_sha256=p_enrollment;
 RETURN QUERY SELECT h,p_original;
END $body$;

CREATE OR REPLACE FUNCTION serverware_rbac_witness.complete(p_enrollment text,p_intent text,p_original text,p_head text)
RETURNS TABLE(completion_original text,completion_sha256 text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $body$
DECLARE e serverware_rbac_witness.enrollments%ROWTYPE; r serverware_rbac_witness.records%ROWTYPE; v jsonb; h text; hh text;
BEGIN
 IF session_user<>'serverware_rbac_witness_writer' OR (pg_catalog.octet_length(p_original) BETWEEN 1 AND 8388608) IS NOT TRUE
    OR (pg_catalog.octet_length(p_head) BETWEEN 1 AND 16384) IS NOT TRUE THEN RAISE EXCEPTION 'RBAC witness complete role or original bound'; END IF;
 v:=p_original::jsonb;
 SELECT * INTO STRICT e FROM serverware_rbac_witness.enrollments WHERE enrollment_sha256=p_enrollment FOR UPDATE;
 SELECT * INTO STRICT r FROM serverware_rbac_witness.records WHERE intent_sha256=p_intent AND enrollment_sha256=p_enrollment FOR UPDATE;
 IF (SELECT pg_catalog.array_agg(k ORDER BY k) FROM pg_catalog.jsonb_object_keys(v) k) IS DISTINCT FROM
    ARRAY['enrollmentSha256','intentSha256','requestSha256','resultBase64Url','resultSha256','schema','writerReceipt','writerReceiptSha256']::text[]
    OR v->>'schema' IS DISTINCT FROM 'serverware.rbacWitnessCompletion/v1' OR v->>'intentSha256' IS DISTINCT FROM p_intent
    OR v->>'enrollmentSha256' IS DISTINCT FROM p_enrollment OR v->>'requestSha256' IS DISTINCT FROM r.request_sha256
    OR p_head::jsonb IS DISTINCT FROM r.intent_original::jsonb->'afterHead' THEN RAISE EXCEPTION 'RBAC witness completion scope differs'; END IF;
 h:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_original,'UTF8')),'hex');
 hh:='sha256:'||pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p_head,'UTF8')),'hex');
 IF r.completion_original IS NOT NULL THEN
   IF r.completion_original IS DISTINCT FROM p_original OR r.completion_sha256 IS DISTINCT FROM h THEN RAISE EXCEPTION 'RBAC witness completion replay differs'; END IF;
   RETURN QUERY SELECT r.completion_original,r.completion_sha256; RETURN;
 END IF;
 IF e.pending_sha256 IS DISTINCT FROM p_intent OR e.head_sha256 IS DISTINCT FROM r.intent_original::jsonb->>'beforeHeadSha256' THEN
   RAISE EXCEPTION 'RBAC witness pending predecessor differs';
 END IF;
 IF (EXTRACT(epoch FROM pg_catalog.clock_timestamp())*1000000000 < (r.intent_original::jsonb->>'expiresAtEpochNs')::numeric) IS NOT TRUE THEN
   RAISE EXCEPTION 'RBAC witness original completion deadline expired';
 END IF;
 UPDATE serverware_rbac_witness.records SET completion_original=p_original,completion_sha256=h WHERE intent_sha256=p_intent;
 UPDATE serverware_rbac_witness.enrollments SET head_original=p_head,head_sha256=hh,pending_sha256=NULL WHERE enrollment_sha256=p_enrollment;
 RETURN QUERY SELECT p_original,h;
END $body$;

ALTER FUNCTION serverware_rbac_witness.identity() OWNER TO serverware_rbac_witness_owner;
ALTER FUNCTION serverware_rbac_witness.read_head(text) OWNER TO serverware_rbac_witness_owner;
ALTER FUNCTION serverware_rbac_witness.read_record(text,text) OWNER TO serverware_rbac_witness_owner;
ALTER FUNCTION serverware_rbac_witness.reserve(text,text) OWNER TO serverware_rbac_witness_owner;
ALTER FUNCTION serverware_rbac_witness.complete(text,text,text,text) OWNER TO serverware_rbac_witness_owner;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO serverware_rbac_witness_owner;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA serverware_rbac_witness FROM PUBLIC;
GRANT USAGE ON SCHEMA serverware_rbac_witness TO serverware_rbac_witness_reader,serverware_rbac_witness_writer;
GRANT EXECUTE ON FUNCTION serverware_rbac_witness.identity(),serverware_rbac_witness.read_head(text),serverware_rbac_witness.read_record(text,text)
 TO serverware_rbac_witness_reader,serverware_rbac_witness_writer;
GRANT EXECUTE ON FUNCTION serverware_rbac_witness.reserve(text,text),serverware_rbac_witness.complete(text,text,text,text)
 TO serverware_rbac_witness_writer;
"""
