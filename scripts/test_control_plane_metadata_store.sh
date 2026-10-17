#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ADMIN_TOKEN="${CATCHPLATE_ADMIN_TOKEN:-dev-admin-token}"

python3 - "$BASE" "$ADMIN_TOKEN" <<'PY'
import json
import re
import subprocess
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
admin_token = sys.argv[2]
admin_headers = {"X-Catchplate-Admin-Token": admin_token}


def request_json(path: str, *, method: str = "GET") -> dict | list:
    req = urllib.request.Request(f"{base}{path}", method=method, headers=admin_headers)
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read())


request_json("/api/demo/seed", method="POST")
status = request_json("/api/metadata/store/status")
assert status["backend"] == "postgres", status
assert status["ha"] is True, status
tables = status["tables"]
assert int(tables.get("credentials") or 0) >= 1, status
assert int(tables.get("routes") or 0) >= 12, status

table_names = sorted(tables)
assert table_names, status
assert all(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", table) for table in table_names), status
count_expressions = ",\n  ".join(
    f"'{table}', (SELECT COUNT(*) FROM \"{table}\")" for table in table_names
)
sql = f"SELECT json_build_object(\n  {count_expressions}\n)::text;"
raw = subprocess.check_output(
    [
        "docker",
        "compose",
        "exec",
        "-T",
        "grant-store",
        "psql",
        "-U",
        "catchplate",
        "-d",
        "catchplate",
        "-Atc",
        sql,
    ],
    text=True,
).strip()
postgres_counts = json.loads(raw)
for table, count in tables.items():
    assert int(postgres_counts[table]) == int(count), {
        "api": tables,
        "postgres": postgres_counts,
        "table": table,
    }

rbac_probe = r'''
import concurrent.futures
import json
import threading
import uuid

from catchplate import db


assert db.metadata_store_backend_name() == "postgres"
test_id = uuid.uuid4().hex
race_subjects = [
    f"oidc:metadata-race-{test_id}-1@example.com",
    f"oidc:metadata-race-{test_id}-2@example.com",
]
initial = db.get_rbac_authority_state()
expected_generation = initial["generation"]
barrier = threading.Barrier(2)


def race_writer(subject_id: str) -> dict:
    barrier.wait(timeout=10)
    try:
        result = db.mutate_rbac_role_binding(
            subject_id=subject_id,
            roles=["auditor"],
            status="active",
            expected_generation=expected_generation,
            actor_id="test:metadata-store",
            reason="PostgreSQL RBAC CAS verification",
            event_type="rbac.role_changed",
            event={"test": "metadata_store_generation_race"},
        )
        return {
            "outcome": "committed",
            "subject_id": subject_id,
            "generation": result["generation"],
        }
    except db.RBACGenerationConflictError as exc:
        assert type(exc) is db.RBACGenerationConflictError
        return {
            "outcome": "conflict",
            "subject_id": subject_id,
            "expected_generation": exc.expected_generation,
            "current_generation": exc.current_generation,
            "exception": type(exc).__name__,
        }


with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    race_results = list(executor.map(race_writer, race_subjects))

assert sorted(result["outcome"] for result in race_results) == [
    "committed",
    "conflict",
], race_results
post_race = db.get_rbac_authority_state()
assert post_race["generation"] == expected_generation + 1, post_race
committed_subjects = [
    subject_id for subject_id in race_subjects if subject_id in post_race["subjects"]
]
assert len(committed_subjects) == 1, {
    "race_results": race_results,
    "committed_subjects": committed_subjects,
}
conflict = next(result for result in race_results if result["outcome"] == "conflict")
assert conflict["expected_generation"] == expected_generation, conflict
assert conflict["current_generation"] == expected_generation + 1, conflict
assert conflict["exception"] == "RBACGenerationConflictError", conflict

rollback_generation = post_race["generation"]
rollback_subject = f"oidc:metadata-audit-rollback-{test_id}@example.com"
original_append_audit_event = db.append_audit_event


def reject_audit_append(*args, **kwargs):
    raise db.AuditStoreError("injected metadata-store RBAC audit failure")


db.append_audit_event = reject_audit_append
try:
    try:
        db.mutate_rbac_role_binding(
            subject_id=rollback_subject,
            roles=["auditor"],
            status="active",
            expected_generation=rollback_generation,
            actor_id="test:metadata-store",
            reason="PostgreSQL RBAC audit rollback verification",
            event_type="rbac.role_changed",
            event={"test": "metadata_store_audit_rollback"},
        )
    except db.AuditStoreError:
        pass
    else:
        raise AssertionError("RBAC mutation committed after injected audit failure")
finally:
    db.append_audit_event = original_append_audit_event

post_rollback = db.get_rbac_authority_state()
assert post_rollback["generation"] == rollback_generation, post_rollback
assert rollback_subject not in post_rollback["subjects"], post_rollback
assert db.get_rbac_role_binding(rollback_subject) is None

print(
    json.dumps(
        {
            "audit_failure_rolled_back": True,
            "backend": db.metadata_store_backend_name(),
            "committed_subject": committed_subjects[0],
            "generation": post_rollback["generation"],
            "generation_conflicts": 1,
            "race_commits": 1,
        },
        sort_keys=True,
    )
)
'''
rbac_raw = subprocess.check_output(
    ["docker", "compose", "exec", "-T", "catchplate", "python", "-"],
    input=rbac_probe,
    text=True,
).strip()
rbac_result = json.loads(rbac_raw.splitlines()[-1])
assert rbac_result["backend"] == "postgres", rbac_result
assert rbac_result["race_commits"] == 1, rbac_result
assert rbac_result["generation_conflicts"] == 1, rbac_result
assert rbac_result["audit_failure_rolled_back"] is True, rbac_result

print(
    json.dumps(
        {
            "ok": True,
            "metadata_store": "postgres",
            "ha": True,
            "tables": {key: int(value) for key, value in postgres_counts.items()},
            "rbac": rbac_result,
        },
        sort_keys=True,
    )
)
PY
