#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://localhost:3000}"
ADMIN_TOKEN="${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"

python3 - "$BASE" "$ADMIN_TOKEN" <<'PY'
import json
import re
import subprocess
import sys
import urllib.request

base = sys.argv[1].rstrip("/")
admin_token = sys.argv[2]
admin_headers = {"X-Serverware-Admin-Token": admin_token}


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
        "serverware",
        "-d",
        "serverware",
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

print(
    json.dumps(
        {
            "ok": True,
            "metadata_store": "postgres",
            "ha": True,
            "tables": {key: int(value) for key, value in postgres_counts.items()},
        },
        sort_keys=True,
    )
)
PY
