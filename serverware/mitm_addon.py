from __future__ import annotations

import json

from mitmproxy import http

from serverware import db, runtime
from serverware.policy_bundle import get_policy_snapshot
from serverware.policy_engine import evaluate_request, evaluate_response, redact_url


class ServerwareAddon:
    def load(self, loader):
        db.init_db()
        runtime.start_runtime_workers()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        snapshot = get_policy_snapshot()
        host = flow.request.host.lower().rstrip(".")
        port = flow.request.port
        if snapshot and any(route.host == host and route.port == port for route in snapshot.routes):
            return
        flow.response = http.Response.make(
            403,
            json.dumps({"error": "unknown_connect_denied", "host": host, "port": port}).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        runtime.log_request(None, "CONNECT", f"{host}:{port}", "blocked", 403, "unknown CONNECT denied")

    def request(self, flow: http.HTTPFlow) -> None:
        evaluation = evaluate_request(flow)
        decision = evaluation.decision
        if not decision.allowed:
            flow.response = http.Response.make(
                decision.status_code,
                json.dumps(decision.payload or {"error": decision.reason}).encode("utf-8"),
                {"Content-Type": "application/json"},
            )

    def response(self, flow: http.HTTPFlow) -> None:
        decision = evaluate_response(flow)
        if not decision.allowed:
            flow.response = http.Response.make(
                decision.status_code,
                json.dumps(decision.payload or {"error": decision.reason}).encode("utf-8"),
                {"Content-Type": "application/json"},
            )


addons = [ServerwareAddon()]
