from __future__ import annotations

import ipaddress
import json

from mitmproxy import connection, http, tls

from serverware import db, runtime
from serverware.config import RELEASE_CHANNEL
from serverware.policy_bundle import get_policy_snapshot
from serverware.policy_engine import (
    _client_ip,
    complete_release_authorization,
    complete_release_authorization_for_error,
    dispatch_release_authorization,
    evaluate_request,
    evaluate_response,
)


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}


def _require_development_release_channel() -> None:
    if RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS:
        raise RuntimeError(
            "legacy Python mitmproxy addon is development-only; "
            "use the Rust decision gate for non-development release channels"
        )


def _connection_key(client: object) -> str:
    connection_id = getattr(client, "id", None)
    return str(connection_id) if connection_id is not None else f"object:{id(client)}"


def _normalized_host(host: str) -> str:
    normalized = host.strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).compressed.lower()
    except ValueError:
        return normalized.lower().rstrip(".")


def _host_requires_sni(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def _terminate_tls_connection(data: tls.ClientHelloData, reason: str) -> None:
    data.context.client.error = reason
    data.context.server.error = reason
    data.context.client.state = connection.ConnectionState.CLOSED
    data.context.server.state = connection.ConnectionState.CLOSED


def _install_blocked_response(
    flow: http.HTTPFlow,
    status_code: int,
    payload: dict[str, object],
) -> None:
    flow.metadata["serverware_blocked_response"] = True
    flow.response = http.Response.make(
        status_code,
        json.dumps(payload).encode("utf-8"),
        {"Content-Type": "application/json"},
    )


class ServerwareAddon:
    def __init__(self) -> None:
        _require_development_release_channel()
        self._admitted_connect_authorities: dict[str, tuple[str, int]] = {}

    def load(self, loader):
        _require_development_release_channel()
        db.init_db()
        runtime.start_runtime_workers()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        connection_key = _connection_key(flow.client_conn)
        self._admitted_connect_authorities.pop(connection_key, None)
        try:
            snapshot = get_policy_snapshot()
            host = _normalized_host(flow.request.host)
            port = int(flow.request.port)
            principal = (
                snapshot.identify_principal(_client_ip(flow), flow.request.headers)
                if snapshot is not None
                else None
            )
            if principal is not None and any(
                route.scheme == "https"
                and route.host == host
                and route.port == port
                and (
                    principal.id in route.principals
                    or "*" in route.principals
                )
                for route in snapshot.routes
            ):
                self._admitted_connect_authorities[connection_key] = (host, port)
                return
            _install_blocked_response(
                flow,
                403,
                {"error": "unknown_connect_denied", "host": host, "port": port},
            )
            runtime.log_request(
                None,
                "CONNECT",
                f"{host}:{port}",
                "blocked",
                403,
                "unknown CONNECT denied",
            )
        except Exception:
            _install_blocked_response(
                flow,
                503,
                {"error": "connect_hook_failed_closed"},
            )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        try:
            authority = self._admitted_connect_authorities.get(
                _connection_key(data.context.client)
            )
            if authority is None:
                _terminate_tls_connection(data, "TLS denied without an admitted CONNECT authority")
                return
            admitted_host, admitted_port = authority
            server_address = data.context.server.address
            if (
                not isinstance(server_address, tuple)
                or len(server_address) != 2
                or _normalized_host(str(server_address[0])) != admitted_host
                or int(server_address[1]) != admitted_port
            ):
                _terminate_tls_connection(
                    data,
                    "TLS tunnel authority does not match the admitted CONNECT authority",
                )
                return
            raw_sni = data.client_hello.sni
            if raw_sni is None:
                if _host_requires_sni(admitted_host):
                    _terminate_tls_connection(
                        data,
                        "TLS denied because SNI is required for the admitted CONNECT authority",
                    )
                return
            if _normalized_host(raw_sni) != admitted_host:
                _terminate_tls_connection(
                    data,
                    "TLS SNI does not match the admitted CONNECT authority",
                )
        except Exception:
            _terminate_tls_connection(data, "TLS ClientHello policy hook failed closed")

    def client_disconnected(self, client: connection.Client) -> None:
        self._admitted_connect_authorities.pop(_connection_key(client), None)

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # Request policy and its digest require the complete buffered body.
        if getattr(flow.request, "stream", False):
            _install_blocked_response(
                flow,
                503,
                {"error": "request_streaming_unsupported"},
            )
            return
        flow.request.stream = False

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            if (
                flow.metadata.get("serverware_blocked_response") is True
                and getattr(flow, "response", None) is not None
            ):
                return
            if getattr(flow.request, "stream", False):
                _install_blocked_response(
                    flow,
                    503,
                    {"error": "request_streaming_unsupported"},
                )
                return
            evaluation = evaluate_request(flow)
            decision = evaluation.decision
            if not decision.allowed:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    decision.status_code,
                    decision.payload or {"error": decision.reason},
                )
                return
            flow.metadata.pop("serverware_blocked_response", None)
            dispatch = dispatch_release_authorization(flow)
            if not dispatch.allowed:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    dispatch.status_code,
                    dispatch.payload or {"error": dispatch.reason},
                )
        except Exception:
            try:
                complete_release_authorization_for_error(flow)
            except Exception:
                pass
            _install_blocked_response(
                flow,
                503,
                {"error": "request_hook_failed_closed"},
            )

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.metadata.get("serverware_blocked_response") is not True:
                completion = complete_release_authorization(flow, "forwarded")
                if not completion.allowed:
                    _install_blocked_response(
                        flow,
                        completion.status_code,
                        completion.payload or {"error": completion.reason},
                    )
                    return
            decision = evaluate_response(flow)
            if not decision.allowed:
                _install_blocked_response(
                    flow,
                    decision.status_code,
                    decision.payload or {"error": decision.reason},
                )
        except Exception:
            _install_blocked_response(
                flow,
                503,
                {"error": "response_hook_failed_closed"},
            )

    def error(self, flow: http.HTTPFlow) -> None:
        complete_release_authorization_for_error(flow)


addons = [ServerwareAddon()]
