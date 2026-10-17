from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from mitmproxy import connection, http, tls

from catchplate import db, runtime
from catchplate.config import RELEASE_CHANNEL
from catchplate.policy_bundle import (
    get_policy_snapshot,
    validate_raw_absolute_target,
    validate_raw_connect_authority,
)
from catchplate.policy_engine import (
    LEGACY_MITM_TRANSPORT_METADATA_KEY,
    RAW_INGRESS_TARGET_METADATA_KEY,
    RAW_INGRESS_VALIDATED_METADATA_KEY,
    _client_ip,
    complete_release_authorization,
    complete_release_authorization_for_error,
    discard_response_guards,
    dispatch_release_authorization,
    evaluate_request,
    evaluate_response,
    mark_provider_dispatch_uncertain,
    prepare_response,
    validate_response_completion,
)


_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_MAX_RAW_REQUEST_FIELD_BYTES = 64 * 1024
_RAW_CONNECT_AUTHORITY_METADATA_KEY = "catchplate_raw_connect_authority"


def _require_development_release_channel() -> None:
    if RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS:
        raise RuntimeError(
            "legacy Python mitmproxy addon is development-only; "
            "use the Rust decision gate for non-development release channels"
        )


def _connection_key(client: object) -> str:
    connection_id = getattr(client, "id", None)
    return str(connection_id) if connection_id is not None else f"object:{id(client)}"


@dataclass(frozen=True)
class _AdmittedConnectTunnel:
    authority: str
    host: str
    port: int
    client_connection_key: str
    connect_flow_key: str
    server_connection_key: str
    server_address: tuple[str, int]


def _flow_key(flow: object) -> str:
    flow_id = getattr(flow, "id", None)
    return str(flow_id) if flow_id is not None else f"object:{id(flow)}"


def _exact_server_address(server: object) -> tuple[str, int]:
    address = getattr(server, "address", None)
    if (
        not isinstance(address, tuple)
        or len(address) != 2
        or not isinstance(address[0], str)
        or type(address[1]) is not int
    ):
        raise ValueError("server connection address is unavailable")
    host = _bounded_raw_ascii(address[0], "server connection host")
    port = address[1]
    if not 1 <= port <= 65535:
        raise ValueError("server connection port is invalid")
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        if host != host.lower() or host.endswith("."):
            raise ValueError("server connection DNS host is noncanonical")
    else:
        if parsed_ip.compressed != host:
            raise ValueError("server connection IP host is noncanonical")
    return host, port


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
    flow.metadata["catchplate_blocked_response"] = True
    flow.response = http.Response.make(
        status_code,
        json.dumps(payload).encode("utf-8"),
        {"Content-Type": "application/json"},
    )


def _bounded_raw_ascii(value: object, label: str, *, allow_empty: bool = False) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("ascii")
    else:
        raise ValueError(f"{label} is unavailable")
    if len(raw) > _MAX_RAW_REQUEST_FIELD_BYTES or (not allow_empty and not raw):
        raise ValueError(f"{label} is unavailable or oversized")
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not ASCII") from exc


def _raw_header_values(request: object, name: bytes) -> list[str]:
    data = getattr(request, "data", None)
    headers = getattr(data, "headers", None)
    fields = getattr(headers, "fields", None)
    if not isinstance(fields, (tuple, list)):
        raise ValueError("raw physical request headers are unavailable")
    values: list[str] = []
    for field in fields:
        if not isinstance(field, (tuple, list)) or len(field) != 2:
            raise ValueError("raw request headers are unavailable")
        raw_name = _bounded_raw_ascii(field[0], "raw request header name")
        if raw_name.lower().encode("ascii") == name:
            values.append(
                _bounded_raw_ascii(field[1], "raw request header value")
            )
    return values


def _request_first_line_format(request: object) -> str:
    value = getattr(request, "first_line_format", None)
    if not isinstance(value, str) or value not in {
        "absolute",
        "authority",
        "relative",
    }:
        raise ValueError("request first-line form is unavailable")
    return value


def _raw_http_version(request: object) -> str:
    data = getattr(request, "data", None)
    version = _bounded_raw_ascii(
        getattr(data, "http_version", None),
        "raw HTTP version",
    )
    normalized = str(getattr(request, "http_version", ""))
    if normalized != version:
        raise ValueError("raw and normalized HTTP versions differ")
    if version not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/2"}:
        raise ValueError("HTTP version is unsupported")
    return version


def _admit_raw_absolute_request_target(
    flow: http.HTTPFlow,
) -> tuple[str, str, int]:
    request = flow.request
    data = getattr(request, "data", None)
    if data is None:
        raise ValueError("raw request data is unavailable")
    first_line_format = _request_first_line_format(request)
    if first_line_format not in {"absolute", "relative"}:
        raise ValueError("request is not absolute-form or origin-form")
    method = _bounded_raw_ascii(getattr(data, "method", None), "raw method")
    scheme = _bounded_raw_ascii(getattr(data, "scheme", None), "raw scheme")
    path = _bounded_raw_ascii(getattr(data, "path", None), "raw path")
    if method != str(getattr(request, "method", "")):
        raise ValueError("raw and normalized request methods differ")
    if scheme != str(getattr(request, "scheme", "")):
        raise ValueError("raw and normalized request schemes differ")
    if not path.startswith("/"):
        raise ValueError("raw request path is not origin-form")

    raw_authority = _bounded_raw_ascii(
        getattr(data, "authority", None),
        "raw authority",
        allow_empty=True,
    )
    host_values = _raw_header_values(request, b"host")
    http_version = _raw_http_version(request)
    if http_version in {"HTTP/1.0", "HTTP/1.1"}:
        if len(host_values) != 1:
            raise ValueError("HTTP/1.x requires exactly one physical Host field")
        if first_line_format == "absolute":
            if not raw_authority:
                raise ValueError("absolute-form raw authority is unavailable")
            authority = raw_authority
            if host_values[0] != authority:
                raise ValueError(
                    "absolute-form Host does not exactly match raw authority"
                )
        else:
            authority = host_values[0]
            if raw_authority and raw_authority != authority:
                raise ValueError("raw authority and Host field differ")
    else:
        if first_line_format != "relative":
            raise ValueError("HTTP/2 request must use origin-form")
        if host_values:
            raise ValueError("HTTP/2 physical Host field is ambiguous")
        if not raw_authority:
            raise ValueError("HTTP/2 raw :authority is unavailable")
        authority = raw_authority

    target = f"{scheme}://{authority}{path}"
    parts = validate_raw_absolute_target(target)
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    if (
        str(getattr(request, "host", "")) != host
        or int(getattr(request, "port", 0)) != port
        or str(getattr(request, "path", "")) != path
        or str(getattr(request, "pretty_url", "")) != target
        or str(getattr(data, "host", "")) != host
        or int(getattr(data, "port", 0)) != port
    ):
        raise ValueError("normalized request fields do not preserve the raw target")
    flow.metadata[RAW_INGRESS_TARGET_METADATA_KEY] = target
    flow.metadata[RAW_INGRESS_VALIDATED_METADATA_KEY] = True
    return target, host, port


def _admit_raw_connect_authority(flow: http.HTTPFlow) -> tuple[str, int]:
    request = flow.request
    data = getattr(request, "data", None)
    if data is None or _request_first_line_format(request) != "authority":
        raise ValueError("raw CONNECT first-line data is unavailable")
    if _bounded_raw_ascii(getattr(data, "method", None), "raw method") != "CONNECT":
        raise ValueError("raw CONNECT method is invalid")
    if _raw_http_version(request) not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("CONNECT transport must use HTTP/1.x authority-form")
    if _bounded_raw_ascii(
        getattr(data, "scheme", None),
        "raw CONNECT scheme",
        allow_empty=True,
    ):
        raise ValueError("CONNECT request unexpectedly contains a raw scheme")
    raw_path = _bounded_raw_ascii(
        getattr(data, "path", None),
        "raw CONNECT target",
        allow_empty=True,
    )
    raw_authority = _bounded_raw_ascii(
        getattr(data, "authority", None),
        "raw CONNECT authority",
        allow_empty=True,
    )
    candidates = {value for value in (raw_path, raw_authority) if value}
    if len(candidates) != 1:
        raise ValueError("raw CONNECT authority fields are unavailable or inconsistent")
    authority = candidates.pop()
    host_values = _raw_header_values(request, b"host")
    if host_values != [authority]:
        raise ValueError("raw CONNECT Host field does not exactly match authority")
    host, port = validate_raw_connect_authority(authority)
    if (
        str(getattr(request, "method", "")) != "CONNECT"
        or str(getattr(request, "host", "")) != host
        or int(getattr(request, "port", 0)) != port
        or str(getattr(data, "host", "")) != host
        or int(getattr(data, "port", 0)) != port
    ):
        raise ValueError("normalized CONNECT fields do not preserve raw authority")
    flow.metadata[_RAW_CONNECT_AUTHORITY_METADATA_KEY] = authority
    return host, port


class CatchplateAddon:
    def __init__(self) -> None:
        _require_development_release_channel()
        self._admitted_connect_authorities: dict[str, _AdmittedConnectTunnel] = {}
        self._admitted_server_connections: dict[str, str] = {}

    def _clear_client_tunnel(self, connection_key: str) -> None:
        self._admitted_connect_authorities.pop(connection_key, None)

    def load(self, loader):
        _require_development_release_channel()
        db.init_db()
        runtime.start_runtime_workers()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        connection_key = _connection_key(flow.client_conn)
        if connection_key in self._admitted_connect_authorities:
            _install_blocked_response(
                flow,
                400,
                {"error": "invalid_connect_target"},
            )
            return
        try:
            host, port = _admit_raw_connect_authority(flow)
            server_address = _exact_server_address(flow.server_conn)
            server_connection_key = _connection_key(flow.server_conn)
            if server_address != (host, port):
                raise ValueError(
                    "CONNECT server address does not exactly match raw authority"
                )
            if server_connection_key in self._admitted_server_connections:
                raise ValueError(
                    "server connection is already assigned to an admitted tunnel"
                )
        except Exception:
            _install_blocked_response(
                flow,
                400,
                {"error": "invalid_connect_target"},
            )
            return
        try:
            snapshot = get_policy_snapshot()
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
                authority = flow.metadata[_RAW_CONNECT_AUTHORITY_METADATA_KEY]
                self._admitted_connect_authorities[connection_key] = (
                    _AdmittedConnectTunnel(
                        authority=authority,
                        host=host,
                        port=port,
                        client_connection_key=connection_key,
                        connect_flow_key=_flow_key(flow),
                        server_connection_key=server_connection_key,
                        server_address=server_address,
                    )
                )
                self._admitted_server_connections[server_connection_key] = (
                    _flow_key(flow)
                )
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
            tunnel = self._admitted_connect_authorities.get(
                _connection_key(data.context.client)
            )
            if tunnel is None:
                _terminate_tls_connection(data, "TLS denied without an admitted CONNECT authority")
                return
            server_connection_key = _connection_key(data.context.server)
            server_address = _exact_server_address(data.context.server)
            if (
                server_connection_key != tunnel.server_connection_key
                or server_address != tunnel.server_address
                or server_address != (tunnel.host, tunnel.port)
            ):
                _terminate_tls_connection(
                    data,
                    "TLS tunnel authority does not match the admitted CONNECT authority",
                )
                return
            raw_sni = data.client_hello.sni
            if raw_sni is None:
                if _host_requires_sni(tunnel.host):
                    _terminate_tls_connection(
                        data,
                        "TLS denied because SNI is required for the admitted CONNECT authority",
                    )
                return
            exact_sni = _bounded_raw_ascii(raw_sni, "TLS SNI")
            if (
                exact_sni != tunnel.host
                or exact_sni != exact_sni.lower()
                or exact_sni.endswith(".")
            ):
                _terminate_tls_connection(
                    data,
                    "TLS SNI does not match the admitted CONNECT authority",
                )
        except Exception:
            _terminate_tls_connection(data, "TLS ClientHello policy hook failed closed")

    def client_disconnected(self, client: connection.Client) -> None:
        self._clear_client_tunnel(_connection_key(client))

    def server_disconnected(self, server: connection.Server) -> None:
        server_key = _connection_key(server)
        self._admitted_server_connections.pop(server_key, None)
        for client_key, tunnel in list(
            self._admitted_connect_authorities.items()
        ):
            if tunnel.server_connection_key == server_key:
                self._admitted_connect_authorities.pop(client_key, None)

    def _assert_tunnel_request_binding(
        self,
        flow: http.HTTPFlow,
        *,
        host: str,
        port: int,
    ) -> None:
        connection_key = _connection_key(flow.client_conn)
        tunnel = self._admitted_connect_authorities.get(connection_key)
        first_line_format = _request_first_line_format(flow.request)
        if tunnel is None:
            if (
                str(getattr(flow.request, "scheme", "")) == "https"
                and first_line_format == "relative"
            ):
                raise ValueError(
                    "intercepted HTTPS request has no admitted CONNECT tunnel"
                )
            return
        server_key = _connection_key(flow.server_conn)
        server_address = _exact_server_address(flow.server_conn)
        if (
            tunnel.client_connection_key != connection_key
            or server_key != tunnel.server_connection_key
            or server_address != tunnel.server_address
            or server_address != (host, port)
            or (host, port) != (tunnel.host, tunnel.port)
            or first_line_format != "relative"
        ):
            raise ValueError(
                "inner request does not match the admitted CONNECT tunnel"
            )
        flow.metadata["catchplate_connect_tunnel_identity"] = (
            f"{tunnel.client_connection_key}:"
            f"{tunnel.connect_flow_key}:"
            f"{tunnel.server_connection_key}"
        )

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
        flow.metadata[LEGACY_MITM_TRANSPORT_METADATA_KEY] = True
        try:
            _, host, port = _admit_raw_absolute_request_target(flow)
            self._assert_tunnel_request_binding(
                flow,
                host=host,
                port=port,
            )
        except Exception:
            _install_blocked_response(
                flow,
                400,
                {"error": "invalid_request_target"},
            )
            return
        try:
            if (
                flow.metadata.get("catchplate_blocked_response") is True
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
            flow.metadata.pop("catchplate_blocked_response", None)
            route = evaluation.route
            if route is None:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    503,
                    {"error": "request_route_context_missing"},
                )
                return
            if route.credential_ref:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    503,
                    {"error": "legacy_mitm_credential_transport_denied"},
                )
                return
            if route.resolved_cidrs is not None:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    503,
                    {"error": "legacy_mitm_resolved_cidrs_unsupported"},
                )
                return
            dispatch = dispatch_release_authorization(flow)
            if not dispatch.allowed:
                complete_release_authorization_for_error(flow)
                _install_blocked_response(
                    flow,
                    dispatch.status_code,
                    dispatch.payload or {"error": dispatch.reason},
                )
                return
            # Only credentialless development traffic reaches mitmproxy's
            # upstream send path. Production dispatch is owned by the Rust gate.
            mark_provider_dispatch_uncertain(flow)
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

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # The development transport must retain the complete upstream entity until
        # response constraints have run; otherwise mitmproxy streaming settings
        # could release bytes before a synthetic denial replaces the response.
        flow.response.stream = False

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            if flow.metadata.get("catchplate_blocked_response") is not True:
                prepared = prepare_response(flow)
                decision = (
                    evaluate_response(flow)
                    if prepared.allowed
                    else prepared
                )
                completion = complete_release_authorization(
                    flow,
                    "forwarded",
                )
                if not decision.allowed or not completion.allowed:
                    discard_response_guards(flow)
                    denial = (
                        completion
                        if not completion.allowed
                        else decision
                    )
                    _install_blocked_response(
                        flow,
                        denial.status_code,
                        denial.payload or {"error": denial.reason},
                    )
                    return
                completed = validate_response_completion(flow)
                if not completed.allowed:
                    discard_response_guards(flow)
                    _install_blocked_response(
                        flow,
                        completed.status_code,
                        completed.payload or {"error": completed.reason},
                    )
        except Exception:
            if flow.metadata.get("catchplate_blocked_response") is not True:
                try:
                    complete_release_authorization(flow, "forwarded")
                except Exception:
                    pass
            discard_response_guards(flow)
            _install_blocked_response(
                flow,
                503,
                {"error": "response_hook_failed_closed"},
            )

    def error(self, flow: http.HTTPFlow) -> None:
        complete_release_authorization_for_error(flow)


addons = [CatchplateAddon()]
