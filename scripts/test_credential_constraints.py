from __future__ import annotations

# ruff: noqa: E402

import base64
import copy
import hashlib
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PROXY_TRANSPORT_ONLY = "--proxy-transport-only" in sys.argv

tmpdir = tempfile.TemporaryDirectory()
os.environ["SERVERWARE_DATA_DIR"] = tmpdir.name
os.environ["SERVERWARE_RELEASE_CHANNEL"] = "test"
os.environ["SERVERWARE_METADATA_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_AUDIT_STORE_BACKEND"] = "sqlite"
os.environ["SERVERWARE_GRANT_STORE_BACKEND"] = "sqlite"
for name in (
    "SERVERWARE_METADATA_STORE_POSTGRES_DSN",
    "SERVERWARE_AUDIT_STORE_POSTGRES_DSN",
    "SERVERWARE_GRANT_STORE_POSTGRES_DSN",
):
    os.environ.pop(name, None)

from serverware import db, runtime
from serverware.adapters import X_V2_READ_OPERATION_PATHS, X_V2_READ_OPERATIONS, _x_read_operation, get_adapter
from serverware.constraints import (
    _enforce_request_time_window,
    evaluate_request_constraints,
    evaluate_response_binding_sources,
    evaluate_response_constraints,
    reset_local_constraint_state,
)
from serverware.policy_bundle import (
    X_V2_BOUNDED_READ_OPERATIONS,
    X_V2_RECENT_SEARCH_PATHS,
    CredentialPolicy,
    PolicyBundleError,
    _load_raw_policy,
    bounded_pattern_matches,
    canonical_json,
    compile_policy_bundle,
    demo_policy_bundle,
    provider_account_scope_value,
    sign_policy_bundle,
    strict_json_loads,
    validate_policy_schema,
)
try:
    from serverware.policy_engine import (
        _canonical_forwarded_request_headers,
        _canonical_request,
        _bind_provider_account_scope,
        _credential_injection_collision,
        _digest,
        _inject_credential,
        _operation_digest,
        _validated_successful_release_reserve,
        evaluate_response,
    )
    from serverware.mitm_addon import ServerwareAddon
except ModuleNotFoundError as exc:
    if exc.name != "mitmproxy":
        raise
    if PROXY_TRANSPORT_ONLY:
        raise AssertionError(
            "proxy transport assertions require mitmproxy==11.0.2"
        ) from exc
    _inject_credential = None
    _bind_provider_account_scope = None
    _operation_digest = None
    _validated_successful_release_reserve = None
    _canonical_forwarded_request_headers = None
    _canonical_request = None
    _credential_injection_collision = None
    _digest = None
    evaluate_response = None
    ServerwareAddon = None


class Request:
    def __init__(self, method: str, url: str, body: dict | None = None, content_type: str = "application/json") -> None:
        self.method = method
        self.pretty_url = url
        self.headers = {"content-type": content_type}
        self.raw_content = json.dumps(body or {}).encode("utf-8") if body is not None else b""
        self.query = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


class Response:
    def __init__(self, payload: dict, *, status_code: int = 200, headers: dict | None = None) -> None:
        self.raw_content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.status_code = status_code

    @property
    def content(self) -> bytes:
        return self.raw_content

    @content.setter
    def content(self, value: bytes) -> None:
        self.raw_content = value

    def get_text(self, strict: bool = False) -> str:
        return self.raw_content.decode("utf-8", errors="strict" if strict else "replace")

    def set_text(self, value: str) -> None:
        self.raw_content = value.encode("utf-8")


def flow(method: str, url: str, body: dict | None = None, response: dict | None = None) -> SimpleNamespace:
    item = SimpleNamespace(
        request=Request(method, url, body),
        client_conn=SimpleNamespace(peername=("127.0.0.1", 12345)),
        metadata={},
    )
    if response is not None:
        item.response = Response(response)
    return item


def route(snapshot, route_id: str):
    for item in snapshot.routes:
        if item.id == route_id:
            return item
    raise AssertionError(f"missing route {route_id}")


def request_decision(
    route_policy,
    item,
    operation: str,
    *,
    consume: bool = False,
    principal_id: str = "agent:demo",
    credential_ref: str | None = None,
    operation_fields: dict[str, str] | None = None,
):
    return evaluate_request_constraints(
        item,
        route_policy,
        principal_id=principal_id,
        credential_ref=credential_ref or route_policy.credential_ref,
        credential_version=1,
        operation_fields=operation_fields or {"operation": operation},
        consume_rate_limits=consume,
        policy_hash="sha256:" + "1" * 64,
        rate_limits_only=consume,
    )


def iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def epoch_ms_days_ago(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp() * 1000)


def assert_denied(decision, error: str) -> None:
    assert not decision.allowed, decision
    assert decision.payload.get("error") == error, decision.payload


def assert_response_binding_denied(
    decision,
    error: str,
    *,
    binding_id: str | None,
    evidence: bool = True,
    sensitive_values: tuple[str, ...] = (),
) -> None:
    assert_denied(decision, error)
    expected_keys = {
        "error",
        "constraint_id",
        "constraint_type",
    }
    if evidence:
        expected_keys.add("evidence_digest")
        evidence_digest = decision.payload["evidence_digest"]
        assert evidence_digest.startswith("sha256:") and len(evidence_digest) == 71
        assert set(evidence_digest.removeprefix("sha256:")) <= set("0123456789abcdef")
    else:
        assert "evidence_digest" not in decision.payload
    if binding_id is None:
        assert "binding_id" not in decision.payload
    else:
        expected_keys.add("binding_id")
        assert decision.payload["binding_id"] == binding_id
    assert set(decision.payload) == expected_keys, decision.payload
    rendered_denial = json.dumps(
        {"reason": decision.reason, "payload": decision.payload},
        sort_keys=True,
    )
    for value in sensitive_values:
        assert value not in rendered_denial, rendered_denial


def schema_validation_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except Exception as exc:
        raise AssertionError("jsonschema is required; policy tests must not downgrade semantic coverage") from exc
    return True


def assert_policy_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(bundle, validate_schema=use_schema)
        except PolicyBundleError:
            continue
        raise AssertionError(f"{message}; validate_schema={use_schema}")


def assert_signed_policy_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    signed = sign_policy_bundle(bundle)
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(
                signed,
                verify_signature=True,
                validate_schema=use_schema,
            )
        except PolicyBundleError:
            continue
        raise AssertionError(f"{message}; validate_schema={use_schema}")


def assert_signed_policy_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    signed = sign_policy_bundle(bundle)
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(
                signed,
                verify_signature=True,
                validate_schema=use_schema,
            )
        except PolicyBundleError as exc:
            assert str(exc) == expected_reason, str(exc)
            continue
        raise AssertionError(
            f"compiler accepted signed policy expected to fail with: {expected_reason}; "
            f"validate_schema={use_schema}"
        )


def assert_policy_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    try:
        compile_policy_bundle(bundle, validate_schema=False)
    except PolicyBundleError as exc:
        assert str(exc) == expected_reason, str(exc)
    else:
        raise AssertionError(f"compiler accepted policy expected to fail with: {expected_reason}")
    if not validate_schema:
        return
    try:
        validate_policy_schema(bundle)
    except PolicyBundleError:
        return
    raise AssertionError(f"policy schema accepted policy expected to fail with: {expected_reason}")


def assert_compiler_rejected_reason(
    bundle: dict,
    expected_reason: str,
    *,
    validate_schema: bool,
) -> None:
    for use_schema in ((False, True) if validate_schema else (False,)):
        try:
            compile_policy_bundle(bundle, validate_schema=use_schema)
        except PolicyBundleError as exc:
            assert str(exc) == expected_reason, str(exc)
            continue
        raise AssertionError(
            f"compiler accepted policy expected to fail with: {expected_reason}; "
            f"validate_schema={use_schema}"
        )


def assert_injection_rejected(bundle: dict, message: str, *, validate_schema: bool) -> None:
    assert_policy_rejected(bundle, message, validate_schema=validate_schema)
    if not validate_schema:
        return
    try:
        validate_policy_schema(bundle)
    except PolicyBundleError:
        return
    raise AssertionError(f"policy schema accepted {message}")


def _proxy_http_headers(sock: socket.socket) -> bytes:
    received = bytearray()
    while b"\r\n\r\n" not in received:
        chunk = sock.recv(4096)
        if not chunk:
            break
        received.extend(chunk)
        if len(received) > 65536:
            raise AssertionError("proxy returned oversized CONNECT response headers")
    return bytes(received)


def _assert_no_upstream_connection(listener: socket.socket, label: str) -> None:
    listener.settimeout(0.5)
    try:
        upstream, _address = listener.accept()
    except TimeoutError:
        return
    try:
        upstream.settimeout(0.1)
        try:
            payload = upstream.recv(4096)
        except TimeoutError:
            payload = b""
    finally:
        upstream.close()
    raise AssertionError(f"{label} reached the upstream TCP listener: {payload!r}")


def _live_proxy_transport_assertions(runner_module) -> None:
    from serverware.config import POLICY_BUNDLE_PATH

    bundle = demo_policy_bundle("cred-demo-bearer")
    echo_route = next(item for item in bundle["routes"] if item["id"] == "demo.echo")

    upstream_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream_listener.bind(("127.0.0.1", 0))
    upstream_listener.listen(8)
    upstream_port = upstream_listener.getsockname()[1]
    echo_route["match"]["host"] = "localhost"
    echo_route["match"]["port"] = upstream_port
    signed_bundle = sign_policy_bundle(bundle)
    compile_policy_bundle(signed_bundle, verify_signature=True, validate_schema=True)
    POLICY_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    POLICY_BUNDLE_PATH.write_text(canonical_json(signed_bundle), encoding="utf-8")

    port_reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_reservation.bind(("127.0.0.1", 0))
    proxy_port = port_reservation.getsockname()[1]
    port_reservation.close()

    command = runner_module._mitmdump_command()
    command[command.index("--listen-host") + 1] = "127.0.0.1"
    command[command.index("--listen-port") + 1] = str(proxy_port)
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(ROOT), env.get("PYTHONPATH", "")) if item
    )
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    def open_connect(agent: str) -> tuple[socket.socket, bytes]:
        tunnel = socket.create_connection(("127.0.0.1", proxy_port), timeout=2)
        tunnel.settimeout(2)
        tunnel.sendall(
            (
                f"CONNECT localhost:{upstream_port} HTTP/1.1\r\n"
                f"Host: localhost:{upstream_port}\r\n"
                f"X-Serverware-Agent: {agent}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        return tunnel, _proxy_http_headers(tunnel)

    try:
        deadline = time.monotonic() + 8
        while True:
            if process.poll() is not None:
                output = process.communicate()[0]
                raise AssertionError(f"mitmdump exited before live assertions:\n{output}")
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError("mitmdump did not listen within 8 seconds")
                time.sleep(0.05)

        denied_tunnel, denied_headers = open_connect("not-admitted")
        denied_tunnel.close()
        assert denied_headers.startswith(b"HTTP/1.1 403"), denied_headers
        _assert_no_upstream_connection(upstream_listener, "unadmitted CONNECT")

        admitted_tunnel, admitted_headers = open_connect("demo-agent")
        assert admitted_headers.startswith(b"HTTP/1.1 200"), admitted_headers
        admitted_tunnel.sendall(b"SERVERWARE-UNKNOWN-RAW-TCP\x00\x01\x02")
        admitted_tunnel.close()
        _assert_no_upstream_connection(upstream_listener, "raw TCP after admitted CONNECT")

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE

        matching_tunnel, matching_headers = open_connect("demo-agent")
        assert matching_headers.startswith(b"HTTP/1.1 200"), matching_headers
        matching_tls = tls_context.wrap_socket(
            matching_tunnel,
            server_hostname="localhost",
        )
        matching_tls.close()
        _assert_no_upstream_connection(upstream_listener, "matching SNI handshake")

        for server_hostname, label in (
            ("mismatch.example.test", "mismatched SNI"),
            (None, "absent SNI for DNS CONNECT authority"),
        ):
            invalid_tunnel, invalid_headers = open_connect("demo-agent")
            assert invalid_headers.startswith(b"HTTP/1.1 200"), invalid_headers
            try:
                invalid_tls = tls_context.wrap_socket(
                    invalid_tunnel,
                    server_hostname=server_hostname,
                )
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            else:
                invalid_tls.close()
                raise AssertionError(f"{label} completed a TLS handshake")
            _assert_no_upstream_connection(upstream_listener, label)
    finally:
        upstream_listener.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)


def run_proxy_transport_assertions() -> None:
    if ServerwareAddon is None:
        raise AssertionError("proxy transport assertions did not import the mitmproxy addon")
    assert version("mitmproxy") == "11.0.2"

    from mitmproxy import connection, http, tls
    from mitmproxy.options import Options
    from mitmproxy.proxy.context import Context
    from serverware import mitm_addon, runner

    expected_command = [
        "mitmdump",
        "--listen-host",
        runner.PROXY_HOST,
        "--listen-port",
        str(runner.PROXY_PORT),
        "--set",
        f"confdir={runner.MITMPROXY_CONF_DIR}",
        "--set",
        "rawtcp=false",
        "--set",
        "connection_strategy=lazy",
        "--set",
        "ssl_insecure=false",
        "--set",
        "block_global=false",
        "-s",
        str(Path(runner.__file__).with_name("mitm_addon.py")),
    ]
    assert runner._mitmdump_command() == expected_command
    assert "ssl_insecure=true" not in runner._mitmdump_command()

    production_env = os.environ.copy()
    production_env["SERVERWARE_RELEASE_CHANNEL"] = "production"
    production_env["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(ROOT), production_env.get("PYTHONPATH", "")) if item
    )
    for module_name, expected_error in (
        ("serverware.runner", "legacy Python mitmproxy transport is development-only"),
        ("serverware.mitm_addon", "legacy Python mitmproxy addon is development-only"),
    ):
        result = subprocess.run(
            [sys.executable, "-c", f"import {module_name}"],
            cwd=ROOT,
            env=production_env,
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode != 0, module_name
        assert expected_error in result.stderr, result.stderr

    addon = ServerwareAddon()
    original_snapshot = mitm_addon.get_policy_snapshot
    original_log_request = runtime.log_request
    route_policy = SimpleNamespace(
        scheme="https",
        host="connect.example.test",
        port=443,
        principals=("agent:connect-assigned",),
    )

    def identify_principal(_client_ip, headers):
        if headers.get("X-Serverware-Agent") == "connect-agent":
            return SimpleNamespace(id="agent:connect-assigned")
        return None

    snapshot = SimpleNamespace(
        routes=(route_policy,),
        identify_principal=identify_principal,
    )

    def connect_flow(agent: str):
        client = connection.Client(
            peername=("127.0.0.1", 51234),
            sockname=("127.0.0.1", 8080),
            state=connection.ConnectionState.OPEN,
        )
        server = connection.Server(
            address=("connect.example.test", 443),
            state=connection.ConnectionState.CLOSED,
        )
        item = http.HTTPFlow(client, server)
        item.request = http.Request.make(
            "CONNECT",
            "https://connect.example.test:443",
            headers={"X-Serverware-Agent": agent},
        )
        return item

    def client_hello_data(item, sni):
        context = Context(item.client_conn, Options())
        context.server = item.server_conn
        return tls.ClientHelloData(context, SimpleNamespace(sni=sni))

    mitm_addon.get_policy_snapshot = lambda: snapshot
    runtime.log_request = lambda *_args, **_kwargs: None
    try:
        denied = connect_flow("not-admitted")
        addon.http_connect(denied)
        assert denied.response.status_code == 403
        assert denied.metadata["serverware_blocked_response"] is True

        admitted = connect_flow("connect-agent")
        addon.http_connect(admitted)
        assert admitted.response is None
        matching = client_hello_data(admitted, "CONNECT.EXAMPLE.TEST.")
        addon.tls_clienthello(matching)
        assert matching.context.client.state is connection.ConnectionState.OPEN
        assert matching.context.client.error is None

        absent = connect_flow("connect-agent")
        addon.http_connect(absent)
        absent_data = client_hello_data(absent, None)
        addon.tls_clienthello(absent_data)
        assert absent_data.context.client.state is connection.ConnectionState.CLOSED
        assert "SNI is required" in absent_data.context.client.error

        mismatched = connect_flow("connect-agent")
        addon.http_connect(mismatched)
        mismatched_data = client_hello_data(mismatched, "other.example.test")
        addon.tls_clienthello(mismatched_data)
        assert mismatched_data.context.client.state is connection.ConnectionState.CLOSED
        assert "does not match" in mismatched_data.context.client.error

        wrong_authority = connect_flow("connect-agent")
        addon.http_connect(wrong_authority)
        wrong_authority.server_conn.address = ("connect.example.test", 444)
        wrong_authority_data = client_hello_data(
            wrong_authority,
            "connect.example.test",
        )
        addon.tls_clienthello(wrong_authority_data)
        assert wrong_authority_data.context.client.state is connection.ConnectionState.CLOSED
        assert "tunnel authority does not match" in wrong_authority_data.context.client.error

        unadmitted = connect_flow("not-admitted")
        unadmitted_data = client_hello_data(unadmitted, "connect.example.test")
        addon.tls_clienthello(unadmitted_data)
        assert unadmitted_data.context.client.state is connection.ConnectionState.CLOSED
        assert "without an admitted CONNECT" in unadmitted_data.context.client.error

        addon.client_disconnected(admitted.client_conn)
        disconnected_data = client_hello_data(admitted, "connect.example.test")
        addon.tls_clienthello(disconnected_data)
        assert disconnected_data.context.client.state is connection.ConnectionState.CLOSED
    finally:
        runtime.log_request = original_log_request
        mitm_addon.get_policy_snapshot = original_snapshot

    _live_proxy_transport_assertions(runner)
    print("proxy transport assertions passed; mitmproxy=11.0.2")


def main() -> None:
    if PROXY_TRANSPORT_ONLY:
        run_proxy_transport_assertions()
        return
    db.init_db()
    validate_schema = schema_validation_available()
    demo_bundle = demo_policy_bundle("cred-demo-bearer")
    for encoded in (
        '{"duplicate":1,"duplicate":1}',
        '{"number":NaN}',
        '{"number":Infinity}',
        '{"number":-Infinity}',
        '{"number":1e400}',
        '{"number":' + "1" + "0" * 400 + "}",
    ):
        try:
            strict_json_loads(encoded)
        except ValueError:
            pass
        else:
            raise AssertionError(f"strict JSON decoder accepted invalid input: {encoded[:80]}")

    for value in (float("nan"), float("inf"), float("-inf"), 10**400):
        try:
            canonical_json({"number": value})
        except ValueError:
            pass
        else:
            raise AssertionError(f"canonical JSON accepted an invalid number: {value!r}")

        invalid = copy.deepcopy(demo_bundle)
        invalid["metadata"]["sequence"] = value
        try:
            sign_policy_bundle(invalid)
        except PolicyBundleError:
            pass
        else:
            raise AssertionError(f"policy signer accepted an invalid number: {value!r}")

    signed_demo = sign_policy_bundle(demo_bundle)
    compile_policy_bundle(signed_demo, verify_signature=True, validate_schema=validate_schema)
    duplicate_signed_json = json.dumps(signed_demo, sort_keys=True).replace(
        '"kind": "PolicyBundle"',
        '"kind": "PolicyBundle", "kind": "PolicyBundle"',
        1,
    )
    duplicate_signed_path = Path(tmpdir.name) / "duplicate-signed-policy.json"
    duplicate_signed_path.write_text(duplicate_signed_json)
    try:
        _load_raw_policy(duplicate_signed_path)
    except ValueError:
        pass
    else:
        raise AssertionError("strict policy loading accepted duplicate keys in a validly signed policy")

    checked_in_demo = json.loads((ROOT / "policies" / "demo.policy.json").read_text())
    assert checked_in_demo == demo_bundle, "policies/demo.policy.json drifted from demo_policy_bundle()"
    demo = compile_policy_bundle(demo_bundle, validate_schema=validate_schema)
    examples = json.loads((ROOT / "policies" / "credential-limits.examples.json").read_text())
    example_snapshot = compile_policy_bundle(examples, validate_schema=validate_schema)

    unknown_field_mutations: list[tuple[str, dict]] = []

    unknown_top = copy.deepcopy(examples)
    unknown_top["unknownPolicyField"] = True
    unknown_field_mutations.append(("top-level", unknown_top))

    unknown_default = copy.deepcopy(examples)
    unknown_default["defaults"]["unknownDefaultField"] = True
    unknown_field_mutations.append(("defaults", unknown_default))

    unknown_route = copy.deepcopy(examples)
    unknown_route["routes"][0]["unknownRouteField"] = True
    unknown_field_mutations.append(("route", unknown_route))

    unknown_jit = copy.deepcopy(examples)
    jit_route = next(item for item in unknown_jit["routes"] if "jit" in item)
    jit_route["jit"]["unknownJitField"] = True
    unknown_field_mutations.append(("JIT", unknown_jit))

    unknown_generic_request = copy.deepcopy(examples)
    generic_route = next(
        item for item in unknown_generic_request["routes"] if item["adapter"]["type"] == "generic.rest"
    )
    generic_route["adapter"]["config"]["request"]["unknownRequestField"] = True
    unknown_field_mutations.append(("generic request", unknown_generic_request))

    for layer, mutation in unknown_field_mutations:
        assert_policy_rejected(
            mutation,
            f"compiler accepted an unknown {layer} policy field",
            validate_schema=validate_schema,
        )
        assert_signed_policy_rejected(
            mutation,
            f"signed compiler path accepted an unknown {layer} policy field",
            validate_schema=validate_schema,
        )

    for aliases, subject in (
        (("x", "twitter", "x.oauth", "x.oauth2", " X.OAUTH2 "), "verified-x-user-id"),
        (("google", "google.oauth", "google.oauth2", " GOOGLE.OAUTH2 "), "verified-google-sub"),
    ):
        alias_scopes = {provider_account_scope_value(alias, subject) for alias in aliases}
        assert len(alias_scopes) == 1, (aliases, alias_scopes)
        assert None not in alias_scopes
        assert provider_account_scope_value(aliases[0], f"{subject}-other") not in alias_scopes

    object_store_example = next(
        item for item in examples["routes"] if item["id"] == "example.object_store.small_puts"
    )
    object_store_operation = object_store_example["adapter"]["config"]["request"]["operation"]
    object_store_body_constraint = next(
        constraint
        for constraint in object_store_example["constraints"]
        if constraint["type"] == "jsonBody"
    )
    assert object_store_operation["bodySha256Field"] == "requestBodySha256"
    assert "sha256" not in object_store_operation.get("jsonFields", [])
    assert "sha256" not in object_store_body_constraint["allowedFields"]
    assert "sha256" not in object_store_body_constraint["requiredFields"]
    assert list(example_snapshot.credentials["cred-gmail"].scopes) == [
        "openid",
        "email",
        "https://www.googleapis.com/auth/gmail.readonly",
    ]
    for credential_id in ("cred-gmail", "cred-x"):
        assert example_snapshot.credentials[credential_id].injection == {
            "type": "bearer",
            "header": "Authorization",
            "field": "access_token",
        }
    assert example_snapshot.credentials["cred-object-store"].injection == {
        "type": "header",
        "name": "X-Api-Key",
    }
    assert example_snapshot.credentials["cred-basic-structured"].injection == {
        "type": "basic",
        "username": "service-account",
        "field": "password",
    }
    assert example_snapshot.credentials["cred-query-structured"].injection == {
        "type": "query",
        "name": "api_key",
        "field": "credentials.api_key",
    }
    assert example_snapshot.credentials["cred-cookie-structured"].injection == {
        "type": "cookie",
        "name": "session_token",
        "field": "session.token",
    }
    example_route_ids = {route.id for route in example_snapshot.routes}
    for route_id in (
        "example.basic.structured_secret_read",
        "example.query.structured_secret_read",
        "example.cookie.structured_secret_read",
    ):
        assert route_id in example_route_ids
    valid_injections = (
        {"type": "bearer"},
        {"type": "bearer", "header": "Authorization", "field": "access_token", "prefix": "Bearer "},
        {"type": "basic", "username": "service-account", "header": "Authorization", "field": "password"},
        {"type": "header", "name": "X-Api-Key", "field": "api.key", "prefix": "Token "},
        {"type": "query", "name": "api_key", "field": "token"},
        {"type": "cookie", "name": "session_token", "field": "token"},
    )
    for injection in valid_injections:
        valid = copy.deepcopy(demo_bundle)
        valid["credentials"][0]["injection"] = injection
        compiled = compile_policy_bundle(valid, validate_schema=validate_schema)
        assert compiled.credentials["cred-demo-bearer"].injection == injection

    invalid_injections = (
        ({}, "an injection without a type"),
        ({"type": "basic"}, "Basic injection without a username"),
        ({"type": "basic", "username": ""}, "Basic injection with an empty username"),
        ({"type": "basic", "username": 7}, "Basic injection with a non-string username"),
        ({"type": "basic", "username": "user:name"}, "Basic injection with a colon in its username"),
        ({"type": "basic", "username": "user name"}, "Basic injection with whitespace in its username"),
        ({"type": "basic", "username": "a" * 257}, "Basic injection with an oversized username"),
        ({"type": "header"}, "header injection without a name"),
        ({"type": "query"}, "query injection without a name"),
        ({"type": "cookie"}, "cookie injection without a name"),
        ({"type": "header", "name": ""}, "header injection with an empty name"),
        ({"type": "query", "name": ""}, "query injection with an empty name"),
        ({"type": "cookie", "name": ""}, "cookie injection with an empty name"),
        ({"type": "header", "name": "Bad Header"}, "header injection with an invalid name"),
        ({"type": "query", "name": "api key"}, "query injection with an invalid name"),
        ({"type": "cookie", "name": "session;token"}, "cookie injection with an invalid name"),
        ({"type": "query", "name": "a" * 129}, "query injection with an oversized name"),
        ({"type": "header", "name": "Authorization"}, "custom header injection into Authorization"),
        ({"type": "bearer", "header": "Host"}, "bearer injection into Host"),
        ({"type": "basic", "username": "service", "header": "Cookie"}, "Basic injection into Cookie"),
        ({"type": "header", "name": "X-Serverware-Admin-Token"}, "header injection into service auth"),
        ({"type": "bearer", "name": "X-Api-Key"}, "bearer injection with a header-only name field"),
        ({"type": "basic", "username": "service", "prefix": "Basic "}, "Basic injection with a prefix"),
        ({"type": "header", "name": "X-Api-Key", "username": "service"}, "header injection with a username"),
        ({"type": "query", "name": "api_key", "prefix": "Token "}, "query injection with a prefix"),
        ({"type": "cookie", "name": "session_token", "header": "Cookie"}, "cookie injection with a header"),
        ({"type": "bearer", "header": 7}, "bearer injection with a non-string header"),
        ({"type": "header", "name": 7}, "header injection with a non-string name"),
        ({"type": "bearer", "field": ["access_token"]}, "bearer injection with a non-string field"),
        ({"type": "bearer", "prefix": "Bearer\r\nX-Evil: 1"}, "bearer injection with a multiline prefix"),
        ({"type": "bearer", "unknown": True}, "bearer injection with an unknown field"),
        ({"type": "unsupported"}, "unsupported injection type"),
    )
    for injection, description in invalid_injections:
        invalid = copy.deepcopy(demo_bundle)
        invalid["credentials"][0]["injection"] = injection
        assert_injection_rejected(
            invalid,
            f"compiler accepted {description}",
            validate_schema=validate_schema,
        )
    missing_injection = copy.deepcopy(demo_bundle)
    missing_injection["credentials"][0].pop("injection")
    assert_injection_rejected(
        missing_injection,
        "compiler accepted a credential without an injection declaration",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    stripe = next(
        item for item in invalid["routes"] if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe["adapter"]["config"]["request"]["requiredHeaders"]["idempotency-key"]["type"] = "integer"
    assert_policy_rejected(
        invalid,
        "compiler accepted a non-string generic required header",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    stripe = next(
        item for item in invalid["routes"] if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe["adapter"]["config"]["request"]["requiredHeaders"]["idempotency-key"]["maxLength"] = 9000
    assert_policy_rejected(
        invalid,
        "compiler accepted an unbounded generic required header",
        validate_schema=validate_schema,
    )

    def response_binding_candidate() -> tuple[dict, dict]:
        candidate = copy.deepcopy(examples)
        stripe_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.stripe.payment_intent.tokenized_jit"
        )
        binding_constraint = next(
            constraint
            for constraint in stripe_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        return candidate, binding_constraint

    def json_path_response_binding_candidate() -> tuple[dict, dict, dict]:
        candidate, binding_constraint = response_binding_candidate()
        route_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.stripe.payment_intent.tokenized_jit"
        )
        route_candidate["match"]["paths"] = ["/v1/payment_intents/{payment_intent_id}"]
        request = route_candidate["adapter"]["config"]["request"]
        request["bodyMode"] = "json"
        request["operation"] = {
            "name": "stripe.payment_intents.create",
            "jsonFields": ["amount", "currency", "payment_method"],
            "pathParams": ["payment_intent_id"],
        }
        form_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "formBody"
        )
        form_constraint.clear()
        form_constraint.update(
            {
                "id": "payment-intent-json",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["amount", "currency", "payment_method"],
                "requiredFields": ["amount", "currency", "payment_method"],
                "fields": {
                    "amount": {"type": "integer", "min": 50, "max": 50000},
                    "currency": {"type": "string", "equals": "usd"},
                    "payment_method": {
                        "type": "string",
                        "pattern": "^pm_[A-Za-z0-9]{8,64}$",
                        "maxLength": 67,
                    },
                },
            }
        )
        binding_constraint["bindings"].append(
            {
                "id": "payment-intent-id",
                "operationField": "payment_intent_id",
                "responseField": "id",
                "comparison": "exactString",
            }
        )
        return candidate, route_candidate, binding_constraint

    def generated_response_bindings(count: int) -> list[dict]:
        return [
            {
                "id": f"binding-{index}",
                "operationField": "amount",
                "responseField": f"field_{index}",
                "comparison": "canonicalInteger",
            }
            for index in range(count)
        ]

    def body_sha256_candidate() -> tuple[dict, dict, dict]:
        candidate = copy.deepcopy(examples)
        route_candidate = next(
            item
            for item in candidate["routes"]
            if item["id"] == "example.object_store.small_puts"
        )
        binding_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        return candidate, route_candidate, binding_constraint

    for binding_count in (1, 8):
        valid, response_binding = response_binding_candidate()
        response_binding["bindings"] = generated_response_bindings(binding_count)
        compile_policy_bundle(valid, validate_schema=validate_schema)
    for binding_count in (0, 9):
        invalid, response_binding = response_binding_candidate()
        response_binding["bindings"] = generated_response_bindings(binding_count)
        assert_policy_rejected(
            invalid,
            f"compiler accepted {binding_count} response bindings",
            validate_schema=validate_schema,
        )

    valid_json_path, _, _ = json_path_response_binding_candidate()
    json_path_snapshot = compile_policy_bundle(valid_json_path, validate_schema=validate_schema)

    valid_body_sha256, _, _ = body_sha256_candidate()
    compile_policy_bundle(valid_body_sha256, validate_schema=validate_schema)

    valid_form_body_sha256, form_binding = response_binding_candidate()
    form_route = next(
        item
        for item in valid_form_body_sha256["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_route["adapter"]["config"]["request"]["operation"]["bodySha256Field"] = (
        "requestBodySha256"
    )
    form_binding["bindings"].append(
        {
            "id": "request-body-sha256",
            "operationField": "requestBodySha256",
            "responseField": "request_body_sha256",
            "comparison": "exactString",
        }
    )
    compile_policy_bundle(valid_form_body_sha256, validate_schema=validate_schema)

    for invalid_mode in (
        "none",
        "any",
        "stream",
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        invalid, route_candidate, binding_constraint = body_sha256_candidate()
        route_candidate.pop("credentialRef")
        route_candidate["adapter"]["config"]["request"]["bodyMode"] = invalid_mode
        route_candidate["constraints"] = [
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] != "jsonBody"
        ]
        binding_constraint = next(
            constraint
            for constraint in route_candidate["constraints"]
            if constraint["type"] == "responseBinding"
        )
        binding_constraint["bindings"] = [binding_constraint["bindings"][-1]]
        assert_policy_rejected(
            invalid,
            f"compiler accepted bodySha256Field with non-buffered body mode {invalid_mode}",
            validate_schema=validate_schema,
        )

    for invalid_name in (None, "operation", "1digest", "digest/value", "a" * 129):
        invalid, route_candidate, _ = body_sha256_candidate()
        route_candidate["adapter"]["config"]["request"]["operation"]["bodySha256Field"] = (
            invalid_name
        )
        assert_policy_rejected(
            invalid,
            f"compiler accepted invalid bodySha256Field name {invalid_name!r}",
            validate_schema=validate_schema,
        )

    for source_key, source_value in (
        ("jsonFields", ["requestBodySha256"]),
        ("pathParams", ["requestBodySha256"]),
        ("formFields", ["requestBodySha256"]),
    ):
        invalid, route_candidate, _ = body_sha256_candidate()
        request = route_candidate["adapter"]["config"]["request"]
        if source_key == "formFields":
            route_candidate.pop("credentialRef")
            request["bodyMode"] = "formUrlencoded"
            route_candidate["constraints"] = [
                constraint
                for constraint in route_candidate["constraints"]
                if constraint["type"] != "jsonBody"
            ]
        request["operation"][source_key] = source_value
        assert_policy_rejected(
            invalid,
            f"compiler accepted bodySha256Field duplicated by {source_key}",
            validate_schema=validate_schema,
        )

    invalid, _, binding_constraint = body_sha256_candidate()
    digest_binding = next(
        binding
        for binding in binding_constraint["bindings"]
        if binding["operationField"] == "requestBodySha256"
    )
    digest_binding["comparison"] = "canonicalInteger"
    assert_policy_rejected(
        invalid,
        "compiler accepted canonicalInteger for a bodySha256Field response binding",
        validate_schema=validate_schema,
    )

    valid_path_only, path_only_route, path_only_binding = json_path_response_binding_candidate()
    path_only_request = path_only_route["adapter"]["config"]["request"]
    path_only_request["bodyMode"] = "none"
    path_only_request["maxBodyBytes"] = 0
    path_only_request["operation"].pop("jsonFields")
    path_only_route["constraints"] = [
        constraint
        for constraint in path_only_route["constraints"]
        if constraint["type"] != "jsonBody"
    ]
    path_only_binding["bindings"] = [
        {
            "id": "payment-intent-id",
            "operationField": "payment_intent_id",
            "responseField": "id",
            "comparison": "exactString",
        }
    ]
    compile_policy_bundle(valid_path_only, validate_schema=validate_schema)

    valid_stable_path_source, stable_path_route, _ = json_path_response_binding_candidate()
    stable_path_route["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{left}",
        "/v1/payment_intents/{payment_intent_id}/{right}",
    ]
    compile_policy_bundle(valid_stable_path_source, validate_schema=validate_schema)

    for operation_update, description in (
        ({"jsonFields": ["operation"]}, "the reserved operation field as a JSON source"),
        ({"formFields": ["currency"]}, "mixed form and JSON source kinds"),
        ({"pathParams": ["currency"]}, "a source duplicated across JSON and path sources"),
        ({"jsonFields": ["amount", "amount"]}, "duplicate JSON sources"),
        ({"jsonFields": ["metadata.id"]}, "a dotted JSON source"),
        ({"jsonFields": None}, "a null JSON source declaration"),
        ({"jsonFields": ["amount", []]}, "a non-string JSON source"),
        ({"jsonFields": [f"field_{index}" for index in range(17)]}, "more than 16 JSON sources"),
    ):
        invalid, route_candidate, _ = json_path_response_binding_candidate()
        route_candidate["adapter"]["config"]["request"]["operation"].update(operation_update)
        assert_policy_rejected(
            invalid,
            f"compiler accepted {description}",
            validate_schema=validate_schema,
        )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["adapter"]["config"]["request"]["bodyMode"] = "formUrlencoded"
    assert_policy_rejected(
        invalid,
        "compiler accepted JSON operation sources for a form request",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["adapter"]["config"]["request"]["operation"]["pathParams"] = ["missing_id"]
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source absent from the matched path",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"].append("/v1/payment_intents/static")
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source absent from one matched path",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{other}",
        "/v1/payment_intents/{other}/{payment_intent_id}",
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted a path source mapped to different positions in ambiguous templates",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    route_candidate["match"]["paths"] = [
        "/v1/payment_intents/{payment_intent_id}/{payment_intent_id}"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted a repeated path placeholder",
        validate_schema=validate_schema,
    )

    invalid, _, binding_constraint = json_path_response_binding_candidate()
    binding_constraint["bindings"][-1]["comparison"] = "canonicalInteger"
    assert_policy_rejected(
        invalid,
        "compiler accepted canonicalInteger for a path source",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    json_constraint = next(
        constraint for constraint in route_candidate["constraints"] if constraint["type"] == "jsonBody"
    )
    json_constraint["requiredFields"].remove("amount")
    assert_policy_rejected(
        invalid,
        "compiler accepted an optional JSON response binding source",
        validate_schema=validate_schema,
    )

    invalid, route_candidate, _ = json_path_response_binding_candidate()
    json_constraint = next(
        constraint for constraint in route_candidate["constraints"] if constraint["type"] == "jsonBody"
    )
    json_constraint["fields"]["amount"] = {"type": "string", "maxLength": 20}
    assert_policy_rejected(
        invalid,
        "compiler accepted a mistyped JSON response binding source",
        validate_schema=validate_schema,
    )

    invalid, response_binding = response_binding_candidate()
    response_binding["phase"] = "request"
    assert_policy_rejected(
        invalid,
        "compiler accepted a response binding in the request phase",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["unexpected"] = True
    assert_policy_rejected(
        invalid,
        "compiler accepted an extra response binding constraint field",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["unexpected"] = True
    assert_policy_rejected(
        invalid,
        "compiler accepted an extra response binding field",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][1]["id"] = response_binding["bindings"][0]["id"]
    assert_policy_rejected(
        invalid,
        "compiler accepted duplicate response binding ids",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][1]["responseField"] = response_binding["bindings"][0][
        "responseField"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted duplicate response binding paths",
        validate_schema=validate_schema,
    )
    for malformed_path in (".amount", "amount.", "amount..value", "amount[*]"):
        invalid, response_binding = response_binding_candidate()
        response_binding["bindings"][0]["responseField"] = malformed_path
        assert_policy_rejected(
            invalid,
            f"compiler accepted malformed response binding path {malformed_path!r}",
            validate_schema=validate_schema,
        )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["comparison"] = "caseInsensitive"
    assert_policy_rejected(
        invalid,
        "compiler accepted an unsupported response binding comparison",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    response_binding["bindings"][0]["operationField"] = "uncaptured"
    assert_policy_rejected(
        invalid,
        "compiler accepted a response binding source not captured by the operation classifier",
        validate_schema=validate_schema,
    )
    for missing_field in ("successStatusCodes", "contentTypes"):
        invalid, response_binding = response_binding_candidate()
        response_binding.pop(missing_field)
        assert_policy_rejected(
            invalid,
            f"compiler accepted response binding without {missing_field}",
            validate_schema=validate_schema,
        )
    for field, value in (
        ("successStatusCodes", [199]),
        ("successStatusCodes", [200, 200]),
        ("contentTypes", ["Application/JSON"]),
        ("contentTypes", ["application/json", "application/json"]),
    ):
        invalid, response_binding = response_binding_candidate()
        response_binding[field] = value
        assert_policy_rejected(
            invalid,
            f"compiler accepted invalid response binding {field}",
            validate_schema=validate_schema,
        )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_constraint = next(
        constraint
        for constraint in stripe_candidate["constraints"]
        if constraint["type"] == "formBody"
    )
    form_constraint["requiredFields"].remove("amount")
    assert_policy_rejected(
        invalid,
        "compiler accepted an optional response binding source",
        validate_schema=validate_schema,
    )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    form_constraint = next(
        constraint
        for constraint in stripe_candidate["constraints"]
        if constraint["type"] == "formBody"
    )
    form_constraint["fields"]["amount"]["type"] = "string"
    form_constraint["fields"]["amount"].pop("min")
    form_constraint["fields"]["amount"].pop("max")
    assert_policy_rejected(
        invalid,
        "compiler accepted a mistyped response binding source",
        validate_schema=validate_schema,
    )
    invalid, _ = response_binding_candidate()
    stripe_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    stripe_candidate["adapter"]["config"]["response"]["mode"] = "stream"
    assert_policy_rejected(
        invalid,
        "compiler accepted a streaming response binding",
        validate_schema=validate_schema,
    )
    invalid, response_binding = response_binding_candidate()
    gmail_candidate = next(
        item
        for item in invalid["routes"]
        if item["id"] == "example.gmail.last_30_days"
    )
    gmail_candidate["constraints"].append(copy.deepcopy(response_binding))
    assert_policy_rejected(
        invalid,
        "compiler accepted response binding on a non-generic adapter",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    object_store = next(item for item in invalid["routes"] if item["id"] == "example.object_store.small_puts")
    object_store["adapter"]["config"]["request"]["allowedHeaders"].append("x-api-key")
    assert_policy_rejected(
        invalid,
        "compiler accepted an agent header collision with credential injection",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    object_store_credential = next(item for item in invalid["credentials"] if item["id"] == "cred-object-store")
    object_store_credential["injection"] = {"type": "query", "name": "api_key"}
    object_store = next(item for item in invalid["routes"] if item["id"] == "example.object_store.small_puts")
    object_store["adapter"]["config"]["request"]["allowedQueryKeys"].append("api_key")
    assert_policy_rejected(
        invalid,
        "compiler accepted an agent query collision with credential injection",
        validate_schema=validate_schema,
    )
    for provider, subject in (
        ("generic", "verified-subject"),
        ("", "verified-subject"),
        (None, "verified-subject"),
        ("google", " leading-space"),
        ("google", "control\x00character"),
    ):
        invalid_subject = copy.deepcopy(examples)
        credential = invalid_subject["credentials"][1]
        if provider is None:
            credential.pop("provider", None)
        else:
            credential["provider"] = provider
        credential["providerSubject"] = subject
        assert_policy_rejected(
            invalid_subject,
            f"compiler accepted invalid provider subject binding {provider!r} {subject!r}",
            validate_schema=validate_schema,
        )
    x_write_example = next(
        item for item in examples["routes"] if item["id"] == "example.x.tweet.one_per_day"
    )
    account_quota = next(
        item for item in x_write_example["constraints"] if item["type"] == "rateLimit"
    )
    assert account_quota["key"] == {
        "scope": ["route", "operation"],
        "operationFields": ["providerAccount"],
    }
    invalid = copy.deepcopy(examples)
    x_credential = next(item for item in invalid["credentials"] if item["id"] == "cred-x")
    x_credential["provider"] = "custom-x"
    x_credential.pop("providerSubject")
    assert_policy_rejected(
        invalid,
        "compiler accepted a provider-account quota without account identity",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    invalid_x_write = next(
        item for item in invalid["routes"] if item["id"] == "example.x.tweet.one_per_day"
    )
    invalid_quota = next(
        item for item in invalid_x_write["constraints"] if item["type"] == "rateLimit"
    )
    invalid_quota["key"]["scope"].append("principal")
    assert_policy_rejected(
        invalid,
        "compiler accepted a provider-account quota partitioned by principal",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(examples)
    invalid_recent = next(
        item for item in invalid["routes"] if item["id"] == "example.x.search.seven_days"
    )
    invalid_recent["match"]["paths"] = ["/2/tweets/search/all"]
    assert_policy_rejected(
        invalid,
        "compiler accepted an X historical endpoint in recent-search mode",
        validate_schema=validate_schema,
    )
    x_schema = json.loads((ROOT / "schemas" / "adapters" / "x.v2.schema.json").read_text())
    x_schema_operations = set(x_schema["properties"]["allowedReadOperations"]["items"]["enum"])
    assert x_schema_operations == X_V2_READ_OPERATIONS
    assert X_V2_BOUNDED_READ_OPERATIONS == X_V2_READ_OPERATIONS - {"streams.read"}
    assert X_V2_RECENT_SEARCH_PATHS == {
        "/2/tweets/counts/recent",
        "/2/tweets/search/recent",
    }
    for operation, templates in X_V2_READ_OPERATION_PATHS:
        for template in templates:
            concrete_path = "/".join(
                "catalog-value" if segment.startswith("{") and segment.endswith("}") else segment
                for segment in template.split("/")
            )
            assert _x_read_operation(concrete_path) == operation, (concrete_path, operation)
    if validate_schema:
        invalid_field = json.loads(json.dumps(examples))
        invalid_field["credentials"][0]["injection"]["field"] = "*.access_token"
        try:
            compile_policy_bundle(invalid_field, validate_schema=True)
        except Exception:
            pass
        else:
            raise AssertionError("schema accepted wildcard credential injection field")

    for invalid_mode in ("bogus", 7, None):
        invalid = copy.deepcopy(demo_bundle)
        invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = invalid_mode
        assert_policy_rejected(
            invalid,
            f"compiler accepted unsupported response mode {invalid_mode!r}",
            validate_schema=validate_schema,
        )
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"].pop("mode")
    assert_policy_rejected(invalid, "compiler accepted a missing response mode", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["response"]["mode"] = "any"
    assert_policy_rejected(
        invalid,
        "compiler accepted an opaque credential-bearing response",
        validate_schema=validate_schema,
    )
    explicit_opaque = copy.deepcopy(demo_bundle)
    explicit_opaque_route = explicit_opaque["routes"][0]
    explicit_opaque_route.pop("credentialRef")
    explicit_opaque_route.pop("constraints", None)
    explicit_opaque_route["adapter"]["config"]["request"]["bodyMode"] = "any"
    explicit_opaque_response = explicit_opaque_route["adapter"]["config"]["response"]
    explicit_opaque_response["mode"] = "any"
    explicit_opaque_response.pop("allowedFields")
    explicit_opaque_snapshot = compile_policy_bundle(
        explicit_opaque,
        validate_schema=validate_schema,
    )
    assert route(explicit_opaque_snapshot, "demo.echo").credential_ref is None
    for projection_value, failure in (
        (None, "is missing allowedFields"),
        ([], "allowedFields must not be empty"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        generic_response = invalid["routes"][0]["adapter"]["config"]["response"]
        if projection_value is None:
            generic_response.pop("allowedFields")
        else:
            generic_response["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.echo credential-bearing JSON success response {failure}",
            validate_schema=validate_schema,
        )

        invalid = copy.deepcopy(demo_bundle)
        x_write = next(item for item in invalid["routes"] if item["id"] == "demo.x.tweet.one_per_day")
        if projection_value is None:
            x_write["adapter"]["config"]["response"].pop("allowedFields")
        else:
            x_write["adapter"]["config"]["response"]["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.x.tweet.one_per_day credential-bearing JSON success response {failure}",
            validate_schema=validate_schema,
        )

    for response_mode in (
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        for projection_value, failure in (
            (None, "is missing allowedFields"),
            ([], "allowedFields must not be empty"),
        ):
            invalid = copy.deepcopy(demo_bundle)
            response = invalid["routes"][0]["adapter"]["config"]["response"]
            response["mode"] = response_mode
            if projection_value is None:
                response.pop("allowedFields")
            else:
                response["allowedFields"] = projection_value
            assert_policy_rejected_reason(
                invalid,
                f"route demo.echo credential-bearing {response_mode} success response {failure}",
                validate_schema=validate_schema,
            )
    for projection_value, failure in (
        (None, "is missing allowedFields"),
        ([], "allowedFields must not be empty"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        error_response = {
            "mode": "json",
            "maxBodyBytes": 4096,
            "allowedFields": ["error", "code"],
            "allowedHeaders": [],
            "onInvalid": "block",
        }
        invalid["routes"][0]["adapter"]["config"]["response"]["error"] = error_response
        if projection_value is None:
            error_response.pop("allowedFields")
        else:
            error_response["allowedFields"] = projection_value
        assert_policy_rejected_reason(
            invalid,
            f"route demo.echo credential-bearing JSON error response {failure}",
            validate_schema=validate_schema,
        )

    missing_json_body_policy = copy.deepcopy(demo_bundle)
    missing_json_route = missing_json_body_policy["routes"][0]
    missing_json_route["adapter"]["config"]["request"]["bodyMode"] = "json"
    missing_json_route.pop("constraints", None)
    assert_compiler_rejected_reason(
        missing_json_body_policy,
        "route demo.echo credential-bearing generic.rest bodyMode json requires "
        "a jsonBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    wrong_json_body_policy = copy.deepcopy(missing_json_body_policy)
    wrong_json_body_policy["routes"][0]["constraints"] = [
        {
            "id": "wrong-form-body-policy",
            "type": "formBody",
            "allowedFields": ["safe"],
        }
    ]
    assert_compiler_rejected_reason(
        wrong_json_body_policy,
        "route demo.echo credential-bearing generic.rest bodyMode json requires "
        "a jsonBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    credential_json_bundle = copy.deepcopy(missing_json_body_policy)
    credential_json_bundle["routes"][0]["constraints"] = [
        {
            "id": "echo-json-body",
            "type": "jsonBody",
            "contentTypes": ["application/json"],
            "allowedFields": ["safe", "nested.value"],
        }
    ]
    credential_json_snapshot = compile_policy_bundle(
        credential_json_bundle,
        validate_schema=validate_schema,
    )
    opaque_credential_body = copy.deepcopy(demo_bundle)
    opaque_credential_body["routes"][0]["adapter"]["config"]["request"]["bodyMode"] = "any"
    assert_compiler_rejected_reason(
        opaque_credential_body,
        "route demo.echo credential-bearing generic.rest routes cannot use opaque bodyMode any",
        validate_schema=validate_schema,
    )
    empty_json_allowlist = copy.deepcopy(credential_json_bundle)
    empty_json_allowlist["routes"][0]["constraints"][0]["allowedFields"] = []
    assert_policy_rejected(
        empty_json_allowlist,
        "compiler accepted a credential-bearing JSON body policy with an empty allowlist",
        validate_schema=validate_schema,
    )

    missing_form_body_policy = copy.deepcopy(examples)
    missing_form_route = next(
        item
        for item in missing_form_body_policy["routes"]
        if item["id"] == "example.stripe.payment_intent.tokenized_jit"
    )
    missing_form_route["constraints"] = [
        constraint
        for constraint in missing_form_route["constraints"]
        if constraint["type"] != "formBody"
    ]
    assert_compiler_rejected_reason(
        missing_form_body_policy,
        "route example.stripe.payment_intent.tokenized_jit credential-bearing generic.rest "
        "bodyMode formUrlencoded requires a formBody constraint with non-empty allowedFields",
        validate_schema=validate_schema,
    )

    for request_mode in (
        "jsonlStream",
        "jsonArrayStream",
        "jsonSseStream",
        "jsonNestedStream",
        "formUrlencodedStream",
        "csvStream",
    ):
        valid_stream_request = copy.deepcopy(demo_bundle)
        valid_stream_route = valid_stream_request["routes"][0]
        valid_stream_route.pop("credentialRef")
        stream_request = valid_stream_route["adapter"]["config"]["request"]
        stream_request["bodyMode"] = request_mode
        stream_request["allowedFields"] = ["safe", "nested.value"]
        compile_policy_bundle(valid_stream_request, validate_schema=validate_schema)

        missing_stream_fields = copy.deepcopy(valid_stream_request)
        missing_stream_fields["routes"][0]["adapter"]["config"]["request"].pop("allowedFields")
        assert_policy_rejected(
            missing_stream_fields,
            f"compiler accepted {request_mode} request without allowedFields",
            validate_schema=validate_schema,
        )

    invalid_stream_fields = (
        ([], "empty"),
        (["safe", "safe"], "duplicate"),
        (["safe.*"], "non-dotted-path"),
        (["a" * 257], "overlong"),
        ([f"field{index}" for index in range(65)], "oversized"),
    )
    for allowed_fields, description in invalid_stream_fields:
        invalid_stream_request = copy.deepcopy(demo_bundle)
        invalid_stream_route = invalid_stream_request["routes"][0]
        invalid_stream_route.pop("credentialRef")
        request = invalid_stream_route["adapter"]["config"]["request"]
        request["bodyMode"] = "jsonlStream"
        request["allowedFields"] = allowed_fields
        assert_policy_rejected(
            invalid_stream_request,
            f"compiler accepted {description} structured stream request allowedFields",
            validate_schema=validate_schema,
        )

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["adapter"]["config"]["request"]["bodyMode"] = "stream"
    assert_policy_rejected(
        invalid,
        "compiler accepted a credential-bearing mutating request stream",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["adapter"]["config"]["response"]["allowedHeaders"] = ["etag"]
    assert_policy_rejected(
        invalid,
        "compiler accepted released upstream headers on a streaming response",
        validate_schema=validate_schema,
    )
    invalid = copy.deepcopy(demo_bundle)
    npm_route = next(item for item in invalid["routes"] if item["adapter"]["type"] == "npm.registry")
    npm_route["adapter"]["config"].pop("response")
    assert_policy_rejected(invalid, "compiler accepted npm without a response policy", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["metadata"]["validFrom"] = "2030-01-01T00:00:00Z"
    assert_policy_rejected(invalid, "compiler accepted unenforced validFrom", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["defaults"]["validationFailure"] = "allowWithAudit"
    assert_policy_rejected(invalid, "compiler accepted fail-open validation", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid.pop("defaults")
    assert_policy_rejected(invalid, "compiler accepted implicit policy defaults", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:spiffe", "spiffeIds": ["spiffe://example.test/agent"]}
    assert_policy_rejected(invalid, "compiler accepted unsupported SPIFFE identity", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["principals"][0] = {"id": "agent:unconstrained"}
    assert_policy_rejected(invalid, "compiler accepted unconstrained principal", validate_schema=validate_schema)

    jit_route = next(item for item in demo_bundle["routes"] if item.get("jit"))
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["approvers"]["quorum"] = 2
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT quorum", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["approvers"]["users"] = ["*"]
    assert_policy_rejected(invalid, "compiler accepted wildcard JIT approver authority", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    approver_users = next(
        item for item in invalid["routes"] if item["id"] == jit_route["id"]
    )["jit"]["approvers"]["users"]
    approver_users.append(approver_users[0])
    assert_policy_rejected(invalid, "compiler accepted duplicate JIT approvers", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["consumeOn"] = "successfulResponse"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT consumption", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["mode"] = "perRequest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT mode", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == jit_route["id"])["jit"]["binding"]["type"] = "unknownDigest"
    assert_policy_rejected(invalid, "compiler accepted unsupported JIT binding", validate_schema=validate_schema)

    gmail_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "gmail.v1")
    for mutation, message in (
        (lambda item: item["adapter"]["config"].__setitem__("forceQuery", False), "disabled Gmail query bounding"),
        (
            lambda item: item["adapter"]["config"]["response"].__setitem__("validateInternalDate", False),
            "disabled Gmail response age validation",
        ),
        (lambda item: item.pop("credentialRef"), "credentialless Gmail route"),
    ):
        invalid = copy.deepcopy(demo_bundle)
        target = next(item for item in invalid["routes"] if item["id"] == gmail_route_raw["id"])
        mutation(target)
        assert_policy_rejected(invalid, f"compiler accepted {message}", validate_schema=validate_schema)

    npm_route_raw = next(item for item in demo_bundle["routes"] if item["adapter"]["type"] == "npm.registry")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"]).pop("jit")
    assert_policy_rejected(invalid, "compiler accepted npm writes without JIT", validate_schema=validate_schema)
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])["jit"]["approvers"]["authn"][
        "requireHardwareAttestation"
    ] = False
    assert_policy_rejected(invalid, "compiler accepted npm writes without hardware attestation", validate_schema=validate_schema)

    public_npm = copy.deepcopy(demo_bundle)
    public_npm_route = next(
        item for item in public_npm["routes"] if item["id"] == npm_route_raw["id"]
    )
    public_npm_route["match"]["host"] = "registry.npmjs.org"
    public_npm_route["constraints"] = [
        constraint
        for constraint in public_npm_route["constraints"]
        if constraint["type"] not in {"responseBinding", "responseJson"}
    ]
    compile_policy_bundle(
        sign_policy_bundle(public_npm),
        verify_signature=True,
        validate_schema=validate_schema,
    )

    non_public_without_response_identity = copy.deepcopy(public_npm)
    non_public_route = next(
        item
        for item in non_public_without_response_identity["routes"]
        if item["id"] == npm_route_raw["id"]
    )
    non_public_route["match"]["host"] = "registry.example.test"
    assert_signed_policy_rejected_reason(
        non_public_without_response_identity,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseBinding scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["constraints"] = [
        constraint
        for constraint in invalid_npm["constraints"]
        if constraint["type"] != "responseBinding"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseBinding scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["constraints"] = [
        constraint
        for constraint in invalid_npm["constraints"]
        if constraint["type"] != "responseJson"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish requires a responseJson success constraint scoped only to npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_json = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseJson"
    )
    response_json["fields"]["published"]["equals"] = False
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} signed npm.publish responseJson success constraint must require published to equal true",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["bindings"] = [
        binding for binding in response_binding["bindings"] if binding["operationField"] != "packageVersion"
    ]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} must bind npm.publish packageName and packageVersion",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["operations"] = ["npm.distTagWrite"]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} must be scoped only to configured npm.publish",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["successStatusCodes"] = [202]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} npm.publish successStatusCodes may contain only 200 or 201",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    response_binding = next(
        constraint for constraint in invalid_npm["constraints"] if constraint["type"] == "responseBinding"
    )
    response_binding["contentTypes"] = ["application/problem+json"]
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding {response_binding['id']} npm.publish contentTypes must be exactly application/json",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_npm = next(item for item in invalid["routes"] if item["id"] == npm_route_raw["id"])
    invalid_npm["adapter"]["config"]["response"]["maxBodyBytes"] = 65537
    assert_signed_policy_rejected_reason(
        invalid,
        f"route {npm_route_raw['id']} responseBinding requires a buffered JSON response capped at 65536 bytes",
        validate_schema=validate_schema,
    )

    x_read_route_raw = next(item for item in demo_bundle["routes"] if item["id"] == "demo.x.readonly")
    invalid = copy.deepcopy(demo_bundle)
    next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])["match"]["methods"].append(
        "POST"
    )
    assert_policy_rejected(invalid, "compiler accepted writes on an X read route", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_read = next(item for item in invalid["routes"] if item["id"] == x_read_route_raw["id"])
    invalid_x_read["adapter"]["config"]["allowedReadOperations"].append("streams.read")
    assert_policy_rejected(
        invalid,
        "compiler accepted streams mixed with bounded X reads",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid_x_write = next(item for item in invalid["routes"] if item["id"] == "demo.x.tweet.one_per_day")
    invalid_x_write["constraints"] = [
        constraint for constraint in invalid_x_write["constraints"] if constraint["type"] != "jsonBody"
    ]
    assert_policy_rejected(
        invalid,
        "compiler accepted an unconstrained X post body",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {"id": "empty-schedule", "type": "requestTimeWindow", "timezone": "UTC"}
    ]
    assert_policy_rejected(invalid, "compiler accepted an empty request schedule", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "overlapping-schedule",
            "type": "requestTimeWindow",
            "timezone": "UTC",
            "dailyWindows": [
                {"start": "09:00", "end": "12:00"},
                {"start": "11:00", "end": "13:00"},
            ],
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted overlapping request windows", validate_schema=validate_schema)

    schedule = {
        "id": "weekday-hours",
        "type": "requestTimeWindow",
        "timezone": "UTC",
        "notBefore": "2026-01-01T00:00:00Z",
        "notAfter": "2027-01-01T00:00:00Z",
        "weekdays": ["mon", "tue", "wed", "thu", "fri"],
        "dailyWindows": [{"start": "13:00", "end": "15:00"}],
    }
    assert _enforce_request_time_window(
        schedule,
        now=datetime(2026, 7, 14, 14, 0, tzinfo=timezone.utc),
    ).allowed
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 14, 15, 0, tzinfo=timezone.utc),
        ),
        "request_time_daily_window_denied",
    )
    assert_denied(
        _enforce_request_time_window(
            schedule,
            now=datetime(2026, 7, 18, 14, 0, tzinfo=timezone.utc),
        ),
        "request_time_weekday_denied",
    )

    numeric_route_raw = next(
        item
        for item in demo_bundle["routes"]
        if any(constraint.get("type") == "queryNumericBounds" for constraint in item.get("constraints") or [])
    )
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint.pop("min", None)
    numeric_constraint.pop("max", None)
    assert_policy_rejected(invalid, "compiler accepted a no-op numeric bound", validate_schema=validate_schema)
    for bound in ("min", "max"):
        for value in (float("nan"), float("inf"), float("-inf"), 10**400):
            invalid = copy.deepcopy(demo_bundle)
            numeric_constraint = next(
                constraint
                for constraint in next(
                    item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"]
                )["constraints"]
                if constraint["type"] == "queryNumericBounds"
            )
            numeric_constraint[bound] = value
            assert_policy_rejected(
                invalid,
                f"compiler accepted invalid query numeric {bound}: {value!r}",
                validate_schema=validate_schema,
            )
    invalid = copy.deepcopy(demo_bundle)
    numeric_constraint = next(
        constraint
        for constraint in next(item for item in invalid["routes"] if item["id"] == numeric_route_raw["id"])["constraints"]
        if constraint["type"] == "queryNumericBounds"
    )
    numeric_constraint["allowedOperations"] = ["silently.ignored"]
    assert_policy_rejected(invalid, "compiler accepted a cross-type constraint field", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    body_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] in {"jsonBody", "formBody"}
    )
    body_constraint.pop("allowedFields", None)
    assert_policy_rejected(
        invalid,
        "compiler accepted a body policy that could not reject unknown fields",
        validate_schema=validate_schema,
    )

    invalid = copy.deepcopy(demo_bundle)
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["phase"] = "request"
    assert_policy_rejected(invalid, "compiler accepted request-phase response constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    response_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseDateWindow"
    )
    response_constraint["operations"] = []
    assert_policy_rejected(invalid, "compiler accepted an empty response operation selector", validate_schema=validate_schema)

    invalid = copy.deepcopy(examples)
    response_json = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseJson"
    )
    response_json["fields"] = {}
    assert_policy_rejected(invalid, "compiler accepted responseJson without field assertions", validate_schema=validate_schema)

    invalid = copy.deepcopy(examples)
    response_json = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "responseJson"
    )
    response_json["items"] = ["bad.*.path"]
    assert_policy_rejected(invalid, "compiler accepted wildcard responseJson items", validate_schema=validate_schema)

    for field, value, label in (
        ("required", "yes", "non-boolean responseJson required flag"),
        ("items", [{"path": "data"}], "non-string responseJson item path"),
        ("operations", [{"operation": "widgets.read"}], "non-string responseJson operation"),
    ):
        invalid = copy.deepcopy(examples)
        response_json = next(
            constraint
            for item in invalid["routes"]
            for constraint in item.get("constraints", [])
            if constraint["type"] == "responseJson"
        )
        response_json[field] = value
        assert_policy_rejected(invalid, f"compiler accepted {label}", validate_schema=validate_schema)

    invalid_response_rules = (
        ({"type": "string", "unknown": True}, "unknown responseJson field rule"),
        ({"required": "yes"}, "non-boolean responseJson required rule"),
        ({"enum": []}, "empty responseJson enum"),
        ({"enum": ["same", "same"]}, "duplicate responseJson enum"),
        ({"minLength": 1}, "string length rule without an explicit type"),
        ({"type": "number", "maxLength": 10}, "string length rule on a numeric field"),
        ({"type": "string", "min": 0}, "numeric rule on a string field"),
        ({"max": 10}, "numeric rule without an explicit type"),
        ({"type": "string", "minItems": 0}, "array item rule on a string field"),
        ({"maxItems": 10}, "array item rule without an explicit type"),
        ({"minLength": 5, "maxLength": 4}, "inverted responseJson length range"),
        ({"min": 5, "max": 4}, "inverted responseJson numeric range"),
        ({"pattern": "^[0-9]{1,4}$"}, "unbounded responseJson pattern input"),
        (
            {"pattern": "^[0-9]{1,4}$", "maxLength": 4097},
            "oversized responseJson pattern input",
        ),
        (
            {"pattern": "^[0-9]+$", "maxLength": 64},
            "responseJson pattern outside bounded runtime grammar",
        ),
    )
    for rule, label in invalid_response_rules:
        invalid = copy.deepcopy(examples)
        response_json = next(
            constraint
            for item in invalid["routes"]
            for constraint in item.get("constraints", [])
            if constraint["type"] == "responseJson"
        )
        response_json["fields"]["id"] = rule
        assert_policy_rejected(invalid, f"compiler accepted {label}", validate_schema=validate_schema)

    assert bounded_pattern_matches("^v1.:[0-9]{1,2}$", "v1.:12") is True
    assert bounded_pattern_matches("^v1.:[0-9]{1,2}$", "v1X:12") is False

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["phase"] = "both"
    assert_policy_rejected(invalid, "compiler accepted ambiguous constraint phase", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    request_constraint = next(
        constraint
        for item in invalid["routes"]
        for constraint in item.get("constraints", [])
        if constraint["type"] == "operationPolicy"
    )
    request_constraint["operations"] = ["unsupported.request.selector"]
    assert_policy_rejected(invalid, "compiler accepted response-only operation selectors on a request constraint", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["match"]["paths"] = ["/allowed/**/suffix"]
    assert_policy_rejected(invalid, "compiler accepted a non-terminal recursive wildcard", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsupported-extension",
            "type": "operationPolicy",
            "allowedOperations": ["read"],
            "extensions": {"runtime": "not-attested"},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unattested policy extension", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    invalid["routes"][0]["constraints"] = [
        {
            "id": "unsafe-pattern",
            "type": "jsonBody",
            "allowedFields": ["name"],
            "fields": {"name": {"type": "string", "pattern": "(a+)+$", "maxLength": 100}},
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted an unsafe regex policy", validate_schema=validate_schema)

    invalid = copy.deepcopy(demo_bundle)
    stream_route = next(item for item in invalid["routes"] if item["id"] == "demo.stream")
    stream_route["constraints"] = [
        {
            "id": "stream-response-window",
            "type": "responseDateWindow",
            "phase": "response",
            "dateFields": ["created_at"],
            "formats": ["rfc3339"],
            "maxAgeDays": 1,
            "required": True,
        }
    ]
    assert_policy_rejected(invalid, "compiler accepted whole-response validation on a stream", validate_schema=validate_schema)

    generic_route = route(example_snapshot, "example.stripe.customers.list")
    generic_adapter = get_adapter(generic_route.adapter_type)
    generic_request = flow("GET", "https://api.stripe.com/v1/customers?limit=5")
    assert generic_adapter.validate_request(generic_request, generic_route, {}).allowed
    generic_request.request.headers["x-http-method-override"] = "POST"
    assert_denied(generic_adapter.validate_request(generic_request, generic_route, {}), "request_header_not_allowed")
    generic_with_body = flow("GET", "https://api.stripe.com/v1/customers", {"unexpected": True})
    assert_denied(generic_adapter.validate_request(generic_with_body, generic_route, {}), "request_body_too_large")

    credential_json_route = route(credential_json_snapshot, "demo.echo")
    credential_json_adapter = get_adapter(credential_json_route.adapter_type)
    credential_json_bypass = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {
            "safe": "expected",
            "admin": True,
            "callback_url": "https://attacker.example",
        },
    )
    original_json_body = credential_json_bypass.request.raw_content
    assert credential_json_adapter.validate_request(
        credential_json_bypass,
        credential_json_route,
        {},
    ).allowed
    assert_denied(
        request_decision(credential_json_route, credential_json_bypass, "echo"),
        "json_body_field_not_allowed",
    )
    assert credential_json_bypass.request.raw_content == original_json_body
    assert credential_json_adapter.rewrite_request(
        credential_json_bypass,
        credential_json_route,
        {},
    ).allowed
    assert credential_json_bypass.request.raw_content == original_json_body

    for invalid_json_body in (
        b'{"safe":"first","safe":"second"}',
        b'{"nested":{"value":1,"value":2}}',
        b'{"safe":NaN}',
        b'{"safe":Infinity}',
        b'{"safe":-Infinity}',
        b'{"safe":1e400}',
    ):
        invalid_json_request = flow(
            "POST",
            "https://demo-upstream:8443/echo",
            {"safe": "placeholder"},
        )
        invalid_json_request.request.raw_content = invalid_json_body
        assert_denied(
            request_decision(credential_json_route, invalid_json_request, "echo"),
            "json_body_invalid",
        )

    for stale_constraints in (
        (),
        ({"type": "jsonBody", "allowedFields": []},),
        (
            {
                "type": "jsonBody",
                "phase": "response",
                "allowedFields": ["safe"],
            },
        ),
    ):
        stale_json_route = SimpleNamespace(
            credential_ref=credential_json_route.credential_ref,
            adapter_config=credential_json_route.adapter_config,
            constraints=stale_constraints,
        )
        stale_json_decision = credential_json_adapter.validate_request(
            credential_json_bypass,
            stale_json_route,
            {},
        )
        assert_denied(stale_json_decision, "credential_request_body_policy_missing")
        assert stale_json_decision.status_code == 500
        assert stale_json_decision.payload["requiredConstraint"] == "jsonBody"

    stale_opaque_route = SimpleNamespace(
        credential_ref=credential_json_route.credential_ref,
        adapter_config={
            **credential_json_route.adapter_config,
            "request": {
                **credential_json_route.adapter_config["request"],
                "bodyMode": "any",
            },
        },
        constraints=(),
    )
    assert_denied(
        credential_json_adapter.validate_request(
            credential_json_bypass,
            stale_opaque_route,
            {},
        ),
        "credential_opaque_request_body_denied",
    )

    credentialless_json_bundle = copy.deepcopy(missing_json_body_policy)
    credentialless_json_bundle["routes"][0].pop("credentialRef")
    credentialless_json_snapshot = compile_policy_bundle(
        credentialless_json_bundle,
        validate_schema=validate_schema,
    )
    credentialless_json_route = route(credentialless_json_snapshot, "demo.echo")
    credentialless_json_request = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {"safe": "expected", "unrestricted_public_field": True},
    )
    credentialless_json_body = credentialless_json_request.request.raw_content
    assert credential_json_adapter.validate_request(
        credentialless_json_request,
        credentialless_json_route,
        {},
    ).allowed
    assert credential_json_adapter.rewrite_request(
        credentialless_json_request,
        credentialless_json_route,
        {},
    ).allowed
    assert credentialless_json_request.request.raw_content == credentialless_json_body

    explicit_any_route = route(explicit_opaque_snapshot, "demo.echo")
    explicit_any_request = flow(
        "POST",
        "https://demo-upstream:8443/echo",
        {"explicitly": "opaque", "admin": True},
    )
    explicit_any_body = explicit_any_request.request.raw_content
    assert generic_adapter.validate_request(explicit_any_request, explicit_any_route, {}).allowed
    assert generic_adapter.rewrite_request(explicit_any_request, explicit_any_route, {}).allowed
    assert explicit_any_request.request.raw_content == explicit_any_body

    slack_route = route(example_snapshot, "example.slack.chat_post.hourly")
    slack_request = flow(
        "POST",
        "https://slack.com/api/chat.postMessage",
        {"channel": "C123", "text": "bounded message"},
    )
    slack_body = slack_request.request.raw_content
    assert generic_adapter.validate_request(slack_request, slack_route, {}).allowed
    assert generic_adapter.rewrite_request(slack_request, slack_route, {}).allowed
    assert slack_request.request.raw_content == slack_body

    for stream_fields, expected_error in (
        (None, "streaming_redaction_request_allowed_fields_missing"),
        (["safe", "safe"], "streaming_redaction_request_allowed_fields_invalid"),
    ):
        stream_request_config = {
            "allowedHeaders": ["content-type"],
            "allowedQueryKeys": [],
            "bodyMode": "jsonlStream",
            "maxBodyBytes": 4096,
        }
        if stream_fields is not None:
            stream_request_config["allowedFields"] = stream_fields
        stale_stream_route = SimpleNamespace(
            credential_ref=None,
            adapter_config={"request": stream_request_config},
            constraints=(),
        )
        stale_stream_request = flow(
            "POST",
            "https://api.example.test/events",
            {"safe": "value"},
        )
        assert_denied(
            generic_adapter.validate_request(stale_stream_request, stale_stream_route, {}),
            expected_error,
        )

    for projection in (None, []):
        response_config = {"mode": "json", "maxBodyBytes": 4096, "allowedHeaders": []}
        if projection is not None:
            response_config["allowedFields"] = projection
        unprojected_route = SimpleNamespace(
            credential_ref="cred-generic",
            adapter_config={"response": response_config},
        )
        unprojected = flow(
            "GET",
            "https://api.example.test/data",
            response={"id": "safe", "provider_internal_secret": "must-not-release"},
        )
        decision = generic_adapter.validate_response(unprojected, unprojected_route, {})
        assert_denied(decision, "credential_response_projection_required")
        assert decision.status_code == 502
        assert decision.reason == "credential-bearing response requires a non-empty allowedFields projection"
        assert decision.payload == {
            "error": "credential_response_projection_required",
            "adapter": "generic.rest",
            "mode": "json",
        }

    source_with_siblings = {
        "data": {"id": "safe", "provider_internal_secret": "nested-secret"},
        "provider_internal_secret": "top-level-secret",
    }
    assert generic_adapter._redact_json(source_with_siblings, []) == {}
    assert generic_adapter._redact_json([source_with_siblings], []) == []
    projected_route = SimpleNamespace(
        credential_ref="cred-generic",
        adapter_config={
            "response": {
                "mode": "json",
                "maxBodyBytes": 4096,
                "allowedFields": ["data.id"],
                "allowedHeaders": [],
            }
        },
    )
    projected = flow(
        "GET",
        "https://api.example.test/data",
        response=source_with_siblings,
    )
    assert generic_adapter.validate_response(projected, projected_route, {}).allowed
    assert json.loads(projected.response.get_text()) == {"data": {"id": "safe"}}

    explicit_opaque_route = SimpleNamespace(
        credential_ref=None,
        adapter_config={
            "response": {"mode": "any", "maxBodyBytes": 4096, "allowedHeaders": []}
        },
    )
    explicit_opaque_response = flow(
        "GET",
        "https://public.example.test/data",
        response=source_with_siblings,
    )
    original_opaque_body = explicit_opaque_response.response.raw_content
    assert generic_adapter.validate_response(
        explicit_opaque_response,
        explicit_opaque_route,
        {},
    ).allowed
    assert explicit_opaque_response.response.raw_content == original_opaque_body

    x_projection_route = route(demo, "demo.x.tweet.one_per_day")
    x_projection = flow(
        "POST",
        "https://demo-upstream:8443/2/tweets",
        response=source_with_siblings,
    )
    assert get_adapter("x.v2").validate_response(x_projection, x_projection_route, {}).allowed
    assert json.loads(x_projection.response.get_text()) == {"data": {"id": "safe"}}

    object_store_route = route(example_snapshot, "example.object_store.small_puts")
    object_store_adapter = get_adapter(object_store_route.adapter_type)
    object_store_body = b'{"content":"hello","contentType":"text/plain"}'
    expected_object_store_digest = (
        "sha256:292df0fecc76d806319901d8e74c1f5de3cd776d05d4e4e72bdc44e83492d010"
    )
    assert expected_object_store_digest == f"sha256:{hashlib.sha256(object_store_body).hexdigest()}"
    object_store_request = flow(
        "PUT",
        "https://objects.example.com/v1/objects/report-1",
    )
    object_store_request.request.raw_content = object_store_body
    object_store_operation = object_store_adapter.operation_fields(
        object_store_request,
        object_store_route,
        {"artifact_id": "report-1"},
    )
    assert object_store_operation == {
        "operation": "object_store.objects.put",
        "artifact_id": "report-1",
        "requestBodySha256": expected_object_store_digest,
    }
    assert request_decision(
        object_store_route,
        object_store_request,
        "object_store.objects.put",
        operation_fields=object_store_operation,
    ).allowed

    caller_digest = "sha256:" + "0" * 64
    caller_digest_request = copy.deepcopy(object_store_request)
    caller_digest_request.request.raw_content = json.dumps(
        {"content": "hello", "requestBodySha256": caller_digest},
        separators=(",", ":"),
    ).encode("utf-8")
    caller_digest_operation = object_store_adapter.operation_fields(
        caller_digest_request,
        object_store_route,
        {"artifact_id": "report-1"},
    )
    assert caller_digest_operation["requestBodySha256"] == (
        f"sha256:{hashlib.sha256(caller_digest_request.request.raw_content).hexdigest()}"
    )
    assert caller_digest_operation["requestBodySha256"] != caller_digest

    object_store_response = flow(
        "PUT",
        "https://objects.example.com/v1/objects/report-1",
        response={"ok": True, "id": "report-1", "sha256": expected_object_store_digest},
    )
    object_store_response.metadata["serverware_operation"] = object_store_operation
    assert evaluate_response_constraints(object_store_response, object_store_route).allowed
    mismatched_object_store_digest = copy.deepcopy(object_store_response)
    mismatched_object_store_digest.response.raw_content = json.dumps(
        {"ok": True, "id": "report-1", "sha256": "sha256:" + "a" * 64}
    ).encode("utf-8")
    assert_response_binding_denied(
        evaluate_response_constraints(mismatched_object_store_digest, object_store_route),
        "response_binding_mismatch",
        binding_id="sha256",
    )
    wrong_object_store_status = copy.deepcopy(object_store_response)
    wrong_object_store_status.response.raw_content = json.dumps(
        {"ok": False, "id": "report-1", "sha256": expected_object_store_digest}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(wrong_object_store_status, object_store_route),
        "response_json_field_equals_denied",
    )
    malformed_object_store_digest = copy.deepcopy(object_store_response)
    malformed_object_store_digest.response.raw_content = json.dumps(
        {"ok": True, "id": "report-1", "sha256": "not-a-digest"}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(malformed_object_store_digest, object_store_route),
        "response_json_field_pattern_denied",
    )
    missing_object_store_id = copy.deepcopy(object_store_response)
    missing_object_store_id.response.raw_content = json.dumps(
        {"ok": True, "sha256": "sha256:" + "a" * 64}
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(missing_object_store_id, object_store_route),
        "response_json_required_field_missing",
    )
    response_items_route = SimpleNamespace(
        constraints=[
            {
                "id": "typed-results",
                "type": "responseJson",
                "phase": "response",
                "items": ["data"],
                "required": True,
                "fields": {
                    "status": {"required": True, "type": "string", "enum": ["ready", "done"]},
                    "score": {"required": True, "type": "number", "min": 0, "max": 1},
                    "tags": {"type": "array", "maxItems": 3},
                },
            }
        ]
    )
    typed_results = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "ready", "score": 0.8, "tags": ["safe"]}]},
    )
    assert evaluate_response_constraints(typed_results, response_items_route).allowed
    bad_result = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "unknown", "score": 0.8}]},
    )
    assert_denied(
        evaluate_response_constraints(bad_result, response_items_route),
        "response_json_field_enum_denied",
    )
    high_score = flow(
        "GET",
        "https://api.example.test/results",
        response={"data": [{"status": "ready", "score": 1.1}]},
    )
    assert_denied(
        evaluate_response_constraints(high_score, response_items_route),
        "response_json_field_max",
    )
    for invalid_response_body in (
        b'{"data":[{"status":"ready","status":"done","score":0.8}]}',
        b'{"data":[{"status":"ready","score":NaN}]}',
        b'{"data":[{"status":"ready","score":Infinity}]}',
        b'{"data":[{"status":"ready","score":-Infinity}]}',
        b'{"data":[{"status":"ready","score":1e400}]}',
    ):
        invalid_result = flow(
            "GET",
            "https://api.example.test/results",
            response={"data": []},
        )
        invalid_result.response.raw_content = invalid_response_body
        assert_denied(
            evaluate_response_constraints(invalid_result, response_items_route),
            "response_json_invalid",
        )
    missing_results = flow("GET", "https://api.example.test/results", response={"meta": {}})
    assert_denied(
        evaluate_response_constraints(missing_results, response_items_route),
        "response_json_items_missing",
    )

    stripe_route = route(example_snapshot, "example.stripe.payment_intent.tokenized_jit")
    stripe_adapter = get_adapter(stripe_route.adapter_type)
    stripe_request = flow("POST", "https://api.stripe.com/v1/payment_intents")
    stripe_request.request.headers["content-type"] = "application/x-www-form-urlencoded"
    stripe_request.request.raw_content = (
        b"amount=5000&currency=usd&payment_method=pm_12345678&confirm=true&"
        b"metadata%5Bagent_request_id%5D=req-123"
    )
    assert_denied(
        stripe_adapter.validate_request(stripe_request, stripe_route, {}),
        "required_header_missing",
    )
    stripe_request.request.headers["idempotency-key"] = "agent-payment:req-123"
    assert stripe_adapter.validate_request(stripe_request, stripe_route, {}).allowed
    invalid_idempotency_key = copy.deepcopy(stripe_request)
    invalid_idempotency_key.request.headers["idempotency-key"] = "invalid key with spaces"
    assert_denied(
        stripe_adapter.validate_request(invalid_idempotency_key, stripe_route, {}),
        "required_header_invalid",
    )
    stripe_operation = stripe_adapter.operation_fields(stripe_request, stripe_route, {})
    assert stripe_operation == {
        "operation": "stripe.payment_intents.create",
        "amount": "5000",
        "currency": "usd",
        "payment_method": "pm_12345678",
        "confirm": "true",
        "metadata.agent_request_id": "req-123",
    }, stripe_operation
    stripe_digest_route = copy.deepcopy(stripe_route)
    stripe_digest_route.adapter_config["request"]["operation"]["bodySha256Field"] = (
        "requestBodySha256"
    )
    stripe_digest_operation = stripe_adapter.operation_fields(
        stripe_request,
        stripe_digest_route,
        {},
    )
    assert stripe_digest_operation["requestBodySha256"] == (
        f"sha256:{hashlib.sha256(stripe_request.request.raw_content).hexdigest()}"
    )
    assert evaluate_response_binding_sources(stripe_route, stripe_operation).allowed
    assert request_decision(stripe_route, stripe_request, "stripe.payment_intents.create").allowed

    json_source_route = SimpleNamespace(
        adapter_config={
            "request": {
                "bodyMode": "json",
                "operation": {
                    "name": "example.json.capture",
                    "jsonFields": [
                        "text",
                        "minimum",
                        "maximum",
                        "boolean",
                        "floating",
                        "null_value",
                        "array_value",
                        "object_value",
                        "too_large",
                        "lone_surrogate",
                    ],
                    "pathParams": ["artifact_id"],
                },
            }
        }
    )
    json_source_request = flow(
        "PUT",
        "https://api.example.test/artifacts/artifact-123",
        body={
            "text": "Gr\u00fc\u00dfe",
            "minimum": -(2**63),
            "maximum": 2**63 - 1,
            "metadata.id": "literal-top-level",
            "metadata": {"id": "must-not-traverse"},
            "boolean": True,
            "floating": 1.0,
            "null_value": None,
            "array_value": ["value"],
            "object_value": {"value": "nested"},
            "too_large": 2**63,
        },
    )
    json_source_fields = stripe_adapter.operation_fields(
        json_source_request,
        json_source_route,
        {"artifact_id": "artifact-123"},
    )
    assert json_source_fields == {
        "operation": "example.json.capture",
        "artifact_id": "artifact-123",
        "text": "Gr\u00fc\u00dfe",
        "minimum": str(-(2**63)),
        "maximum": str(2**63 - 1),
    }, json_source_fields

    dotted_json_source_route = copy.deepcopy(json_source_route)
    dotted_json_source_route.adapter_config["request"]["operation"]["jsonFields"] = ["metadata.id"]
    assert stripe_adapter.operation_fields(
        json_source_request,
        dotted_json_source_route,
        {"artifact_id": "artifact-123"},
    ) == {
        "operation": "example.json.capture",
        "artifact_id": "artifact-123",
    }

    invalid_json_source_bodies = (
        b'{"text":"first-secret","text":"second-secret"}',
        b'{"text":',
        b'["not-an-object"]',
        b'{"text":"\\ud800"}',
        b'{"minimum":-0}',
    )
    for invalid_body in invalid_json_source_bodies:
        invalid_json_source = copy.deepcopy(json_source_request)
        invalid_json_source.request.raw_content = invalid_body
        assert stripe_adapter.operation_fields(
            invalid_json_source,
            json_source_route,
            {"artifact_id": "artifact-123"},
        ) == {
            "operation": "example.json.capture",
            "artifact_id": "artifact-123",
        }

    json_binding_route = route(
        json_path_snapshot,
        "example.stripe.payment_intent.tokenized_jit",
    )
    malformed_bound_json = flow(
        "POST",
        "https://api.stripe.com/v1/payment_intents/pi_12345678",
        body={"amount": 5000, "currency": "usd", "payment_method": "pm_12345678"},
    )
    malformed_bound_json.request.headers["idempotency-key"] = "agent-payment:req-json"
    malformed_bound_json.request.raw_content = (
        b'{"amount":5000,"amount":5001,"currency":"usd",'
        b'"payment_method":"pm_12345678"}'
    )
    malformed_operation_fields = stripe_adapter.operation_fields(
        malformed_bound_json,
        json_binding_route,
        {"payment_intent_id": "pi_12345678"},
    )
    assert malformed_operation_fields == {
        "operation": "stripe.payment_intents.create",
        "payment_intent_id": "pi_12345678",
    }
    assert_denied(
        request_decision(
            json_binding_route,
            malformed_bound_json,
            "stripe.payment_intents.create",
            operation_fields=malformed_operation_fields,
        ),
        "json_body_invalid",
    )
    assert_response_binding_denied(
        evaluate_response_binding_sources(json_binding_route, malformed_operation_fields),
        "response_binding_source_missing",
        binding_id="amount",
        evidence=False,
    )

    secret_path_source = "path-source-canary-never-disclose"
    path_source_route = SimpleNamespace(
        constraints=(
            {
                "id": "path-source-binding",
                "type": "responseBinding",
                "phase": "response",
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "artifact-id",
                        "operationField": "artifact_id",
                        "responseField": "id",
                        "comparison": "exactString",
                    }
                ],
            },
        )
    )
    path_source_denial = evaluate_response_binding_sources(
        path_source_route,
        {"artifact_id": secret_path_source + "x" * 4096},
    )
    assert_response_binding_denied(
        path_source_denial,
        "response_binding_source_missing",
        binding_id="artifact-id",
        evidence=False,
        sensitive_values=(secret_path_source,),
    )

    matching_stripe_response = flow(
        "POST",
        "https://api.stripe.com/v1/payment_intents",
        response={
            "id": "pi_12345678",
            "object": "payment_intent",
            "amount": 5000,
            "currency": "usd",
            "payment_method": "pm_12345678",
            "status": "succeeded",
        },
    )
    matching_stripe_response.metadata.update(
        {
            "serverware_operation": stripe_operation,
            "serverware_policy_hash": "sha256:" + "1" * 64,
            "serverware_request_digest": "sha256:" + "2" * 64,
            "serverware_operation_digest": "sha256:" + "3" * 64,
        }
    )
    matching_binding_decision = evaluate_response_constraints(
        matching_stripe_response,
        stripe_route,
        constraint_types={"responseBinding"},
    )
    assert matching_binding_decision.allowed
    assert len(matching_binding_decision.payload["bindings"]) == 3
    assert "pm_12345678" not in json.dumps(matching_binding_decision.payload)
    assert evaluate_response_constraints(matching_stripe_response, stripe_route).allowed
    wrong_stripe_object = copy.deepcopy(matching_stripe_response)
    wrong_stripe_object.response.raw_content = json.dumps(
        {
            "id": "obj_12345678",
            "object": "arbitrary",
            "amount": 5000,
            "currency": "usd",
            "payment_method": "pm_12345678",
        }
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(wrong_stripe_object, stripe_route),
        "response_json_field_pattern_denied",
    )
    if evaluate_response is not None:
        original_response_log = runtime.log_request
        response_logs: list[tuple] = []
        runtime.log_request = lambda *args, **_kwargs: response_logs.append(args)
        try:
            audited_response = copy.deepcopy(matching_stripe_response)
            audited_response.metadata.update(
                {
                    "serverware_route": stripe_route,
                    "serverware_route_id": stripe_route.id,
                    "serverware_params": {},
                    "serverware_principal_id": "agent:example",
                    "serverware_credential_id": stripe_route.credential_ref,
                    "serverware_credential_version": 1,
                }
            )
            assert evaluate_response(audited_response).allowed
            released_event = response_logs[-1][6]
            assert released_event["response_validation"]["ok"] is True
            assert len(released_event["response_validation"]["bindings"]) == 3
            assert "serverware_operation" not in released_event
            assert "pm_12345678" not in json.dumps(released_event)

            response_logs.clear()
            denied_response = copy.deepcopy(audited_response)
            denied_response.response.raw_content = json.dumps(
                {
                    "id": "pi_12345678",
                    "object": "payment_intent",
                    "amount": 5001,
                    "currency": "usd",
                    "payment_method": "pm_12345678",
                }
            ).encode("utf-8")
            assert_denied(evaluate_response(denied_response), "response_binding_mismatch")
            blocked_event = response_logs[-1][6]
            assert blocked_event["response_validation"]["ok"] is False
            assert blocked_event["response_validation"]["binding_id"] == "amount"
            assert blocked_event["response_validation"]["evidence_digest"].startswith("sha256:")
            assert "pm_12345678" not in json.dumps(blocked_event)
            assert "5001" not in json.dumps(blocked_event)
        finally:
            runtime.log_request = original_response_log

    for status_code, headers, expected_error in (
        (201, {"content-type": "application/json"}, "response_binding_status_denied"),
        (200, {"content-type": "text/plain"}, "response_binding_content_type_denied"),
        (200, {"content-type": "application/json", "content-encoding": "gzip"}, "response_binding_content_encoding_denied"),
    ):
        denied_envelope = copy.deepcopy(matching_stripe_response)
        denied_envelope.response.status_code = status_code
        denied_envelope.response.headers = headers
        assert_response_binding_denied(
            evaluate_response_constraints(
                denied_envelope,
                stripe_route,
                constraint_types={"responseBinding"},
            ),
            expected_error,
            binding_id=None,
        )

    ordered_envelope_denial = copy.deepcopy(matching_stripe_response)
    ordered_envelope_denial.response.status_code = 201
    ordered_envelope_denial.response.raw_content = b"not-json"
    assert_response_binding_denied(
        evaluate_response_constraints(ordered_envelope_denial, stripe_route),
        "response_binding_status_denied",
        binding_id=None,
    )

    for array_body in (
        b'[{"amount":5000,"currency":"usd","payment_method":"pm_12345678"}]',
        b'[{"amount":5000},{"currency":"usd"},{"payment_method":"pm_12345678"}]',
    ):
        array_response = copy.deepcopy(matching_stripe_response)
        array_response.response.raw_content = array_body
        assert_response_binding_denied(
            evaluate_response_constraints(
                array_response,
                stripe_route,
                constraint_types={"responseBinding"},
            ),
            "response_binding_object_required",
            binding_id=None,
        )
    nested_array_route = copy.deepcopy(stripe_route)
    nested_binding = next(
        constraint
        for constraint in nested_array_route.constraints
        if constraint.get("type") == "responseBinding"
    )
    nested_binding["bindings"][0]["responseField"] = "data.amount"
    nested_array_response = copy.deepcopy(matching_stripe_response)
    nested_array_response.response.raw_content = (
        b'{"data":[{"amount":5000}],"currency":"usd","payment_method":"pm_12345678"}'
    )
    assert_response_binding_denied(
        evaluate_response_constraints(
            nested_array_response,
            nested_array_route,
            constraint_types={"responseBinding"},
        ),
        "response_binding_field_ambiguous",
        binding_id="amount",
    )
    for invalid_body, sensitive_values in (
        (
            b'{"amount":5000,"currency":"response-json-canary-a","currency":"usd"}',
            ("response-json-canary-a",),
        ),
        (b'{"amount":NaN,"currency":"usd"}', ()),
    ):
        invalid_json_response = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response={},
        )
        invalid_json_response.response.raw_content = invalid_body
        invalid_json_response.metadata["serverware_operation"] = stripe_operation
        decision = evaluate_response_constraints(
            invalid_json_response,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            "response_binding_json_invalid",
            binding_id=None,
            sensitive_values=sensitive_values,
        )

    for response, binding_id, expected_error in (
        (
            {"amount": 5001, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": "eur", "payment_method": "pm_12345678"},
            "currency",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": "usd"},
            "payment-method",
            "response_binding_field_ambiguous",
        ),
        (
            {"currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_field_ambiguous",
        ),
        (
            {"amount": "5000", "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000.0, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": True, "currency": "usd", "payment_method": "pm_12345678"},
            "amount",
            "response_binding_mismatch",
        ),
        (
            {"amount": 5000, "currency": 7, "payment_method": "pm_12345678"},
            "currency",
            "response_binding_mismatch",
        ),
    ):
        mismatched = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response=response,
        )
        mismatched.metadata["serverware_operation"] = stripe_operation
        decision = evaluate_response_constraints(
            mismatched,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            expected_error,
            binding_id=binding_id,
        )
        assert decision.status_code == 502

    missing_binding_source = dict(stripe_operation)
    missing_binding_source.pop("amount")
    decision = evaluate_response_binding_sources(stripe_route, missing_binding_source)
    assert_response_binding_denied(
        decision,
        "response_binding_source_missing",
        binding_id="amount",
        evidence=False,
    )
    noncanonical_binding_source = {**stripe_operation, "amount": "05000"}
    assert_response_binding_denied(
        evaluate_response_binding_sources(stripe_route, noncanonical_binding_source),
        "response_binding_source_invalid",
        binding_id="amount",
        evidence=False,
    )

    source_canary = "request-source-canary-never-disclose"
    assert_response_binding_denied(
        evaluate_response_binding_sources(
            stripe_route,
            {**stripe_operation, "amount": source_canary},
        ),
        "response_binding_source_invalid",
        binding_id="amount",
        evidence=False,
        sensitive_values=(source_canary,),
    )

    i64_route = SimpleNamespace(
        constraints=(
            {
                "id": "signed-i64-response-binding",
                "type": "responseBinding",
                "phase": "response",
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "signed-i64",
                        "operationField": "authorized_value",
                        "responseField": "value",
                        "comparison": "canonicalInteger",
                    }
                ],
            },
        )
    )
    min_i64 = -(2**63)
    max_i64 = 2**63 - 1
    for boundary in (min_i64, max_i64):
        boundary_operation = {"authorized_value": str(boundary)}
        assert evaluate_response_binding_sources(i64_route, boundary_operation).allowed
        boundary_response = flow(
            "POST",
            "https://api.example.test/i64",
            response={"value": boundary},
        )
        boundary_response.metadata["serverware_operation"] = boundary_operation
        assert evaluate_response_constraints(
            boundary_response,
            i64_route,
            constraint_types={"responseBinding"},
        ).allowed

    for out_of_range in (min_i64 - 1, max_i64 + 1):
        assert_response_binding_denied(
            evaluate_response_binding_sources(
                i64_route,
                {"authorized_value": str(out_of_range)},
            ),
            "response_binding_source_invalid",
            binding_id="signed-i64",
            evidence=False,
        )
        out_of_range_response = flow(
            "POST",
            "https://api.example.test/i64",
            response={"value": out_of_range},
        )
        out_of_range_response.metadata["serverware_operation"] = {
            "authorized_value": str(max_i64 if out_of_range > 0 else min_i64)
        }
        assert_response_binding_denied(
            evaluate_response_constraints(
                out_of_range_response,
                i64_route,
                constraint_types={"responseBinding"},
            ),
            "response_binding_mismatch",
            binding_id="signed-i64",
        )

    for suffix in ("a", "b"):
        request_canary = f"request-binding-canary-{suffix}-never-disclose"
        response_canary = f"response-binding-canary-{suffix}-never-disclose"
        canary_operation = {**stripe_operation, "currency": request_canary}
        canary_response = flow(
            "POST",
            "https://api.stripe.com/v1/payment_intents",
            response={
                "amount": 5000,
                "currency": response_canary,
                "payment_method": "pm_12345678",
            },
        )
        canary_response.metadata["serverware_operation"] = canary_operation
        decision = evaluate_response_constraints(
            canary_response,
            stripe_route,
            constraint_types={"responseBinding"},
        )
        assert_response_binding_denied(
            decision,
            "response_binding_mismatch",
            binding_id="currency",
            sensitive_values=(request_canary, response_canary),
        )

    stale_stripe_route = SimpleNamespace(
        credential_ref=stripe_route.credential_ref,
        adapter_config=stripe_route.adapter_config,
        constraints=(),
    )
    stale_stripe_decision = stripe_adapter.validate_request(
        stripe_request,
        stale_stripe_route,
        {},
    )
    assert_denied(stale_stripe_decision, "credential_request_body_policy_missing")
    assert stale_stripe_decision.status_code == 500
    assert stale_stripe_decision.payload["requiredConstraint"] == "formBody"

    sibling_form_field = copy.deepcopy(stripe_request)
    sibling_form_field.request.raw_content += (
        b"&transfer_data%5Bdestination%5D=acct_attacker"
    )
    original_form_body = sibling_form_field.request.raw_content
    assert stripe_adapter.validate_request(sibling_form_field, stripe_route, {}).allowed
    assert_denied(
        request_decision(
            stripe_route,
            sibling_form_field,
            "stripe.payment_intents.create",
        ),
        "form_body_field_not_allowed",
    )
    assert stripe_adapter.rewrite_request(sibling_form_field, stripe_route, {}).allowed
    assert sibling_form_field.request.raw_content == original_form_body

    if _canonical_forwarded_request_headers is not None:
        stripe_credential = example_snapshot.credentials[stripe_route.credential_ref]
        principal = example_snapshot.principals["agent:example"]
        forwarded_headers = _canonical_forwarded_request_headers(stripe_request, stripe_credential)
        assert forwarded_headers == {
            "content-length": str(len(stripe_request.request.raw_content)),
            "content-type": "application/x-www-form-urlencoded",
            "host": "api.stripe.com",
            "idempotency-key": "agent-payment:req-123",
        }
        canonical = _canonical_request(
            stripe_request,
            principal=principal,
            route=stripe_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=stripe_operation,
            forwarded_headers=forwarded_headers,
        )
        changed_idempotency_key = copy.deepcopy(stripe_request)
        changed_idempotency_key.request.headers["idempotency-key"] = "agent-payment:req-124"
        changed_forwarded_headers = _canonical_forwarded_request_headers(
            changed_idempotency_key,
            stripe_credential,
        )
        changed_canonical = _canonical_request(
            changed_idempotency_key,
            principal=principal,
            route=stripe_route,
            credential_version="1",
            policy_hash=example_snapshot.hash,
            operation_fields=stripe_operation,
            forwarded_headers=changed_forwarded_headers,
        )
        assert _digest(canonical) != _digest(changed_canonical)
        assert _operation_digest(canonical) != _operation_digest(changed_canonical)

        header_collision = copy.deepcopy(stripe_request)
        header_collision.request.headers["Authorization"] = "Bearer agent-controlled"
        assert_denied(
            _credential_injection_collision(header_collision, stripe_credential),
            "credential_injection_header_collision",
        )
        query_collision = flow(
            "PUT",
            "https://objects.example.com/agent-artifacts/report-1?api_key=agent-controlled",
        )
        assert_denied(
            _credential_injection_collision(
                query_collision,
                SimpleNamespace(injection={"type": "query", "name": "api_key"}),
            ),
            "credential_injection_query_collision",
        )

    excessive_amount = copy.deepcopy(stripe_request)
    excessive_amount.request.raw_content = b"amount=50001&currency=usd&payment_method=pm_12345678&confirm=true"
    assert_denied(
        request_decision(stripe_route, excessive_amount, "stripe.payment_intents.create"),
        "form_body_field_max",
    )
    duplicate_amount = copy.deepcopy(stripe_request)
    duplicate_amount.request.raw_content = (
        b"amount=50&amount=50000&currency=usd&payment_method=pm_12345678&confirm=true"
    )
    assert_denied(
        request_decision(stripe_route, duplicate_amount, "stripe.payment_intents.create"),
        "form_body_duplicate_field_denied",
    )
    raw_card = copy.deepcopy(stripe_request)
    raw_card.request.raw_content = (
        b"amount=5000&currency=usd&confirm=true&payment_method_data%5Bcard%5D%5Bnumber%5D=4242424242424242"
    )
    assert_denied(
        request_decision(stripe_route, raw_card, "stripe.payment_intents.create"),
        "form_body_field_not_allowed",
    )

    x_route = route(example_snapshot, "example.x.search.seven_days")
    x_request = flow("GET", "https://api.x.com/2/tweets/search/recent?query=serverware&tweet.fields=author_id")
    x_adapter = get_adapter(x_route.adapter_type)
    assert x_adapter.rewrite_request(x_request, x_route, {}).allowed
    assert set(x_request.request.query["tweet.fields"].split(",")) == {"author_id", "created_at"}
    for historical_path in ("/2/tweets/search/all", "/2/tweets/counts/all"):
        assert_denied(
            x_adapter.validate_request(
                flow("GET", f"https://api.x.com{historical_path}?query=serverware"),
                x_route,
                {},
            ),
            "x_recent_search_endpoint_denied",
        )
    assert x_adapter.validate_request(
        flow("GET", "https://api.x.com/2/tweets/counts/recent?query=serverware"),
        x_route,
        {},
    ).allowed

    full_x_route = route(example_snapshot, "example.x.full_bounded_read")
    full_x_adapter = get_adapter(full_x_route.adapter_type)
    expected_x_reads = {
        "https://api.x.com/2/tweets/123": "tweets.read",
        "https://api.x.com/2/tweets/analytics": "analytics.read",
        "https://api.x.com/2/tweets/search/recent?query=serverware": "search.read",
        "https://api.x.com/2/tweets/search/all?query=serverware": "search.read",
        "https://api.x.com/2/users/me": "users.read",
        "https://api.x.com/2/users/123/bookmarks/folders/456": "bookmarks.read",
        "https://api.x.com/2/users/123/owned_lists": "lists.read",
        "https://api.x.com/2/dm_events": "directMessages.read",
        "https://api.x.com/2/media/upload?id=123": "media.read",
        "https://api.x.com/2/spaces/search?query=security": "spaces.read",
    }
    for url, operation in expected_x_reads.items():
        x_read = flow("GET", url)
        assert full_x_adapter.operation_fields(x_read, full_x_route, {}) == {"operation": operation}
        assert full_x_adapter.validate_request(x_read, full_x_route, {}).allowed
    assert_denied(
        full_x_adapter.validate_request(
            flow("GET", "https://api.x.com/2/future/unknown_endpoint"),
            full_x_route,
            {},
        ),
        "x_unknown_operation_blocked",
    )
    assert_denied(
        full_x_adapter.validate_request(
            flow("POST", "https://api.x.com/2/tweets", {"text": "blocked on read route"}),
            full_x_route,
            {},
        ),
        "x_write_blocked",
    )

    npm_route = route(example_snapshot, "example.npm.publish.yubikey_jit")
    tarball = b"captured npm package tarball bytes"
    npm_document = {
        "_id": "@scope/example",
        "name": "@scope/example",
        "dist-tags": {"latest": "1.2.3"},
        "versions": {
            "1.2.3": {
                "name": "@scope/example",
                "version": "1.2.3",
                "dist": {},
            }
        },
        "_attachments": {
            "example-1.2.3.tgz": {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tarball).decode("ascii"),
                "length": len(tarball),
            }
        },
    }
    npm_request = flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_document)
    npm_adapter = get_adapter(npm_route.adapter_type)
    assert set(npm_route.adapter_config["operations"]) == {
        "publish",
        "unpublish",
        "distTagWrite",
        "tokenWrite",
        "metadataWrite",
    }
    assert "operation" in npm_route.jit["binding"]["fields"]
    npm_fields = npm_adapter.operation_fields(npm_request, npm_route, {"package": "@scope%2fexample"})
    assert npm_fields["packageName"] == "@scope/example", npm_fields
    assert npm_fields["packageVersion"] == "1.2.3", npm_fields
    assert npm_fields["tarballIntegrity"].startswith("sha512-"), npm_fields
    assert npm_adapter.validate_request(npm_request, npm_route, {"package": "@scope%2fexample"}).allowed

    valid_npm_json = npm_request.request.raw_content.decode("utf-8")
    invalid_npm_publish_bodies = (
        valid_npm_json.replace(
            '"name": "@scope/example"',
            '"name": "@scope/example", "name": "@scope/attacker"',
            1,
        ).encode("utf-8"),
        (valid_npm_json[:-1] + ', "nonFinite": NaN}').encode("utf-8"),
        (valid_npm_json[:-1] + ', "overflow": 1e400}').encode("utf-8"),
    )
    for invalid_body in invalid_npm_publish_bodies:
        invalid_publish = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
        invalid_publish.request.raw_content = invalid_body
        assert_denied(
            npm_adapter.validate_request(
                invalid_publish,
                npm_route,
                {"package": "@scope%2fexample"},
            ),
            "npm_publish_invalid_json",
        )
        try:
            npm_adapter.operation_fields(
                invalid_publish,
                npm_route,
                {"package": "@scope%2fexample"},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("npm JIT operation fields accepted an invalid publish body")

    invalid_metadata = flow("POST", "https://registry.npmjs.org/-/npm/v1/user")
    invalid_metadata.request.raw_content = b'{"email":"owner@example.test","email":"attacker@example.test"}'
    assert_denied(
        npm_adapter.validate_request(invalid_metadata, npm_route, {}),
        "npm_write_invalid_json",
    )

    invalid_revision = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
    invalid_revision.request.raw_content = b'{"_rev":"1-safe","_rev":"2-attacker"}'
    credential_accesses: list[str] = []
    upstream_contacts: list[str] = []
    invalid_revision_decision = npm_adapter.validate_request(
        invalid_revision,
        npm_route,
        {"package": "@scope%2fexample"},
    )
    if invalid_revision_decision.allowed:
        credential_accesses.append("cred-npm")
        upstream_contacts.append(invalid_revision.request.pretty_url)
    assert_denied(invalid_revision_decision, "npm_publish_invalid_json")
    assert credential_accesses == []
    assert upstream_contacts == []

    if ServerwareAddon is not None:
        from serverware import policy_engine

        original_get_policy_snapshot = policy_engine.get_policy_snapshot
        original_get_credential = runtime.get_credential
        original_get_credential_version = runtime.get_credential_version
        original_atomic_mode = runtime.atomic_release_authorization_enabled
        original_reserve = runtime.reserve_release_authorization
        original_dispatch = runtime.dispatch_release_authorization
        credential_reads: list[str | None] = []
        authorization_calls: list[str] = []

        def reject_credential_read(credential_id: str | None):
            credential_reads.append(credential_id)
            raise AssertionError("invalid npm body reached credential access")

        policy_engine.get_policy_snapshot = lambda: example_snapshot
        runtime.get_credential = reject_credential_read
        runtime.get_credential_version = reject_credential_read
        runtime.atomic_release_authorization_enabled = lambda: True
        runtime.reserve_release_authorization = lambda **_kwargs: authorization_calls.append("reserve")
        runtime.dispatch_release_authorization = lambda **_kwargs: authorization_calls.append("dispatch")
        try:
            blocked_npm = flow("PUT", "https://registry.npmjs.org/@scope%2fexample")
            blocked_npm.request.headers["X-Serverware-Agent"] = "example-agent"
            blocked_npm.request.raw_content = invalid_npm_publish_bodies[0]
            ServerwareAddon().request(blocked_npm)
            assert credential_reads == [], credential_reads
            assert authorization_calls == [], authorization_calls
            assert blocked_npm.metadata.get("serverware_blocked_response") is True
            assert blocked_npm.response.status_code == 403
            assert json.loads(blocked_npm.response.raw_content)["error"] == "npm_publish_invalid_json"
        finally:
            runtime.dispatch_release_authorization = original_dispatch
            runtime.reserve_release_authorization = original_reserve
            runtime.atomic_release_authorization_enabled = original_atomic_mode
            runtime.get_credential_version = original_get_credential_version
            runtime.get_credential = original_get_credential
            policy_engine.get_policy_snapshot = original_get_policy_snapshot

        missing_lifecycle = flow("POST", "https://demo-upstream:8443/echo")
        runtime.atomic_release_authorization_enabled = lambda: True
        try:
            assert_denied(
                policy_engine.dispatch_release_authorization(missing_lifecycle),
                "release_authorization_lifecycle_missing",
            )
            runtime.atomic_release_authorization_enabled = lambda: False
            assert policy_engine.dispatch_release_authorization(missing_lifecycle).allowed
        finally:
            runtime.atomic_release_authorization_enabled = original_atomic_mode

        successful_reserve = {
            "authorized": True,
            "state": "reserved",
            "reason": "reserved",
            "attempt_id": "attempt:successful-reserve",
            "binding_digest": "sha256:" + "9" * 64,
            "idempotent_replay": False,
            "grant_id": "grant:successful-reserve",
            "approval_request_id": "approval:successful-reserve",
            "approval_status": None,
            "approval_expires_at": None,
            "approval_created": None,
            "reservation_expires_at_epoch_ms": 123456,
            "dispatch_started_at_epoch_ms": None,
            "dispatch_expires_at_epoch_ms": None,
            "completion_outcome": None,
            "retry_after_seconds": 0,
        }
        validated_jit_reserve = _validated_successful_release_reserve(
            successful_reserve,
            attempt_id="attempt:successful-reserve",
            jit_required=True,
        )
        assert validated_jit_reserve == {
            "binding_digest": "sha256:" + "9" * 64,
            "reservation_expires_at_epoch_ms": 123456,
            "grant_id": "grant:successful-reserve",
            "approval_request_id": "approval:successful-reserve",
        }
        for field, invalid_value in (
            ("grant_id", None),
            ("grant_id", ""),
            ("grant_id", " grant:whitespace"),
            ("grant_id", "g" * 257),
            ("grant_id", "grant:invalid\nidentity"),
            ("approval_request_id", None),
            ("approval_request_id", ""),
            ("approval_request_id", "approval:whitespace "),
            ("approval_request_id", "a" * 257),
            ("approval_request_id", "approval:invalid\nidentity"),
        ):
            invalid_identity = {**successful_reserve, field: invalid_value}
            assert (
                _validated_successful_release_reserve(
                    invalid_identity,
                    attempt_id="attempt:successful-reserve",
                    jit_required=True,
                )
                is None
            ), (field, invalid_value)
        for field, invalid_value in (
            ("state", "dispatching"),
            ("reason", "authorized"),
            ("reservation_expires_at_epoch_ms", None),
            ("dispatch_started_at_epoch_ms", 123),
            ("completion_outcome", "forwarded"),
            ("retry_after_seconds", 1),
            ("approval_status", "pending"),
        ):
            invalid_lifecycle = {**successful_reserve, field: invalid_value}
            assert (
                _validated_successful_release_reserve(
                    invalid_lifecycle,
                    attempt_id="attempt:successful-reserve",
                    jit_required=True,
                )
                is None
            ), (field, invalid_value)
        non_jit_reserve = {
            **successful_reserve,
            "grant_id": None,
            "approval_request_id": None,
        }
        assert _validated_successful_release_reserve(
            non_jit_reserve,
            attempt_id="attempt:successful-reserve",
            jit_required=False,
        ) is not None
        for unexpected_identity in (
            {"grant_id": "grant:unexpected"},
            {"approval_request_id": "approval:unexpected"},
        ):
            assert (
                _validated_successful_release_reserve(
                    {**non_jit_reserve, **unexpected_identity},
                    attempt_id="attempt:successful-reserve",
                    jit_required=False,
                )
                is None
            )

        lifecycle_metadata = flow("POST", "https://demo-upstream:8443/echo")
        stored_lifecycle = policy_engine._store_release_lifecycle(
            lifecycle_metadata,
            attempt_id="attempt:successful-reserve",
            binding_digest="sha256:" + "9" * 64,
            state="reserved",
            grant_id="grant:successful-reserve",
            approval_request_id="approval:successful-reserve",
            reservation_expires_at_epoch_ms=123456,
        )
        assert stored_lifecycle["grant_id"] == "grant:successful-reserve"
        assert (
            stored_lifecycle["approval_request_id"]
            == "approval:successful-reserve"
        )
        assert (
            lifecycle_metadata.metadata["serverware_release_grant_id"]
            == "grant:successful-reserve"
        )
        assert (
            lifecycle_metadata.metadata["serverware_release_approval_request_id"]
            == "approval:successful-reserve"
        )

        original_atomic_snapshot = policy_engine.get_policy_snapshot
        original_atomic_get_version = runtime.get_credential_version
        original_atomic_get_credential = runtime.get_credential
        original_atomic_reserve = runtime.reserve_release_authorization
        original_atomic_complete = runtime.complete_release_authorization
        invalid_reserve_credential_reads: list[str | None] = []
        invalid_reserve_completions: list[str] = []

        def invalid_successful_reserve(**kwargs):
            return {
                **successful_reserve,
                "attempt_id": kwargs["attempt_id"],
                "grant_id": None,
            }

        def reject_invalid_reserve_credential_read(credential_id):
            invalid_reserve_credential_reads.append(credential_id)
            raise AssertionError("invalid atomic reserve reached credential access")

        def cancel_invalid_successful_reserve(**kwargs):
            invalid_reserve_completions.append(kwargs["outcome"])
            return {
                "authorized": False,
                "state": "cancelled",
                "attempt_id": kwargs["attempt_id"],
                "binding_digest": kwargs["binding_digest"],
                "completion_outcome": kwargs["outcome"],
            }

        policy_engine.get_policy_snapshot = lambda: example_snapshot
        runtime.atomic_release_authorization_enabled = lambda: True
        runtime.get_credential_version = lambda _credential_id: 1
        runtime.get_credential = reject_invalid_reserve_credential_read
        runtime.reserve_release_authorization = invalid_successful_reserve
        runtime.complete_release_authorization = cancel_invalid_successful_reserve
        try:
            invalid_success = copy.deepcopy(npm_request)
            invalid_success.request.headers["X-Serverware-Agent"] = "example-agent"
            invalid_success_decision = policy_engine.evaluate_request(
                invalid_success
            ).decision
            assert_denied(
                invalid_success_decision,
                "release_authorization_reserve_invalid",
            )
            assert invalid_reserve_credential_reads == []
            assert invalid_reserve_completions == ["not_forwarded"]
            assert invalid_success.metadata["serverware_release_state"] == "cancelled"
        finally:
            runtime.complete_release_authorization = original_atomic_complete
            runtime.reserve_release_authorization = original_atomic_reserve
            runtime.get_credential = original_atomic_get_credential
            runtime.get_credential_version = original_atomic_get_version
            runtime.atomic_release_authorization_enabled = original_atomic_mode
            policy_engine.get_policy_snapshot = original_atomic_snapshot

        from serverware import mitm_addon

        addon = ServerwareAddon()
        original_connect_snapshot = mitm_addon.get_policy_snapshot
        original_connect_log = runtime.log_request
        connect_routes = (
            SimpleNamespace(
                scheme="https",
                host="connect.example.test",
                port=443,
                principals=("agent:connect-assigned",),
            ),
            SimpleNamespace(
                scheme="http",
                host="connect.example.test",
                port=443,
                principals=("agent:http-only",),
            ),
        )
        identified_inputs: list[tuple[str | None, object]] = []

        def connect_flow():
            item = flow("CONNECT", "https://connect.example.test:443")
            item.request.host = "CONNECT.EXAMPLE.TEST."
            item.request.port = 443
            item.request.headers = {
                "Proxy-Authorization": "Basic must-not-enter-audit",
                "X-Serverware-Agent": "connect-agent",
            }
            item.client_conn.peername = ("10.42.0.9", 51234)
            return item

        def connect_snapshot(principal):
            def identify(client_ip, headers):
                identified_inputs.append((client_ip, headers))
                return principal

            return SimpleNamespace(
                routes=connect_routes,
                identify_principal=identify,
            )

        connect_logs: list[tuple[tuple, dict]] = []
        runtime.log_request = lambda *args, **kwargs: connect_logs.append((args, kwargs))
        try:
            unknown_principal = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(None)
            addon.http_connect(unknown_principal)
            assert unknown_principal.response.status_code == 403
            assert unknown_principal.metadata["serverware_blocked_response"] is True
            assert json.loads(unknown_principal.response.raw_content)["error"] == "unknown_connect_denied"

            unassigned_principal = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(
                SimpleNamespace(id="agent:connect-unassigned")
            )
            addon.http_connect(unassigned_principal)
            assert unassigned_principal.response.status_code == 403
            assert unassigned_principal.metadata["serverware_blocked_response"] is True

            snapshot_failure = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: (_ for _ in ()).throw(
                RuntimeError("forced CONNECT snapshot failure")
            )
            addon.http_connect(snapshot_failure)
            assert snapshot_failure.response.status_code == 503
            assert json.loads(snapshot_failure.response.raw_content) == {
                "error": "connect_hook_failed_closed"
            }

            log_failure = connect_flow()
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(None)
            runtime.log_request = lambda *_args, **_kwargs: (_ for _ in ()).throw(
                RuntimeError("forced CONNECT audit failure")
            )
            addon.http_connect(log_failure)
            assert log_failure.response.status_code == 503
            assert log_failure.metadata["serverware_blocked_response"] is True
            assert json.loads(log_failure.response.raw_content) == {
                "error": "connect_hook_failed_closed"
            }

            assigned = connect_flow()
            assigned_principal = SimpleNamespace(id="agent:connect-assigned")
            mitm_addon.get_policy_snapshot = lambda: connect_snapshot(assigned_principal)
            runtime.log_request = lambda *args, **kwargs: connect_logs.append((args, kwargs))
            addon.http_connect(assigned)
            assert getattr(assigned, "response", None) is None
            assert assigned.metadata.get("serverware_blocked_response") is not True
            assert identified_inputs[-1] == ("10.42.0.9", assigned.request.headers)
            assert "must-not-enter-audit" not in repr(connect_logs)
        finally:
            runtime.log_request = original_connect_log
            mitm_addon.get_policy_snapshot = original_connect_snapshot

        original_addon_evaluate_request = mitm_addon.evaluate_request
        original_addon_dispatch = mitm_addon.dispatch_release_authorization
        original_complete = runtime.complete_release_authorization
        completion_outcomes: list[str] = []
        dispatch_calls: list[str] = []

        def complete_failed_hook(**kwargs):
            completion_outcomes.append(kwargs["outcome"])
            expected_state = {
                "not_forwarded": "cancelled",
                "unknown": "committed_indeterminate",
            }[kwargs["outcome"]]
            return {
                "authorized": expected_state != "cancelled",
                "state": expected_state,
                "attempt_id": kwargs["attempt_id"],
                "binding_digest": kwargs["binding_digest"],
                "completion_outcome": kwargs["outcome"],
            }

        def install_lifecycle(item, *, dispatch_attempted: bool = False):
            item.metadata["serverware_release_authorization"] = {
                "attempt_id": "attempt:addon-failure",
                "flow_id": "attempt:addon-failure",
                "binding_digest": "sha256:" + "8" * 64,
                "state": "reserved",
                "dispatch_attempted": dispatch_attempted,
            }

        def fail_after_reserve(item):
            install_lifecycle(item)
            raise RuntimeError("request evaluation failed after reserve")

        def allow_with_reservation(item):
            install_lifecycle(item)
            return SimpleNamespace(decision=policy_engine.PolicyDecision(True))

        def fail_during_dispatch(item):
            dispatch_calls.append("dispatch")
            item.metadata["serverware_release_authorization"]["dispatch_attempted"] = True
            raise RuntimeError("dispatch transport failed unexpectedly")

        runtime.complete_release_authorization = complete_failed_hook
        try:
            mitm_addon.evaluate_request = fail_after_reserve
            mitm_addon.dispatch_release_authorization = lambda _item: dispatch_calls.append(
                "unexpected_dispatch"
            )
            reserved_failure = flow("POST", "https://demo-upstream:8443/echo")
            addon.request(reserved_failure)
            assert reserved_failure.response is not None
            assert reserved_failure.response.status_code == 503
            assert reserved_failure.metadata["serverware_blocked_response"] is True
            assert json.loads(reserved_failure.response.raw_content) == {
                "error": "request_hook_failed_closed"
            }
            assert dispatch_calls == [], dispatch_calls
            assert completion_outcomes == ["not_forwarded"], completion_outcomes
            assert reserved_failure.metadata["serverware_release_state"] == "cancelled"

            mitm_addon.evaluate_request = allow_with_reservation
            mitm_addon.dispatch_release_authorization = fail_during_dispatch
            dispatch_failure = flow("POST", "https://demo-upstream:8443/echo")
            addon.request(dispatch_failure)
            assert dispatch_failure.response is not None
            assert dispatch_failure.response.status_code == 503
            assert dispatch_failure.metadata["serverware_blocked_response"] is True
            assert completion_outcomes == ["not_forwarded", "unknown"], completion_outcomes
            assert dispatch_failure.metadata["serverware_release_state"] == "committed_indeterminate"

            mitm_addon.evaluate_request = lambda _item: (_ for _ in ()).throw(
                AssertionError("streamed request reached policy evaluation")
            )
            streamed = flow("POST", "https://demo-upstream:8443/echo")
            streamed.request.stream = True
            addon.requestheaders(streamed)
            addon.request(streamed)
            assert streamed.response.status_code == 503
            assert json.loads(streamed.response.raw_content) == {
                "error": "request_streaming_unsupported"
            }
        finally:
            runtime.complete_release_authorization = original_complete
            mitm_addon.dispatch_release_authorization = original_addon_dispatch
            mitm_addon.evaluate_request = original_addon_evaluate_request

    npm_extra_version = copy.deepcopy(npm_document)
    npm_extra_version["versions"]["9.9.9"] = {"name": "@scope/example", "version": "9.9.9"}
    assert_denied(
        npm_adapter.validate_request(
            flow("PUT", "https://registry.npmjs.org/@scope%2fexample", npm_extra_version),
            npm_route,
            {"package": "@scope%2fexample"},
        ),
        "npm_publish_requires_exactly_one_version",
    )

    npm_operations = (
        (
            flow("DELETE", "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef"),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample/-rev/42-deadbeef",
                {"_rev": "42-deadbeef", "name": "@scope/example", "versions": {}},
            ),
            {"package": "@scope%2fexample", "revision": "42-deadbeef"},
            "npm.unpublish",
        ),
        (
            flow("DELETE", "https://registry.npmjs.org/-/package/@scope%2fexample/dist-tags/next"),
            {"package": "@scope%2fexample", "tag": "next"},
            "npm.distTagWrite",
        ),
        (
            flow("POST", "https://registry.npmjs.org/-/npm/v1/tokens", {"readonly": True}),
            {},
            "npm.tokenWrite",
        ),
        (
            flow("DELETE", "https://registry.npmjs.org/-/npm/v1/tokens/token/token-key"),
            {"token": "token-key"},
            "npm.tokenWrite",
        ),
        (
            flow("POST", "https://registry.npmjs.org/-/package/@scope%2fexample/access", {"access": "public"}),
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
        (
            flow("POST", "https://registry.npmjs.org/-/npm/v1/user", {"email": "owner@example.test"}),
            {},
            "npm.metadataWrite",
        ),
        (
            flow(
                "PUT",
                "https://registry.npmjs.org/@scope%2fexample",
                {"_rev": "42-deadbeef", "name": "@scope/example", "versions": {}},
            ),
            {"package": "@scope%2fexample"},
            "npm.metadataWrite",
        ),
    )
    for npm_write, params, expected_operation in npm_operations:
        fields = npm_adapter.operation_fields(npm_write, npm_route, params)
        assert fields["operation"] == expected_operation, fields
        assert npm_adapter.validate_request(npm_write, npm_route, params).allowed, fields

    if _bind_provider_account_scope is not None:
        db.clear_rate_limit_counters((x_write_example["id"],))
        account_route = route(example_snapshot, x_write_example["id"])
        account_credential = example_snapshot.credentials[account_route.credential_ref]
        first_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, account_credential, first_operation) is None
        assert first_operation["providerAccount"] == (
            "sha256:a807912d32ff627e2bcaeea09bad5a4ba3b43c74e891cdfb13d913f4230b122e"
        )
        account_tweet = flow("POST", "https://api.x.com/2/tweets", {"text": "first"})
        assert request_decision(
            account_route,
            account_tweet,
            "tweets.write",
            consume=True,
            principal_id="agent:first",
            credential_ref="cred-x:first-version",
            operation_fields=first_operation,
        ).allowed

        rotated_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, account_credential, rotated_operation) is None
        assert_denied(
            request_decision(
                account_route,
                account_tweet,
                "tweets.write",
                consume=True,
                principal_id="agent:second",
                credential_ref="cred-x:rotated-version",
                operation_fields=rotated_operation,
            ),
            "credential_rate_limit_exceeded",
        )

        for alias in ("twitter", "x.oauth", "x.oauth2", " X.OAUTH2 "):
            alias_account = CredentialPolicy(
                id=f"cred-x:{alias.strip().lower()}",
                provider=alias,
                provider_subject=account_credential.provider_subject,
            )
            alias_operation = {"operation": "tweets.write"}
            assert _bind_provider_account_scope(account_route, alias_account, alias_operation) is None
            assert alias_operation["providerAccount"] == first_operation["providerAccount"]
            assert_denied(
                request_decision(
                    account_route,
                    account_tweet,
                    "tweets.write",
                    consume=True,
                    principal_id=f"agent:{alias.strip().lower()}",
                    credential_ref=alias_account.id,
                    operation_fields=alias_operation,
                ),
                "credential_rate_limit_exceeded",
            )

        other_account = CredentialPolicy(
            id="cred-x:other-account",
            provider="x",
            provider_subject="different-x-user-id",
        )
        other_operation = {"operation": "tweets.write"}
        assert _bind_provider_account_scope(account_route, other_account, other_operation) is None
        assert other_operation["providerAccount"] != first_operation["providerAccount"]
        assert request_decision(
            account_route,
            account_tweet,
            "tweets.write",
            consume=True,
            principal_id="agent:third",
            credential_ref=other_account.id,
            operation_fields=other_operation,
        ).allowed

        missing_account = CredentialPolicy(id="cred-x:missing-account", provider="custom-x")
        missing_decision = _bind_provider_account_scope(
            account_route,
            missing_account,
            {"operation": "tweets.write"},
        )
        assert_denied(missing_decision, "provider_account_identity_unavailable")
        db.clear_rate_limit_counters((x_write_example["id"],))

    reset_local_constraint_state()
    tweet_route = route(demo, "demo.x.tweet.one_per_day")
    tweet = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it"})
    assert request_decision(tweet_route, tweet, "tweets.write").allowed
    assert request_decision(tweet_route, tweet, "tweets.write", consume=True).allowed
    assert_denied(
        request_decision(tweet_route, tweet, "tweets.write", consume=True),
        "credential_rate_limit_exceeded",
    )

    db.clear_rate_limit_counters(("demo.x.tweet.one_per_day",))
    reset_local_constraint_state()
    tweet_with_media = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "ship it", "media": {"ids": ["1"]}})
    assert_denied(request_decision(tweet_route, tweet_with_media, "tweets.write"), "json_body_field_not_allowed")

    for unexpected_empty in ({}, [], [{}], {"nested": []}):
        tweet_with_empty_unknown = flow(
            "POST",
            "https://demo-upstream:8443/2/tweets",
            {"text": "ship it", "unexpected": unexpected_empty},
        )
        assert_denied(
            request_decision(tweet_route, tweet_with_empty_unknown, "tweets.write"),
            "json_body_field_not_allowed",
        )

    explicit_container_route = SimpleNamespace(
        id="test.explicit-empty-container",
        credential_ref=None,
        constraints=[
            {
                "id": "explicit-empty-container-body",
                "type": "jsonBody",
                "contentTypes": ["application/json"],
                "allowedFields": ["items"],
                "requiredFields": ["items"],
                "fields": {"items": {"type": "array", "minItems": 0, "maxItems": 1}},
            }
        ],
    )
    for allowed_items in ([], [{}]):
        assert request_decision(
            explicit_container_route,
            flow("POST", "https://api.example.test/items", {"items": allowed_items}),
            "items.write",
        ).allowed
    assert_denied(
        request_decision(
            explicit_container_route,
            flow("POST", "https://api.example.test/items", {"items": [{}, {}]}),
            "items.write",
        ),
        "json_body_field_max_items",
    )

    readonly_route = route(demo, "demo.x.readonly")
    readonly_write = flow("POST", "https://demo-upstream:8443/2/tweets", {"text": "nope"})
    readonly_adapter = get_adapter(readonly_route.adapter_type)
    assert_denied(readonly_adapter.validate_request(readonly_write, readonly_route, {}), "x_write_blocked")

    search_route = route(demo, "demo.x.search.recent")
    old_search = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(10)}&max_results=10",
    )
    assert_denied(request_decision(search_route, old_search, "search.read"), "query_date_window_exceeded")

    huge_page = flow(
        "GET",
        f"https://demo-upstream:8443/2/tweets/search/recent?query=serverware&start_time={iso_days_ago(1)}&max_results=500",
    )
    assert_denied(request_decision(search_route, huge_page, "search.read"), "query_numeric_max_exceeded")

    for non_finite in ("NaN", "Infinity", "-Infinity", "1e400"):
        non_finite_query = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent"
            f"?query=serverware&start_time={iso_days_ago(1)}&max_results={non_finite}",
        )
        assert_denied(
            request_decision(search_route, non_finite_query, "search.read"),
            "query_numeric_parameter_invalid",
        )
        non_finite_date_query = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent"
            f"?query=serverware&start_time={non_finite}&max_results=10",
        )
        assert_denied(
            request_decision(search_route, non_finite_date_query, "search.read"),
            "query_date_parameter_invalid",
        )

    old_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": [{"id": "1", "text": "old", "created_at": iso_days_ago(10)}]},
    )
    assert_denied(evaluate_response_constraints(old_response, search_route), "response_date_window_exceeded")
    for invalid_date_body in (
        b'{"data":[{"created_at":"first","created_at":"second"}]}',
        b'{"data":[{"created_at":NaN}]}',
        b'{"data":[{"created_at":Infinity}]}',
        b'{"data":[{"created_at":-Infinity}]}',
        b'{"data":[{"created_at":1e400}]}',
    ):
        invalid_date_response = flow(
            "GET",
            "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
            response={"data": []},
        )
        invalid_date_response.response.raw_content = invalid_date_body
        assert_denied(
            evaluate_response_constraints(invalid_date_response, search_route),
            "response_json_invalid",
        )
    empty_response = flow(
        "GET",
        "https://demo-upstream:8443/2/tweets/search/recent?query=serverware",
        response={"data": []},
    )
    assert evaluate_response_constraints(empty_response, search_route).allowed

    gmail_route = route(demo, "demo.gmail.recent")
    gmail_old_list = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "msg-old", "internalDate": str(epoch_ms_days_ago(45))}]},
    )
    gmail_old_list.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(gmail_old_list, gmail_route), "response_date_window_exceeded")

    gmail_detail = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent-message-1",
        response={"id": "recent-message-1", "internalDate": str(epoch_ms_days_ago(1))},
    )
    assert_denied(evaluate_response_constraints(gmail_detail, gmail_route), "response_operation_context_missing")
    gmail_detail.metadata["serverware_operation"] = {"operation": "gmail.message.get"}
    assert evaluate_response_constraints(gmail_detail, gmail_route).allowed

    gmail_adapter = get_adapter(gmail_route.adapter_type)
    for projection in (None, []):
        unprojected_gmail_route = copy.deepcopy(gmail_route)
        response_config = unprojected_gmail_route.adapter_config["response"]
        if projection is None:
            response_config.pop("allowedFields")
        else:
            response_config["allowedFields"] = projection
        unprojected_gmail = flow(
            "GET",
            "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
            response={
                "id": "recent",
                "internalDate": str(epoch_ms_days_ago(1)),
                "provider_internal_secret": "must-not-release",
            },
        )
        decision = gmail_adapter.validate_response(
            unprojected_gmail,
            unprojected_gmail_route,
            {"user": "me", "message_id": "recent"},
        )
        assert_denied(decision, "credential_response_projection_required")
        assert decision.status_code == 502
        assert decision.reason == "credential-bearing response requires a non-empty allowedFields projection"
        assert decision.payload == {
            "error": "credential_response_projection_required",
            "adapter": "gmail.v1",
            "mode": "json",
        }

    gmail_unproven = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={
            "messages": [
                {"id": "unproven", "snippet": "must not escape"},
                {"id": "recent", "internalDate": str(epoch_ms_days_ago(1))},
            ]
        },
    )
    gmail_unproven.metadata.update(
        {
            "serverware_principal_id": "agent:demo",
            "serverware_credential_id": gmail_route.credential_ref,
            "serverware_credential_version": 1,
            "serverware_policy_hash": demo.hash,
        }
    )
    assert gmail_adapter.validate_response(gmail_unproven, gmail_route, {"user": "me"}).allowed
    released = json.loads(gmail_unproven.response.get_text())
    assert [item["id"] for item in released["messages"]] == ["recent"], released

    gmail_headers = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "id": "recent",
            "internalDate": str(epoch_ms_days_ago(1)),
            "provider_internal_secret": "top-level-secret",
            "payload": {
                "body": {"data": "nested-secret"},
                "headers": [
                    {"name": "From", "value": "sender@example.test"},
                    {"name": "Subject", "value": "allowed"},
                    {"name": "Bcc", "value": "must-not-release@example.test"},
                ]
            },
        },
    )
    gmail_headers.response.headers.update(
        {"set-cookie": "provider_session=secret", "location": "https://evil.test/"}
    )
    gmail_detail_params = {"user": "me", "message_id": "recent"}
    assert gmail_adapter.validate_response(gmail_headers, gmail_route, gmail_detail_params).allowed
    released_gmail = json.loads(gmail_headers.response.get_text())
    released_headers = released_gmail["payload"]["headers"]
    assert [item["name"] for item in released_headers] == ["From", "Subject"], released_headers
    assert "provider_internal_secret" not in released_gmail
    assert "body" not in released_gmail["payload"]
    assert "top-level-secret" not in gmail_headers.response.get_text()
    assert "nested-secret" not in gmail_headers.response.get_text()
    assert set(name.lower() for name in gmail_headers.response.headers) == {
        "content-type",
        "content-length",
    }, gmail_headers.response.headers

    gmail_error = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={
            "error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "slow down"},
            "providerInternal": "must not release",
        },
    )
    gmail_error.response.status_code = 429
    gmail_error.response.headers.update(
        {
            "retry-after": "30",
            "www-authenticate": 'Bearer realm="gmail"',
            "set-cookie": "provider_session=secret",
        }
    )
    assert gmail_adapter.validate_response(gmail_error, gmail_route, gmail_detail_params).allowed
    assert json.loads(gmail_error.response.get_text()) == {
        "error": {"code": 429, "message": "slow down", "status": "RESOURCE_EXHAUSTED"}
    }
    assert gmail_error.response.headers.get("retry-after") == "30"
    assert gmail_error.response.headers.get("www-authenticate") == 'Bearer realm="gmail"'
    assert "set-cookie" not in {name.lower() for name in gmail_error.response.headers}

    gmail_redirect = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages/recent",
        response={"redirect": True},
    )
    gmail_redirect.response.status_code = 302
    gmail_redirect.response.headers["location"] = "https://evil.test/"
    assert_denied(
        gmail_adapter.validate_response(gmail_redirect, gmail_route, gmail_detail_params),
        "response_redirect_not_allowed",
    )

    npm_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "denied", "reason": "policy", "internal": "must not release"},
    )
    npm_error.response.status_code = 403
    npm_adapter = get_adapter(route(demo, "demo.npm.publish.jit").adapter_type)
    npm_demo_route = route(demo, "demo.npm.publish.jit")
    npm_demo_request = flow(
        "PUT",
        "https://demo-upstream:8443/npm/@scope%2fexample",
        npm_document,
    )
    npm_demo_fields = npm_adapter.operation_fields(
        npm_demo_request,
        npm_demo_route,
        {"package": "@scope%2fexample"},
    )
    npm_demo_success = flow(
        "PUT",
        "https://demo-upstream:8443/npm/@scope%2fexample",
        response={
            "package": "@scope/example",
            "version": "1.2.3",
            "published": True,
        },
    )
    npm_demo_success.metadata["serverware_operation"] = npm_demo_fields
    assert evaluate_response_constraints(npm_demo_success, npm_demo_route).allowed
    npm_demo_wrong_version = copy.deepcopy(npm_demo_success)
    npm_demo_wrong_version.response.raw_content = json.dumps(
        {
            "package": "@scope/example",
            "version": "9.9.9",
            "published": True,
        }
    ).encode("utf-8")
    assert_denied(
        evaluate_response_constraints(npm_demo_wrong_version, npm_demo_route),
        "response_binding_mismatch",
    )
    assert npm_adapter.validate_response(npm_error, npm_demo_route, {"package": "@scope%2fexample"}).allowed
    assert json.loads(npm_error.response.get_text()) == {"error": "denied", "reason": "policy"}

    npm_invalid_error = flow(
        "PUT",
        "https://demo-upstream:8443/@scope%2fexample",
        response={"error": "invalid"},
    )
    npm_invalid_error.response.status_code = 500
    npm_invalid_error.response.raw_content = b"not-json"
    assert_denied(
        npm_adapter.validate_response(npm_invalid_error, npm_demo_route, {"package": "@scope%2fexample"}),
        "response_invalid_json",
    )

    wrong_epoch_format = flow(
        "GET",
        "https://demo-upstream:8443/gmail/v1/users/me/messages",
        response={"messages": [{"id": "seconds", "internalDate": int(datetime.now(timezone.utc).timestamp())}]},
    )
    wrong_epoch_format.metadata["serverware_operation"] = {"operation": "gmail.messages.list"}
    assert_denied(evaluate_response_constraints(wrong_epoch_format, gmail_route), "response_date_field_invalid")

    if evaluate_response is not None:
        missing_response_context = flow(
            "GET",
            "https://demo-upstream:8443/unknown",
            response={"secret": "must not escape"},
        )
        assert_denied(evaluate_response(missing_response_context), "response_policy_context_missing")
        missing_response_context.metadata["serverware_blocked_response"] = True
        assert evaluate_response(missing_response_context).allowed

        guard_route = SimpleNamespace(
            id="response.credential.guard",
            adapter_type="generic.rest",
            adapter_config={
                "response": {
                    "mode": "json",
                    "maxBodyBytes": 4096,
                    "allowedFields": ["echo", "ok", "authorization_sha256"],
                }
            },
            constraints=[],
            credential_ref="response-guard-credential",
        )

        def guarded_response(secret: str, payload: dict, injection: dict | None = None):
            guarded = flow("GET", "https://demo-upstream:8443/guarded", response=payload)
            guarded.metadata.update(
                {
                    "serverware_route": guard_route,
                    "serverware_route_id": guard_route.id,
                    "serverware_params": {},
                    "serverware_principal_id": "agent:demo",
                    "serverware_credential_id": guard_route.credential_ref,
                    "serverware_credential_version": 1,
                    "serverware_policy_hash": demo.hash,
                }
            )
            _inject_credential(
                guarded,
                SimpleNamespace(injection=injection or {"type": "bearer"}),
                {"secret": secret, "kind": "bearer", "metadata": {}},
            )
            return guarded

        audit_calls = []
        original_log_request = runtime.log_request
        runtime.log_request = lambda *args, **kwargs: audit_calls.append((args, kwargs))
        try:
            from serverware import mitm_addon

            lifecycle_order: list[str] = []
            lifecycle_response = guarded_response(
                "prototype-lifecycle-secret",
                {"ok": True},
            )
            lifecycle_response.metadata.update(
                {
                    "serverware_release_authorization": {
                        "attempt_id": "attempt:response-completion",
                        "flow_id": "attempt:response-completion",
                        "binding_digest": "sha256:" + "7" * 64,
                        "state": "dispatching",
                        "dispatch_attempted": True,
                    },
                    "serverware_release_attempt_id": "attempt:response-completion",
                    "serverware_release_binding_digest": "sha256:" + "7" * 64,
                    "serverware_release_state": "dispatching",
                }
            )
            original_complete_release = runtime.complete_release_authorization
            original_addon_evaluate_response = mitm_addon.evaluate_response

            def complete_forwarded(**kwargs):
                lifecycle_order.append("complete:forwarded")
                return {
                    "authorized": True,
                    "state": "committed",
                    "attempt_id": kwargs["attempt_id"],
                    "binding_digest": kwargs["binding_digest"],
                    "completion_outcome": kwargs["outcome"],
                }

            def observe_response_policy(item):
                lifecycle_order.append("response_policy")
                return original_addon_evaluate_response(item)

            runtime.complete_release_authorization = complete_forwarded
            mitm_addon.evaluate_response = observe_response_policy
            try:
                ServerwareAddon().response(lifecycle_response)
            finally:
                mitm_addon.evaluate_response = original_addon_evaluate_response
                runtime.complete_release_authorization = original_complete_release
            assert lifecycle_order == ["complete:forwarded", "response_policy"], lifecycle_order
            assert lifecycle_response.metadata["serverware_release_state"] == "committed"

            evaluator_secret = "prototype-evaluator-failure-secret-6bf4"
            evaluator_failure = guarded_response(
                evaluator_secret,
                {"echo": evaluator_secret},
            )
            original_evaluator_response = evaluator_failure.response
            mitm_addon.evaluate_response = lambda _item: (_ for _ in ()).throw(
                RuntimeError("forced response evaluator failure")
            )
            try:
                ServerwareAddon().response(evaluator_failure)
            finally:
                mitm_addon.evaluate_response = original_addon_evaluate_response
            assert evaluator_failure.response is not original_evaluator_response
            assert evaluator_failure.metadata["serverware_blocked_response"] is True
            assert evaluator_failure.response.status_code == 503
            assert json.loads(evaluator_failure.response.get_text()) == {
                "error": "response_hook_failed_closed"
            }
            assert evaluator_secret not in evaluator_failure.response.get_text()

            escaped_secret = 'prototype-"credential /? value'
            reflected = guarded_response(escaped_secret, {"echo": escaped_secret})
            reflected_decision = evaluate_response(reflected)
            assert_denied(reflected_decision, "response_credential_reflection")
            assert reflected_decision.reason == "response credential reflection denied"
            assert escaped_secret not in repr(audit_calls)
            assert not hasattr(reflected, "_serverware_response_credential_guard")

            addon_secret = "prototype-addon-reflection-83e1"
            addon_reflection = guarded_response(addon_secret, {"echo": addon_secret})
            ServerwareAddon().response(addon_reflection)
            assert addon_reflection.response.status_code == 502
            addon_payload = json.loads(addon_reflection.response.get_text())
            assert addon_payload == {"error": "response_credential_reflection"}, addon_payload
            assert addon_secret not in addon_reflection.response.get_text()
            assert addon_secret not in repr(audit_calls)

            basic_secret = "prototype-basic-password-9f4b"
            basic_reflection = guarded_response(
                basic_secret,
                {"ok": True},
                {"type": "basic", "username": "prototype-user"},
            )
            basic_reflection.response.headers["x-upstream-authorization"] = basic_reflection.request.headers["Authorization"]
            assert evaluate_response(basic_reflection).allowed
            assert "x-upstream-authorization" not in {
                name.lower() for name in basic_reflection.response.headers
            }
            assert basic_secret not in repr(audit_calls)

            hash_secret = "prototype-hash-reflection-7d2c"
            hash_reflection = guarded_response(
                hash_secret,
                {
                    "authorization_sha256": "sha256:"
                    + hashlib.sha256(f"Bearer {hash_secret}".encode("utf-8")).hexdigest()
                },
            )
            assert_denied(evaluate_response(hash_reflection), "response_credential_reflection")
            assert hash_secret not in repr(audit_calls)

            exact_secret = "exact-credential-value-123"
            near_match = guarded_response(exact_secret, {"echo": "exact-credential-value-124"})
            assert evaluate_response(near_match).allowed

            redacted_route = SimpleNamespace(
                id="response.credential.guard.redacted",
                adapter_type="generic.rest",
                adapter_config={
                    "response": {
                        "mode": "json",
                        "maxBodyBytes": 4096,
                        "allowedFields": ["safe"],
                    }
                },
                constraints=[
                    {
                        "id": "hidden-provider-status",
                        "type": "responseJson",
                        "phase": "response",
                        "fields": {"provider_status": {"type": "string", "enum": ["ok"]}},
                    }
                ],
                credential_ref=guard_route.credential_ref,
            )
            malformed_hidden = guarded_response(
                exact_secret,
                {"safe": "released", "provider_status": "corrupt"},
            )
            malformed_hidden.metadata["serverware_route"] = redacted_route
            malformed_hidden.metadata["serverware_route_id"] = redacted_route.id
            assert_denied(evaluate_response(malformed_hidden), "response_json_field_enum_denied")

            redacted = guarded_response(
                exact_secret,
                {"safe": "released", "leak": exact_secret, "provider_status": "ok"},
            )
            redacted.metadata["serverware_route"] = redacted_route
            redacted.metadata["serverware_route_id"] = redacted_route.id
            assert evaluate_response(redacted).allowed
            assert exact_secret.encode("utf-8") not in redacted.response.raw_content
            assert json.loads(redacted.response.raw_content) == {"safe": "released"}
        finally:
            runtime.log_request = original_log_request

    print(f"credential constraint tests passed; schema_validation={validate_schema}")


if __name__ == "__main__":
    try:
        main()
    finally:
        tmpdir.cleanup()
