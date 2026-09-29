from __future__ import annotations

import asyncio
from importlib.metadata import version
from typing import Any
from urllib.parse import unquote

import httptools
from uvicorn import __version__ as uvicorn_version
from uvicorn._types import ASGI3Application
from uvicorn.protocols.http.httptools_impl import (
    HttpToolsProtocol,
    RequestResponseCycle as HttpToolsRequestResponseCycle,
)


_SUPPORTED_UVICORN_VERSION = "0.34.0"
_SUPPORTED_HTTPTOOLS_VERSION = "0.8.0"
_INSTALLED_HTTPTOOLS_VERSION = version("httptools")


def validate_signed_http_protocol(*, limit_concurrency: int | None = None) -> None:
    if uvicorn_version != _SUPPORTED_UVICORN_VERSION:
        raise RuntimeError(
            "signed-only HTTP requires the audited Uvicorn 0.34.0 protocol"
        )
    if _INSTALLED_HTTPTOOLS_VERSION != _SUPPORTED_HTTPTOOLS_VERSION:
        raise RuntimeError(
            "signed-only HTTP requires the audited httptools 0.8.0 parser"
        )
    if limit_concurrency is not None:
        raise RuntimeError(
            "signed-only HTTP forbids Uvicorn's unsigned concurrency response"
        )


class _SignedResponseCycle:
    async def run_asgi(self, app: ASGI3Application) -> None:
        if self.waiting_for_100_continue:
            self.logger.warning(
                "closing HTTP connection because unsigned interim responses "
                "are disabled"
            )
            self.transport.close()
            return
        try:
            result = await app(self.scope, self.receive, self.send)
        except BaseException as exc:
            self.logger.error("Exception in signed ASGI application", exc_info=exc)
            self.transport.close()
        else:
            if result is not None:
                self.logger.error(
                    "Signed ASGI callable returned a non-None result"
                )
                self.transport.close()
            elif not self.response_started and not self.disconnected:
                self.logger.error(
                    "Signed ASGI callable returned without starting a response"
                )
                self.transport.close()
            elif not self.response_complete and not self.disconnected:
                self.logger.error(
                    "Signed ASGI callable returned without completing a response"
                )
                self.transport.close()
        finally:
            self.on_response = lambda: None


class _SignedHttpToolsRequestResponseCycle(
    _SignedResponseCycle, HttpToolsRequestResponseCycle
):
    pass


class SignedOnlyHttpToolsProtocol(HttpToolsProtocol):
    """Fail-closed HTTP/1.1 protocol using the fast pinned httptools parser."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        config = kwargs.get("config")
        if config is None and args:
            config = args[0]
        validate_signed_http_protocol(
            limit_concurrency=getattr(config, "limit_concurrency", None)
        )
        super().__init__(*args, **kwargs)

    def data_received(self, data: bytes) -> None:
        try:
            super().data_received(data)
        except Exception:
            self.logger.error(
                "closing HTTP connection after parser callback failure"
            )
            self.transport.close()

    def send_400_response(self, msg: str) -> None:
        del msg
        self.logger.warning(
            "closing HTTP connection because unsigned protocol errors are disabled"
        )
        self.transport.close()

    def on_headers_complete(self) -> None:
        http_version = self.parser.get_http_version()
        method = self.parser.get_method()
        self.scope["method"] = method.decode("ascii")
        if http_version != "1.1":
            self.scope["http_version"] = http_version
        if self.parser.should_upgrade():
            raise httptools.HttpParserError(
                "HTTP protocol upgrades are disabled"
            )
        parsed_url = httptools.parse_url(self.url)
        raw_path = parsed_url.path
        path = raw_path.decode("ascii")
        if "%" in path:
            path = unquote(path)
        self.scope["path"] = self.root_path + path
        self.scope["raw_path"] = self.root_path.encode("ascii") + raw_path
        self.scope["query_string"] = parsed_url.query or b""
        if self.scope["path"] == "/api/data-plane/audit":
            from serverware import control_plane_data_plane_audit as measured_audit
            self.scope["serverware.measured_audit_peer"] = measured_audit.peer_from_transport(self.transport)
        if self.scope["path"] in {"/api/data-plane/policy-canary/controlled-evidence", "/api/data-plane/policy-canary/controlled-evidence/inspect"}:
            from serverware import control_plane_policy_canary_startup as policy_canary
            self.scope[policy_canary.PEER_SCOPE] = policy_canary.peer_from_transport(self.transport)

        existing_cycle = self.cycle
        self.cycle = _SignedHttpToolsRequestResponseCycle(
            scope=self.scope,
            transport=self.transport,
            flow=self.flow,
            logger=self.logger,
            access_logger=self.access_logger,
            access_log=self.access_log,
            default_headers=self.server_state.default_headers,
            message_event=asyncio.Event(),
            expect_100_continue=self.expect_100_continue,
            keep_alive=http_version != "1.0",
            on_response=self.on_response_complete,
        )
        if existing_cycle is None or existing_cycle.response_complete:
            task = self.loop.create_task(self.cycle.run_asgi(self.app))
            task.add_done_callback(self.tasks.discard)
            self.tasks.add(task)
        else:
            self.flow.pause_reading()
            self.pipeline.appendleft((self.cycle, self.app))
