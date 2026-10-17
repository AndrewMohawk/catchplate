#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import HTTPException, Response

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from catchplate import auth


ADMIN_TOKEN = "csrf-test-admin-token-32-bytes-minimum"


def fake_request(
    *,
    method: str,
    path: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    scheme: str = "https",
) -> Any:
    return SimpleNamespace(
        method=method,
        url=SimpleNamespace(path=path, scheme=scheme),
        headers=headers or {},
        cookies=cookies or {},
    )


def expect_ok(name: str, request: Any) -> None:
    try:
        auth.validate_csrf_request(request)
    except HTTPException as exc:
        raise AssertionError(f"{name} unexpectedly failed CSRF validation: {exc.detail}") from exc


def expect_csrf_failure(name: str, request: Any) -> None:
    try:
        auth.validate_csrf_request(request)
    except HTTPException as exc:
        if exc.status_code != 403 or "CSRF token required" not in str(exc.detail):
            raise AssertionError(f"{name} failed with wrong error: {exc.status_code} {exc.detail}") from exc
        return
    raise AssertionError(f"{name} unexpectedly passed CSRF validation")


def main() -> None:
    os.environ["CATCHPLATE_ADMIN_TOKEN"] = ADMIN_TOKEN
    auth.admin_token.cache_clear()

    cookie_auth = {"catchplate_admin": ADMIN_TOKEN}
    csrf_cookie = {**cookie_auth, auth.CSRF_COOKIE_NAME: "csrf-token"}
    csrf_header = {auth.CSRF_HEADER_NAME: "csrf-token"}

    expect_ok("safe GET with admin cookie", fake_request(method="GET", path="/api/bootstrap", cookies=cookie_auth))
    expect_ok(
        "unsafe mutation with double-submit CSRF",
        fake_request(method="POST", path="/api/routes", headers=csrf_header, cookies=csrf_cookie),
    )
    expect_ok(
        "unsafe mutation with header token automation",
        fake_request(
            method="POST",
            path="/api/routes",
            headers={"X-Catchplate-Admin-Token": ADMIN_TOKEN},
            cookies=cookie_auth,
        ),
    )
    expect_ok(
        "unsafe mutation with bearer token automation",
        fake_request(
            method="POST",
            path="/api/routes",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            cookies=cookie_auth,
        ),
    )
    expect_ok(
        "data-plane endpoint is not cookie-admin CSRF scoped",
        fake_request(method="POST", path="/api/data-plane/audit", cookies=cookie_auth),
    )

    expect_csrf_failure(
        "unsafe cookie mutation without CSRF",
        fake_request(method="POST", path="/api/routes", cookies=cookie_auth),
    )
    expect_csrf_failure(
        "unsafe cookie mutation with mismatched CSRF",
        fake_request(
            method="DELETE",
            path="/api/logs",
            headers={auth.CSRF_HEADER_NAME: "wrong"},
            cookies=csrf_cookie,
        ),
    )

    response = Response()
    token = auth.issue_csrf_cookie(response, fake_request(method="GET", path="/api/csrf"), token="fixed-csrf")
    set_cookie = response.headers.get("set-cookie", "")
    if token != "fixed-csrf" or "catchplate_csrf=fixed-csrf" not in set_cookie or "SameSite=strict" not in set_cookie:
        raise AssertionError(f"CSRF cookie was not issued with strict double-submit settings: {set_cookie}")

    print(json.dumps({"control_plane_csrf": "pass", "ok": True}, sort_keys=True))


if __name__ == "__main__":
    main()
