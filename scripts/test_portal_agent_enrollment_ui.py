#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="serverware-portal-enrollment-") as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(Path(tmp) / "policy-bundle.json")
        os.environ["SERVERWARE_POLICY_SIGNING_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pem")
        os.environ["SERVERWARE_POLICY_SIGNING_PUBLIC_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pub.pem")

        from serverware.enrollment import policy_principal_summaries
        from serverware.policy_bundle import compile_policy_bundle, demo_policy_bundle, sign_policy_bundle

        signed = sign_policy_bundle(demo_policy_bundle("cred-demo-bearer"))
        snapshot = compile_policy_bundle(signed, verify_signature=True, validate_schema=False)

        principals = {item["id"]: item for item in policy_principal_summaries(snapshot)}
        demo = principals.get("agent:demo-proxy-token")
        if not demo:
            raise AssertionError(f"principal summary did not expose policy principals: {principals}")
        if demo.get("routeCount", 0) <= 0:
            raise AssertionError(f"principal route count is missing: {demo}")
        if demo.get("requiredHeaders") != {"X-Serverware-Agent": "demo-token-agent"}:
            raise AssertionError(f"principal identity summary is wrong: {demo}")

        app_source = (ROOT / "serverware" / "app.py").read_text(encoding="utf-8")
        try:
            ui_html = app_source.split('UI_HTML = r"""', 1)[1].rsplit('"""', 1)[0]
        except IndexError as exc:
            raise AssertionError("could not locate UI_HTML literal") from exc

        required_markup = (
            'id="agent-enrollment-form"',
            'id="enrollment-principal"',
            'name="proxyEgressCidrs"',
            'id="enrollment-output"',
            "/api/agents/enrollment",
            "copyEnrollment()",
            "downloadEnrollment()",
            "state.enrollmentPacket",
        )
        for marker in required_markup:
            if marker not in ui_html:
                raise AssertionError(f"portal enrollment UI marker missing: {marker}")

        forbidden_markup = ("tokenSha256", "proxy bearer token")
        for marker in forbidden_markup:
            if marker in ui_html:
                raise AssertionError(f"portal UI should not mention secret-bearing enrollment internals: {marker}")

    print(canonical_json({"ok": True, "portal_agent_enrollment_ui": "pass"}))


if __name__ == "__main__":
    main()
