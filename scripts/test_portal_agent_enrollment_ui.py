#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def javascript_function_source(
    source: str, name_pattern: str, *, label: str
) -> tuple[str, str]:
    match = re.search(
        rf"(?:async\s+)?function\s+(?P<name>{name_pattern})\s*\([^)]*\)\s*\{{",
        source,
        flags=re.IGNORECASE,
    )
    if match is None:
        raise AssertionError(f"could not locate {label} function")
    following = source[match.end() :]
    next_function = re.search(
        r"\n\s{4}(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(",
        following,
    )
    end = len(source) if next_function is None else match.end() + next_function.start()
    return match.group("name"), source[match.start() : end]


def assert_approval_review_decision_ui(ui_html: str) -> None:
    try:
        review_fn = ui_html.split("function renderApprovalReview()", 1)[1].split(
            "async function approve", 1
        )[0]
    except IndexError as exc:
        raise AssertionError("could not isolate renderApprovalReview function") from exc

    review_action_markers = (
        "const actionsTarget = $('approval-review-actions')",
        "actionsTarget.hidden = review.status !== 'pending'",
        'for="${denialNoteId}"',
        'id="${denialNoteId}"',
        "approvalReviewActionBlockReason(approvalItem)",
        "() => approve('${review.id}')",
        "() => deny('${review.id}')",
        "review.status === 'pending'",
        "review.decision_note",
    )
    missing_review_actions = [
        marker for marker in review_action_markers if marker not in review_fn
    ]
    if missing_review_actions:
        raise AssertionError(
            "approval review decision controls are incomplete; "
            f"missing={missing_review_actions}; renderer={review_fn[:1200]!r}"
        )
    if "api(`/api/approvals/" in review_fn:
        raise AssertionError(
            "approval review renderer must reuse approve(id)/deny(id), not issue decision API requests"
        )

    _, approve_fn = javascript_function_source(
        ui_html, "approve", label="JIT approval decision"
    )
    approve_markers = (
        "approvalReviewBlockReason(item)",
        "state.approvalReview?.review_receipt?.id",
        "navigator.credentials.get",
        "await api(`/api/approvals/${id}/approve",
        "await refresh()",
        "await loadApprovalReview(id)",
    )
    missing_approve_markers = [
        marker for marker in approve_markers if marker not in approve_fn
    ]
    if missing_approve_markers:
        raise AssertionError(
            "review approval path lost receipt, WebAuthn, or completed-review behavior; "
            f"missing={missing_approve_markers}; approve={approve_fn[:1200]!r}"
        )
    if approve_fn.rfind("await loadApprovalReview(id)") < approve_fn.rfind(
        "await refresh()"
    ):
        raise AssertionError(
            "review approval path must reload the canonical completed document after refresh"
        )

    _, deny_fn = javascript_function_source(ui_html, "deny", label="JIT denial decision")
    deny_markers = (
        "const reviewNote = $(`approval-review-deny-note-${id}`)",
        "(reviewNote || $(`jit-deny-note-${id}`))?.value.trim()",
        "await api(`/api/approvals/${id}/deny`",
        "if (reviewed) await loadApprovalReview(id)",
    )
    missing_deny_markers = [marker for marker in deny_markers if marker not in deny_fn]
    if missing_deny_markers:
        raise AssertionError(
            "review denial path lost its local note or completed-review behavior; "
            f"missing={missing_deny_markers}; deny={deny_fn[:1000]!r}"
        )
    if deny_fn.count("/api/approvals/${id}/deny") != 1:
        raise AssertionError("review denial path must issue exactly one decision request")

    for marker in (
        "access_token",
        "refresh_token",
        "secretToken",
        "top-secret-value",
        "Bearer top-secret-value",
    ):
        if marker in review_fn:
            raise AssertionError(
                f"approval review UI must not hard-code secret-bearing examples: {marker}"
            )


class PortalAccessibilityParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.control_ids: list[str] = []
        self.label_targets: set[str] = set()
        self.h1_count = 0
        self.skip_target: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "h1":
            self.h1_count += 1
        if tag == "a" and values.get("class") == "skip-link":
            self.skip_target = values.get("href")
        if tag == "label" and values.get("for"):
            self.label_targets.add(str(values["for"]))
        if tag in {"input", "select", "textarea"}:
            control_id = values.get("id")
            if not control_id:
                raise AssertionError(f"portal {tag} control is missing an id: {attrs}")
            self.control_ids.append(control_id)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--approval-review-only",
        action="store_true",
        help="run only the focused static approval-review decision contract",
    )
    parser.add_argument(
        "--policy-templates-only",
        action="store_true",
        help="run only the focused static specialized-provider template contract",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="serverware-portal-enrollment-") as tmp:
        os.environ["SERVERWARE_DATA_DIR"] = tmp
        os.environ["SERVERWARE_POLICY_BUNDLE"] = str(Path(tmp) / "policy-bundle.json")
        os.environ["SERVERWARE_POLICY_SIGNING_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pem")
        os.environ["SERVERWARE_POLICY_SIGNING_PUBLIC_KEY"] = str(Path(tmp) / "policy-signing-ed25519.pub.pem")

        from serverware.enrollment import policy_principal_summaries
        from serverware.policy_bundle import (
            compile_policy_bundle,
            demo_policy_bundle,
            provider_request_profile,
            sign_policy_bundle,
        )

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
            'id="enrollment-copy-agent-instructions"',
            "function agentInstructionText(packet)",
            "function copyAgentInstructions()",
            "packet.agentHandoff?.instructionsText",
            "Enrollment packet is missing signed agent instructions",
            "state.enrollmentPacket",
            "copyEnrollmentVerifier",
            "Generate an enrollment packet first so the verifier is bound to its pins",
            "async function downloadEnrollmentBinding()",
            "const packetFilename = downloadEnrollment(packetText);",
            "crypto.subtle.digest('SHA-256'",
            "set -eu",
            "SERVERWARE_PACKET_SHA256",
            "--emit-verified-instructions",
            "SERVERWARE_ENROLLMENT_PACKET:-$HOME/Downloads/",
            'serverware-enrollment --verify-packet "$ENROLLMENT_PACKET"',
            "--expected-packet-sha256",
            "--expected-principal",
            "--expected-nonce",
            '> "$VERIFIED_ENROLLMENT_PACKET"',
            "pinning.policySigningKeyId",
            "pinning.rollbackEpoch",
            "serverware-attestation --base",
            '--enrollment-packet "$VERIFIED_ENROLLMENT_PACKET"',
            "--expected-policy-key-hash",
            "--expected-rollback-epoch",
            "if (control.id.startsWith('setup-')) return;",
        )
        for marker in required_markup:
            if marker not in ui_html:
                raise AssertionError(f"portal enrollment UI marker missing: {marker}")

        oauth_uncertainty_markers = (
            'id="oauth-uncertain-section"',
            'id="oauth-issuance-uncertainties"',
            "state.oauthIssuanceUncertainties",
            "function renderOAuthIssuanceUncertainties()",
            "function resolveOAuthIssuanceUncertainty(id)",
            "/api/oauth/issuance-uncertainties/${id}/resolve",
            "confirmedProviderRevocation: true",
            "Provider issuance requires review",
            "I confirmed the provider-side app grant was revoked.",
        )
        for marker in oauth_uncertainty_markers:
            if marker not in ui_html:
                raise AssertionError(
                    f"portal OAuth issuance-uncertainty UI marker missing: {marker}"
                )

        workspace_markers = (
            'class="workspace-nav" aria-label="Portal workspaces"',
            'href="#setup-workspace"',
            'href="#credential-workspace"',
            'href="#policy-workspace"',
            'href="#approval-workspace"',
            'href="#audit-workspace"',
            'href="#attestation-workspace"',
            'id="oauth-connected-section"',
            'id="oauth-connected-accounts"',
            "function renderOAuthConnectedAccounts()",
            "function credentialMetadataDisclosure(item)",
        )
        for marker in workspace_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal workspace UX marker missing: {marker}")

        try:
            enrollment_binding_fn = ui_html.split(
                "async function downloadEnrollmentBinding()", 1
            )[1].split("\n\n    async function deleteCredential", 1)[0]
            agent_instruction_copy_fn = ui_html.split(
                "async function copyAgentInstructions()", 1
            )[1].split("\n\n    function enrollmentFilename", 1)[0]
            enrollment_verifier_fn = ui_html.split("async function copyEnrollmentVerifier()", 1)[1].split(
                "$('admin-token').value", 1
            )[0]
        except IndexError as exc:
            raise AssertionError("could not isolate enrollment verifier handoff") from exc
        binding_order = (
            "enrollmentPacketText(packet)",
            "downloadEnrollment(packetText)",
            "crypto.subtle.digest('SHA-256'",
        )
        binding_positions = [enrollment_binding_fn.index(marker) for marker in binding_order]
        if binding_positions != sorted(binding_positions):
            raise AssertionError("portal must hash the exact bytes written to the enrollment download")
        agent_instruction_order = (
            "await downloadEnrollmentBinding()",
            "SERVERWARE_PACKET_SHA256",
            "--verify-packet",
            "--emit-verified-instructions",
            "navigator.clipboard.writeText(command.join('\\n'))",
        )
        instruction_positions = [agent_instruction_copy_fn.index(marker) for marker in agent_instruction_order]
        if instruction_positions != sorted(instruction_positions):
            raise AssertionError("portal agent instructions must be emitted only after exact packet verification")
        if "navigator.clipboard.writeText(instructions)" in agent_instruction_copy_fn:
            raise AssertionError("portal must not copy unauthenticated packet instruction text")
        ordered_enrollment_handoff = (
            "await downloadEnrollmentBinding()",
            "serverware-enrollment --verify-packet",
            "serverware-attestation --base",
            "install -D -m 0644",
        )
        handoff_positions = [enrollment_verifier_fn.index(marker) for marker in ordered_enrollment_handoff]
        if handoff_positions != sorted(handoff_positions):
            raise AssertionError("portal must download and verify the exact enrollment packet before CA install")
        if "dev-admin-token" in enrollment_verifier_fn or "SERVERWARE_ADMIN_TOKEN" in enrollment_verifier_fn:
            raise AssertionError("portal enrollment handoff must not require or embed an admin secret")
        if (
            "SERVERWARE_SETUP_ENROLLMENT_VERIFIER_SIGNING_KEY" in enrollment_verifier_fn
            or "--sign-setup-receipt" in enrollment_verifier_fn
            or "--setup-receipt-signing-key" in enrollment_verifier_fn
        ):
            raise AssertionError(
                "portal agent handoff must not expose or invoke the independent verifier signing key"
            )
        if "JSON.stringify(packet" in enrollment_verifier_fn:
            raise AssertionError("portal enrollment handoff must reference the downloaded packet instead of embedding it")

        required_approval_review_markup = (
            'id="approval-review"',
            'id="approval-review-actions"',
            "state.approvalReview",
            "loadApprovalReview",
            "renderApprovalReview",
            "reviewPill",
            "approvalReviewBlockReason",
            "approvalReviewActionBlockReason",
            "approvalIdFromLocation",
            "resolvedApprovalDeepLink",
            "window.history.replaceState({}, '', `/approvals/${encodeURIComponent(id)}`)",
            "`/api/approvals/${encodeURIComponent(id)}/review`",
            "Open review first",
            "Approval expired",
            "Policy changed; request a new approval",
            "Review receipt unavailable or expired; refresh the review",
            "const approvalBlockReason = approvalReviewActionBlockReason(item)",
            "risk_flags",
            "retry_semantics",
            "previous_similar_approvals",
            "normalized_operation_fields",
            "redacted_payload_summary",
            "credential_version",
            "policy_hash",
            "request_digest",
            "operation_digest",
        )
        for marker in required_approval_review_markup:
            if marker not in ui_html:
                raise AssertionError(f"portal approval-review UI marker missing: {marker}")
        assert_approval_review_decision_ui(ui_html)
        if args.approval_review_only:
            print(
                canonical_json(
                    {"ok": True, "portal_approval_review_decision_ui": "pass"}
                )
            )
            return

        parser = PortalAccessibilityParser()
        parser.feed(ui_html)
        if parser.h1_count != 1:
            raise AssertionError(f"portal must expose exactly one h1, found {parser.h1_count}")
        if parser.skip_target != "#main-content":
            raise AssertionError(f"portal skip link does not target main content: {parser.skip_target}")
        missing_labels = sorted(set(parser.control_ids) - parser.label_targets)
        if missing_labels:
            raise AssertionError(f"portal controls are missing explicit labels: {missing_labels}")

        accessibility_markers = (
            'id="main-content" tabindex="-1"',
            'id="operator-status"',
            'role="status" aria-live="polite" aria-atomic="true"',
            "target.setAttribute('role', tone === 'error' ? 'alert' : 'status')",
            "setStatus(`Refresh failed: ${error.message}`, 'error')",
            'id="oauth-status" role="status" aria-live="polite"',
            'class="approval-block-reason" role="status"',
            'aria-disabled="true" aria-describedby=',
        )
        for marker in accessibility_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal accessibility/status marker missing: {marker}")

        if "localStorage" in ui_html:
            raise AssertionError("portal must not persist operator or mutation state in localStorage")
        auth_markers = (
            "$('admin-token').value = '';",
            "'X-Serverware-Admin-Token': token",
            "'Authorization': `Bearer ${token}`",
            'id="operator-sign-in"',
            'id="operator-session-verify"',
            'id="operator-sign-out"',
            "fetch('/api/auth/status'",
            "const query = new URLSearchParams({return_to: returnTo})",
            "fetch(`/api/auth/oidc/start?${query}`",
            "window.location.assign(payload.authorizationUrl)",
            "sessionApi('/api/auth/logout')",
            "sessionApi('/api/auth/session/webauthn/options')",
            "sessionApi('/api/auth/session/webauthn/verify'",
            "navigator.credentials.get({publicKey: prepareRequestOptions(options)})",
            "async function ensureCsrfToken()",
            "'X-Serverware-CSRF-Token': csrf",
            "credentials: 'same-origin'",
        )
        for marker in auth_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal dual admin/OIDC session auth marker missing: {marker}")
        if "serverware.adminToken" in ui_html or "tokenKey" in ui_html:
            raise AssertionError("portal must keep manually entered operator tokens in memory only")

        preservation_markers = (
            "function captureControlState()",
            "function restoreControlState(values)",
            "render(captureControlState());",
            "restoreControlState(controlState);",
            "let refreshInFlight = null",
        )
        for marker in preservation_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal refresh preservation marker missing: {marker}")
        if "const controlState = captureControlState();" in ui_html:
            raise AssertionError("portal refresh must not restore a stale pre-request form snapshot")

        mutation_markers = (
            "class ApiError extends Error",
            "async function runControlPlaneMutation(original)",
            "detail.error === 'control_plane_webauthn_required'",
            "'/api/control-plane/mutations/webauthn/options'",
            "detail.error === 'control_plane_approval_required'",
            "delete mfa.assertion",
            "approvalId: detail.approvalId",
            "async function continuePendingMutation()",
            "kind: 'control-plane-approval'",
            "label: `Approve control-plane request ${id}`",
            "Continue approved request",
            "approval.status !== 'approved'",
            "sessionStorage.setItem(pendingMutationKey",
        )
        for marker in mutation_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal control-plane mutation marker missing: {marker}")
        if '"error": "control_plane_webauthn_required"' not in app_source:
            raise AssertionError("control-plane 412 response must expose the challenge binding fields")
        for marker in ('"action": action', '"resourceId": resource_id', '"payloadDigest": payload_digest'):
            if marker not in app_source:
                raise AssertionError(f"control-plane WebAuthn challenge detail missing: {marker}")

        if re.search(
            r"<h2[^>]*>\s*(?:Operator\s+)?Passkeys\s*</h2>",
            ui_html,
            flags=re.IGNORECASE,
        ) is None:
            raise AssertionError("portal must expose an operator passkey lifecycle view")
        passkey_renderer_name, passkey_renderer = javascript_function_source(
            ui_html,
            r"render\w*(?:passkey|webauthn)\w*",
            label="passkey lifecycle renderer",
        )
        for marker in (
            "state.webauthnCredentials",
            "item.label",
            "item.id",
            "item.active",
            "item.authenticator_class",
            "item.current_trust",
            "item.attestation_root_sha256",
            "item.last_used_at",
            "item.revoked_at",
            "item.revocation_source",
            "Revoke",
        ):
            if marker not in passkey_renderer:
                raise AssertionError(
                    f"portal passkey lifecycle view omitted safe field or action: {marker}"
                )
        if re.search(rf"\b{re.escape(passkey_renderer_name)}\s*\(\s*\)\s*;", ui_html) is None:
            raise AssertionError("portal passkey lifecycle renderer is not wired into rendering")
        for forbidden in (
            "public_key_cose",
            "dev_private_key_pem",
            "json(item)",
            "JSON.stringify(item)",
            "BEGIN PRIVATE KEY",
            "BEGIN PUBLIC KEY",
        ):
            if forbidden in passkey_renderer:
                raise AssertionError(
                    f"portal passkey lifecycle view may render key material: {forbidden}"
                )
        if re.search(r"item\.credential_id(?!_sha256)", passkey_renderer):
            raise AssertionError(
                "portal passkey lifecycle view must not render the raw credential id"
            )
        for private_field in ("public_key_cose", "dev_private_key_pem"):
            if private_field in ui_html:
                raise AssertionError(
                    f"portal JavaScript must not reference WebAuthn key material: {private_field}"
                )

        _, passkey_revoke = javascript_function_source(
            ui_html,
            r"(?:revoke\w*(?:passkey|webauthn)\w*|(?:passkey|webauthn)\w*revoke\w*)",
            label="passkey revoke command",
        )
        revoke_markers = (
            "runControlPlaneMutation(",
            "method: 'POST'",
            ".trim()",
        )
        for marker in revoke_markers:
            if marker not in passkey_revoke:
                raise AssertionError(f"portal passkey revoke command missing: {marker}")
        if not re.search(
            r"`/api/webauthn/credentials/\$\{encodeURIComponent\([^)]+\)\}/revoke`",
            passkey_revoke,
        ):
            raise AssertionError("portal passkey revoke command must URL-encode the credential record id")
        if not re.search(
            r"body\s*:\s*\{\s*reason\s*:\s*reason\.trim\(\)\s*\}",
            passkey_revoke,
        ):
            raise AssertionError(
                "portal passkey revoke command must send only the trimmed revocation reason"
            )
        if "window.confirm" not in passkey_revoke and "window.prompt" not in passkey_revoke:
            raise AssertionError("portal passkey revoke command must require explicit operator confirmation")

        oauth_markers = (
            "const oauthDraftKey = 'serverware.oauthDraft'",
            "Connect Provider Credential",
            "Connect with OAuth",
            "function saveOAuthDraft()",
            "function restoreOAuthDraft()",
            "persist: true, path: '/api/oauth/start'",
            "${esc(item.displayName)}${item.configured ? '' : ' (not configured)'}",
            "$('oauth-submit').disabled = !provider.configured",
            "The selected OAuth provider is not configured",
            "$('oauth-status').textContent = error.message",
            "Waiting for approval ${completed.approval.approvalId}",
            "function credentialAccountStatus(item)",
            "metadata.provider_account || metadata.account || metadata.account_email || metadata.provider_subject || metadata.subject",
            "metadata.provider_identity_verified === true",
            "verified identity",
            "<span class=\"pill warn\">refresh on use</span>",
            "Verified accounts awaiting activation",
            "function renderPendingOAuthCredentials()",
            "state.pendingOAuthCredentials",
            "item.requester_id === state.currentUserId",
            "review.provider_account",
            "review.provider_subject",
            "review.scopes",
            "Request approval and activate",
            "`/api/oauth/pending/${id}/activate`",
            "cancelPendingOAuthCredential",
            "revokePendingOAuthCredential",
            "item.revocation_status",
            "Retry provider revocation",
        )
        for marker in oauth_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal OAuth production-flow marker missing: {marker}")

        queue_markers = (
            'id="control-plane-approvals"',
            "api('/api/control-plane/approvals?limit=100')",
            "function renderControlPlaneApprovals()",
            "function safeControlPlaneRequest(request)",
            "safeControlPlaneRequest(item.request)",
            "requester_id",
            "payload_digest",
            "`/api/control-plane/approvals/${id}/${decision}`",
            "A different authorized operator must decide pending mutations",
            'id="control-plane-status-filter"',
            'id="control-plane-search"',
            "queueStatusRank",
            "renderJitApprovals",
            'id="jit-approval-status-filter"',
            'id="jit-approval-search"',
            'aria-current="true"',
            "window.matchMedia?.('(prefers-reduced-motion: reduce)')",
            "scrollIntoView({behavior: reducedMotion ? 'auto' : 'smooth', block: 'start'})",
            'disabled aria-disabled="true" aria-describedby=',
            "<h3>Approval review</h3>",
            "review.expires_at",
        )
        for marker in queue_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal control-plane approval queue marker missing: {marker}")
        for filter_id in ("control-plane-status-filter", "jit-approval-status-filter"):
            filter_markup = ui_html.split(f'id="{filter_id}"', 1)[1].split("</select>", 1)[0]
            if '<option value="pending">Pending</option>' not in filter_markup.split(">", 1)[1]:
                raise AssertionError(f"portal approval filter must include pending status: {filter_id}")
            if not filter_markup.split(">", 1)[1].lstrip().startswith('<option value="pending">'):
                raise AssertionError(f"portal approval filter must default to pending status: {filter_id}")
        try:
            queue_renderer = ui_html.split("function renderControlPlaneApprovals()", 1)[1].split(
                "function queueStatusRank", 1
            )[0]
        except IndexError as exc:
            raise AssertionError("could not isolate control-plane approval queue renderer") from exc
        for forbidden in (
            "json(item.request)",
            "JSON.stringify(item.request)",
            "item.request_json",
            "access_token",
            "refresh_token",
            "secret",
            "authorizationUrl",
        ):
            if forbidden in queue_renderer:
                raise AssertionError(f"control-plane approval queue may expose secret-bearing request data: {forbidden}")
        safe_summary = ui_html.split("function safeControlPlaneRequest(request)", 1)[1].split(
            "function renderControlPlaneApprovals()", 1
        )[0]
        for expected in ("'provider'", "'scopes'", "'metadata_keys'", "'candidate_policy_hash'", "'dry_run'"):
            if expected not in safe_summary:
                raise AssertionError(f"control-plane approval summary omitted safe review field: {expected}")
        for forbidden in ("access_token", "refresh_token", "authorizationUrl", "secret"):
            if forbidden in safe_summary:
                raise AssertionError(f"control-plane approval summary allowlist contains secret-bearing field: {forbidden}")

        policy_markers = (
            'id="policy-route-form"',
            'id="policy-template-summary"',
            'id="setup-template-summary"',
            "const policyTemplates = {",
            "gmail-response-last-30-days",
            "x-one-post-per-day",
            "calendarWindow",
            "utcDay",
            "x.full-bounded-read",
            "npm.common-writes.yubikey-jit",
            "'query', 'selectedHeaders', 'bodySha256'",
            "example.slack.chat_post.hourly",
            "slack-response-binding",
            "example.stripe.customers.list",
            "example.stripe.customers.get",
            "stripe-customer-get-binding",
            "example.stripe.payment_intent.tokenized_jit",
            "payment-intent-tokenized-only",
            "example.object_store.small_puts",
            "object-store-response-binding",
            "function storedCredentialInjection(credential)",
            "function normalizedInjectionShape(injection)",
            "function injectionShapesCompatible(actual, required)",
            "function oauthCredentialGrantedScopes(credential)",
            "function oauthCredentialProviderSubject(credential)",
            "function policyCredentialInjection(credential, activeCredential, template)",
            "function policyConstraintLabel(constraint)",
            "function renderPolicyEffect(targetId, template)",
            "Unknown host, path, method, or validation result is denied",
            "Human approval required",
            "hardware attestation required",
            "item.metadata?.provider_account",
            "item.metadata?.provider_subject",
            'id="policy-custom-route"',
            "function syncPolicyTemplateEditor(reset = false)",
            'id="policy-approvers"',
            "parseApproverPrincipals(form.get('approvers'))",
            "route.jit.approvers.users",
            "Custom route policy requires match and adapter objects",
            "belongs to ${providerId || 'an unknown provider'}, not ${template.provider}",
            "is missing required scopes:",
            "is missing its OAuth app ID binding",
            "route.adapter.config.appIds",
            "function renderPolicyCredentialOptions(preferredCredential = '')",
            "item.compatible ? '' : 'disabled'",
            "unavailable:",
            "renderPolicyCredentialOptions();",
            "function buildPolicyCandidate()",
            "state.activePolicy.bundle",
            "delete bundle.metadata.signature",
            "delete bundle.metadata.signingKeyId",
            "uses an injection shape that is incompatible with this template",
            "bundle.credentials.push",
            "...(grantedScopes ? {scopes: grantedScopes} : {})",
            "...(providerSubject ? {providerSubject} : {})",
            "activeCredential.scopes = grantedScopes",
            "activeCredential.providerSubject = providerSubject",
            "injection: candidateInjection",
            "expect: 'allow'",
            "expect: 'deny'",
            "api('/api/policy/candidate'",
            "path: '/api/policy/publish'",
            "activationMode: 'canary'",
            "Stage candidate",
            "Staged candidate lifecycle",
            'id="policy-canary-status"',
            'id="policy-activate-button"',
            'id="policy-cancel-button"',
            "api('/api/policy/canary/status')",
            "No policy candidate is staged.",
            "path: '/api/policy/canary/activate'",
            "path: '/api/policy/canary/cancel'",
            "function renderPolicyCanary()",
            "function activatePolicyCanary()",
            "function cancelPolicyCanary()",
            "policyCanary: policyCanaryResult.status === 'fulfilled'",
            "Active policy changed after preview",
            "Signed candidate, diff, and dry-run",
            "Local-only CRUD; not part of the signed production PolicyBundle",
            "Array.isArray(report?.dryRun?.results)",
            "report?.dryRun?.passed === true",
            "!dryRunPassed",
            "The signed candidate dry-run did not pass every check",
        )
        for marker in policy_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal signed PolicyBundle assignment marker missing: {marker}")
        for misleading_canary_marker in ('Canary traffic percent', 'id="policy-canary-percent"', "canaryPercent"):
            if misleading_canary_marker in ui_html:
                raise AssertionError(f"portal still implies unsupported candidate traffic routing: {misleading_canary_marker}")
        if "disabled title=" in ui_html:
            raise AssertionError("approval blocking reasons must not be hidden on disabled controls")
        setup_markers = (
            'class="setup-section"',
            'id="setup-form"',
            'id="setup-session"',
            'id="setup-assignee"',
            'id="setup-handoff-button"',
            'id="setup-template"',
            'id="setup-principal"',
            'id="setup-credential"',
            'id="setup-route-id"',
            'id="setup-configuration-status"',
            'id="setup-runtime-status"',
            'id="setup-hardware-status"',
            'id="setup-enrollment-receipt"',
            'id="setup-hardware-assurance"',
            'id="setup-hardware-receipt"',
            'id="setup-proxy-statement"',
            'id="setup-final-receipt"',
            "function renderSetupWorkflow(controlState = {})",
            "function setupVerificationForSelection",
            "result.setupSessionId === session.id",
            "result.setupRevision === session.revision",
            "result.assignmentDigest === session.assignmentDigest",
            "assignment.policyHash === state.activePolicy?.policy_hash",
            "assignment.credentialVersion === credential?.credential_version",
            "assignment.routePolicyDigest === session.routePolicyDigest",
            "session.enrollmentSessionId === state.enrollmentPacket?.ca?.installSession?.id",
            "function prepareSetupProviderLogin()",
            "async function createSetupSession()",
            "if (activeRoute) body.routePolicyDigest = await sha256CanonicalJson(activeRoute)",
            "async function loadSetupSession(id)",
            "async function handoffSetupSession()",
            "async function bindSetupCredential()",
            "function previewSetupAssignment()",
            "function generateSetupEnrollment()",
            "function verifySetupEvidence()",
            "async function submitSetupEnrollmentReceipt()",
            "async function issueSetupAttestationChallenge()",
            "async function submitSetupHardwareVerification()",
            "async function finalizeSetupAttestation()",
            "api('/api/setup/sessions?limit=100')",
            "/api/setup/sessions/${encodeURIComponent(session.id)}/verify",
            "/api/setup/sessions/${encodeURIComponent(session.id)}/enrollment-receipt",
            "/api/setup/sessions/${encodeURIComponent(session.id)}/attestation-challenge",
            "/api/setup/sessions/${encodeURIComponent(session.id)}/hardware-verification",
            "/api/setup/sessions/${encodeURIComponent(session.id)}/final-receipt",
            "expectedRevision: session.revision",
            "setupSessionId: setupSession.id",
            "setupRevision: setupSession.revision",
            "configurationReady",
            "runtimeVerified",
            "hardwareVerified",
            "fullyVerified",
            "assignmentDigest",
            "data_plane.credential.release_started",
            "data_plane.jit.grant_consumed",
            "jit.grant.consumed",
            '"apiVersion": "serverware.setupVerification/v1"',
            '"serverware.setupSession/v1"',
            '"setup.verification.checked"',
        )
        for marker in setup_markers:
            source = (
                app_source
                if marker.startswith('"') or marker.startswith("data_plane.") or marker == "jit.grant.consumed"
                else ui_html
            )
            if marker not in source:
                raise AssertionError(f"portal Setup and Verify marker missing: {marker}")
        if ui_html.index('class="setup-section"') > ui_html.index('class="jit-approvals-section"'):
            raise AssertionError("portal Setup and Verify workflow must be the first operational section")
        ordered_sections = (
            'class="jit-approvals-section"',
            'class="control-plane-approvals-section"',
            'id="credential-workspace"',
            'class="credentials-section"',
            'class="audit-investigation-section"',
        )
        section_positions = [ui_html.index(marker) for marker in ordered_sections]
        if section_positions != sorted(section_positions):
            raise AssertionError("portal DOM order must put approval queues before setup and later operational tables")

        runtime_handler_markers = (
            "const scopes = parseOAuthScopes(form.get('scopes'));",
            "const proxyEgressCidrs = parseProxyEgressCidrs(form.get('proxyEgressCidrs'));",
            "const enrollmentNonce = generateEnrollmentNonce();",
            "(provider.defaultScopes || []).join('\\n')",
            "renderOAuthDefaults(true);",
            'class="approval-table"',
            'data-label="Actions"',
        )
        for marker in runtime_handler_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal corrected runtime helper is not wired to its caller: {marker}")

        if "id=\"ttl-${item.id}\"" in ui_html or "$('ttl-' + id)" in ui_html:
            raise AssertionError("portal must not imply that policy-derived JIT grant lifetime is operator-editable")
        for marker in ("grantTtlSeconds", "policy grant", "retry_semantics?.grant_ttl_seconds"):
            if marker not in ui_html:
                raise AssertionError(f"portal policy-derived JIT lifetime marker missing: {marker}")

        audit_markers = (
            'id="audit-search-form"',
            'id="audit-summary"',
            'id="audit-events"',
            "function auditSearchParams({exportMode = false} = {})",
            "api(`/api/audit/search?${auditSearchParams()}`)",
            "api('/api/audit/verify')",
            "`/api/audit/export?${auditSearchParams({exportMode: true})}`",
            "serverware-audit-export.jsonl",
            "function redactAuditEvidence(value, key = '')",
            "complete scan",
            "partial scan",
        )
        for marker in audit_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal audit-investigation UI marker missing: {marker}")

        attestation_markers = (
            'class="attestation-section"',
            'id="attestation-summary"',
            'id="attestation-evidence"',
            "function renderAttestation()",
            "function refreshAttestation()",
            "assurance.hardware_proof === true",
            "assurance.workload_custody_proven === true",
            "assurance.tls_peer_binding_proven === true",
            "not hardware verified",
            "document.source_tree_digest",
            "document.data_plane_binary_digest",
            "document.tls_exporter_binding || 'not bound'",
            "api(`/attestation?nonce=${encodeURIComponent(generateEnrollmentNonce())}`)",
        )
        for marker in attestation_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal attestation UI marker missing: {marker}")
        if '"hardware_proof": False' not in (ROOT / "serverware" / "attestation.py").read_text(encoding="utf-8"):
            raise AssertionError("current attestation must expose its non-hardware assurance ceiling")

        confirmation_markers = (
            "Delete credential ${id}? Agents using it will fail closed.",
            "Delete local prototype route ${id}? Matching requests will be denied.",
            "Clear the local traffic log? The append-only audit chain is not deleted.",
            "Cancel staged policy candidate ${canary.id}?",
        )
        for marker in confirmation_markers:
            if marker not in ui_html:
                raise AssertionError(f"portal destructive-action confirmation missing: {marker}")

        node = shutil.which("node")
        if node:
            script_source = ui_html.split("<script>", 1)[1].split("</script>", 1)[0]
            syntax = subprocess.run(
                [node, "--check", "-"],
                input=script_source,
                text=True,
                capture_output=True,
                check=False,
            )
            if syntax.returncode != 0:
                raise AssertionError(f"portal JavaScript syntax check failed: {syntax.stderr.strip()}")

            try:
                template_literal = ui_html.split("const policyTemplates = ", 1)[1].split(
                    "\n    };\n\n    function adminToken()", 1
                )[0] + "\n}"
            except IndexError as exc:
                raise AssertionError("could not isolate policyTemplates JavaScript object") from exc
            evaluated = subprocess.run(
                [
                    node,
                    "-e",
                    "const fs=require('fs');const value=eval('('+fs.readFileSync(0,'utf8')+')');process.stdout.write(JSON.stringify(value));",
                ],
                input=template_literal,
                text=True,
                capture_output=True,
                check=False,
            )
            if evaluated.returncode != 0:
                raise AssertionError(f"could not evaluate policyTemplates: {evaluated.stderr.strip()}")
            templates = json.loads(evaluated.stdout)

            try:
                scope_function = "function oauthCredentialGrantedScopes(credential)" + ui_html.split(
                    "function oauthCredentialGrantedScopes(credential)", 1
                )[1].split("\n\n    function policyCredentialInjection", 1)[0]
            except IndexError as exc:
                raise AssertionError("could not isolate OAuth granted-scope portal validator") from exc
            scope_check = subprocess.run(
                [
                    node,
                    "-e",
                    scope_function
                    + ";const good=oauthCredentialGrantedScopes({id:'cred',kind:'oauth2',metadata:{scopes:['scope.z','scope.a']}});"
                    + "if(JSON.stringify(good)!=='[\"scope.a\",\"scope.z\"]')process.exit(2);"
                    + "for(const scopes of [null,[],[''],[' scope.a'],['scope.a scope.b'],['scope.a','scope.a']]){"
                    + "let failed=false;try{oauthCredentialGrantedScopes({id:'cred',kind:'oauth2',metadata:{scopes}})}catch(_){failed=true}"
                    + "if(!failed)process.exit(3)}",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if scope_check.returncode != 0:
                raise AssertionError(
                    f"portal OAuth scope validator did not fail closed: {scope_check.returncode} {scope_check.stderr.strip()}"
                )

            try:
                enrollment_helpers = "function bytesToB64(value)" + ui_html.split(
                    "function bytesToB64(value)", 1
                )[1].split("\n\n    function credentialToJson", 1)[0]
            except IndexError as exc:
                raise AssertionError("could not isolate enrollment runtime helpers") from exc
            enrollment_check = subprocess.run(
                [
                    node,
                    "-e",
                    "globalThis.btoa=(value)=>Buffer.from(value,'binary').toString('base64');"
                    + enrollment_helpers
                    + r"""
const oauth=parseOAuthScopes('scope.a\nscope.b, scope.c');
if(JSON.stringify(oauth)!=='["scope.a","scope.b","scope.c"]')process.exit(10);
const cidrs=parseProxyEgressCidrs('127.0.0.1/32\n10.0.0.0/8, 2001:db8::/32');
if(JSON.stringify(cidrs)!=='["127.0.0.1/32","10.0.0.0/8","2001:db8::/32"]')process.exit(11);
const source={getRandomValues(value){for(let index=0;index<value.length;index+=1)value[index]=index;return value;}};
const nonce=generateEnrollmentNonce(source);
if(nonce.length!==43||!/^[A-Za-z0-9_-]+$/.test(nonce)||/[=+/]/.test(nonce))process.exit(12);
if(bytesToB64(Uint8Array.from([251,255]))!=='-_8')process.exit(15);
const approvers=parseApproverPrincipals('user:release-manager, oidc:auth0|operator-1');
if(JSON.stringify(approvers)!=='["user:release-manager","oidc:auth0|operator-1"]')process.exit(13);
for(const value of ['', 'release-manager', 'user:*', 'user:one,user:one']){
  let failed=false;try{parseApproverPrincipals(value)}catch(_){failed=true}
  if(!failed)process.exit(14);
}
""",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if enrollment_check.returncode != 0:
                raise AssertionError(
                    "portal OAuth/enrollment helpers failed in Node: "
                    f"{enrollment_check.returncode} {enrollment_check.stderr.strip()}"
                )

            try:
                instruction_function = "function agentInstructionText(packet)" + ui_html.split(
                    "function agentInstructionText(packet)", 1
                )[1].split("\n\n    async function copyAgentInstructions", 1)[0]
            except IndexError as exc:
                raise AssertionError("could not isolate agent instruction generator") from exc
            instruction_check = subprocess.run(
                [
                    node,
                    "-e",
                    instruction_function
                    + r"""
const packet={
  apiVersion:'serverware.agentEnrollment/v1',principalId:'agent:test',
  ca:{installPath:'/etc/serverware/ca.pem'},secret:'DO_NOT_COPY',
  agentHandoff:{
    instructionsText:'SIGNED HANDOFF\nDENY-BY-DEFAULT EGRESS\nALLOW CANARY\nHTTP 428: retry only the identical request.\n'
  }
};
const output=agentInstructionText(packet);
for(const expected of ['SIGNED HANDOFF','DENY-BY-DEFAULT EGRESS','ALLOW CANARY','HTTP 428','identical request']){
  if(!output.includes(expected))process.exit(20);
}
if(output.includes('DO_NOT_COPY'))process.exit(21);
let failed=false;try{agentInstructionText({apiVersion:'wrong'})}catch(_){failed=true}
if(!failed)process.exit(22);
failed=false;try{agentInstructionText({apiVersion:'serverware.agentEnrollment/v1',agentHandoff:{}})}catch(_){failed=true}
if(!failed)process.exit(23);
""",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if instruction_check.returncode != 0:
                raise AssertionError(
                    "portal agent instruction generator failed in Node: "
                    f"{instruction_check.returncode} {instruction_check.stderr.strip()}"
                )

            try:
                policy_builder_functions = "function materializePolicyPath(path)" + ui_html.split(
                    "function materializePolicyPath(path)", 1
                )[1].split("\n\n    async function previewPolicyCandidate", 1)[0]
                selector_functions = "function policyCredentialOptions(template)" + ui_html.split(
                    "function policyCredentialOptions(template)", 1
                )[1].split("\n\n    function render(controlState", 1)[0]
                oauth_defaults_function = "function renderOAuthDefaults(applyDefaults = true)" + ui_html.split(
                    "function renderOAuthDefaults(applyDefaults = true)", 1
                )[1].split("\n\n    function safeControlPlaneRequest", 1)[0]
            except IndexError as exc:
                raise AssertionError("could not isolate refresh-time credential selector helpers") from exc
            selector_check = subprocess.run(
                [
                    node,
                    "-e",
                    r"""
const elements={
  'policy-template':{value:'gmail_recent'},
  'policy-credential':{innerHTML:'',value:'',disabled:false},
  'enrollment-principal':{innerHTML:''},
  'enrollment-control-plane-url':{value:''},
  'policy-principal':{innerHTML:''},
  'policy-route-form':{},
  'oauth-provider':{value:'google'},
  'oauth-scopes':{value:''},
  'oauth-status':{textContent:''},
  'oauth-submit':{disabled:false}
};
const $=(id)=>elements[id];
const esc=(value)=>String(value??'').replace(/[&<>"']/g,'');
const policyTemplates={gmail_recent:{provider:'google',injection:{type:'bearer',field:'access_token'},match:{scheme:'https',host:'gmail.googleapis.com',port:443,methods:['GET'],paths:['/gmail/v1/users/{user}/messages']},adapter:{type:'gmail.v1',config:{}},constraints:[]}};
let state={
  activePolicy:{ready:true,policy_hash:'base-hash',bundle:{metadata:{sequence:1},credentials:[],routes:[]}},
  credentials:[
    {id:'cred-google',name:'Google fixture',kind:'oauth2',metadata:{oauth:true,provider_identity_verified:true,provider_id:'google',provider_account:'operator@example.com',provider_subject:'google-subject-123',scopes:['gmail.readonly']}},
    {id:'cred-google-inactive',name:'Inactive Google fixture',kind:'oauth2',lifecycle_status:'revocation_pending',metadata:{oauth:true,provider_identity_verified:true,provider_id:'google',provider_account:'inactive@example.com',provider_subject:'google-subject-inactive',scopes:['gmail.readonly']}}
  ],
  policyPrincipals:[{id:'agent:mail-reader',routeCount:2}],
  oauthProviders:[{id:'google',displayName:'Google',configured:true,defaultScopes:['openid','email'],redirectUri:'https://serverware.test/callback'}]
};
"""
                    + policy_builder_functions
                    + selector_functions
                    + oauth_defaults_function
                    + r"""
const shapes=[
  [{id:'bearer',kind:'bearer',metadata:{}},{type:'bearer',header:'Authorization'}],
  [{id:'header',kind:'header',metadata:{injection_name:'x-api-key'}},{type:'header',name:'x-api-key'}],
  [{id:'query',kind:'query',metadata:{injection_name:'api_key'}},{type:'query',name:'api_key'}],
  [{id:'cookie',kind:'cookie',metadata:{injection_name:'session_token'}},{type:'cookie',name:'session_token'}],
  [{id:'basic',kind:'basic',metadata:{username:'service-account'}},{type:'basic',username:'service-account'}]
];
for(const [credential,expected] of shapes){
  const actual=storedCredentialInjection(credential);
  for(const [key,value] of Object.entries(expected))if(actual[key]!==value)process.exit(20);
}
const xReadOnly={id:'x-read',kind:'oauth2',metadata:{oauth:true,provider_identity_verified:true,provider_id:'x',provider_subject:'x-user',scopes:['tweet.read','users.read']}};
const xWriteTemplate={provider:'x',requiredScopes:['tweet.read','tweet.write','users.read'],injection:{type:'bearer',field:'access_token'}};
let writeScopeAccepted=false;
try{policyCredentialInjection(xReadOnly,null,xWriteTemplate);writeScopeAccepted=true}catch(_){}
if(writeScopeAccepted)process.exit(32);
const xWriter={...xReadOnly,metadata:{...xReadOnly.metadata,scopes:['tweet.read','tweet.write','users.read']}};
if(policyCredentialInjection(xWriter,null,xWriteTemplate).type!=='bearer')process.exit(33);
const stripeTemplate={provider:'stripe',injection:{type:'bearer'}};
const stripeCredential={id:'cred-stripe',kind:'bearer',metadata:{provider:'stripe'}};
if(policyCredentialInjection(stripeCredential,null,stripeTemplate).type!=='bearer')process.exit(34);
const objectTemplate={provider:'object-store',injection:{type:'header',name:'X-Api-Key'}};
const objectCredential={id:'cred-object',kind:'header',metadata:{provider:'object-store',injection_name:'X-Api-Key'}};
const objectInjection=policyCredentialInjection(objectCredential,null,objectTemplate);
if(objectInjection.type!=='header'||objectInjection.name!=='X-Api-Key')process.exit(36);
let bearerObjectAccepted=false;
try{policyCredentialInjection({id:'wrong-object',kind:'bearer',metadata:{provider:'object-store'}},null,objectTemplate);bearerObjectAccepted=true}catch(_){}
if(bearerObjectAccepted)process.exit(37);
for(const credential of [
  {id:'unbound-stripe',kind:'bearer',metadata:{}},
  {id:'wrong-stripe',kind:'bearer',metadata:{provider:'github'}}
]){
  let failed=false;try{policyCredentialInjection(credential,null,stripeTemplate)}catch(_){failed=true}
  if(!failed)process.exit(35);
}
for(const credential of [
  {id:'header',kind:'header',metadata:{}},
  {id:'header',kind:'header',metadata:{injection_name:'authorization'}},
  {id:'basic',kind:'basic',metadata:{username:'bad:name'}}
]){
  let failed=false;try{storedCredentialInjection(credential)}catch(_){failed=true}
  if(!failed)process.exit(21);
}
renderPolicyPrincipalOptions();
renderPolicyCredentialOptions();
if(!elements['enrollment-principal'].innerHTML.includes('agent:mail-reader'))process.exit(22);
if(!elements['policy-principal'].innerHTML.includes('agent:mail-reader'))process.exit(23);
if(!elements['policy-credential'].innerHTML.includes('cred-google'))process.exit(24);
if(elements['policy-credential'].value!=='cred-google'||elements['policy-credential'].disabled)process.exit(25);
if(elements['policy-credential'].innerHTML.includes('cred-google-inactive'))process.exit(38);
renderOAuthDefaults(true);
if(elements['oauth-scopes'].value!=='openid\nemail'||elements['oauth-scopes'].value.includes('\\n'))process.exit(26);
if(oauthCredentialProviderSubject(state.credentials[0])!=='google-subject-123')process.exit(27);
let malformedSubjectAccepted=false;
try{oauthCredentialProviderSubject({id:'bad',kind:'oauth2',metadata:{oauth:true,provider_identity_verified:true,provider_id:'google',provider_subject:' bad ',scopes:['gmail.readonly']}});malformedSubjectAccepted=true}catch(_){}
if(malformedSubjectAccepted)process.exit(28);
let unverifiedSubjectAccepted=false;
try{oauthCredentialProviderSubject({id:'unverified',kind:'oauth2',metadata:{oauth:true,provider_identity_verified:false,provider_id:'google',provider_subject:'google-subject-123',scopes:['gmail.readonly']}});unverifiedSubjectAccepted=true}catch(_){}
if(unverifiedSubjectAccepted)process.exit(31);
global.FormData=class {get(name){return {template:'gmail_recent',routeId:'gmail.bound',principalId:'agent:mail-reader',credentialRef:'cred-google'}[name]??null;}};
const newCandidate=buildPolicyCandidate();
const newCredential=newCandidate.bundle.credentials.find((item)=>item.id==='cred-google');
if(newCredential.providerSubject!=='google-subject-123'||JSON.stringify(newCredential.scopes)!=='["gmail.readonly"]')process.exit(29);
state.activePolicy.bundle.credentials=[{id:'cred-google',provider:'google',providerSubject:'old-subject',scopes:['old.scope'],injection:{type:'bearer',field:'access_token'}}];
const updatedCandidate=buildPolicyCandidate();
const updatedCredential=updatedCandidate.bundle.credentials.find((item)=>item.id==='cred-google');
if(updatedCredential.providerSubject!=='google-subject-123'||JSON.stringify(updatedCredential.scopes)!=='["gmail.readonly"]')process.exit(30);
""",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if selector_check.returncode != 0:
                raise AssertionError(
                    "portal refresh-time selector helpers failed in Node: "
                    f"{selector_check.returncode} {selector_check.stderr.strip()}"
                )

            try:
                run_ui_action_function = "async function runUiAction(label, action)" + ui_html.split(
                    "async function runUiAction(label, action)", 1
                )[1].split("\n\n    function controlStateKey", 1)[0]
                approve_function = "async function approve(id)" + ui_html.split(
                    "async function approve(id)", 1
                )[1].split("\n    async function deny", 1)[0]
            except IndexError as exc:
                raise AssertionError("could not isolate approval action runtime helpers") from exc
            approval_action_check = subprocess.run(
                [
                    node,
                    "-e",
                    r"""
let statusEvents=[];
function setStatus(message,tone=''){statusEvents.push({message,tone});}
let state={approvals:[{id:'approval-test',grant_ttl_seconds:30}],approvalReview:null,blockReason:''};
let apiCalls=0;
async function api(){apiCalls+=1;throw new Error('approval API must not be called');}
async function loadApprovalReview(id){state.approvalReview={id,retry_semantics:{grant_ttl_seconds:30}};}
function approvalReviewBlockReason(item){
  if(!state.approvalReview||state.approvalReview.id!==item.id)return 'Open review first';
  return state.blockReason;
}
const window={};
const navigator={};
function prepareRequestOptions(value){return value;}
function credentialToJson(value){return value;}
"""
                    + run_ui_action_function
                    + approve_function
                    + r"""
(async()=>{
  const reviewResult=await runUiAction('Approve request',()=>approve('approval-test'));
  if(!reviewResult?.pending||!reviewResult.reviewLoaded||apiCalls!==0)process.exit(31);
  if(statusEvents[statusEvents.length-1]?.tone!=='pending'||/complete/i.test(statusEvents[statusEvents.length-1]?.message||''))process.exit(32);
  state.blockReason='Policy changed; request a new approval';
  const blockedResult=await runUiAction('Approve request',()=>approve('approval-test'));
  if(!blockedResult?.blocked||apiCalls!==0)process.exit(33);
  if(statusEvents[statusEvents.length-1]?.tone!=='error'||!/cannot be approved/.test(statusEvents[statusEvents.length-1]?.message||''))process.exit(34);
})().catch((error)=>{console.error(error);process.exit(35);});
""",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if approval_action_check.returncode != 0:
                raise AssertionError(
                    "portal blocked approval action failed in Node: "
                    f"{approval_action_check.returncode} {approval_action_check.stderr.strip()}"
                )
            if set(templates) != {
                "gmail_recent",
                "x_read_recent",
                "x_full_bounded_read",
                "x_one_post_daily",
                "npm_write_mfa",
                "slack_chat_post",
                "stripe_customers_list",
                "stripe_customer_get",
                "stripe_payment_intent_jit",
                "object_store_put",
                "custom_json",
            }:
                raise AssertionError(f"unexpected common PolicyBundle template set: {sorted(templates)}")

            specialized_profiles = {
                "gmail_recent": ("gmail.v1", None),
                "x_read_recent": ("x.v2", "recentSearchOnly"),
                "x_full_bounded_read": ("x.v2", "readOnly"),
                "x_one_post_daily": ("x.v2", "controlledWrite"),
                "npm_write_mfa": ("npm.registry", None),
            }
            for template_id, (adapter_type, mode) in specialized_profiles.items():
                adapter = templates[template_id].get("adapter") or {}
                config = adapter.get("config") or {}
                if adapter.get("type") != adapter_type or config.get("mode") != mode:
                    raise AssertionError(
                        f"portal specialized adapter identity drifted: {template_id}: {adapter}"
                    )
                expected_request = provider_request_profile(adapter_type, mode)
                actual_request = config.get("request")
                if actual_request != expected_request:
                    raise AssertionError(
                        f"portal provider request profile drifted: {template_id}: "
                        f"expected={canonical_json(expected_request)} "
                        f"actual={canonical_json(actual_request)}"
                    )

            canonical_examples = json.loads(
                (ROOT / "policies" / "credential-limits.examples.json").read_text()
            )
            canonical_routes = {
                route["id"]: route for route in canonical_examples["routes"]
            }
            canonical_credentials = {
                credential["id"]: credential
                for credential in canonical_examples["credentials"]
            }

            def assert_exact_policy_parity(
                template_id: str,
                route_id: str,
                *,
                credential_derived_app_ids: bool = False,
                operator_selected_approvers: bool = False,
            ) -> None:
                template = templates[template_id]
                canonical_route = canonical_routes[route_id]
                policy_fields = ("match", "adapter", "constraints", "jit")
                actual = {
                    key: copy.deepcopy(template[key])
                    for key in policy_fields
                    if key in template
                }
                expected = {
                    key: copy.deepcopy(canonical_route[key])
                    for key in policy_fields
                    if key in canonical_route
                }
                if credential_derived_app_ids:
                    expected["adapter"]["config"].pop("appIds", None)
                if operator_selected_approvers:
                    expected["jit"]["approvers"]["users"] = []
                if actual != expected:
                    raise AssertionError(
                        f"portal and canonical policy drifted: {template_id}: "
                        f"expected={canonical_json(expected)} actual={canonical_json(actual)}"
                    )

            assert_exact_policy_parity(
                "x_full_bounded_read",
                "example.x.full_bounded_read",
                credential_derived_app_ids=True,
            )
            assert_exact_policy_parity(
                "npm_write_mfa",
                "example.npm.publish.yubikey_jit",
                operator_selected_approvers=True,
            )
            expected_x_read_scopes = [
                scope
                for scope in canonical_credentials["cred-x"]["scopes"]
                if scope not in {"offline.access", "tweet.write"}
            ]
            if (
                templates["x_full_bounded_read"].get("requiredScopes")
                != expected_x_read_scopes
            ):
                raise AssertionError(
                    "X full-read template scopes drifted from the canonical read-only scope set"
                )

            npm_template = templates["npm_write_mfa"]
            npm_config = npm_template["adapter"]["config"]
            expected_npm_operations = [
                "publish",
                "unpublish",
                "distTagWrite",
                "tokenWrite",
                "metadataWrite",
            ]
            if npm_config.get("operations") != expected_npm_operations:
                raise AssertionError(
                    f"public npm template does not cover all canonical writes: {npm_config.get('operations')}"
                )
            if (
                npm_config.get("publishResponseContract")
                != "npm-public-registry-receipt-v1"
            ):
                raise AssertionError("public npm template lost its receipt contract")
            npm_response = npm_config.get("response") or {}
            if {
                key: npm_response.get(key)
                for key in ("mode", "maxBodyBytes", "allowedFields", "allowedHeaders")
            } != {
                "mode": "json",
                "maxBodyBytes": 65536,
                "allowedFields": ["ok", "published"],
                "allowedHeaders": [],
            }:
                raise AssertionError(
                    f"public npm template release is not the bounded receipt projection: {npm_response}"
                )
            npm_constraints = npm_template.get("constraints") or []
            if any(
                item.get("type") in {"responseBinding", "responseJson"}
                for item in npm_constraints
            ):
                raise AssertionError(
                    "public npm receipt must not use compatible-registry response identity rules"
                )
            npm_operation_policy = next(
                (
                    item
                    for item in npm_constraints
                    if item.get("type") == "operationPolicy"
                ),
                None,
            )
            if not npm_operation_policy or npm_operation_policy.get(
                "allowedOperations"
            ) != [f"npm.{operation}" for operation in expected_npm_operations]:
                raise AssertionError(
                    f"public npm template does not allow all canonical npm writes: {npm_constraints}"
                )
            npm_jit = npm_template.get("jit") or {}
            npm_authn = (npm_jit.get("approvers") or {}).get("authn") or {}
            if not (
                npm_jit.get("required") is True
                and npm_jit.get("mode") == "perOperation"
                and npm_jit.get("maxUses") == 1
                and npm_jit.get("consumeOn") == "forwardStart"
                and npm_authn.get("webauthnRequired") is True
                and npm_authn.get("userVerification") == "required"
                and npm_authn.get("requireHardwareAttestation") is True
                and set(npm_authn.get("allowedAuthenticatorClasses") or [])
                == {"yubikey", "hardware"}
            ):
                raise AssertionError(
                    f"public npm template lost one-use hardware WebAuthn JIT: {npm_jit}"
                )
            if args.policy_templates_only:
                print(
                    canonical_json(
                        {"ok": True, "portal_provider_policy_templates": "pass"}
                    )
                )
                return
            if "tweet.write" not in templates["x_one_post_daily"].get("requiredScopes", []):
                raise AssertionError("X write template does not require the provider tweet.write scope")
            x_daily_limit = next(
                (
                    item
                    for item in templates["x_one_post_daily"].get("constraints", [])
                    if item.get("id") == "x-one-post-per-day"
                ),
                None,
            )
            if not x_daily_limit or x_daily_limit.get("key") != {
                "scope": ["route", "operation"],
                "operationFields": ["providerAccount"],
            }:
                raise AssertionError(
                    "X one-post template quota is not stable across principal and credential rotation"
                )
            if (
                x_daily_limit.get("calendarWindow") != "utcDay"
                or "windowSeconds" in x_daily_limit
            ):
                raise AssertionError(
                    "X one-post template must use a UTC calendar-day quota, not a rolling fixed window"
                )
            x_daily_label = str(templates["x_one_post_daily"].get("label") or "")
            if "UTC calendar day" not in x_daily_label or "00:00 UTC" not in x_daily_label:
                raise AssertionError(
                    "X one-post template label must name the UTC calendar day and its 00:00 UTC reset"
                )

            def template_constraint(template_id: str, constraint_id: str) -> dict | None:
                return next(
                    (
                        item
                        for item in templates[template_id].get("constraints", [])
                        if item.get("id") == constraint_id
                    ),
                    None,
                )

            slack_request = templates["slack_chat_post"]["adapter"]["config"]["request"]
            if slack_request.get("operation") != {
                "name": "slack.chat.postMessage",
                "jsonFields": ["channel", "text"],
            }:
                raise AssertionError("Slack template does not capture its bounded request identity")
            if template_constraint("slack_chat_post", "slack-response-ok") != {
                "id": "slack-response-ok",
                "type": "responseJson",
                "phase": "response",
                "operations": ["slack.chat.postMessage"],
                "fields": {"ok": {"required": True, "type": "boolean", "equals": True}},
            }:
                raise AssertionError("Slack template does not require an explicit successful response")
            if template_constraint("slack_chat_post", "slack-response-binding") != {
                "id": "slack-response-binding",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["slack.chat.postMessage"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "channel",
                        "operationField": "channel",
                        "responseField": "channel",
                        "comparison": "exactString",
                    },
                ],
            }:
                raise AssertionError("Slack template does not bind the response to the requested channel")

            stripe_list_request = templates["stripe_customers_list"]["adapter"]["config"]["request"]
            if stripe_list_request.get("operation") != {"name": "stripe.customers.list"}:
                raise AssertionError("Stripe customer-list template has no stable operation identity")
            if template_constraint("stripe_customers_list", "stripe-customer-list-shape") != {
                "id": "stripe-customer-list-shape",
                "type": "responseJson",
                "phase": "response",
                "operations": ["stripe.customers.list"],
                "fields": {
                    "object": {"required": True, "type": "string", "equals": "list"},
                    "has_more": {"required": True, "type": "boolean"},
                },
            }:
                raise AssertionError("Stripe customer-list template does not prove the list envelope")
            if template_constraint("stripe_customers_list", "stripe-customer-list-items") != {
                "id": "stripe-customer-list-items",
                "type": "responseJson",
                "phase": "response",
                "operations": ["stripe.customers.list"],
                "items": ["data"],
                "fields": {
                    "id": {
                        "required": True,
                        "type": "string",
                        "minLength": 5,
                        "maxLength": 255,
                        "pattern": "^cus_[A-Za-z0-9]{1,251}$",
                    },
                    "object": {"required": True, "type": "string", "equals": "customer"},
                    "deleted": {"required": False, "type": "boolean"},
                },
            }:
                raise AssertionError("Stripe customer-list template does not validate customer items")

            stripe_get_request = templates["stripe_customer_get"]["adapter"]["config"]["request"]
            if stripe_get_request.get("operation") != {
                "name": "stripe.customers.get",
                "pathParams": ["customer_id"],
            }:
                raise AssertionError("Stripe customer-get template does not capture the requested customer")
            if template_constraint("stripe_customer_get", "stripe-customer-get-binding") != {
                "id": "stripe-customer-get-binding",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["stripe.customers.get"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "customer-id",
                        "operationField": "approvedCustomerId",
                        "responseField": "id",
                        "comparison": "exactString",
                    }
                ],
            }:
                raise AssertionError("Stripe customer-get template does not bind the returned customer")

            object_store_request = templates["object_store_put"]["adapter"]["config"]["request"]
            if object_store_request.get("operation") != {
                "name": "object_store.objects.put",
                "bodySha256Field": "requestBodySha256",
                "pathParams": ["artifact_id"],
            }:
                raise AssertionError(
                    "Object-store template does not capture artifact identity and the computed body digest"
                )
            if templates["object_store_put"]["match"]["paths"] != [
                "/v1/buckets/{bucket}/objects/{artifact_id}"
            ]:
                raise AssertionError("Object-store template is not scoped to the bounded object PUT route")
            if template_constraint("object_store_put", "object-store-response-binding") != {
                "id": "object-store-response-binding",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["object_store.objects.put"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "artifact-id",
                        "operationField": "validatedObjectKey",
                        "responseField": "id",
                        "comparison": "exactString",
                    },
                    {
                        "id": "sha256",
                        "operationField": "requestBodySha256",
                        "responseField": "sha256",
                        "comparison": "exactString",
                    },
                ],
            }:
                raise AssertionError("Object-store template does not bind the returned object identity")

            def assert_utc_calendar_quota(
                constraints: list[dict], constraint_id: str, *, label: str
            ) -> None:
                quota = next(
                    (item for item in constraints if item.get("id") == constraint_id),
                    None,
                )
                if quota is None:
                    raise AssertionError(f"{label} calendar quota is missing")
                if quota.get("calendarWindow") != "utcDay" or "windowSeconds" in quota:
                    raise AssertionError(
                        f"{label} must use calendarWindow utcDay without windowSeconds"
                    )

            def assert_no_rolling_calendar_wording(value: object, *, label: str) -> None:
                serialized = json.dumps(value, sort_keys=True).lower()
                for misleading in (
                    "24h",
                    "24-hour",
                    "24 hour",
                    "24 hours",
                    "86400",
                    "86,400",
                ):
                    if misleading in serialized:
                        raise AssertionError(
                            f"{label} contains misleading rolling-window wording: {misleading}"
                        )

            assert_utc_calendar_quota(
                canonical_routes["example.x.tweet.one_per_day"].get("constraints", []),
                "one-tweet-per-provider-account-per-day",
                label="canonical X one-post example",
            )
            assert_utc_calendar_quota(
                templates["x_one_post_daily"].get("constraints", []),
                "x-one-post-per-day",
                label="portal X one-post template",
            )
            assert_no_rolling_calendar_wording(
                canonical_routes["example.x.tweet.one_per_day"],
                label="canonical X one-post example",
            )
            assert_no_rolling_calendar_wording(
                templates["x_one_post_daily"],
                label="portal X one-post template",
            )
            assert_utc_calendar_quota(
                canonical_routes["example.stripe.payment_intent.tokenized_jit"].get(
                    "constraints", []
                ),
                "payment-intent-five-per-assignment-day",
                label="canonical Stripe PaymentIntent example",
            )
            assert_utc_calendar_quota(
                templates["stripe_payment_intent_jit"].get("constraints", []),
                "payment-intent-five-per-assignment-day",
                label="portal Stripe PaymentIntent template",
            )
            assert_no_rolling_calendar_wording(
                canonical_routes["example.stripe.payment_intent.tokenized_jit"],
                label="canonical Stripe PaymentIntent example",
            )
            assert_no_rolling_calendar_wording(
                templates["stripe_payment_intent_jit"],
                label="portal Stripe PaymentIntent template",
            )
            stripe_daily_label = str(
                templates["stripe_payment_intent_jit"].get("label") or ""
            )
            if (
                "UTC calendar day" not in stripe_daily_label
                or "00:00 UTC" not in stripe_daily_label
            ):
                raise AssertionError(
                    "Stripe PaymentIntent template label must name the UTC calendar day and its 00:00 UTC reset"
                )

            demo_policy = json.loads(
                (ROOT / "policies" / "demo.policy.json").read_text()
            )
            demo_x_route = next(
                route
                for route in demo_policy["routes"]
                if route.get("id") == "demo.x.tweet.one_per_day"
            )
            assert_utc_calendar_quota(
                demo_x_route.get("constraints", []),
                "x-one-tweet-per-day",
                label="demo X one-post example",
            )
            assert_no_rolling_calendar_wording(
                demo_x_route,
                label="demo X one-post example",
            )

            x_calendar_template_sources = [
                section.split("npm_write_mfa: {", 1)[0]
                for section in ui_html.split("x_one_post_daily: {")[1:]
            ]
            if len(x_calendar_template_sources) != 2:
                raise AssertionError(
                    "portal must expose exactly one legacy and one PolicyBundle X calendar template"
                )
            calendar_template_source = "\n".join(
                x_calendar_template_sources
                + [
                    ui_html.split("stripe_payment_intent_jit: {", 1)[1].split(
                        "object_store_put: {", 1
                    )[0]
                ]
            )
            assert_no_rolling_calendar_wording(
                calendar_template_source,
                label="portal calendar quota source",
            )
            synchronized_examples = {
                "slack_chat_post": "example.slack.chat_post.hourly",
                "stripe_customers_list": "example.stripe.customers.list",
                "stripe_customer_get": "example.stripe.customers.get",
                "stripe_payment_intent_jit": "example.stripe.payment_intent.tokenized_jit",
                "object_store_put": "example.object_store.small_puts",
            }
            for template_id, route_id in synchronized_examples.items():
                template = templates[template_id]
                canonical_route = canonical_routes.get(route_id)
                if canonical_route is None:
                    raise AssertionError(f"canonical example is missing: {route_id}")
                if template["match"] != canonical_route["match"]:
                    raise AssertionError(f"portal and canonical route match drifted: {template_id}")
                template_config = template["adapter"]["config"]
                canonical_config = canonical_route["adapter"]["config"]
                if template_config["request"].get("operation") != canonical_config["request"].get("operation"):
                    raise AssertionError(f"portal and canonical operation capture drifted: {template_id}")
                for response_field in ("mode", "maxBodyBytes", "allowedFields", "allowedHeaders", "error"):
                    if template_config["response"].get(response_field) != canonical_config["response"].get(
                        response_field
                    ):
                        raise AssertionError(
                            f"portal and canonical success response {response_field} drifted: {template_id}"
                        )
                if template.get("constraints", []) != canonical_route.get("constraints", []):
                    raise AssertionError(f"portal and canonical constraints drifted: {template_id}")

            stripe_required_headers = (
                templates["stripe_payment_intent_jit"]["adapter"]["config"]["request"].get("requiredHeaders")
                or {}
            )
            if "idempotency-key" not in stripe_required_headers:
                raise AssertionError("Stripe payment template does not require a bounded idempotency key")
            stripe_response_binding = next(
                (
                    item
                    for item in templates["stripe_payment_intent_jit"].get("constraints", [])
                    if item.get("id") == "payment-intent-response-binding"
                ),
                None,
            )
            if stripe_response_binding != {
                "id": "payment-intent-response-binding",
                "type": "responseBinding",
                "phase": "response",
                "operations": ["stripe.payment_intents.create"],
                "successStatusCodes": [200],
                "contentTypes": ["application/json"],
                "bindings": [
                    {
                        "id": "amount",
                        "operationField": "amount",
                        "responseField": "amount",
                        "comparison": "canonicalInteger",
                    },
                    {
                        "id": "currency",
                        "operationField": "currency",
                        "responseField": "currency",
                        "comparison": "exactString",
                    },
                    {
                        "id": "payment-method",
                        "operationField": "payment_method",
                        "responseField": "payment_method",
                        "comparison": "exactString",
                    },
                ],
            }:
                raise AssertionError("Stripe payment template does not bind its success response")
            stripe_response_shape = next(
                (
                    item
                    for item in templates["stripe_payment_intent_jit"].get("constraints", [])
                    if item.get("id") == "payment-intent-response-shape"
                ),
                None,
            )
            if stripe_response_shape != {
                "id": "payment-intent-response-shape",
                "type": "responseJson",
                "phase": "response",
                "operations": ["stripe.payment_intents.create"],
                "fields": {
                    "id": {
                        "required": True,
                        "type": "string",
                        "minLength": 4,
                        "maxLength": 255,
                        "pattern": "^pi_[A-Za-z0-9]{1,252}$",
                    },
                    "object": {
                        "required": True,
                        "type": "string",
                        "equals": "payment_intent",
                    },
                    "status": {
                        "required": True,
                        "type": "string",
                        "enum": [
                            "requires_payment_method",
                            "requires_confirmation",
                            "requires_action",
                            "processing",
                            "requires_capture",
                            "canceled",
                            "succeeded",
                        ],
                    },
                },
            }:
                raise AssertionError("Stripe payment template does not prove PaymentIntent identity")

            for index, (template_id, template) in enumerate(templates.items(), start=1):
                candidate = copy.deepcopy(snapshot.raw)
                candidate["metadata"]["sequence"] = int(candidate["metadata"].get("sequence") or 0) + index
                candidate["metadata"].pop("signature", None)
                candidate["metadata"].pop("signingKeyId", None)
                route_id = f"portal.contract.{template_id}"
                route = {
                    "id": route_id,
                    "principals": ["agent:demo-proxy-token"],
                    "match": template["match"],
                    "credentialRef": "cred-demo-bearer",
                    "adapter": template["adapter"],
                    "constraints": template.get("constraints", []),
                }
                response = route["adapter"]["config"]["response"]
                if response.get("allowedHeaders") != []:
                    raise AssertionError(f"PolicyBundle portal template has an unsafe success header release: {template_id}")
                error_response = response.get("error")
                if (
                    not isinstance(error_response, dict)
                    or error_response.get("mode") != "json"
                    or error_response.get("onInvalid") != "block"
                    or not error_response.get("allowedFields")
                ):
                    raise AssertionError(f"PolicyBundle portal template lacks a bounded error projection: {template_id}")
                if route["adapter"]["type"] == "x.v2":
                    route["adapter"]["config"]["appIds"] = ["demo-x-app"]
                if any(
                    "providerAccount" in (constraint.get("key") or {}).get("operationFields", [])
                    for constraint in route["constraints"]
                ):
                    candidate["credentials"][0]["providerSubject"] = "portal-test-account"
                if template.get("jit"):
                    route["jit"] = copy.deepcopy(template["jit"])
                    route["jit"]["approvers"]["users"] = ["user:portal-test-approver"]
                candidate["routes"].append(route)
                compiled = compile_policy_bundle(sign_policy_bundle(candidate), verify_signature=True, validate_schema=True)
                allow_path = re.sub(r"\{[^}]+\}", "example", route["match"]["paths"][0])
                if allow_path.endswith("/**"):
                    allow_path = allow_path[:-3] + "/example"
                matched = compiled.match_route(
                    route["match"]["scheme"],
                    route["match"]["host"],
                    route["match"]["port"],
                    route["match"]["methods"][0],
                    allow_path,
                    "agent:demo-proxy-token",
                )
                if not matched or matched.route.id != route_id:
                    raise AssertionError(f"PolicyBundle portal template did not match its allow dry-run: {template_id}")

        forbidden_markup = ("tokenSha256", "proxy bearer token")
        for marker in forbidden_markup:
            if marker in ui_html:
                raise AssertionError(f"portal UI should not mention secret-bearing enrollment internals: {marker}")

    print(
        canonical_json(
            {
                "ok": True,
                "portal_accessibility_ui": "pass",
                "portal_agent_enrollment_ui": "pass",
                "portal_approval_review_ui": "pass",
                "portal_control_plane_mutation_ui": "pass",
                "portal_audit_investigation_ui": "pass",
                "portal_policy_templates": "pass" if node else "static-only",
            }
        )
    )


if __name__ == "__main__":
    main()
