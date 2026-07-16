.PHONY: up down logs e2e bench bench-gate-rs decision-gate-bench-evidence release-provenance production-release-provenance image-signatures sign-production-images build-agent-enrollment-wheel fetch-production-dependency-cache refresh-production-dependency-cache verify-production-dependency-cache build-production-images publish-production-images merge-production-images-env production-handoff production-release-input-preflight validate-production-policy-identity verify-production-agent-enrollment-evidence production-host-preflight deploy-production build-production-python-runtime build-production-launcher install-production-launcher generate-production-launch-manifest run-production-readiness-final production-release-proof capture-reproducible-build validate-reproducible-builds validate-policy-activation-evidence prepare-aws-kms-materials install-apparmor verify-apparmor-contract verify-apparmor-runtime verify-cosign-sigstore verify-release-image-signing verify-production-image-publish verify-production-images-env-merge verify-production-handoff verify-production-release-input-preflight verify-production-policy-identity verify-production-host-preflight verify-production-python-runtime verify-production-launch-assets verify-launch-authorization verify-production-release-proof verify-credential-policy-contracts verify-control-plane-startup verify-portal-browser-oauth verify-custody-response-proof verify-reproducible-builds verify-policy-activation-evidence verify-transparency-checkpoint verify-nitro-nsm-attest verify-aws-kms-recipient-release verify-aws-nitro-kms-unseal verify-prepare-aws-kms-materials verify-ca-install-sessions verify-control-plane-csrf verify-control-plane-oidc verify-webauthn-recovery verify-oauth-credentials verify-credential-lease-delivery verify-control-plane-mutation-mfa verify-control-plane-two-person verify-control-plane-rbac-audit verify-break-glass-grants verify-approval-denial-reason verify-approval-review verify-policy-publish-workflow verify-policy-canary-workflow verify-audit-search verify-audit-export verify-agent-enrollment verify-setup-session-api verify-production-images-no-shell scan-production-images-no-shell verify-production-image-builds generate-production-readiness-claims verify-production-readiness-claims verify-production-readiness-runner verify-release-completion verify-production-config verify-production-readiness run-production-readiness collect-nitro-kms-evidence verify-nitro-kms-evidence verify-nitro-tee verify-decision-gate-attestation verify-codebase-attestation install-ca verify-attestation reset

PRODUCTION_READINESS_CLAIMS_FILE ?= .tmp/production-readiness-claims.json
override PRODUCTION_PLATFORM := linux/amd64
AGENT_ENROLLMENT_WHEEL_DIRECTORY ?= .tmp/agent-enrollment-wheel
AGENT_ENROLLMENT_RUNTIME_LOCK ?= serverware_agent_trust/requirements.lock
AGENT_ENROLLMENT_WHEEL_MANIFEST ?= $(AGENT_ENROLLMENT_WHEEL_DIRECTORY)/wheelhouse-manifest.json
AGENT_ENROLLMENT_TARGET_PLATFORM ?= manylinux2014_x86_64
AGENT_ENROLLMENT_TARGET_PYTHON ?= 311
AGENT_ENROLLMENT_TARGET_ABI ?= cp311
PLAYWRIGHT_RUN ?= uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock --with playwright==1.61.0
TEST_PYTHON_RUN ?= uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python
MITMPROXY_TEST_RUN ?= uv run --no-project --isolated --python 3.11 --with mitmproxy==11.0.2 --with fastapi==0.136.1 --with cbor2==5.9.0 --with jsonschema==4.23.0 --with 'psycopg[binary]==3.2.3' --with python-multipart==0.0.31 --with 'uvicorn[standard]==0.34.0'
PRODUCTION_READINESS_CLAIMS_ARGS ?=
PRODUCTION_READINESS_OUT ?= .tmp/production-readiness.json
PRODUCTION_READINESS_CONFIG_OUT ?= .tmp/production-readiness-config.json
PRODUCTION_READINESS_ENV ?= ops/production-readiness.env
PRODUCTION_READINESS_PREFLIGHT ?= 1
PRODUCTION_COMPLETION_PROOF_OUT ?= .tmp/serverware-completion-proof.json
PRODUCTION_COMPLETION_VERIFICATION_MODE ?= readiness
PRODUCTION_HARDWARE_ASSURANCE ?=
PRODUCTION_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY ?=
PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE ?=
PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256 ?=
PRODUCTION_HARDWARE_ASSURANCE_ARGS = $(strip $(if $(strip $(PRODUCTION_HARDWARE_ASSURANCE)),--hardware-assurance "$(PRODUCTION_HARDWARE_ASSURANCE)") $(if $(strip $(PRODUCTION_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY)),--hardware-assurance-trusted-public-key "$(PRODUCTION_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY)") $(if $(strip $(PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE)),--hardware-assurance-expected-challenge-nonce "$(PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE)") $(if $(strip $(PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256)),--hardware-assurance-expected-challenge-nonce-sha256 "$(PRODUCTION_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256)"))
PRODUCTION_FINAL_CHALLENGE_RECEIPT ?=
PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY ?=
PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PROVIDER ?=
PRODUCTION_FINAL_CHALLENGE_ARGS = $(strip $(if $(strip $(PRODUCTION_FINAL_CHALLENGE_RECEIPT)),--final-challenge-receipt "$(PRODUCTION_FINAL_CHALLENGE_RECEIPT)") $(if $(strip $(PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY)),--final-challenge-authority-public-key "$(PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY)") $(if $(strip $(PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PROVIDER)),--final-challenge-authority-provider "$(PRODUCTION_FINAL_CHALLENGE_AUTHORITY_PROVIDER)"))
NITRO_KMS_EVIDENCE_OUT ?= .tmp/nitro-kms-evidence.json
PRODUCTION_IMAGES_BUILD_FILE ?= .tmp/production-images-build.json
PRODUCTION_IMAGES_PUBLISHED_FILE ?= .tmp/production-images-published.json
PRODUCTION_IMAGES_ENV_OUT ?= .tmp/production-images.env
PRODUCTION_HANDOFF_OUT ?= .tmp/production-handoff.json
PRODUCTION_RELEASE_INPUT_PREFLIGHT_OUT ?= .tmp/production-release-input-preflight.json
PRODUCTION_HOST_PREFLIGHT_OUT ?= .tmp/production-host-preflight.json
PRODUCTION_POLICY_BUNDLE ?=
PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY ?=
PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT ?= .tmp/production-policy-identity-verification.json
POLICY_ACTIVATION_EVIDENCE_FILE ?= .tmp/policy-activation-evidence.json
POLICY_ACTIVATION_VERIFICATION_OUT ?= .tmp/policy-activation-verification.json
POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY ?= $(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)
POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY ?=
POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR ?=
POLICY_ACTIVATION_VERIFICATION_SIGNATURE ?=
POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY ?=
REPRODUCIBLE_BUILD_CAPTURE_OUT ?= .tmp/reproducible-build-manifest.json
REPRODUCIBLE_BUILD_BUILDER_ID ?=
REPRODUCIBLE_BUILD_SIGNING_KEY ?=
REPRODUCIBLE_BUILD_LEFT ?=
REPRODUCIBLE_BUILD_RIGHT ?=
REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT ?=
REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT ?=
REPRODUCIBLE_BUILD_VERIFICATION_OUT ?= .tmp/reproducible-build-verification.json
REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE ?=
REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY ?=
PRODUCTION_IMAGE_REGISTRY_PREFIX ?=
PRODUCTION_IMAGE_TAG ?= production-candidate
AWS_KMS_MATERIALS_SPEC ?= ops/aws-kms-materials.spec.json
AWS_KMS_MATERIALS_OUT ?= /etc/serverware/kms-materials.json
RELEASE_PROVENANCE_SUMMARY_FILE ?= .tmp/release-provenance-summary.json
RELEASE_PROVENANCE_FILE ?= .tmp/release-provenance.json
RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY ?=
IMAGE_SIGNATURES_SUMMARY_FILE ?= .tmp/image-signatures-summary.json
IMAGE_SIGNATURES_FILE ?= .tmp/image-signatures.json
SIGSTORE_TRUSTED_PUBLIC_KEY ?=
REKOR_TRUSTED_PUBLIC_KEY ?=
EXTERNAL_CHECKPOINT_PROVIDER ?=
EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY ?=
DECISION_GATE_BENCH_FILE ?= .tmp/decision-gate-rs-bench.json
PRODUCTION_DEPLOY_COMMAND ?=
PRODUCTION_SOURCE_TREE_DIGEST ?=
PRODUCTION_RELEASE_ROOT ?=
PRODUCTION_DEPLOYMENT_AUDIENCE ?=
PRODUCTION_DEPLOYMENT_IDENTITY_SHA256 ?=
PRODUCTION_RELEASE_SEQUENCE ?=
PRODUCTION_ROLLBACK_EPOCH ?=
PRODUCTION_STATE_DIRECTORY ?= /var/lib/serverware/production-proof
PRODUCTION_LAUNCH_MANIFEST ?= /etc/serverware/production-release-launch.json
PRODUCTION_SYSTEMD_UNIT_OUT ?= /etc/systemd/system/serverware-production-release-proof.service
PRODUCTION_SYSTEMD_UNIT_NAME ?= serverware-production-release-proof.service
PRODUCTION_LAUNCHER_BUILD_DIRECTORY ?= .tmp/production-launcher-artifact
PRODUCTION_LAUNCHER_BUILD_PATH ?= $(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)/serverware-production-launcher
PRODUCTION_LAUNCHER_INSTALL_PATH_FILE ?= .tmp/production-launcher-install-path
PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY ?= .tmp/production-python-runtime-artifact
PRODUCTION_RELEASE_PYTHON ?= $(PRODUCTION_RELEASE_ROOT)/runtime/python/bin/python3
PRODUCTION_RELEASE_PYTHON_STDLIB ?= $(PRODUCTION_RELEASE_ROOT)/runtime/python/lib/python3.11
PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD ?= $(PRODUCTION_RELEASE_PYTHON_STDLIB)/lib-dynload
PRODUCTION_RELEASE_PYTHON_VENDOR ?= $(PRODUCTION_RELEASE_ROOT)/vendor
PRODUCTION_AGENT_ENROLLMENT_PACKET ?=
PRODUCTION_AGENT_ENROLLMENT_PACKET_FILE_SHA256 ?=
PRODUCTION_AGENT_ENROLLMENT_PACKET_SHA256 ?=
PRODUCTION_AGENT_ENROLLMENT_RECEIPT ?=
PRODUCTION_AGENT_ENROLLMENT_RECEIPT_TRUSTED_PUBLIC_KEY ?=
PRODUCTION_AGENT_ENROLLMENT_RECEIPT_PROVIDER ?=
PRODUCTION_AGENT_ENROLLMENT_RECEIPT_KEY_ID ?=
PRODUCTION_AGENT_EGRESS_EVIDENCE ?=
PRODUCTION_AGENT_EGRESS_TRUSTED_PUBLIC_KEY ?=
PRODUCTION_AGENT_EGRESS_PROVIDER ?=
PRODUCTION_AGENT_EGRESS_KEY_ID ?=
PRODUCTION_AGENT_ENROLLMENT_RECEIPT_ID ?=
PRODUCTION_AGENT_SETUP_SESSION_ID ?=
PRODUCTION_AGENT_ENROLLMENT_SESSION_ID ?=
PRODUCTION_AGENT_PRINCIPAL_ID ?=
PRODUCTION_AGENT_ROUTE_ID ?=
PRODUCTION_AGENT_CREDENTIAL_ID ?=
PRODUCTION_AGENT_CREDENTIAL_VERSION ?=
PRODUCTION_AGENT_POLICY_HASH ?=
PRODUCTION_AGENT_ROUTE_POLICY_DIGEST ?=
PRODUCTION_AGENT_ASSIGNMENT_DIGEST ?=
PRODUCTION_AGENT_VERIFIER_NONCE_SHA256 ?=
PRODUCTION_AGENT_TRUST_PROFILE_SHA256 ?=
PRODUCTION_AGENT_ENROLLMENT_VERIFICATION_OUT ?= .tmp/production-agent-enrollment-verification.json

up:
	docker compose up -d --build serverware demo-upstream audit-anchor

down:
	docker compose down

logs:
	docker compose logs -f serverware demo-upstream audit-anchor

e2e:
	docker compose up -d --build serverware demo-upstream
	docker compose build decision-gate-rs
	SERVERWARE_HARDENING_SERVICES=serverware,audit-anchor,grant-store,demo-upstream ./scripts/test_container_hardening.sh
	SERVERWARE_APPARMOR_DRY_RUN=1 ./scripts/test_apparmor_runtime.sh
	docker compose exec -T serverware python scripts/test_webauthn_attestation.py
	docker compose exec -T serverware python scripts/test_credential_lease_delivery.py
	./scripts/e2e.sh
	./scripts/test_key_release_gate.py

bench:
	docker compose up -d --build serverware demo-upstream
	mkdir -p .tmp
	./scripts/wait_for_serverware.sh
	curl -fsS -H "X-Serverware-Admin-Token: $${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" -X POST http://localhost:3000/api/demo/seed >/dev/null
	SERVERWARE_CA_OUT=.tmp/serverware-ca.pem SERVERWARE_VERIFY_OUT=.tmp/attestation-verify.json ./scripts/install_verified_ca.sh >/dev/null
	docker compose up -d --force-recreate decision-gate-rs
	./scripts/wait_for_decision_gate.sh
	python3 scripts/bench.py

bench-gate-rs:
	docker compose up -d --build serverware demo-upstream
	mkdir -p .tmp
	./scripts/wait_for_serverware.sh
	curl -fsS -H "X-Serverware-Admin-Token: $${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" -X POST http://localhost:3000/api/demo/seed >/dev/null
	./scripts/wait_for_demo_upstream.sh
	./scripts/wait_for_decision_gate_ca.sh
	SERVERWARE_CA_OUT=.tmp/serverware-ca.pem SERVERWARE_VERIFY_OUT=.tmp/attestation-verify.json ./scripts/install_verified_ca.sh >/dev/null
	docker compose up -d --build decision-gate-rs
		./scripts/test_container_hardening.sh
		SERVERWARE_APPARMOR_DRY_RUN=1 ./scripts/test_apparmor_runtime.sh
		./scripts/test_decision_gate_signature.sh
		./scripts/wait_for_decision_gate.sh
		./scripts/test_decision_gate_trust_root.sh
		./scripts/test_decision_gate_policy_reload.sh
	./scripts/test_decision_gate_connect.sh
	./scripts/test_decision_gate_mitm.sh
		./scripts/test_decision_gate_forward.sh
		./scripts/test_decision_gate_streaming.sh
		./scripts/test_decision_gate_request_streaming.sh
		./scripts/test_decision_gate_jsonl_streaming.sh
		./scripts/test_decision_gate_json_array_streaming.sh
			./scripts/test_decision_gate_json_sse_streaming.sh
			./scripts/test_decision_gate_json_nested_streaming.sh
			./scripts/test_decision_gate_form_urlencoded_streaming.sh
			./scripts/test_decision_gate_csv_streaming.sh
				./scripts/test_decision_gate_response.sh
	$(TEST_PYTHON_RUN) scripts/generate_release_provenance.py > .tmp/release-provenance-summary.json
	cat .tmp/release-provenance-summary.json
				./scripts/test_response_proof_capture.sh
					COMPOSE_PROJECT_NAME="serverware-custody-$$(date +%s)-$$$$-$$(openssl rand -hex 6)" ./scripts/test_custody_response_proof.sh
	docker compose exec -T serverware python scripts/test_webauthn_attestation.py
	$(TEST_PYTHON_RUN) scripts/verify_decision_gate_attestation.py
	$(TEST_PYTHON_RUN) scripts/test_key_release_gate.py
	docker compose exec -T -e SERVERWARE_TEE_QUOTE_PROVIDER=external-command -e SERVERWARE_TEE_PLATFORM=fixture-tee -e "SERVERWARE_TEE_QUOTE_COMMAND=python scripts/external_tee_provider.py quote" -e "SERVERWARE_TEE_QUOTE_VERIFY_COMMAND=python scripts/external_tee_provider.py verify" -e "SERVERWARE_KEY_RELEASE_COMMAND=python scripts/external_tee_provider.py release" serverware python scripts/test_external_tee_provider.py
	docker compose exec -T serverware python scripts/test_nitro_tee_provider.py
		./scripts/test_decision_gate_approval_publish.sh
		./scripts/test_decision_gate_audit.sh
		./scripts/test_control_plane_audit_store.sh
		./scripts/test_control_plane_metadata_store.sh
		docker compose exec -T serverware python scripts/test_ca_install_sessions.py
		docker compose exec -T serverware python scripts/test_control_plane_csrf.py
			docker compose exec -T serverware python scripts/test_control_plane_oidc.py
			$(TEST_PYTHON_RUN) scripts/test_http_client.py
			$(TEST_PYTHON_RUN) scripts/test_oauth_credentials.py --compose-contract-only
			docker compose exec -T serverware python scripts/test_oauth_credentials.py
			docker compose exec -T serverware python scripts/test_oauth_http_flow.py
			$(MAKE) verify-portal-browser-oauth
		docker compose exec -T serverware python scripts/test_credential_lease_delivery.py
		docker compose exec -T serverware python scripts/test_control_plane_mutation_mfa.py
		docker compose exec -T serverware python scripts/test_control_plane_two_person.py
		docker compose exec -T serverware python scripts/test_control_plane_rbac_audit.py
		docker compose exec -T serverware python scripts/test_break_glass_grants.py
		docker compose exec -T serverware python scripts/test_approval_denial_reason.py
		docker compose exec -T serverware python scripts/test_approval_review.py
		docker compose exec -T serverware python scripts/test_webauthn_recovery.py
		docker compose exec -T serverware python scripts/test_policy_publish_workflow.py
		docker compose exec -T serverware python scripts/test_policy_canary_workflow.py
		docker compose exec -T serverware python scripts/test_audit_search.py
		docker compose exec -T serverware python scripts/test_audit_export.py
		$(TEST_PYTHON_RUN) scripts/test_agent_enrollment.py
		$(TEST_PYTHON_RUN) scripts/test_transparency_checkpoint.py
		$(TEST_PYTHON_RUN) scripts/test_nitro_nsm_attest.py
		docker compose exec -T serverware python scripts/test_aws_kms_recipient_release.py
		docker compose exec -T serverware python scripts/test_aws_nitro_kms_unseal.py
		docker compose exec -T serverware python scripts/test_prepare_aws_kms_materials.py
		$(TEST_PYTHON_RUN) scripts/test_production_readiness_claims.py
		$(TEST_PYTHON_RUN) scripts/test_production_readiness.py
		$(MAKE) verify-production-readiness-runner
		$(MAKE) verify-release-completion
		docker compose exec -T serverware python scripts/test_portal_agent_enrollment_ui.py
		BASE=http://localhost:3000 AUDIT_ANCHOR_BASE=http://localhost:9100 \
			SERVERWARE_ADMIN_TOKEN=dev-admin-token \
			SERVERWARE_AUDIT_ANCHOR_TOKEN=dev-audit-anchor-token \
			./scripts/test_audit_anchor.sh
	docker compose exec -T \
		-e DECISION_GATE_BASE=http://decision-gate-rs:9091 \
		-e PROXY=http://decision-gate-rs:9090 \
		-e BASE=http://localhost:3000 \
		serverware python scripts/bench_decision_gate.py --self-test > .tmp/decision-gate-rs-bench.json
	cat .tmp/decision-gate-rs-bench.json
	BASE=http://localhost:3000 DECISION_GATE_BASE=http://localhost:9091 \
		DECISION_GATE_HOST=localhost DECISION_GATE_PORT=9090 \
		SERVERWARE_ADMIN_TOKEN=dev-admin-token \
		SERVERWARE_DATA_PLANE_MANAGEMENT_TOKEN=dev-rust-management-token \
		./scripts/test_decision_gate_shared_rate_limits.sh
	env -u SERVERWARE_PRODUCTION_IMAGES \
		-u SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY \
		-u SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY \
		-u SERVERWARE_TRANSPARENCY_EXPECTED_PROVIDER \
		-u SERVERWARE_TRANSPARENCY_EXPECTED_LOG_ID \
		-u SERVERWARE_COSIGN_CERT_IDENTITY \
		-u SERVERWARE_COSIGN_CERT_OIDC_ISSUER \
		-u SERVERWARE_COSIGN_KEY_ID \
		-u SERVERWARE_COSIGN_EXPECTED_REKOR_LOG_ID \
		-u SERVERWARE_COSIGN_REKOR_URL \
		-u SERVERWARE_COSIGN_SIGN_EXTRA_ARGS \
		-u SERVERWARE_COSIGN_VERIFY_EXTRA_ARGS \
		-u SERVERWARE_COSIGN_TLOG_UPLOAD \
		-u SERVERWARE_COSIGN_FIXTURE_NO_TRANSPARENCY \
		-u SERVERWARE_COSIGN_FIXTURE_VERIFY_FAIL \
		-u SERVERWARE_COSIGN_WORKLOAD_IDENTITY \
		SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command \
		SERVERWARE_IMAGE_SIGN_COMMAND="python3 scripts/cosign_sigstore.py sign" \
		SERVERWARE_IMAGE_VERIFY_COMMAND="python3 scripts/cosign_sigstore.py verify" \
		SERVERWARE_COSIGN_BINARY="python3 scripts/cosign_fixture.py" \
		SERVERWARE_COSIGN_FIXTURE_KEY=.tmp/cosign-fixture-ed25519.pem \
		SERVERWARE_COSIGN_FIXTURE_LOG=.tmp/cosign-fixture-rekor.jsonl \
		SERVERWARE_COSIGN_KEY=.tmp/cosign-fixture-ed25519.pem \
		SERVERWARE_COSIGN_YES=1 \
		SERVERWARE_RELEASE_ANCHOR_CA_BUNDLE= \
		SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1 \
		$(TEST_PYTHON_RUN) scripts/sign_release_images.py \
			--base http://localhost:3000 \
			--gate http://localhost:9090 \
			--anchor http://localhost:9100 \
			--anchor-token dev-audit-anchor-token \
			> .tmp/image-signatures-summary.json
	cat .tmp/image-signatures-summary.json

decision-gate-bench-evidence:
	docker compose up -d --build serverware demo-upstream
	mkdir -p .tmp
	./scripts/wait_for_serverware.sh
	curl -fsS -H "X-Serverware-Admin-Token: $${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" -X POST http://localhost:3000/api/demo/seed >/dev/null
	./scripts/wait_for_demo_upstream.sh
	./scripts/wait_for_decision_gate_ca.sh
	SERVERWARE_CA_OUT=.tmp/serverware-ca.pem SERVERWARE_VERIFY_OUT=.tmp/attestation-verify.json ./scripts/install_verified_ca.sh >/dev/null
	docker compose up -d --build decision-gate-rs
	./scripts/wait_for_decision_gate.sh
	rm -f "$(DECISION_GATE_BENCH_FILE)"
	docker compose exec -T \
		-e DECISION_GATE_BASE=http://decision-gate-rs:9091 \
		-e PROXY=http://decision-gate-rs:9090 \
		-e BASE=http://localhost:3000 \
		serverware python scripts/bench_decision_gate.py --self-test > "$(DECISION_GATE_BENCH_FILE)"
	cat "$(DECISION_GATE_BENCH_FILE)"

release-provenance:
	./scripts/generate_release_provenance.py \
		--out "$(RELEASE_PROVENANCE_FILE)" > "$(RELEASE_PROVENANCE_SUMMARY_FILE)"
	cat "$(RELEASE_PROVENANCE_SUMMARY_FILE)"

production-release-provenance:
	./scripts/generate_release_provenance.py \
		--production \
		--env-file "$(PRODUCTION_READINESS_ENV)" \
		--production-images-build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--production-images-published "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" \
		--production-images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--reproducible-build-verification "$(REPRODUCIBLE_BUILD_VERIFICATION_OUT)" \
		--out "$(RELEASE_PROVENANCE_FILE)" > "$(RELEASE_PROVENANCE_SUMMARY_FILE)"
	cat "$(RELEASE_PROVENANCE_SUMMARY_FILE)"

image-signatures: release-provenance
	SERVERWARE_IMAGE_SIGNATURE_PROVIDER="$${SERVERWARE_IMAGE_SIGNATURE_PROVIDER:-sigstore-command}" \
	SERVERWARE_IMAGE_SIGN_COMMAND="$${SERVERWARE_IMAGE_SIGN_COMMAND:-python3 scripts/cosign_sigstore.py sign}" \
	SERVERWARE_IMAGE_VERIFY_COMMAND="$${SERVERWARE_IMAGE_VERIFY_COMMAND:-python3 scripts/cosign_sigstore.py verify}" \
	SERVERWARE_COSIGN_BINARY="$${SERVERWARE_COSIGN_BINARY:-python3 scripts/cosign_fixture.py}" \
	SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY="$${SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY:-1}" \
	python3 scripts/sign_release_images.py \
		--provenance "$(RELEASE_PROVENANCE_FILE)" \
		--out "$(IMAGE_SIGNATURES_FILE)" > "$(IMAGE_SIGNATURES_SUMMARY_FILE)"
	cat "$(IMAGE_SIGNATURES_SUMMARY_FILE)"

sign-production-images:
	python3 scripts/sign_release_images.py \
		--env-file "$(PRODUCTION_READINESS_ENV)" \
		--provenance "$(RELEASE_PROVENANCE_FILE)" \
		--production-images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--out "$(IMAGE_SIGNATURES_FILE)" > "$(IMAGE_SIGNATURES_SUMMARY_FILE)"
	cat "$(IMAGE_SIGNATURES_SUMMARY_FILE)"

build-agent-enrollment-wheel:
	rm -rf "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)"
	mkdir -p "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)"
	python3 -m pip download --require-hashes --only-binary=:all: --platform "$(AGENT_ENROLLMENT_TARGET_PLATFORM)" --implementation cp --python-version "$(AGENT_ENROLLMENT_TARGET_PYTHON)" --abi "$(AGENT_ENROLLMENT_TARGET_ABI)" --dest "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)" --requirement "$(AGENT_ENROLLMENT_RUNTIME_LOCK)"
	SOURCE_DATE_EPOCH="$${SOURCE_DATE_EPOCH:-0}" python3 -m pip wheel --no-build-isolation --no-deps --wheel-dir "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)" .
	cp "$(AGENT_ENROLLMENT_RUNTIME_LOCK)" "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)/requirements.lock"
	test "$$(find "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)" -maxdepth 1 -type f -name 'serverware_enrollment-*.whl' | wc -l | tr -d ' ')" = 1
	python3 scripts/generate_offline_artifact_manifest.py --root "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)" --output "$(AGENT_ENROLLMENT_WHEEL_MANIFEST)" --require 'serverware_enrollment-*.whl' --require 'cryptography-*.whl' --require 'cffi-*.whl' --require 'pycparser-*.whl' --require requirements.lock --label serverware-enrollment-cpython311-linux-amd64 --python-tag cp311 --platform-tag "$(AGENT_ENROLLMENT_TARGET_PLATFORM)" --architecture amd64
	python3 scripts/verify_offline_artifact_manifest.py --root "$(AGENT_ENROLLMENT_WHEEL_DIRECTORY)" --manifest "$(AGENT_ENROLLMENT_WHEEL_MANIFEST)" --label serverware-enrollment-cpython311-linux-amd64 --python-tag cp311 --platform-tag "$(AGENT_ENROLLMENT_TARGET_PLATFORM)" --architecture amd64

fetch-production-dependency-cache:
	python3 production-dependencies/prefetch.py fetch

refresh-production-dependency-cache:
	python3 production-dependencies/prefetch.py refresh

verify-production-dependency-cache:
	python3 production-dependencies/prefetch.py verify

verify-production-agent-enrollment-evidence:
	@set -eu; for value in \
		"$(PRODUCTION_AGENT_ENROLLMENT_PACKET)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_PACKET_FILE_SHA256)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_PACKET_SHA256)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_TRUSTED_PUBLIC_KEY)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_PROVIDER)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_KEY_ID)" \
		"$(PRODUCTION_AGENT_EGRESS_EVIDENCE)" \
		"$(PRODUCTION_AGENT_EGRESS_TRUSTED_PUBLIC_KEY)" \
		"$(PRODUCTION_AGENT_EGRESS_PROVIDER)" \
		"$(PRODUCTION_AGENT_EGRESS_KEY_ID)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_ID)" \
		"$(PRODUCTION_AGENT_SETUP_SESSION_ID)" \
		"$(PRODUCTION_AGENT_ENROLLMENT_SESSION_ID)" \
		"$(PRODUCTION_AGENT_PRINCIPAL_ID)" \
		"$(PRODUCTION_AGENT_ROUTE_ID)" \
		"$(PRODUCTION_AGENT_CREDENTIAL_ID)" \
		"$(PRODUCTION_AGENT_CREDENTIAL_VERSION)" \
		"$(PRODUCTION_AGENT_POLICY_HASH)" \
		"$(PRODUCTION_AGENT_ROUTE_POLICY_DIGEST)" \
		"$(PRODUCTION_AGENT_ASSIGNMENT_DIGEST)" \
		"$(PRODUCTION_AGENT_VERIFIER_NONCE_SHA256)" \
		"$(PRODUCTION_AGENT_TRUST_PROFILE_SHA256)"; do test -n "$$value" || { echo "all PRODUCTION_AGENT_* enrollment evidence variables are required" >&2; exit 2; }; done
	$(TEST_PYTHON_RUN) scripts/verify_production_agent_enrollment.py \
		--enrollment-packet "$(PRODUCTION_AGENT_ENROLLMENT_PACKET)" \
		--expected-enrollment-packet-file-sha256 "$(PRODUCTION_AGENT_ENROLLMENT_PACKET_FILE_SHA256)" \
		--enrollment-packet-sha256 "$(PRODUCTION_AGENT_ENROLLMENT_PACKET_SHA256)" \
		--receipt "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT)" \
		--receipt-trusted-public-key "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_TRUSTED_PUBLIC_KEY)" \
		--receipt-provider "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_PROVIDER)" \
		--expected-receipt-key-id "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_KEY_ID)" \
		--egress-evidence "$(PRODUCTION_AGENT_EGRESS_EVIDENCE)" \
		--egress-evidence-trusted-public-key "$(PRODUCTION_AGENT_EGRESS_TRUSTED_PUBLIC_KEY)" \
		--egress-evidence-provider "$(PRODUCTION_AGENT_EGRESS_PROVIDER)" \
		--expected-egress-evidence-key-id "$(PRODUCTION_AGENT_EGRESS_KEY_ID)" \
		--receipt-id "$(PRODUCTION_AGENT_ENROLLMENT_RECEIPT_ID)" \
		--setup-session-id "$(PRODUCTION_AGENT_SETUP_SESSION_ID)" \
		--enrollment-session-id "$(PRODUCTION_AGENT_ENROLLMENT_SESSION_ID)" \
		--principal-id "$(PRODUCTION_AGENT_PRINCIPAL_ID)" \
		--route-id "$(PRODUCTION_AGENT_ROUTE_ID)" \
		--credential-id "$(PRODUCTION_AGENT_CREDENTIAL_ID)" \
		--credential-version "$(PRODUCTION_AGENT_CREDENTIAL_VERSION)" \
		--policy-hash "$(PRODUCTION_AGENT_POLICY_HASH)" \
		--route-policy-digest "$(PRODUCTION_AGENT_ROUTE_POLICY_DIGEST)" \
		--expected-assignment-digest "$(PRODUCTION_AGENT_ASSIGNMENT_DIGEST)" \
		--verifier-nonce-sha256 "$(PRODUCTION_AGENT_VERIFIER_NONCE_SHA256)" \
		--trust-profile-sha256 "$(PRODUCTION_AGENT_TRUST_PROFILE_SHA256)" \
		--out "$(PRODUCTION_AGENT_ENROLLMENT_VERIFICATION_OUT)"

build-production-images: verify-production-dependency-cache
	python3 scripts/build_production_images.py --platform "$(PRODUCTION_PLATFORM)" --out "$(PRODUCTION_IMAGES_BUILD_FILE)"

publish-production-images:
	@if [ -z "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)" ]; then echo "PRODUCTION_IMAGE_REGISTRY_PREFIX is required, for example registry.prod.serverware.dev/serverware" >&2; exit 2; fi
	@set -eu; python3 -c 'import json,sys; document=json.load(open(sys.argv[1], encoding="utf-8")); [print(item["image_id"]) for item in document["images"]]' "$(PRODUCTION_IMAGES_BUILD_FILE)" | while IFS= read -r image; do test "$$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$$image")" = "$(PRODUCTION_PLATFORM)" || { echo "refusing to publish a non-$(PRODUCTION_PLATFORM) image: $$image" >&2; exit 2; }; done
	python3 scripts/publish_production_images.py \
		--build-file "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--registry-prefix "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)" \
		--tag "$(PRODUCTION_IMAGE_TAG)" \
		--out "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" \
		--env-out "$(PRODUCTION_IMAGES_ENV_OUT)"

merge-production-images-env:
	python3 scripts/merge_production_images_env.py \
		--images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--env-file "$(PRODUCTION_READINESS_ENV)"

production-handoff:
	python3 scripts/generate_production_handoff.py \
		--production-images-build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--registry-prefix "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)" \
		--tag "$(PRODUCTION_IMAGE_TAG)" \
		--out "$(PRODUCTION_HANDOFF_OUT)"

production-release-input-preflight:
	python3 scripts/production_release_input_preflight.py \
		--env-file "$(PRODUCTION_READINESS_ENV)" \
		--kms-spec "$(AWS_KMS_MATERIALS_SPEC)" \
		--registry-prefix "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)" \
		--deploy-command "$(PRODUCTION_DEPLOY_COMMAND)" \
		--policy-bundle "$(PRODUCTION_POLICY_BUNDLE)" \
		--policy-trusted-public-key "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)" \
		--policy-identity-verification "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)" \
		--policy-activation-verification "$(POLICY_ACTIVATION_VERIFICATION_OUT)" \
		--policy-activation-signature "$(POLICY_ACTIVATION_VERIFICATION_SIGNATURE)" \
		--policy-activation-trusted-public-key "$(POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		--reproducible-build-verification "$(REPRODUCIBLE_BUILD_VERIFICATION_OUT)" \
		--reproducible-build-signature "$(REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE)" \
		--reproducible-build-trusted-public-key "$(REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		--out "$(PRODUCTION_RELEASE_INPUT_PREFLIGHT_OUT)"

validate-production-policy-identity:
	@if [ -z "$(PRODUCTION_POLICY_BUNDLE)" ] || [ -z "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)" ]; then echo "PRODUCTION_POLICY_BUNDLE and PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY are required" >&2; exit 2; fi
	python3 scripts/verify_production_policy_identity.py \
		--bundle "$(PRODUCTION_POLICY_BUNDLE)" \
		--trusted-public-key "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)" \
		--out "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)"

production-host-preflight:
	python3 scripts/production_host_preflight.py \
		--env-file "$(PRODUCTION_READINESS_ENV)" \
		--production-images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--production-images-published "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" \
		--production-images-build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--release-provenance-summary "$(RELEASE_PROVENANCE_SUMMARY_FILE)" \
		--release-provenance "$(RELEASE_PROVENANCE_FILE)" \
		--image-signatures-summary "$(IMAGE_SIGNATURES_SUMMARY_FILE)" \
		--image-signatures "$(IMAGE_SIGNATURES_FILE)" \
		--bench "$(DECISION_GATE_BENCH_FILE)" \
		--policy-bundle "$(PRODUCTION_POLICY_BUNDLE)" \
		--policy-trusted-public-key "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)" \
		--policy-identity-verification "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)" \
		--policy-activation-verification "$(POLICY_ACTIVATION_VERIFICATION_OUT)" \
		--policy-activation-signature "$(POLICY_ACTIVATION_VERIFICATION_SIGNATURE)" \
		--policy-activation-trusted-public-key "$(POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		--reproducible-build-verification "$(REPRODUCIBLE_BUILD_VERIFICATION_OUT)" \
		--reproducible-build-signature "$(REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE)" \
		--reproducible-build-trusted-public-key "$(REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		--kms-materials "$(AWS_KMS_MATERIALS_OUT)" \
		--out "$(PRODUCTION_HOST_PREFLIGHT_OUT)"

deploy-production:
	@if [ -z "$(PRODUCTION_DEPLOY_COMMAND)" ]; then echo "PRODUCTION_DEPLOY_COMMAND is required and must deploy the published digest-pinned images to the production host" >&2; exit 2; fi
	@test -x "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/bin/python3" || { echo "build-production-python-runtime must produce the release runtime artifact before deployment" >&2; exit 2; }
	@test -d "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/vendor" || { echo "production Python runtime artifact is missing vendor" >&2; exit 2; }
	SERVERWARE_PRODUCTION_PYTHON_RUNTIME_ARTIFACT="$(abspath $(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY))" $(PRODUCTION_DEPLOY_COMMAND)

build-production-python-runtime: verify-production-dependency-cache
	@test -n "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" && test "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" != / || { echo "PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY is unsafe" >&2; exit 2; }
	rm -rf "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)"
	mkdir -p "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)"
	docker buildx build --network=none --platform "$(PRODUCTION_PLATFORM)" --target production-python-runtime-artifact --output "type=local,dest=$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" -f Dockerfile.production .
	test -x "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/bin/python3"
	test -d "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/lib/python3.11/lib-dynload"
	test -f "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/lib/libpython3.11.so.1.0"
	test -d "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/vendor"

build-production-launcher: verify-production-dependency-cache
	mkdir -p "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)"
	docker buildx build --network=none --platform "$(PRODUCTION_PLATFORM)" --target production-launcher-artifact --output "type=local,dest=$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" -f data-plane/decision-gate-rs/Dockerfile.production .
	test -x "$(PRODUCTION_LAUNCHER_BUILD_PATH)"

install-production-launcher:
	@test "$$(id -u)" = 0 || { echo "install-production-launcher must run as root on the production host" >&2; exit 2; }
	@test -x "$(PRODUCTION_LAUNCHER_BUILD_PATH)" || { echo "build-production-launcher must produce $(PRODUCTION_LAUNCHER_BUILD_PATH) first" >&2; exit 2; }
	@set -eu; set -- $$(sha256sum "$(PRODUCTION_LAUNCHER_BUILD_PATH)"); digest="$$1"; expected=$$(python3 -c 'import json,sys; document=json.load(open(sys.argv[1], encoding="utf-8")); matches=[item.get("launcher_binary_digest") for item in document.get("images", []) if item.get("service") == "serverware-decision-gate"]; len(matches) == 1 or sys.exit("production build must contain exactly one decision-gate launcher digest"); print(matches[0])' "$(PRODUCTION_IMAGES_BUILD_FILE)"); test "sha256:$$digest" = "$$expected" || { echo "production launcher artifact does not match the independently reproducible production image" >&2; exit 2; }; destination="/opt/serverware/launchers/sha256-$$digest/serverware-production-launcher"; install -d -o root -g root -m 0755 "$${destination%/*}"; install -o root -g root -m 0500 "$(PRODUCTION_LAUNCHER_BUILD_PATH)" "$$destination"; mkdir -p "$$(dirname "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)")"; printf '%s\n' "$$destination" > "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"; chmod 0600 "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"

generate-production-launch-manifest:
	@test "$$(id -u)" = 0 || { echo "generate-production-launch-manifest must run as root on the production host" >&2; exit 2; }
	@test -n "$(PRODUCTION_RELEASE_ROOT)" || { echo "PRODUCTION_RELEASE_ROOT is required" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_SOURCE_TREE_DIGEST)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_SOURCE_TREE_DIGEST must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_DEPLOYMENT_AUDIENCE)" | grep -Eq '^[a-z0-9][a-z0-9._:-]{0,127}$$' || { echo "PRODUCTION_DEPLOYMENT_AUDIENCE is invalid" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_DEPLOYMENT_IDENTITY_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_DEPLOYMENT_IDENTITY_SHA256 must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_RELEASE_SEQUENCE)" | grep -Eq '^[1-9][0-9]*$$' || { echo "PRODUCTION_RELEASE_SEQUENCE must be a positive integer" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_ROLLBACK_EPOCH)" | grep -Eq '^(0|[1-9][0-9]*)$$' || { echo "PRODUCTION_ROLLBACK_EPOCH must be a nonnegative integer" >&2; exit 2; }
	@test -x "$(PRODUCTION_RELEASE_PYTHON)" || { echo "production release Python executable is missing or not executable: $(PRODUCTION_RELEASE_PYTHON)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_STDLIB)" || { echo "production release Python stdlib is missing: $(PRODUCTION_RELEASE_PYTHON_STDLIB)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" || { echo "production release Python lib-dynload is missing: $(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_VENDOR)" || { echo "production release Python vendor root is missing: $(PRODUCTION_RELEASE_PYTHON_VENDOR)" >&2; exit 2; }
	@set -eu; launcher_path=$$(cat "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"); install -d -o root -g root -m 0700 "$(PRODUCTION_STATE_DIRECTORY)" /run/serverware; python3 scripts/generate_production_launch_manifest.py \
		--output "$(PRODUCTION_LAUNCH_MANIFEST)" \
		--systemd-unit-out "$(PRODUCTION_SYSTEMD_UNIT_OUT)" \
		--launcher-path "$$launcher_path" \
		--release-root "$(PRODUCTION_RELEASE_ROOT)" \
		--state-directory "$(PRODUCTION_STATE_DIRECTORY)" \
		--source-tree-digest "$(PRODUCTION_SOURCE_TREE_DIGEST)" \
		--deployment-audience "$(PRODUCTION_DEPLOYMENT_AUDIENCE)" \
		--deployment-identity-sha256 "$(PRODUCTION_DEPLOYMENT_IDENTITY_SHA256)" \
		--release-sequence "$(PRODUCTION_RELEASE_SEQUENCE)" \
		--rollback-epoch "$(PRODUCTION_ROLLBACK_EPOCH)" \
		--production-env "/etc/serverware/production-readiness.env" \
		--python "$(PRODUCTION_RELEASE_PYTHON)" \
		--python-import-root "$(PRODUCTION_RELEASE_ROOT)" \
		--python-import-root "$(PRODUCTION_RELEASE_PYTHON_STDLIB)" \
		--python-import-root "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" \
		--python-import-root "$(PRODUCTION_RELEASE_PYTHON_VENDOR)" \
		--preflight-script "$(PRODUCTION_RELEASE_ROOT)/scripts/production_host_preflight.py" \
		--runner-script "$(PRODUCTION_RELEASE_ROOT)/scripts/run_production_readiness.py" \
		--compose-file "$(PRODUCTION_RELEASE_ROOT)/docker-compose.production.yml" \
		--production-images-build "$(PRODUCTION_RELEASE_ROOT)/evidence/production-images-build.json" \
		--production-images-env "$(PRODUCTION_RELEASE_ROOT)/evidence/production-images.env" \
		--production-images-published "$(PRODUCTION_RELEASE_ROOT)/evidence/production-images-published.json" \
		--release-provenance-summary "$(PRODUCTION_RELEASE_ROOT)/evidence/release-provenance-summary.json" \
		--release-provenance "$(PRODUCTION_RELEASE_ROOT)/evidence/release-provenance.json" \
		--image-signatures-summary "$(PRODUCTION_RELEASE_ROOT)/evidence/image-signatures-summary.json" \
		--image-signatures "$(PRODUCTION_RELEASE_ROOT)/evidence/image-signatures.json" \
		--bench "$(PRODUCTION_RELEASE_ROOT)/evidence/decision-gate-rs-bench.json" \
		--kms-materials "$(PRODUCTION_RELEASE_ROOT)/evidence/kms-materials.json" \
		--policy-bundle "$(PRODUCTION_RELEASE_ROOT)/policy/production-policy-bundle.json" \
		--policy-trusted-public-key "$(PRODUCTION_RELEASE_ROOT)/trust/policy-identity.pub.pem" \
		--policy-identity-verification "$(PRODUCTION_RELEASE_ROOT)/evidence/production-policy-identity.json" \
		--policy-activation-verification "$(PRODUCTION_RELEASE_ROOT)/evidence/policy-activation-verification.json" \
		--policy-activation-signature "$(PRODUCTION_RELEASE_ROOT)/evidence/policy-activation-verification.sig.json" \
		--policy-activation-trusted-public-key "$(PRODUCTION_RELEASE_ROOT)/trust/policy-activation.pub.pem" \
		--reproducible-build-verification "$(PRODUCTION_RELEASE_ROOT)/evidence/reproducible-build-verification.json" \
		--reproducible-build-signature "$(PRODUCTION_RELEASE_ROOT)/evidence/reproducible-build-verification.sig.json" \
		--reproducible-build-trusted-public-key "$(PRODUCTION_RELEASE_ROOT)/trust/reproducible-build.pub.pem" \
		--config-out "$(PRODUCTION_STATE_DIRECTORY)/production-readiness-config.json" \
		--claims-file "$(PRODUCTION_STATE_DIRECTORY)/production-readiness-claims.json" \
		--nitro-evidence-out "$(PRODUCTION_STATE_DIRECTORY)/nitro-kms-evidence.json" \
		--readiness-out "$(PRODUCTION_STATE_DIRECTORY)/production-readiness.json" \
		--completion-proof-out "$(PRODUCTION_STATE_DIRECTORY)/serverware-completion-proof.json" \
		--proxy-proof-summary-out "$(PRODUCTION_STATE_DIRECTORY)/proxy-response-proof-summary.json" \
		--production-host-preflight "$(PRODUCTION_STATE_DIRECTORY)/production-host-preflight.json" \
		--print-sha256
	/usr/bin/systemctl daemon-reload

run-production-readiness-final:
	@test "$$(id -u)" = 0 || { echo "run-production-readiness-final must run as root on the production host" >&2; exit 2; }
	/usr/bin/systemctl start "$(PRODUCTION_SYSTEMD_UNIT_NAME)"
	@test "$$(/usr/bin/systemctl show --property=Result --value "$(PRODUCTION_SYSTEMD_UNIT_NAME)")" = success

production-release-proof:
	$(MAKE) verify-credential-policy-contracts
	$(MAKE) verify-custody-response-proof
	$(MAKE) verify-control-plane-startup
	$(MAKE) verify-control-plane-oidc
	$(MAKE) verify-webauthn-recovery
	$(MAKE) verify-portal-browser-oauth
	$(MAKE) verify-agent-enrollment
	$(MAKE) verify-setup-session-api
	$(MAKE) validate-production-policy-identity
	$(MAKE) verify-production-agent-enrollment-evidence
	$(MAKE) validate-policy-activation-evidence
	$(MAKE) validate-reproducible-builds
	$(MAKE) production-release-input-preflight
	$(MAKE) build-production-images
	$(MAKE) decision-gate-bench-evidence
	$(MAKE) publish-production-images
	$(MAKE) merge-production-images-env
	$(MAKE) build-production-python-runtime
	$(MAKE) build-production-launcher
	$(MAKE) production-release-provenance
	$(MAKE) sign-production-images
	$(MAKE) prepare-aws-kms-materials
	$(MAKE) deploy-production
	$(MAKE) install-production-launcher
	$(MAKE) generate-production-launch-manifest
	$(MAKE) run-production-readiness-final

capture-reproducible-build:
	@if [ -z "$(REPRODUCIBLE_BUILD_BUILDER_ID)" ] || [ -z "$(REPRODUCIBLE_BUILD_SIGNING_KEY)" ]; then echo "REPRODUCIBLE_BUILD_BUILDER_ID and REPRODUCIBLE_BUILD_SIGNING_KEY are required" >&2; exit 2; fi
	python3 scripts/verify_reproducible_builds.py capture \
		--build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--builder-id "$(REPRODUCIBLE_BUILD_BUILDER_ID)" \
		--signing-key "$(REPRODUCIBLE_BUILD_SIGNING_KEY)" \
		--out "$(REPRODUCIBLE_BUILD_CAPTURE_OUT)"

validate-reproducible-builds:
	@if [ -z "$(REPRODUCIBLE_BUILD_LEFT)" ] || [ -z "$(REPRODUCIBLE_BUILD_RIGHT)" ] || [ -z "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT)" ] || [ -z "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT)" ]; then echo "REPRODUCIBLE_BUILD_LEFT/RIGHT and both REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT/RIGHT identity=public-key.pem pins are required" >&2; exit 2; fi
	python3 scripts/verify_reproducible_builds.py verify \
		--left "$(REPRODUCIBLE_BUILD_LEFT)" \
		--right "$(REPRODUCIBLE_BUILD_RIGHT)" \
		--trusted-builder "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_LEFT)" \
		--trusted-builder "$(REPRODUCIBLE_BUILD_TRUSTED_BUILDER_RIGHT)" \
		--out "$(REPRODUCIBLE_BUILD_VERIFICATION_OUT)"

validate-policy-activation-evidence:
	@if [ -z "$(POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY)" ] || [ -z "$(POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY)" ] || [ -z "$(POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR)" ]; then echo "POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY, POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY, and POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR are required" >&2; exit 2; fi
	@mkdir -p "$(dir $(POLICY_ACTIVATION_VERIFICATION_OUT))"
	@tmp="$(POLICY_ACTIVATION_VERIFICATION_OUT).tmp"; \
		python3 scripts/verify_policy_activation_evidence.py \
			--evidence-file "$(POLICY_ACTIVATION_EVIDENCE_FILE)" \
			--trusted-policy-public-key "$(POLICY_ACTIVATION_TRUSTED_POLICY_PUBLIC_KEY)" \
			--trusted-audit-checkpoint-public-key "$(POLICY_ACTIVATION_TRUSTED_AUDIT_CHECKPOINT_PUBLIC_KEY)" \
			--expected-data-plane-actor "$(POLICY_ACTIVATION_EXPECTED_DATA_PLANE_ACTOR)" > "$$tmp" && \
		chmod 600 "$$tmp" && mv "$$tmp" "$(POLICY_ACTIVATION_VERIFICATION_OUT)"

prepare-aws-kms-materials:
	python3 scripts/prepare_aws_kms_materials.py \
		--spec "$(AWS_KMS_MATERIALS_SPEC)" \
		--out "$(AWS_KMS_MATERIALS_OUT)" \
		--allow-overwrite

install-apparmor:
	./scripts/install_apparmor_profile.sh

verify-apparmor-contract:
	SERVERWARE_APPARMOR_DRY_RUN=1 ./scripts/test_apparmor_runtime.sh

verify-apparmor-runtime:
	./scripts/test_apparmor_runtime.sh

verify-cosign-sigstore:
	python3 scripts/test_cosign_sigstore.py

verify-release-image-signing:
	python3 scripts/test_sign_release_images.py

verify-production-image-publish:
	python3 scripts/test_publish_production_images.py

verify-production-images-env-merge:
	python3 scripts/test_merge_production_images_env.py

verify-production-handoff:
	python3 scripts/test_production_handoff.py

verify-production-release-input-preflight:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_production_release_input_preflight.py

verify-production-policy-identity:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_production_policy_identity.py

verify-production-host-preflight:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_production_host_preflight.py

verify-production-python-runtime:
	python3 scripts/test_build_production_images.py

verify-production-launch-assets: verify-production-python-runtime
	python3 -I scripts/test_production_launch_assets.py
	python3 -I scripts/test_production_launcher_adversarial.py
	cargo test --locked --manifest-path data-plane/decision-gate-rs/Cargo.toml --bin serverware-production-launcher

verify-launch-authorization:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_launch_authorization.py
	uvx --with cryptography==48.0.1 python scripts/test_launch_authority_service.py

verify-production-release-proof: verify-production-launch-assets verify-launch-authorization verify-production-image-builds verify-production-release-input-preflight verify-production-host-preflight verify-production-readiness-runner verify-release-completion verify-custody-response-proof
	python3 scripts/test_production_release_proof_target.py

verify-credential-policy-contracts:
	uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python scripts/test_credential_constraints.py
	$(MITMPROXY_TEST_RUN) python scripts/test_credential_constraints.py --proxy-transport-only
	cargo test --locked --manifest-path data-plane/decision-gate-rs/Cargo.toml

verify-control-plane-startup:
	uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python scripts/test_control_plane_startup.py

verify-portal-browser-oauth:
	$(PLAYWRIGHT_RUN) python -m playwright install chromium
	$(PLAYWRIGHT_RUN) python scripts/test_portal_browser_oauth.py

verify-custody-response-proof:
	COMPOSE_PROJECT_NAME="$${COMPOSE_PROJECT_NAME:-serverware-custody-$$(date +%s)-$$$$-$$(openssl rand -hex 6)}" ./scripts/test_custody_response_proof.sh

verify-reproducible-builds:
	python3 scripts/test_reproducible_builds.py

verify-policy-activation-evidence:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_policy_activation_evidence.py

verify-transparency-checkpoint:
	python3 scripts/test_transparency_checkpoint.py

verify-nitro-nsm-attest:
	python3 scripts/test_nitro_nsm_attest.py

verify-aws-kms-recipient-release:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_aws_kms_recipient_release.py

verify-aws-nitro-kms-unseal:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_aws_nitro_kms_unseal.py

verify-prepare-aws-kms-materials:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_prepare_aws_kms_materials.py

verify-ca-install-sessions:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_ca_install_sessions.py

verify-control-plane-csrf:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_csrf.py

verify-control-plane-oidc:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_oidc.py

verify-webauthn-recovery:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_webauthn_recovery.py

verify-oauth-credentials:
	docker compose up -d --build serverware
	python3 scripts/test_http_client.py
	python3 scripts/test_oauth_credentials.py --compose-contract-only
	docker compose exec -T serverware python scripts/test_oauth_credentials.py
	docker compose exec -T serverware python scripts/test_oauth_http_flow.py
	$(MAKE) verify-portal-browser-oauth

verify-credential-lease-delivery:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_credential_lease_delivery.py

verify-control-plane-mutation-mfa:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_mutation_mfa.py

verify-control-plane-two-person:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_two_person.py

verify-control-plane-rbac-audit:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_rbac_audit.py

verify-break-glass-grants:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_break_glass_grants.py

verify-approval-denial-reason:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_approval_denial_reason.py

verify-approval-review:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_approval_review.py
	docker compose exec -T serverware python scripts/test_portal_agent_enrollment_ui.py

verify-policy-publish-workflow:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_policy_publish_workflow.py

verify-policy-canary-workflow:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_policy_canary_workflow.py

verify-audit-search:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_audit_search.py

verify-audit-export:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_audit_export.py

verify-agent-enrollment:
	docker compose up -d --build serverware
	$(TEST_PYTHON_RUN) scripts/test_agent_enrollment.py
	docker compose exec -T serverware python scripts/test_portal_agent_enrollment_ui.py
	docker compose exec -T serverware python scripts/test_setup_verify.py

verify-setup-session-api:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_setup_receipts.py
	docker compose exec -T serverware python scripts/test_setup_receipt_api.py
	docker compose exec -T serverware python scripts/test_setup_session_api.py
	docker compose exec -T serverware python scripts/test_setup_sessions.py

verify-production-images-no-shell:
	python3 scripts/test_production_images_no_shell.py

scan-production-images-no-shell:
	python3 scripts/verify_production_images_no_shell.py

verify-production-image-builds: verify-production-python-runtime
	python3 scripts/test_production_image_builds.py

generate-production-readiness-claims:
	mkdir -p .tmp
	python3 scripts/generate_production_readiness_claims.py --out "$(PRODUCTION_READINESS_CLAIMS_FILE)" $(PRODUCTION_READINESS_CLAIMS_ARGS)

verify-production-readiness-claims:
	python3 scripts/test_production_readiness_claims.py

verify-production-readiness-runner:
	$(TEST_PYTHON_RUN) scripts/test_run_production_readiness.py

verify-release-completion:
	uvx --with jsonschema==4.23.0 --with cryptography==48.0.1 python scripts/test_release_completion.py

verify-production-config:
	python3 scripts/verify_production_readiness.py --mode config

run-production-readiness:
	@if [ "$(PRODUCTION_READINESS_PREFLIGHT)" != "0" ]; then $(MAKE) production-host-preflight; fi
	python3 scripts/run_production_readiness.py \
		--env-file "$(PRODUCTION_READINESS_ENV)" \
		--config-out "$(PRODUCTION_READINESS_CONFIG_OUT)" \
		--claims-file "$(PRODUCTION_READINESS_CLAIMS_FILE)" \
		--nitro-evidence-out "$(NITRO_KMS_EVIDENCE_OUT)" \
		--readiness-out "$(PRODUCTION_READINESS_OUT)" \
		--completion-proof-out "$(PRODUCTION_COMPLETION_PROOF_OUT)" \
		--verification-mode "$(PRODUCTION_COMPLETION_VERIFICATION_MODE)" \
		--production-host-preflight "$(PRODUCTION_HOST_PREFLIGHT_OUT)" \
		--production-images-build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--production-images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--production-images-published "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" \
		--release-provenance-summary "$(RELEASE_PROVENANCE_SUMMARY_FILE)" \
		--release-provenance "$(RELEASE_PROVENANCE_FILE)" \
		--release-provenance-trusted-public-key "$(RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY)" \
		--image-signatures-summary "$(IMAGE_SIGNATURES_SUMMARY_FILE)" \
		--image-signatures "$(IMAGE_SIGNATURES_FILE)" \
		--sigstore-trusted-public-key "$(SIGSTORE_TRUSTED_PUBLIC_KEY)" \
		--rekor-trusted-public-key "$(REKOR_TRUSTED_PUBLIC_KEY)" \
		--external-checkpoint-provider "$(EXTERNAL_CHECKPOINT_PROVIDER)" \
		--external-checkpoint-trusted-public-key "$(EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY)" \
		--bench "$(DECISION_GATE_BENCH_FILE)" \
		--policy-bundle "$(PRODUCTION_POLICY_BUNDLE)" \
		--policy-trusted-public-key "$(PRODUCTION_POLICY_TRUSTED_PUBLIC_KEY)" \
		--policy-identity-verification "$(PRODUCTION_POLICY_IDENTITY_VERIFICATION_OUT)" \
		--policy-activation-verification "$(POLICY_ACTIVATION_VERIFICATION_OUT)" \
		--policy-activation-signature "$(POLICY_ACTIVATION_VERIFICATION_SIGNATURE)" \
		--policy-activation-trusted-public-key "$(POLICY_ACTIVATION_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		--reproducible-build-verification "$(REPRODUCIBLE_BUILD_VERIFICATION_OUT)" \
		--reproducible-build-signature "$(REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE)" \
		--reproducible-build-trusted-public-key "$(REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
		$(PRODUCTION_HARDWARE_ASSURANCE_ARGS) $(PRODUCTION_FINAL_CHALLENGE_ARGS) --kms-materials "$(AWS_KMS_MATERIALS_OUT)"

verify-production-readiness:
	if [ -f "$(PRODUCTION_READINESS_CLAIMS_FILE)" ]; then \
		python3 scripts/verify_production_readiness.py --mode live --claims-file "$(PRODUCTION_READINESS_CLAIMS_FILE)" --out "$(PRODUCTION_READINESS_OUT)"; \
	else \
		python3 scripts/verify_production_readiness.py --mode live --out "$(PRODUCTION_READINESS_OUT)"; \
	fi

collect-nitro-kms-evidence:
	mkdir -p .tmp
	if [ -f "$(PRODUCTION_READINESS_CLAIMS_FILE)" ]; then \
		python3 scripts/collect_nitro_kms_evidence.py --claims-file "$(PRODUCTION_READINESS_CLAIMS_FILE)" --out "$(NITRO_KMS_EVIDENCE_OUT)"; \
	else \
		python3 scripts/collect_nitro_kms_evidence.py --out "$(NITRO_KMS_EVIDENCE_OUT)"; \
	fi

verify-nitro-kms-evidence:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_nitro_kms_evidence.py

verify-nitro-tee:
	docker compose up -d --build serverware
	./scripts/wait_for_serverware.sh
	docker compose exec -T serverware python scripts/test_nitro_tee_provider.py

verify-decision-gate-attestation:
	python3 scripts/verify_decision_gate_attestation.py

verify-codebase-attestation:
	SERVERWARE_COSIGN_BINARY="$${SERVERWARE_COSIGN_BINARY:-python3 scripts/cosign_fixture.py}" \
	python3 scripts/verify_codebase_attestation.py \
		--admin-token "$${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" \
		--release-signing-trusted-key "$${SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY:-.tmp/release-signing-ed25519.pem}" \
		--image-signing-trusted-key "$${SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY:-.tmp/cosign-fixture-ed25519.pem}"

install-ca:
	docker compose up -d --build serverware demo-upstream
	./scripts/wait_for_serverware.sh
	curl -fsS -H "X-Serverware-Admin-Token: $${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" -X POST http://localhost:3000/api/demo/seed >/dev/null
	SERVERWARE_CA_OUT=.tmp/serverware-ca.pem SERVERWARE_VERIFY_OUT=.tmp/attestation-verify.json ./scripts/install_verified_ca.sh
	docker compose up -d --force-recreate decision-gate-rs
	./scripts/wait_for_decision_gate.sh

verify-attestation: install-ca

reset:
	docker compose down -v
	rm -rf .tmp
