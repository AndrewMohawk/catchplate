.PHONY: up down logs e2e bench bench-gate-rs decision-gate-bench-evidence release-provenance image-signatures sign-production-images build-production-images publish-production-images merge-production-images-env production-handoff production-host-preflight production-release-proof prepare-aws-kms-materials install-apparmor verify-apparmor-contract verify-apparmor-runtime verify-cosign-sigstore verify-release-image-signing verify-production-image-publish verify-production-images-env-merge verify-production-handoff verify-production-host-preflight verify-production-release-proof verify-transparency-checkpoint verify-nitro-nsm-attest verify-aws-kms-recipient-release verify-prepare-aws-kms-materials verify-ca-install-sessions verify-control-plane-csrf verify-control-plane-oidc verify-oauth-credentials verify-control-plane-mutation-mfa verify-control-plane-two-person verify-control-plane-rbac-audit verify-break-glass-grants verify-approval-denial-reason verify-approval-review verify-policy-publish-workflow verify-policy-canary-workflow verify-audit-search verify-audit-export verify-agent-enrollment verify-production-images-no-shell scan-production-images-no-shell verify-production-image-builds generate-production-readiness-claims verify-production-readiness-claims verify-production-readiness-runner verify-release-completion verify-production-config verify-production-readiness run-production-readiness collect-nitro-kms-evidence verify-nitro-kms-evidence verify-nitro-tee verify-decision-gate-attestation verify-codebase-attestation install-ca verify-attestation reset

PRODUCTION_READINESS_CLAIMS_FILE ?= .tmp/production-readiness-claims.json
PRODUCTION_READINESS_CLAIMS_ARGS ?=
PRODUCTION_READINESS_OUT ?= .tmp/production-readiness.json
PRODUCTION_READINESS_CONFIG_OUT ?= .tmp/production-readiness-config.json
PRODUCTION_READINESS_ENV ?= ops/production-readiness.env
PRODUCTION_READINESS_PREFLIGHT ?= 1
PRODUCTION_COMPLETION_PROOF_OUT ?= .tmp/serverware-completion-proof.json
NITRO_KMS_EVIDENCE_OUT ?= .tmp/nitro-kms-evidence.json
PRODUCTION_IMAGES_BUILD_FILE ?= .tmp/production-images-build.json
PRODUCTION_IMAGES_PUBLISHED_FILE ?= .tmp/production-images-published.json
PRODUCTION_IMAGES_ENV_OUT ?= .tmp/production-images.env
PRODUCTION_HANDOFF_OUT ?= .tmp/production-handoff.json
PRODUCTION_HOST_PREFLIGHT_OUT ?= .tmp/production-host-preflight.json
PRODUCTION_IMAGE_REGISTRY_PREFIX ?=
PRODUCTION_IMAGE_TAG ?= production-candidate
AWS_KMS_MATERIALS_SPEC ?= ops/aws-kms-materials.spec.json
AWS_KMS_MATERIALS_OUT ?= /etc/serverware/kms-materials.json
RELEASE_PROVENANCE_SUMMARY_FILE ?= .tmp/release-provenance-summary.json
RELEASE_PROVENANCE_FILE ?= .tmp/release-provenance.json
IMAGE_SIGNATURES_SUMMARY_FILE ?= .tmp/image-signatures-summary.json
IMAGE_SIGNATURES_FILE ?= .tmp/image-signatures.json
DECISION_GATE_BENCH_FILE ?= .tmp/decision-gate-rs-bench.json

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
	docker compose exec -T serverware python scripts/test_webauthn_attestation.py
	python3 scripts/verify_decision_gate_attestation.py
	./scripts/test_key_release_gate.py
	docker compose exec -T -e SERVERWARE_TEE_QUOTE_PROVIDER=external-command -e SERVERWARE_TEE_PLATFORM=fixture-tee -e "SERVERWARE_TEE_QUOTE_COMMAND=python scripts/external_tee_provider.py quote" -e "SERVERWARE_TEE_QUOTE_VERIFY_COMMAND=python scripts/external_tee_provider.py verify" -e "SERVERWARE_KEY_RELEASE_COMMAND=python scripts/external_tee_provider.py release" serverware python scripts/test_external_tee_provider.py
	docker compose exec -T serverware python scripts/test_nitro_tee_provider.py
		./scripts/test_decision_gate_approval_publish.sh
		./scripts/test_decision_gate_audit.sh
		./scripts/test_control_plane_audit_store.sh
		./scripts/test_control_plane_metadata_store.sh
		docker compose exec -T serverware python scripts/test_ca_install_sessions.py
		docker compose exec -T serverware python scripts/test_control_plane_csrf.py
		docker compose exec -T serverware python scripts/test_control_plane_oidc.py
		docker compose exec -T serverware python scripts/test_oauth_credentials.py
		docker compose exec -T serverware python scripts/test_control_plane_mutation_mfa.py
		docker compose exec -T serverware python scripts/test_control_plane_two_person.py
		docker compose exec -T serverware python scripts/test_control_plane_rbac_audit.py
		docker compose exec -T serverware python scripts/test_break_glass_grants.py
		docker compose exec -T serverware python scripts/test_approval_denial_reason.py
		docker compose exec -T serverware python scripts/test_approval_review.py
		docker compose exec -T serverware python scripts/test_policy_publish_workflow.py
		docker compose exec -T serverware python scripts/test_policy_canary_workflow.py
		docker compose exec -T serverware python scripts/test_audit_search.py
		docker compose exec -T serverware python scripts/test_audit_export.py
		python3 scripts/test_agent_enrollment.py
		python3 scripts/test_transparency_checkpoint.py
		python3 scripts/test_nitro_nsm_attest.py
		python3 scripts/test_aws_kms_recipient_release.py
		python3 scripts/test_prepare_aws_kms_materials.py
		python3 scripts/test_production_readiness_claims.py
		python3 scripts/test_production_readiness.py
		./scripts/test_audit_anchor.sh
	python3 scripts/bench_decision_gate.py --self-test > .tmp/decision-gate-rs-bench.json
	cat .tmp/decision-gate-rs-bench.json
	./scripts/test_decision_gate_shared_rate_limits.sh
	./scripts/generate_release_provenance.py > .tmp/release-provenance-summary.json
	cat .tmp/release-provenance-summary.json
	SERVERWARE_IMAGE_SIGNATURE_PROVIDER="$${SERVERWARE_IMAGE_SIGNATURE_PROVIDER:-sigstore-command}" \
	SERVERWARE_IMAGE_SIGN_COMMAND="$${SERVERWARE_IMAGE_SIGN_COMMAND:-python3 scripts/cosign_sigstore.py sign}" \
	SERVERWARE_IMAGE_VERIFY_COMMAND="$${SERVERWARE_IMAGE_VERIFY_COMMAND:-python3 scripts/cosign_sigstore.py verify}" \
	SERVERWARE_COSIGN_BINARY="$${SERVERWARE_COSIGN_BINARY:-python3 scripts/cosign_fixture.py}" \
	SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY="$${SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY:-1}" \
	python3 scripts/sign_release_images.py > .tmp/image-signatures-summary.json
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
	python3 scripts/bench_decision_gate.py --self-test > "$(DECISION_GATE_BENCH_FILE)"
	cat "$(DECISION_GATE_BENCH_FILE)"

release-provenance:
	./scripts/generate_release_provenance.py \
		--out "$(RELEASE_PROVENANCE_FILE)" > "$(RELEASE_PROVENANCE_SUMMARY_FILE)"
	cat "$(RELEASE_PROVENANCE_SUMMARY_FILE)"

image-signatures:
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

build-production-images:
	python3 scripts/build_production_images.py --out "$(PRODUCTION_IMAGES_BUILD_FILE)"

publish-production-images:
	@if [ -z "$(PRODUCTION_IMAGE_REGISTRY_PREFIX)" ]; then echo "PRODUCTION_IMAGE_REGISTRY_PREFIX is required, for example registry.prod.serverware.dev/serverware" >&2; exit 2; fi
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
		--kms-materials "$(AWS_KMS_MATERIALS_OUT)" \
		--out "$(PRODUCTION_HOST_PREFLIGHT_OUT)"

production-release-proof:
	$(MAKE) build-production-images
	$(MAKE) decision-gate-bench-evidence
	$(MAKE) release-provenance
	$(MAKE) publish-production-images
	$(MAKE) sign-production-images
	$(MAKE) merge-production-images-env
	$(MAKE) prepare-aws-kms-materials
	$(MAKE) run-production-readiness

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

verify-production-host-preflight:
	python3 scripts/test_production_host_preflight.py

verify-production-release-proof:
	python3 scripts/test_production_release_proof_target.py

verify-transparency-checkpoint:
	python3 scripts/test_transparency_checkpoint.py

verify-nitro-nsm-attest:
	python3 scripts/test_nitro_nsm_attest.py

verify-aws-kms-recipient-release:
	python3 scripts/test_aws_kms_recipient_release.py

verify-prepare-aws-kms-materials:
	python3 scripts/test_prepare_aws_kms_materials.py

verify-ca-install-sessions:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_ca_install_sessions.py

verify-control-plane-csrf:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_csrf.py

verify-control-plane-oidc:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_control_plane_oidc.py

verify-oauth-credentials:
	docker compose up -d --build serverware
	docker compose exec -T serverware python scripts/test_oauth_credentials.py

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
	python3 scripts/test_agent_enrollment.py

verify-production-images-no-shell:
	python3 scripts/test_production_images_no_shell.py

scan-production-images-no-shell:
	python3 scripts/verify_production_images_no_shell.py

verify-production-image-builds:
	python3 scripts/test_production_image_builds.py

generate-production-readiness-claims:
	mkdir -p .tmp
	python3 scripts/generate_production_readiness_claims.py --out "$(PRODUCTION_READINESS_CLAIMS_FILE)" $(PRODUCTION_READINESS_CLAIMS_ARGS)

verify-production-readiness-claims:
	python3 scripts/test_production_readiness_claims.py

verify-production-readiness-runner:
	python3 scripts/test_run_production_readiness.py

verify-release-completion:
	python3 scripts/test_release_completion.py

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
		--production-host-preflight "$(PRODUCTION_HOST_PREFLIGHT_OUT)" \
		--production-images-build "$(PRODUCTION_IMAGES_BUILD_FILE)" \
		--production-images-env "$(PRODUCTION_IMAGES_ENV_OUT)" \
		--production-images-published "$(PRODUCTION_IMAGES_PUBLISHED_FILE)" \
		--release-provenance-summary "$(RELEASE_PROVENANCE_SUMMARY_FILE)" \
		--release-provenance "$(RELEASE_PROVENANCE_FILE)" \
		--image-signatures-summary "$(IMAGE_SIGNATURES_SUMMARY_FILE)" \
		--image-signatures "$(IMAGE_SIGNATURES_FILE)" \
		--bench "$(DECISION_GATE_BENCH_FILE)" \
		--kms-materials "$(AWS_KMS_MATERIALS_OUT)"

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
	python3 scripts/verify_codebase_attestation.py --admin-token "$${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}"

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
