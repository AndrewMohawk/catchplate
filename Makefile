.PHONY: up down logs e2e bench bench-gate-rs release-provenance image-signatures install-apparmor verify-apparmor-contract verify-apparmor-runtime verify-cosign-sigstore verify-transparency-checkpoint verify-production-config verify-production-readiness verify-nitro-tee verify-decision-gate-attestation verify-codebase-attestation install-ca verify-attestation reset

up:
	docker compose up -d --build serverware demo-upstream audit-anchor

down:
	docker compose down

logs:
	docker compose logs -f serverware demo-upstream audit-anchor

e2e:
	docker compose up -d --build serverware demo-upstream
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
		python3 scripts/test_transparency_checkpoint.py
		python3 scripts/test_production_readiness.py
		./scripts/test_audit_anchor.sh
	python3 scripts/bench_decision_gate.py --self-test > .tmp/decision-gate-rs-bench.json
	cat .tmp/decision-gate-rs-bench.json
	./scripts/generate_release_provenance.py > .tmp/release-provenance-summary.json
	cat .tmp/release-provenance-summary.json
	SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command \
	SERVERWARE_IMAGE_SIGN_COMMAND="python3 scripts/cosign_sigstore.py sign" \
	SERVERWARE_IMAGE_VERIFY_COMMAND="python3 scripts/cosign_sigstore.py verify" \
	SERVERWARE_COSIGN_BINARY="python3 scripts/cosign_fixture.py" \
	SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1 \
	python3 scripts/sign_release_images.py > .tmp/image-signatures-summary.json
	cat .tmp/image-signatures-summary.json

release-provenance:
	./scripts/generate_release_provenance.py
	SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command \
	SERVERWARE_IMAGE_SIGN_COMMAND="python3 scripts/cosign_sigstore.py sign" \
	SERVERWARE_IMAGE_VERIFY_COMMAND="python3 scripts/cosign_sigstore.py verify" \
	SERVERWARE_COSIGN_BINARY="python3 scripts/cosign_fixture.py" \
	SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1 \
	python3 scripts/sign_release_images.py

image-signatures:
	SERVERWARE_IMAGE_SIGNATURE_PROVIDER=sigstore-command \
	SERVERWARE_IMAGE_SIGN_COMMAND="python3 scripts/cosign_sigstore.py sign" \
	SERVERWARE_IMAGE_VERIFY_COMMAND="python3 scripts/cosign_sigstore.py verify" \
	SERVERWARE_COSIGN_BINARY="python3 scripts/cosign_fixture.py" \
	SERVERWARE_REQUIRE_SIGSTORE_TRANSPARENCY=1 \
	python3 scripts/sign_release_images.py

install-apparmor:
	./scripts/install_apparmor_profile.sh

verify-apparmor-contract:
	SERVERWARE_APPARMOR_DRY_RUN=1 ./scripts/test_apparmor_runtime.sh

verify-apparmor-runtime:
	./scripts/test_apparmor_runtime.sh

verify-cosign-sigstore:
	python3 scripts/test_cosign_sigstore.py

verify-transparency-checkpoint:
	python3 scripts/test_transparency_checkpoint.py

verify-production-config:
	python3 scripts/verify_production_readiness.py --mode config

verify-production-readiness:
	python3 scripts/verify_production_readiness.py --mode live

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

verify-attestation: install-ca

reset:
	docker compose down -v
	rm -rf .tmp
