ifneq ($(filter command line environment environment override,$(origin SHELL)),)
$(error Coder Makefile rejects externally supplied SHELL)
endif
ifneq ($(filter command line environment environment override,$(origin .SHELLFLAGS)),)
$(error Coder Makefile rejects externally supplied .SHELLFLAGS)
endif
ifneq ($(filter command line override,$(origin SERVERWARE_CONTROLLER_ARTIFACT_ROOT)),)
$(error Coder Makefile rejects command-line SERVERWARE_CONTROLLER_ARTIFACT_ROOT)
endif
ifneq ($(filter command line override,$(origin SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)),)
$(error Coder Makefile rejects command-line SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)
endif
SHELL := /bin/sh
.SHELLFLAGS := -eu -c

.PHONY: up down logs e2e bench bench-gate-rs decision-gate-bench-evidence release-provenance production-release-provenance image-signatures sign-production-images build-agent-enrollment-wheel build-portal-browser-artifacts build-consolidated-test-artifacts verify-consolidated-no-build verify-consolidated verify-agent-trust-same-journey verify-agent-enrollment-wheel-clean-room verify-portal-browser-oauth verify-portal-browser-oauth-no-build fetch-production-dependency-cache verify-production-dependency-cache build-production-images publish-production-images merge-production-images-env production-handoff production-release-input-preflight validate-production-policy-identity verify-production-agent-enrollment-evidence production-host-preflight deploy-production build-production-python-runtime build-production-launcher install-production-launcher generate-production-launch-manifest run-production-readiness-final prepare-production-final-v1 finalize-production-final-v1 _production-final-v1-input-preflight production-release-proof capture-reproducible-build validate-reproducible-builds validate-policy-activation-evidence prepare-aws-kms-materials install-apparmor verify-apparmor-contract verify-apparmor-runtime verify-cosign-sigstore verify-release-image-signing verify-production-image-publish verify-production-images-env-merge verify-production-handoff verify-production-release-input-preflight verify-production-policy-identity verify-production-host-preflight verify-production-python-runtime verify-production-launch-assets verify-launch-authorization verify-production-release-proof verify-credential-policy-contracts verify-control-plane-startup verify-onboarding-evidence-tooling verify-custody-response-proof verify-reproducible-builds verify-policy-activation-evidence verify-transparency-checkpoint verify-nitro-nsm-attest verify-aws-kms-recipient-release verify-aws-nitro-kms-unseal verify-prepare-aws-kms-materials verify-ca-install-sessions verify-control-plane-csrf verify-control-plane-oidc verify-webauthn-recovery verify-oauth-credentials verify-credential-lease-delivery verify-control-plane-mutation-mfa verify-control-plane-two-person verify-control-plane-rbac-audit verify-break-glass-grants verify-approval-denial-reason verify-approval-review verify-policy-publish-workflow verify-policy-canary-workflow verify-audit-search verify-audit-export verify-agent-enrollment verify-setup-session-api verify-production-images-no-shell scan-production-images-no-shell verify-production-image-builds generate-production-readiness-claims verify-production-readiness-claims verify-production-readiness-runner verify-release-completion verify-production-config verify-production-readiness run-production-readiness collect-nitro-kms-evidence verify-nitro-kms-evidence verify-nitro-tee verify-decision-gate-attestation verify-codebase-attestation install-ca verify-attestation reset

.PHONY: _build-consolidated-test-artifacts-locked _verify-consolidated-source-snapshot-locked

.PHONY: coder-build-all coder-test-no-build coder-ci _coder-build-all-locked _coder-test-no-build-locked _coder-ci-locked _coder-require-clean _coder-require-lock _coder-require-disposable-daemon _coder-cleanup

.PHONY: coder-trusted-build coder-trusted-unit-no-build coder-trusted-integration-no-build coder-trusted-e2e-no-build coder-trusted-attestation-no-build coder-trusted-sequential coder-controller-static-assets coder-controller-build-execute coder-controller-unit-execute coder-controller-integration-execute coder-controller-e2e-execute coder-controller-attestation-execute
.PHONY: coder-v12-sequential coder-v12-build coder-v12-unit-no-build coder-v12-integration-no-build coder-v12-e2e-no-build coder-v12-attestation-no-build
.PHONY: coder-controller-v12-build-phase coder-controller-v12-unit-phase coder-controller-v12-integration-phase coder-controller-v12-e2e-phase coder-controller-v12-attestation-phase
.PHONY: coder-controller-v12-package-prepare coder-controller-v12-provision coder-controller-v12-install coder-controller-v12-provision-local-trusted-host coder-controller-v12-provision-external-production
.PHONY: render-policy-custody-assets verify-policy-custody-host-ready
.PHONY: verify-production-proxy-ingress-materials
.PHONY: verify-provider-policy-parity verify-webauthn-trust-projection verify-authority-row-mutations
.PHONY: verify-authority-verifier-read verify-authority-planner-writer
.PHONY: production-source-capture production-release-build production-release-publish production-release-sign production-release-deploy
.NOTPARALLEL: production-release-build production-release-publish production-release-sign production-release-deploy production-release-proof

.NOTPARALLEL: build-consolidated-test-artifacts verify-consolidated-no-build verify-consolidated _build-consolidated-test-artifacts-locked _verify-consolidated-source-snapshot-locked coder-build-all coder-test-no-build coder-ci _coder-build-all-locked _coder-test-no-build-locked _coder-ci-locked _coder-require-clean _coder-require-lock _coder-require-disposable-daemon _coder-cleanup coder-trusted-sequential coder-v12-sequential coder-v12-build coder-v12-unit-no-build coder-v12-integration-no-build coder-v12-e2e-no-build coder-v12-attestation-no-build coder-controller-v12-build-phase coder-controller-v12-unit-phase coder-controller-v12-integration-phase coder-controller-v12-e2e-phase coder-controller-v12-attestation-phase coder-controller-v12-package-prepare coder-controller-v12-provision coder-controller-v12-install coder-controller-v12-provision-local-trusted-host coder-controller-v12-provision-external-production

# CONTROLLER V12 LOGICAL-LANE SUBMISSION.
#
# These targets submit fixed identifiers only. They never run Docker, Compose,
# repository build/test bodies, or browsers. The root-owned v12 controller
# validates the signed request-v12 envelope, enforces workflow ordering, and
# delegates each phase to the separately privileged plan executor. The plan
# root lifecycle helper owns private per-lane DinD, netns, nftables, mounts,
# cgroups, and ownership ledgers. Unprivileged services receive only
# capability-scoped proxy/listener FDs. Build performs exact signed operations;
# no-build lanes import exact build outputs into fresh private daemons.

override CODER_V12_CLIENT := /opt/serverware/coder-controller-v12/current/bin/serverware-coder-controller-client-v12
override CODER_V12_PHASE_DRIVER := /opt/serverware/coder-controller-v12/current/bin/serverware-coder-plan-executor-v12
override CODER_V12_WORKFLOW := serverware-coder-five-lane-v12
override CODER_V12_DEADLINE_PROFILE := serverware-coder-five-lane-v12
override CODER_CONTROLLER_V12_INSTALLER := scripts/install_coder_controller_v12.sh
CODER_CONTROLLER_V12_SIGNED_BUNDLE_ROOT ?=
CODER_CONTROLLER_V12_PINNED_RELEASE_SIGNER_PUBLIC_KEY ?=
CODER_CONTROLLER_V12_BUNDLE_MANIFEST_SHA256 ?=
CODER_CONTROLLER_V12_RELEASE_ID ?=
CODER_CONTROLLER_V12_CLIENT_GROUP ?=
CODER_CONTROLLER_V12_DEPLOYMENT_PROFILE ?= local-trusted-host
CODER_CONTROLLER_V12_EXTERNAL_WITNESS_SOCKET ?= /run/serverware/coder/v12/external-witness/control.sock
CODER_CONTROLLER_V12_PRIVATE_DIND_OUTPUT_ROOT ?=
CODER_CONTROLLER_V12_DOCKERD ?=
CODER_CONTROLLER_V12_CONTAINERD ?=
CODER_CONTROLLER_V12_CONTAINERD_SHIM_RUNC_V2 ?=
CODER_CONTROLLER_V12_RUNC ?=
CODER_CONTROLLER_V12_PINNED_PULL_SET ?=
CODER_CONTROLLER_V12_EXACT_BUILD_TUPLE_SET ?=
CODER_V12_BUILD_DEADLINE_MS ?= 7200000
CODER_V12_UNIT_DEADLINE_MS ?= 900000
CODER_V12_INTEGRATION_DEADLINE_MS ?= 1800000
CODER_V12_E2E_DEADLINE_MS ?= 2700000
CODER_V12_ATTESTATION_DEADLINE_MS ?= 900000

# Packaging is intentionally evidence-neutral. The signed bundle producer must
# supply every binary, unit, credential, authorization, genesis/checkpoint,
# witness, Docker schema, OCI archive, digest, and template listed by the
# installer. These targets do not synthesize HSM, TPM, TEE, YubiKey, fs-verity,
# measured-boot, or external-authority evidence.
coder-controller-v12-package-prepare:
	@test -n "$(CODER_CONTROLLER_V12_PRIVATE_DIND_OUTPUT_ROOT)"
	@test -n "$(CODER_CONTROLLER_V12_DOCKERD)"
	@test -n "$(CODER_CONTROLLER_V12_CONTAINERD)"
	@test -n "$(CODER_CONTROLLER_V12_CONTAINERD_SHIM_RUNC_V2)"
	@test -n "$(CODER_CONTROLLER_V12_RUNC)"
	@test -n "$(CODER_CONTROLLER_V12_PINNED_PULL_SET)"
	@test -n "$(CODER_CONTROLLER_V12_EXACT_BUILD_TUPLE_SET)"
	@exec /bin/sh ops/coder-controller-v12/prepare-private-dind-assets-v12.sh \
		"$(CODER_CONTROLLER_V12_PRIVATE_DIND_OUTPUT_ROOT)" \
		"$(CODER_CONTROLLER_V12_DOCKERD)" \
		"$(CODER_CONTROLLER_V12_CONTAINERD)" \
		"$(CODER_CONTROLLER_V12_CONTAINERD_SHIM_RUNC_V2)" \
		"$(CODER_CONTROLLER_V12_RUNC)" \
		"$(CODER_CONTROLLER_V12_PINNED_PULL_SET)" \
		"$(CODER_CONTROLLER_V12_EXACT_BUILD_TUPLE_SET)"

coder-controller-v12-provision:
	@test -n "$(CODER_CONTROLLER_V12_SIGNED_BUNDLE_ROOT)"
	@test -n "$(CODER_CONTROLLER_V12_PINNED_RELEASE_SIGNER_PUBLIC_KEY)"
	@test -n "$(CODER_CONTROLLER_V12_BUNDLE_MANIFEST_SHA256)"
	@test -n "$(CODER_CONTROLLER_V12_RELEASE_ID)"
	@test -n "$(CODER_CONTROLLER_V12_CLIENT_GROUP)"
	@test -n "$(CODER_CONTROLLER_V12_EXTERNAL_WITNESS_SOCKET)"
	@exec "$(CODER_CONTROLLER_V12_INSTALLER)" \
		"$(CODER_CONTROLLER_V12_SIGNED_BUNDLE_ROOT)" \
		"$(CODER_CONTROLLER_V12_PINNED_RELEASE_SIGNER_PUBLIC_KEY)" \
		"$(CODER_CONTROLLER_V12_BUNDLE_MANIFEST_SHA256)" \
		"$(CODER_CONTROLLER_V12_RELEASE_ID)" \
		"$(CODER_CONTROLLER_V12_CLIENT_GROUP)" \
		"$(CODER_CONTROLLER_V12_DEPLOYMENT_PROFILE)" \
		"$(CODER_CONTROLLER_V12_EXTERNAL_WITNESS_SOCKET)"

coder-controller-v12-install: coder-controller-v12-provision

coder-controller-v12-provision-local-trusted-host:
	@exec $(MAKE) --no-print-directory coder-controller-v12-provision \
		CODER_CONTROLLER_V12_DEPLOYMENT_PROFILE=local-trusted-host

coder-controller-v12-provision-external-production:
	@printf '%s\n' \
		'external-production is prerequisite-only and intentionally fail-closed.' \
		'Provide external trust-generation, final-settlement, witness/checkpoint, HSM/TPM/TEE/YubiKey, and verified-boot adapters before enabling this target.' >&2
	@exit 2

coder-v12-sequential:
	@exec "$(CODER_V12_CLIENT)" submit-workflow-v12 \
		--workflow="$(CODER_V12_WORKFLOW)" \
		--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

coder-v12-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_V12_BUILD_DEADLINE_MS)' \
		exec "$(CODER_V12_CLIENT)" submit-fixed-v12 \
			--workflow="$(CODER_V12_WORKFLOW)" --lane=build \
			--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

coder-v12-unit-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_V12_UNIT_DEADLINE_MS)' \
		exec "$(CODER_V12_CLIENT)" submit-fixed-v12 \
			--workflow="$(CODER_V12_WORKFLOW)" --lane=unit \
			--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

coder-v12-integration-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_V12_INTEGRATION_DEADLINE_MS)' \
		exec "$(CODER_V12_CLIENT)" submit-fixed-v12 \
			--workflow="$(CODER_V12_WORKFLOW)" --lane=integration \
			--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

coder-v12-e2e-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_V12_E2E_DEADLINE_MS)' \
		exec "$(CODER_V12_CLIENT)" submit-fixed-v12 \
			--workflow="$(CODER_V12_WORKFLOW)" --lane=e2e \
			--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

coder-v12-attestation-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_V12_ATTESTATION_DEADLINE_MS)' \
		exec "$(CODER_V12_CLIENT)" submit-fixed-v12 \
			--workflow="$(CODER_V12_WORKFLOW)" --lane=attestation \
			--deadline-profile="$(CODER_V12_DEADLINE_PROFILE)"

# Fixed logical phase shims. Internal prepare/body transitions are executor
# details and are not caller-selectable. Each shim accepts one controller-owned
# SOCK_SEQPACKET capability FD and one of the exact five phase identities.

define _CODER_V12_RUN_PHASE
	@set -eu; \
		capability_fd="$${SERVERWARE_CODER_V12_PHASE_CAPABILITY_FD:-}"; \
		case "$$capability_fd" in ""|*[!0-9]*) \
			echo "controller-v12 phase capability FD is required" >&2; exit 2 ;; \
		esac; \
		test "$$capability_fd" -gt 2; \
		test -r "/proc/self/fd/$$capability_fd"; \
		config=/opt/serverware/coder-controller-v12/current/config/plan-executor-v12.conf; \
		config_sha256="$$(sha256sum "$$config" | awk '{print $$1}')"; \
		SERVERWARE_CODER_PLAN_EXECUTOR_CONFIG_SHA256="$$config_sha256" \
		exec "$(CODER_V12_PHASE_DRIVER)" --config "$$config" \
			run-fixed-phase-v12 \
			--capability-fd="$$capability_fd" \
			--logical-phase="$(1)"
endef

coder-controller-v12-build-phase:
	$(call _CODER_V12_RUN_PHASE,BUILD)

coder-controller-v12-unit-phase:
	$(call _CODER_V12_RUN_PHASE,UNIT)

coder-controller-v12-integration-phase:
	$(call _CODER_V12_RUN_PHASE,INTEGRATION)

coder-controller-v12-e2e-phase:
	$(call _CODER_V12_RUN_PHASE,E2E)

coder-controller-v12-attestation-phase:
	$(call _CODER_V12_RUN_PHASE,ATTESTATION)

# UNTRUSTED CONTROLLER SUBMISSION SHIMS.
#
# These five targets are convenience surfaces only. Like every other target in
# this repository Makefile, they are outside the root-owned controller trust
# boundary. Make and its recipe shell receive no request bytes, request or
# capability descriptor, token, key, source descriptor, worker descriptor, or
# trusted evidence. The controller never invokes or trusts any Make target.
#
# The fixed client authenticates to a peer-credential-checked root-owned
# SOCK_SEQPACKET service and submits only a sealed, digest-bound fixed operation
# and plan frame. The daemon returns the cryptographically signed receipt.

CODER_TRUSTED_BUILD_DEADLINE_MS ?= 7200000
CODER_TRUSTED_UNIT_DEADLINE_MS ?= 900000
CODER_TRUSTED_INTEGRATION_DEADLINE_MS ?= 1800000
CODER_TRUSTED_E2E_DEADLINE_MS ?= 2700000
CODER_TRUSTED_ATTESTATION_DEADLINE_MS ?= 900000

coder-trusted-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_BUILD_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=build --plan=serverware-build-v1

coder-trusted-unit-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_UNIT_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-unit-no-build-v1

coder-trusted-integration-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_INTEGRATION_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-integration-no-build-v1

coder-trusted-e2e-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_E2E_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-e2e-no-build-v1

coder-trusted-attestation-no-build:
	@SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_ATTESTATION_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-attestation-no-build-v1

coder-trusted-sequential:
	@set -eu; \
	SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_BUILD_DEADLINE_MS)' /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=build --plan=serverware-build-v1; \
	SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_UNIT_DEADLINE_MS)' /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-unit-no-build-v1; \
	SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_INTEGRATION_DEADLINE_MS)' /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-integration-no-build-v1; \
	SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_E2E_DEADLINE_MS)' /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-e2e-no-build-v1; \
	SERVERWARE_CONTROLLER_DEADLINE_MS='$(CODER_TRUSTED_ATTESTATION_DEADLINE_MS)' exec /usr/local/libexec/serverware-coder-controller-client submit-fixed-v11 --operation=runNoBuild --plan=serverware-attestation-no-build-v1

coder-controller-build-execute:
	@exec $(MAKE) --no-print-directory coder-build-all

coder-controller-unit-execute coder-controller-integration-execute coder-controller-e2e-execute coder-controller-attestation-execute:
	@set -eu; \
		case "$@" in \
			coder-controller-unit-execute) stage=unit ;; \
			coder-controller-integration-execute) stage=integration ;; \
			coder-controller-e2e-execute) stage=e2e ;; \
			coder-controller-attestation-execute) stage=attestation ;; \
			*) exit 2 ;; \
		esac; \
		lock_dir="$(CODER_LOCK_DIRECTORY)"; \
		test -d "$$lock_dir" && test ! -L "$$lock_dir"; \
		test "$$(stat -Lc '%u:%F' "$$lock_dir")" = "0:directory"; \
		exec 9<"$$lock_dir"; \
		flock --exclusive --nonblock 9; \
		exec env \
			CODER_LOCK_FD=9 \
			CODER_LOCK_PATH="$$lock_dir" \
			CODER_CONTROLLER_STAGE="$$stage" \
			$(MAKE) --no-print-directory _coder-test-no-build-locked

PRODUCTION_READINESS_CLAIMS_FILE ?= .tmp/production-readiness-claims.json
override PRODUCTION_PLATFORM := linux/amd64
CONSOLIDATED_OUTPUT_ROOT ?= $(abspath .tmp/consolidated-oci-v6)
CONSOLIDATED_SOURCE_SNAPSHOT ?= $(CONSOLIDATED_OUTPUT_ROOT)/source
CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST ?= $(CONSOLIDATED_OUTPUT_ROOT)/source-snapshot.json
CONSOLIDATED_SOURCE_INPUT_MANIFEST ?=
CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256 ?=
CONSOLIDATED_SOURCE_GIT_INVENTORY_PUBLIC_KEY ?=
CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_SPKI_SHA256 ?=
CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_RAW_SHA256 ?=
CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_PUBLIC_KEY ?=
CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_SPKI_SHA256 ?=
CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_RAW_SHA256 ?=
CONSOLIDATED_SOURCE_EVIDENCE_ARGS = \
	--source-git-inventory-public-key "$(CONSOLIDATED_SOURCE_GIT_INVENTORY_PUBLIC_KEY)" \
	--expected-source-git-inventory-key-spki-sha256 "$(CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_SPKI_SHA256)" \
	--expected-source-git-inventory-key-raw-sha256 "$(CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_RAW_SHA256)" \
	--source-untracked-approval-public-key "$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_PUBLIC_KEY)" \
	--expected-source-untracked-approval-key-spki-sha256 "$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_SPKI_SHA256)" \
	--expected-source-untracked-approval-key-raw-sha256 "$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_RAW_SHA256)"
CONSOLIDATED_FROZEN_VERIFIER ?= $(CONSOLIDATED_SOURCE_SNAPSHOT)/scripts/verify_agent_trust_same_journey.py
CONSOLIDATED_OCI_ROOT ?= $(CONSOLIDATED_OUTPUT_ROOT)/oci
CONSOLIDATED_OCI_BUILD_PLAN ?= $(CONSOLIDATED_OUTPUT_ROOT)/oci-build-plan.v4.json
CONSOLIDATED_OCI_BUILD_BUNDLE ?= $(CONSOLIDATED_OUTPUT_ROOT)/oci-build-bundle.v3.json
CONSOLIDATED_BUILD_WATCHDOG_RECEIPT ?= $(CONSOLIDATED_OUTPUT_ROOT)/build-watchdog-receipt.v4.json
CONSOLIDATED_BUILD_WATCHDOG_HANDSHAKE ?= $(abspath .tmp/consolidated-build-watchdog-handshake.v4.json)
CONSOLIDATED_TEST_ARTIFACTS_FILE ?= $(CONSOLIDATED_OUTPUT_ROOT)/candidate-index.v1.json
CONSOLIDATED_CANDIDATE_FILE ?= $(CONSOLIDATED_OUTPUT_ROOT)/candidate-manifest.v6.json
CONSOLIDATED_DEPENDENCY_BUNDLE_ROOT ?=
CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST ?=
CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_PUBLIC_KEY ?=
CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_SPKI_SHA256 ?=
CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_RAW_SHA256 ?=
CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_ARGS = \
	--dependency-capability-authority-public-key "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_PUBLIC_KEY)" \
	--expected-dependency-capability-authority-key-spki-sha256 "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_SPKI_SHA256)" \
	--expected-dependency-capability-authority-key-raw-sha256 "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_RAW_SHA256)"
CONSOLIDATED_APPARMOR_PROFILE ?=
CONSOLIDATED_SECCOMP_PROFILE ?=
CONSOLIDATED_BUILD_WATCHDOG_CLIENT ?=
CONSOLIDATED_BUILD_WATCHDOG_CLIENT_SHA256 ?=
override CONSOLIDATED_BUILD_WATCHDOG_SOCKET := /run/serverware-build-watchdog/control.sock
CONSOLIDATED_BUILD_WATCHDOG_CONTRACT ?=
CONSOLIDATED_BUILD_WATCHDOG_CONTRACT_SHA256 ?=
CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY ?=
CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256 ?=
CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256 ?=
CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256 ?=
CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256 ?=
CONSOLIDATED_BUILD_PYTHON ?=
CONSOLIDATED_PYTHON ?=
CONSOLIDATED_PYTHON_SHA256 ?=
AGENT_TRUST_SAME_JOURNEY_VERIFIER ?= scripts/verify_agent_trust_same_journey.py
CONSOLIDATED_FROZEN_VERIFIER_RUN = PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(CONSOLIDATED_BUILD_PYTHON)" -I "$(CONSOLIDATED_FROZEN_VERIFIER)"
CONSOLIDATED_TRUSTED_LAUNCHER ?=
CONSOLIDATED_TRUSTED_LAUNCHER_SHA256 ?=
CONSOLIDATED_TRUSTED_RUNTIME_MANIFEST ?=
CONSOLIDATED_TRUSTED_RUNTIME_MANIFEST_SHA256 ?=
CONSOLIDATED_TRUSTED_BASE_MEASUREMENT ?=
CONSOLIDATED_PROMOTION_RECEIPT ?=
CONSOLIDATED_PROMOTION_RECEIPT_SHA256 ?=
CONSOLIDATED_PROMOTION_PUBLIC_KEY ?=
CONSOLIDATED_PROMOTION_PUBLIC_KEY_SPKI_SHA256 ?=
CONSOLIDATED_PROMOTION_PUBLIC_KEY_RAW_SHA256 ?=
CONSOLIDATED_PROMOTION_ACCEPTANCE_SHA256 ?=
CONSOLIDATED_PROMOTED_MANIFEST ?=
CONSOLIDATED_PROMOTED_MANIFEST_SHA256 ?=
CONSOLIDATED_PROMOTED_MANIFEST_FILE_SHA256 ?=
CONSOLIDATED_CANDIDATE_INDEX_SHA256 ?=
CONSOLIDATED_CANDIDATE_FILE_SHA256 ?=
CONSOLIDATED_CANDIDATE_PAYLOAD_SHA256 ?=
CONSOLIDATED_ALLOWED_READ_ONLY_MOUNT_ID_ARGS ?=
TEST_PYTHON_RUN ?= uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python
CRYPTO_SCHEMA_PYTHON_RUN ?= uv run --no-project --isolated --python 3.11 --with jsonschema==4.23.0 --with cryptography==50.0.0 python
CRYPTO_PYTHON_RUN ?= uv run --no-project --isolated --python 3.11 --with cryptography==50.0.0 python
MITMPROXY_TEST_RUN ?= uv run --no-project --isolated --python 3.11 --with mitmproxy==11.0.2 --with fastapi==0.136.1 --with cbor2==5.9.0 --with jsonschema==4.23.0 --with 'psycopg[binary]==3.2.3' --with python-multipart==0.0.31 --with 'uvicorn[standard]==0.34.0'
PRODUCTION_READINESS_CLAIMS_ARGS ?=
PRODUCTION_READINESS_OUT ?= .tmp/production-readiness.json
PRODUCTION_READINESS_CONFIG_OUT ?= .tmp/production-readiness-config.json
PRODUCTION_READINESS_ENV ?= ops/production-readiness.env
PRODUCTION_READINESS_PREFLIGHT ?= 1
POLICY_CUSTODY_RENDER_MANIFEST ?=
POLICY_CUSTODY_RENDER_OUTPUT ?=
POLICY_CUSTODY_SOCKET_ROOT ?= /run/serverware/policy-custody
POLICY_CUSTODY_RUNTIME_CONFIG_ROOT ?= /run/serverware/policy-custody/runtime/current
POLICY_CUSTODY_DRIVER_GROUP ?= swpc-driver
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
override PRODUCTION_READINESS_EXPECTED_OUTPUTS := \
	$(PRODUCTION_STATE_DIRECTORY)/production-readiness-config.json \
	$(PRODUCTION_STATE_DIRECTORY)/production-readiness-claims.json \
	$(PRODUCTION_STATE_DIRECTORY)/nitro-kms-evidence.json \
	$(PRODUCTION_STATE_DIRECTORY)/production-readiness.json \
	$(PRODUCTION_STATE_DIRECTORY)/serverware-completion-proof.json \
	$(PRODUCTION_STATE_DIRECTORY)/proxy-response-proof-summary.json \
	$(PRODUCTION_STATE_DIRECTORY)/production-host-preflight.json
override PRODUCTION_READINESS_INVOCATION_RECEIPT := $(PRODUCTION_STATE_DIRECTORY)/run-production-readiness-final.receipt
override PRODUCTION_READINESS_INVOCATION_LOCK := $(PRODUCTION_STATE_DIRECTORY)/run-production-readiness-final.lock
# Trusted-host readiness manifest-v3 / launch-authority-ledger-v7 trust pins.
# Public-key material and digests are intentionally unset: production operators
# must supply independently authenticated values for each manifest generation.
PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_KEY_ID ?=
PRODUCTION_GLOBAL_ROLE_REGISTRY ?= /etc/serverware/production-launch-global-role-registry.json
PRODUCTION_EXPECTED_GLOBAL_ROLE_REGISTRY_PINS_SHA256 ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_SIGNING_PUBLIC_KEY_SPKI_BASE64URL ?=
PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_KEY_ID ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_IDENTITY_SHA256 ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_ADMINISTRATIVE_DOMAIN_SHA256 ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_SHA256 ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE ?=
PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_PUBLIC_KEY_SPKI_BASE64URL ?=
PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_KEY_ID ?=
PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS ?= /etc/serverware/nonce-rollback-assurance-pins.json
PRODUCTION_EXPECTED_NONCE_ROLLBACK_ASSURANCE_PINS_SHA256 ?=
PRODUCTION_LAUNCH_PIPELINE_METADATA ?= /etc/serverware/production-release-launch.pipeline-metadata.json
PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE ?= /etc/serverware/production-release-launch.pipeline-metadata.sha256
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
# Final-v1 uses the frozen release verifier directly. All evidence, trust pins,
# and public signer identities are explicit; no value is inherited from the
# readiness service. The two output defaults are separate durable artifacts.
PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE ?=
PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS ?=
PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS ?=
PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_TRUST_ROOTS_SHA256 ?=
PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT ?=
PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY ?=
PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_PROVIDER ?=
PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_KEY_ID ?=
PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_SPKI_SHA256 ?=
PRODUCTION_FINAL_V1_EXPECTED_GLOBAL_ROLE_REGISTRY_SHA256 ?=
PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY ?=
PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_PROVIDER ?=
PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_KEY_ID ?=
PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_SPKI_SHA256 ?=
PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT ?= $(PRODUCTION_STATE_DIRECTORY)/release-completion-result-signing-request.v1.json
PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST ?= $(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)
PRODUCTION_FINAL_V1_SIGNING_RESPONSE ?=
PRODUCTION_FINAL_V1_RESULT_OUT ?= $(PRODUCTION_STATE_DIRECTORY)/release-completion-verification.v1.json
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
PRODUCTION_LAUNCHER_ADVERSARIAL_BUILDER ?=
override CODER_COMPOSE_PROJECT_NAME := serverware-coder-ci
SERVERWARE_CONTROLLER_ARTIFACT_ROOT ?= $(abspath ../.serverware-coder-artifacts)
SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET ?= /run/serverware/controller-docker-proxy.sock
override CODER_REPO_TMP_DIR := $(abspath $(SERVERWARE_CONTROLLER_ARTIFACT_ROOT))
override CODER_OUTPUT_DIR := $(CODER_REPO_TMP_DIR)/coder-ci
override CODER_DOCKER_CONFIG_DIR := $(CODER_REPO_TMP_DIR)/coder-docker-config
override CODER_BUILDX_CONFIG_DIR := $(CODER_REPO_TMP_DIR)/coder-buildx-config
override CODER_DOCKER_HOST := unix://$(SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)
override CODER_CONTROLLER_STATIC_TARGET := x86_64-unknown-linux-musl
override CODER_CONTROLLER_STATIC_ROOT := $(CODER_REPO_TMP_DIR)/controller-static-v11

coder-controller-static-assets:
	@set -eu; \
		test "$(CODER_CONTROLLER_STATIC_ROOT)" = "$(CODER_REPO_TMP_DIR)/controller-static-v11"; \
		rm -rf "$(CODER_CONTROLLER_STATIC_ROOT)"; \
		(umask 077 && mkdir -p "$(CODER_CONTROLLER_STATIC_ROOT)/bin" "$(CODER_CONTROLLER_STATIC_ROOT)/plans"); \
		CARGO_TARGET_DIR="$(CODER_CONTROLLER_STATIC_ROOT)/cargo-target" \
			cargo build --locked --release --target "$(CODER_CONTROLLER_STATIC_TARGET)" \
				--manifest-path data-plane/decision-gate-rs/Cargo.toml \
					--bin serverware-coder-controller \
					--bin serverware-coder-controller-client \
					--bin serverware-coder-docker-proxy \
					--bin serverware-coder-controller-launcher \
					--bin serverware-coder-plan; \
			for binary in serverware-coder-controller serverware-coder-controller-client serverware-coder-docker-proxy serverware-coder-controller-launcher serverware-coder-plan; do \
			install -m 0500 \
				"$(CODER_CONTROLLER_STATIC_ROOT)/cargo-target/$(CODER_CONTROLLER_STATIC_TARGET)/release/$$binary" \
				"$(CODER_CONTROLLER_STATIC_ROOT)/bin/$$binary"; \
		done; \
		for plan in build-v1 unit-no-build-v1 integration-no-build-v1 e2e-no-build-v1 attestation-no-build-v1; do \
			install -m 0500 \
				"$(CODER_CONTROLLER_STATIC_ROOT)/bin/serverware-coder-plan" \
				"$(CODER_CONTROLLER_STATIC_ROOT)/plans/$$plan"; \
		done; \
		sha256sum "$(CODER_CONTROLLER_STATIC_ROOT)"/bin/* "$(CODER_CONTROLLER_STATIC_ROOT)"/plans/* \
			> "$(CODER_CONTROLLER_STATIC_ROOT)/SHA256SUMS"
override CODER_DAEMON_DISPOSABLE_LABEL := com.serverware.coder-ci.disposable=true
override CODER_DAEMON_NETWORK_LABEL := com.serverware.coder-ci.network=workspace-shared
override CODER_DAEMON_ID_FILE := $(CODER_OUTPUT_DIR)/daemon-id.txt
override CODER_PLATFORM := linux/amd64
override CODER_BUILDKIT_IMAGE := moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec
override CODER_BUILDKIT_REPO_DIGEST := moby/buildkit@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec
override CODER_BUILDKIT_IMAGE_BINDING_FILE := $(CODER_OUTPUT_DIR)/buildkit-image-binding.txt
override CODER_DECISION_GATE_BINARY_DIGEST_FILE := $(CODER_OUTPUT_DIR)/decision-gate-binary-digest.txt
override CODER_COMPOSE_DIGEST_OVERRIDE_FILE := $(CODER_OUTPUT_DIR)/compose-digest-override.yaml
override CODER_COMPOSE_DIGEST_OVERRIDE_SHA256_FILE := $(CODER_OUTPUT_DIR)/compose-digest-override-sha256.txt
override CODER_HOST_IDENTITY_FILE := $(CODER_OUTPUT_DIR)/host-tool-daemon-identity.tsv
override CODER_HOST_IDENTITY_SHA256_FILE := $(CODER_OUTPUT_DIR)/host-tool-daemon-identity-sha256.txt
override CODER_CURRENT_HOST_IDENTITY_FILE := $(CODER_OUTPUT_DIR)/current-host-tool-daemon-identity.tsv
override CODER_PARENT_CLEANUP_MARKER_FILE := $(CODER_OUTPUT_DIR)/parent-cleanup-token.txt
override CODER_RUN_TOKEN_FILE := $(CODER_OUTPUT_DIR)/run-owner-token.txt
override CODER_RESOURCE_OWNERSHIP_FILE := $(CODER_OUTPUT_DIR)/resource-ownership.tsv
override CODER_TASK_IMAGE_OWNERSHIP_FILE := $(CODER_OUTPUT_DIR)/task-image-ownership.tsv
override CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE := $(CODER_OUTPUT_DIR)/dependency-image-ownership.tsv
override CODER_DEPENDENCY_PREEXISTING_IDS_FILE := $(CODER_OUTPUT_DIR)/dependency-image-preexisting-ids.txt
override CODER_BUILD_PARENT_COMMIT_FILE := $(CODER_OUTPUT_DIR)/build-parent-commit.txt
override CODER_BUILD_BASE_TREE_FILE := $(CODER_OUTPUT_DIR)/build-base-tree.txt
override CODER_CHANGED_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.changed.txt
override CODER_PREPARED_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.prepared.txt
override CODER_BLOCKED_PREREQUISITE_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.blocked-prerequisite.txt
override CODER_EXCLUDED_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.excluded.txt
override CODER_CHANGED_EXCLUDED_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.changed-excluded.txt
override CODER_CHANGED_BLOCKED_PREREQUISITE_TESTS_FILE := $(CODER_OUTPUT_DIR)/test-inventory.changed-blocked-prerequisite.txt
override CODER_OWNER_LABEL_KEY := com.serverware.coder-ci.owner
override CODER_RESOURCE_LABEL_KEY := com.serverware.coder-ci.resource
# The Docker names below are host-global, so every UID locks the same
# root-owned directory inode without creating or truncating a lock file.
override CODER_LOCK_DIRECTORY := /run/lock
override CODER_FROZEN_SOURCE_DIR := $(CODER_OUTPUT_DIR)/source
override CODER_COMPOSE_LIMITS_FILE := $(CODER_OUTPUT_DIR)/compose-limits.yaml
override CODER_COMPOSE_IMAGE_OVERRIDE_FILE := $(CODER_OUTPUT_DIR)/compose-image-override.yaml
override CODER_BUILDER_NAME_PREFIX := sw-coder-
override CODER_BUILDER_BINDING_FILE := $(CODER_OUTPUT_DIR)/buildx-builder-binding.tsv
override CODER_BUILD_SERVICES := serverware decision-gate-rs
override CODER_RUNTIME_SERVICES := grant-store audit-anchor demo-upstream serverware decision-gate-rs
override CODER_SHARED_PYTHON_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-serverware
override CODER_AUDIT_ANCHOR_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-audit-anchor
override CODER_DEMO_UPSTREAM_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-demo-upstream
override CODER_DECISION_GATE_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-decision-gate-rs
override CODER_RUST_TEST_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-decision-gate-rs-tests
override CODER_RUST_TEST_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-rust-unit-tests
override CODER_RUST_TEST_CONTAINER_LABEL := com.serverware.coder-ci.resource=rust-unit-tests
override CODER_PROXY_TEST_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-proxy-tests
override CODER_PROXY_TEST_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-proxy-tests
override CODER_PROXY_TEST_CONTAINER_LABEL := com.serverware.coder-ci.resource=proxy-tests
override CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-production-host-preflight
override CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE := $(CODER_OUTPUT_DIR)/production-host-preflight-image-binding.txt
override CODER_PRODUCTION_HOST_PREFLIGHT_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-production-host-preflight
override CODER_PRODUCTION_HOST_PREFLIGHT_CONTAINER_LABEL := com.serverware.coder-ci.resource=production-host-preflight
override CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT := scripts/test_production_host_preflight.py
override CODER_IMAGE_PYTHON_INTERPRETER := /usr/local/bin/python3.11
override CODER_PYTHON_TEST_ARGV_BINDING_FILE := $(CODER_OUTPUT_DIR)/python-test-argv-bindings.tsv
override CODER_LAUNCHER_ADVERSARIAL_IMAGE := $(CODER_COMPOSE_PROJECT_NAME)-production-launcher-adversarial:coder-v3
override CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE := $(CODER_OUTPUT_DIR)/launcher-adversarial-image.id
override CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE := $(CODER_OUTPUT_DIR)/launcher-adversarial-image-binding.txt
override CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE := $(CODER_OUTPUT_DIR)/launcher-adversarial-build-inputs.json
override CODER_LAUNCHER_ADVERSARIAL_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-launcher-adversarial
override CODER_LAUNCHER_ADVERSARIAL_CONTAINER_LABEL := com.serverware.coder-ci.resource=launcher-adversarial
override CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT := scripts/test_production_launcher_adversarial.py
override CODER_LAUNCHER_ADVERSARIAL_RUST_SLIM_BASE := rust:1.88-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89
override CODER_LAUNCHER_ADVERSARIAL_RUST_ALPINE_BASE := rust:1.88-alpine3.22@sha256:64eba3726734dcfe89e0a62a0485007a3ab7c7372ce5b38c621d8812f70215f0
override CODER_LAUNCHER_ADVERSARIAL_PYTHON_SLIM_BASE := python:3.11-slim-bookworm@sha256:0030323c9ce4d6dfab5f0812577cb0abd13c806f86b3a1f5b5d8f200ebb1421c
override CODER_ISOLATED_TEST_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-isolated-test
override CODER_ISOLATED_TEST_CONTAINER_LABEL := com.serverware.coder-ci.resource=isolated-test
override CODER_DECISION_GATE_MEASURE_CONTAINER := $(CODER_COMPOSE_PROJECT_NAME)-decision-gate-measure
override CODER_DECISION_GATE_MEASURE_CONTAINER_LABEL := com.serverware.coder-ci.resource=decision-gate-measure
override CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE := $(CODER_OUTPUT_DIR)/decision-gate-measure-image-id.txt
override CODER_POSTGRES_IMAGE := postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777
override CODER_RUNTIME_IMAGE_BINDINGS := \
	grant-store=$(CODER_POSTGRES_IMAGE) \
	audit-anchor=$(CODER_AUDIT_ANCHOR_IMAGE) \
	demo-upstream=$(CODER_DEMO_UPSTREAM_IMAGE) \
	serverware=$(CODER_SHARED_PYTHON_IMAGE) \
	decision-gate-rs=$(CODER_DECISION_GATE_IMAGE)
override CODER_TEST_SCRIPTS := \
	scripts/test_http_client.py \
	scripts/test_shared_rate_limits.py \
	scripts/test_credential_lease_delivery.py \
	scripts/test_approval_review.py \
	scripts/test_webauthn_attestation.py \
	scripts/test_production_attestation_bridge.py \
	scripts/test_verify_nitro_tee.py \
	scripts/test_internal_service_auth.py \
	scripts/test_onboarding_evidence.py \
	scripts/test_oci_contract_source_fixtures.py
override CODER_ISOLATED_TEST_SCRIPTS := \
	scripts/test_codebase_attestation.py \
	scripts/test_native_postgres_contract.py \
	scripts/test_native_postgres_batch.py \
	scripts/test_native_postgres_runner.py \
	scripts/test_native_postgres_lifecycle.py \
	scripts/test_native_postgres_probe.py \
	scripts/test_authority_primary_contract.py \
	scripts/test_authority_radix_proof.py \
	scripts/test_authority_radix_batch.py \
	scripts/test_authority_index_range.py \
	scripts/test_authority_index_join.py \
	scripts/test_authority_index_frontier.py \
	scripts/test_authority_index_heads.py \
	scripts/test_authority_index_trace.py \
	scripts/test_authority_index_mutation.py \
	scripts/test_authority_indexed_mutation.py \
	scripts/test_authority_index_mutation_reader.py \
	scripts/test_authority_mutation_inputs.py \
	scripts/test_authority_query_reads.py \
	scripts/test_authority_query_reads_measured.py \
	scripts/test_authority_query_staging.py \
	scripts/test_authority_complete_query.py \
	scripts/test_authority_revocation_query_program.py \
	scripts/test_authority_revocation_query_work.py \
	scripts/test_authority_complete_query_batch.py \
	scripts/test_authority_complete_acquisition.py \
	scripts/test_authority_complete_read_write.py \
	scripts/test_authority_revocation_read_write.py \
	scripts/test_authority_revocation_proof_bundle.py \
	scripts/test_authority_typed_request_work.py \
	scripts/test_authority_revocation_semantics.py \
	scripts/test_authority_revocation_plan_contract.py \
	scripts/test_authority_revocation_plan.py \
	scripts/test_authority_revocation_wire.py \
	scripts/test_authority_revocation_retention.py \
	scripts/test_authority_revocation_persistence.py \
	scripts/test_authority_revocation_reservation.py \
	scripts/test_authority_revocation_capability.py \
	scripts/test_authority_revocation_capability_producer.py \
	scripts/test_authority_revocation_issuance.py \
	scripts/test_authority_revocation_issuance_source.py \
	scripts/test_authority_revocation_issuer.py \
	scripts/test_authority_revocation_issuer_source.py \
	scripts/test_authority_revocation_invocation.py \
	scripts/test_authority_revocation_invocation_source.py \
	scripts/test_authority_revocation_configuration.py \
	scripts/test_authority_revocation_transport.py \
	scripts/test_authority_revocation_service_source.py \
	scripts/test_authority_revocation_roots.py \
	scripts/test_authority_revocation_roots_source.py \
	scripts/test_authority_revocation_observed.py \
	scripts/test_authority_revocation_observed_source.py \
	scripts/test_authority_revocation_handoff.py \
	scripts/test_authority_revocation_handoff_source.py \
	scripts/test_authority_revocation_verifier.py \
	scripts/test_authority_revocation_verifier_source.py \
	scripts/test_authority_revocation_planning.py \
	scripts/test_authority_revocation_planning_source.py \
	scripts/test_authority_revocation_planning_transport.py \
	scripts/test_authority_revocation_planner_configuration.py \
	scripts/test_authority_revocation_planner_configuration_source.py \
	scripts/test_authority_revocation_coordinator_source.py \
	scripts/test_authority_revocation_atomic_source.py \
	scripts/test_authority_revocation_writer_connection_source.py \
	scripts/test_authority_revocation_writer_configuration.py \
	scripts/test_authority_revocation_writer_configuration_source.py \
	scripts/test_authority_revocation_writer_action.py \
	scripts/test_authority_revocation_writer_action_source.py \
	scripts/test_authority_revocation_writer_commitment.py \
	scripts/test_authority_revocation_writer_commitment_source.py \
	scripts/test_authority_revocation_writer_composition.py \
	scripts/test_authority_revocation_writer_composition_source.py \
	scripts/test_authority_revocation_writer_request.py \
	scripts/test_authority_revocation_writer_request_source.py \
	scripts/test_authority_revocation_writer_signer.py \
	scripts/test_authority_revocation_writer_signer_source.py \
	scripts/test_authority_revocation_writer_acknowledgment.py \
	scripts/test_authority_revocation_writer_acknowledgment_storage.py \
	scripts/test_authority_revocation_writer_acknowledgment_storage_source.py \
	scripts/test_authority_revocation_writer_transport.py \
	scripts/test_authority_revocation_writer_transport_source.py \
	scripts/test_authority_revocation_writer_public_key_source.py \
	scripts/test_authority_revocation_writer_ack_expectation_source.py \
	scripts/test_authority_revocation_writer_client.py \
	scripts/test_authority_revocation_writer_client_source.py \
	scripts/test_authority_revocation_writer_producers.py \
	scripts/test_authority_revocation_writer_producers_source.py \
	scripts/test_authority_webauthn_trust.py \
	scripts/test_authority_radix_mutation.py \
	scripts/test_authority_root_transition.py \
	scripts/test_authority_counted_root_transition.py \
	scripts/test_authority_counted_installation.py \
	scripts/test_authority_wire_json_source.py \
	scripts/test_authority_primary_tree_source.py \
	scripts/test_authority_audit_capacity.py \
	scripts/test_authority_audit_capacity_work.py \
	scripts/test_authority_global_audit_capacity.py \
	scripts/test_authority_global_audit_capacity_sql_source.py \
	scripts/test_authority_global_audit_capacity_integration_source.py \
	scripts/test_authority_audit_trace.py \
	scripts/test_authority_audit_inventory.py \
	scripts/test_authority_audit_initialization.py \
	scripts/test_authority_audit_initialization_admission.py \
	scripts/test_authority_witness_journal.py \
	scripts/test_authority_witness_capacity.py \
	scripts/test_authority_audit_backfill_spec.py \
	scripts/test_authority_table_acl_source.py \
	scripts/test_authority_schema_source.py \
	scripts/test_authority_issuer_source.py \
	scripts/test_authority_witness_transport_source.py \
	scripts/test_authority_verifier_read_source.py \
	scripts/test_authority_planner_writer_source.py \
	scripts/test_authority_transition_registry.py \
	scripts/test_webauthn_attestation_core.py \
	scripts/test_webauthn_credential_trust.py \
	scripts/test_webauthn_revoke_authorization.py \
	scripts/test_webauthn_assertion_work.py \
	scripts/test_webauthn_revoke_transition.py \
	scripts/test_webauthn_revocation_work.py \
	scripts/test_webauthn_trust_core.py \
	scripts/test_webauthn_trust_installation.py \
	scripts/test_control_plane_startup.py \
	scripts/test_launch_authority_service.py \
	scripts/test_launch_authorization.py \
	scripts/test_nitro_nsm_attest.py \
	scripts/test_production_release_proof_target.py \
	scripts/test_release_completion.py \
	scripts/test_run_production_readiness.py
override CODER_BLOCKED_PREREQUISITE_TEST_SCRIPTS := \
	scripts/test_agent_trust_clean_room.py \
	scripts/test_portal_browser_oauth.py \
	scripts/test_response_proof_capture.sh
override CODER_EXCLUDED_TEST_SCRIPTS := \
	scripts/test_agent_enrollment.py \
	scripts/test_agent_trust_wheel.py \
	scripts/test_apparmor_runtime.sh \
	scripts/test_approval_denial_reason.py \
	scripts/test_audit_anchor.sh \
	scripts/test_audit_export.py \
	scripts/test_audit_search.py \
	scripts/test_aws_kms_recipient_release.py \
	scripts/test_aws_nitro_kms_unseal.py \
	scripts/test_break_glass_grants.py \
	scripts/test_build_production_images.py \
	scripts/test_ca_install_sessions.py \
	scripts/test_ca_material.py \
	scripts/test_container_hardening.sh \
	scripts/test_control_plane_audit_store.sh \
	scripts/test_control_plane_csrf.py \
	scripts/test_control_plane_metadata_store.sh \
	scripts/test_control_plane_mutation_mfa.py \
	scripts/test_control_plane_oidc.py \
	scripts/test_control_plane_rbac_audit.py \
	scripts/test_control_plane_two_person.py \
	scripts/test_cosign_sigstore.py \
	scripts/test_custody_response_proof.sh \
	scripts/test_decision_gate_approval_publish.sh \
	scripts/test_decision_gate_audit.sh \
	scripts/test_decision_gate_connect.sh \
	scripts/test_decision_gate_csv_streaming.sh \
	scripts/test_decision_gate_form_urlencoded_streaming.sh \
	scripts/test_decision_gate_forward.sh \
	scripts/test_decision_gate_json_array_streaming.sh \
	scripts/test_decision_gate_json_nested_streaming.sh \
	scripts/test_decision_gate_json_sse_streaming.sh \
	scripts/test_decision_gate_jsonl_streaming.sh \
	scripts/test_decision_gate_mitm.sh \
	scripts/test_decision_gate_policy_reload.sh \
	scripts/test_decision_gate_request_streaming.sh \
	scripts/test_decision_gate_response.sh \
	scripts/test_decision_gate_shared_rate_limits.sh \
	scripts/test_decision_gate_signature.sh \
	scripts/test_decision_gate_streaming.sh \
	scripts/test_decision_gate_trust_root.sh \
	scripts/test_external_tee_provider.py \
	scripts/test_gmail_metadata_hydration.py \
	scripts/test_gmail_proof_cache.py \
	scripts/test_http_client_security.py \
	scripts/test_key_release_gate.py \
	scripts/test_merge_production_images_env.py \
	scripts/test_nitro_kms_evidence.py \
	scripts/test_nitro_tee_provider.py \
	scripts/test_oauth_credentials.py \
	scripts/test_oauth_http_flow.py \
	scripts/test_policy_activation_evidence.py \
	scripts/test_policy_canary_workflow.py \
	scripts/test_policy_publish_workflow.py \
	scripts/test_portal_agent_enrollment_ui.py \
	scripts/test_prepare_aws_kms_materials.py \
	scripts/test_production_handoff.py \
	scripts/test_production_image_builds.py \
	scripts/test_production_images_no_shell.py \
	scripts/test_production_launch_assets.py \
	scripts/test_production_policy_identity.py \
	scripts/test_production_readiness.py \
	scripts/test_production_readiness_claims.py \
	scripts/test_production_release_input_preflight.py \
	scripts/test_publish_production_images.py \
	scripts/test_reproducible_builds.py \
	scripts/test_setup_receipt_api.py \
	scripts/test_setup_receipts.py \
	scripts/test_setup_session_api.py \
	scripts/test_setup_sessions.py \
	scripts/test_setup_verify.py \
	scripts/test_sign_release_images.py \
	scripts/test_sigstore_json.py \
	scripts/test_transparency_checkpoint.py \
	scripts/test_checkpoint_sequence.py \
	scripts/test_provider_policy_parity.py \
	scripts/test_webauthn_trust_projection_postgres.py \
	scripts/test_postgres_trigger_manifest.py \
	scripts/test_authority_mutation_postgres.py \
	scripts/test_authority_root_transition_postgres.py \
	scripts/test_authority_primary_tree_postgres.py \
	scripts/test_authority_audit_initialization_postgres.py \
	scripts/test_authority_audit_initialization_store_postgres.py \
	scripts/test_authority_global_audit_capacity_postgres.py \
	scripts/test_authority_verifier_read_postgres.py \
	scripts/test_authority_planner_writer_postgres.py \
	scripts/test_authority_wire_json_postgres.py \
	scripts/test_authority_counted_hash_postgres.py \
	scripts/test_authority_counted_projection_postgres.py \
	scripts/test_authority_counted_store_postgres.py \
	scripts/test_authority_counted_maintenance_postgres.py \
	scripts/test_traversal_response_evidence.py \
	scripts/test_webauthn_recovery.py
# Exact repository-source closure exercised by counted and retained SQL fixtures.
# The complete frozen archive remains the source authority; these presence/
# nonsymlink checks neither replace its digest nor prepare an excluded test.
# Include package imports, imported independent oracles, and db.py, which the
# existing native helper reads as source without importing its runtime facade.
override CODER_COUNTED_NATIVE_SOURCE_DEPENDENCIES := \
	scripts/authority_revocation_observation_fixture.py \
	scripts/authority_revocation_semantics_fixture.py \
	scripts/authority_revocation_trust_fixture.py \
	scripts/test_authority_audit_capacity_work.py \
	scripts/test_authority_audit_initialization.py \
	scripts/test_authority_audit_inventory.py \
	scripts/test_authority_audit_trace.py \
	scripts/test_authority_complete_query.py \
	scripts/test_authority_complete_query_batch.py \
	scripts/test_authority_complete_read_write.py \
	scripts/test_authority_counted_installation.py \
	scripts/test_authority_counted_root_transition.py \
	scripts/test_authority_counted_hash_postgres.py \
	scripts/test_authority_counted_projection_postgres.py \
	scripts/test_authority_counted_store_postgres.py \
	scripts/test_authority_counted_maintenance_postgres.py \
	scripts/test_authority_global_audit_capacity.py \
	scripts/test_authority_index_frontier.py \
	scripts/test_authority_index_heads.py \
	scripts/test_authority_index_join.py \
	scripts/test_authority_indexed_mutation.py \
	scripts/test_authority_index_range.py \
	scripts/test_authority_index_trace.py \
	scripts/test_authority_primary_tree_postgres.py \
	scripts/test_authority_query_reads.py \
	scripts/test_authority_query_reads_measured.py \
	scripts/test_authority_radix_mutation.py \
	scripts/test_authority_radix_proof.py \
	scripts/test_authority_revocation_persistence.py \
	scripts/test_authority_revocation_plan.py \
	scripts/test_authority_revocation_proof_bundle.py \
	scripts/test_authority_revocation_query_program.py \
	scripts/test_authority_revocation_query_work.py \
	scripts/test_authority_revocation_read_write.py \
	scripts/test_authority_revocation_retention.py \
	scripts/test_authority_revocation_semantics.py \
	scripts/test_authority_revocation_wire.py \
	scripts/test_authority_root_transition_postgres.py \
	scripts/test_authority_typed_request_work.py \
	scripts/test_webauthn_assertion_work.py \
	scripts/test_webauthn_revocation_work.py \
	scripts/test_webauthn_revoke_transition.py \
	scripts/test_webauthn_trust_projection_postgres.py \
	serverware/__init__.py \
	serverware/audit_outbox_contract.py \
	serverware/authority_audit_capacity.py \
	serverware/authority_audit_initialization.py \
	serverware/authority_audit_inventory.py \
	serverware/authority_audit_trace.py \
	serverware/authority_complete_query.py \
	serverware/authority_complete_query_batch.py \
	serverware/authority_complete_read_write.py \
	serverware/authority_contract.py \
	serverware/authority_counted_root_transition.py \
	serverware/authority_index_contract.py \
	serverware/authority_index_frontier.py \
	serverware/authority_index_heads.py \
	serverware/authority_index_join.py \
	serverware/authority_index_mutation.py \
	serverware/authority_index_mutation_reader.py \
	serverware/authority_indexed_mutation.py \
	serverware/authority_index_projection.py \
	serverware/authority_index_range.py \
	serverware/authority_index_reader.py \
	serverware/authority_index_trace.py \
	serverware/authority_primary_contract.py \
	serverware/authority_query_read_work.py \
	serverware/authority_query_reads.py \
	serverware/authority_radix_mutation.py \
	serverware/authority_radix_proof.py \
	serverware/authority_request_commitment.py \
	serverware/authority_revocation_bundle_contract.py \
	serverware/authority_revocation_capability.py \
	serverware/authority_revocation_capability_production.py \
	serverware/authority_revocation_configuration.py \
	serverware/authority_revocation_roots.py \
	serverware/authority_revocation_root_reader.py \
	serverware/authority_revocation_observed.py \
	serverware/authority_revocation_handoff.py \
	serverware/authority_revocation_verifier.py \
	serverware/authority_revocation_planning.py \
	serverware/authority_revocation_planning_request.py \
	serverware/authority_revocation_planning_transport.py \
	serverware/authority_revocation_planning_client.py \
	serverware/authority_revocation_planning_receiver.py \
	serverware/authority_revocation_planner_custody_transport.py \
	serverware/authority_revocation_planner_custody_client.py \
	serverware/authority_revocation_planner_custody_receiver.py \
	serverware/authority_revocation_custody_read.py \
	serverware/authority_revocation_custody_read_client.py \
	serverware/authority_revocation_custody_read_transport.py \
	serverware/authority_revocation_planner_configuration.py \
	serverware/authority_revocation_invocation.py \
	serverware/authority_revocation_issuance.py \
	serverware/authority_revocation_persistence.py \
	serverware/authority_revocation_writer_connection.py \
	serverware/authority_revocation_writer_configuration.py \
	serverware/authority_revocation_writer_action.py \
	serverware/authority_revocation_writer_commitment.py \
	serverware/authority_revocation_writer_composition.py \
	serverware/authority_revocation_writer_signer.py \
	serverware/authority_revocation_writer_acknowledgment.py \
	serverware/authority_revocation_writer_transport.py \
	serverware/authority_revocation_writer_ack_expectation.py \
	serverware/authority_revocation_writer_client.py \
	serverware/authority_revocation_writer_producers.py \
	serverware/authority_revocation_plan.py \
	serverware/authority_revocation_plan_contract.py \
	serverware/authority_revocation_plan_production.py \
	serverware/authority_revocation_proof_bundle.py \
	serverware/authority_revocation_read_write.py \
	serverware/authority_revocation_retention.py \
	serverware/authority_revocation_semantics.py \
	serverware/authority_revocation_wire.py \
	serverware/authority_revocation_write_trace.py \
	serverware/authority_root_transition.py \
	serverware/authority_store/__init__.py \
	serverware/authority_store/audit_capacity_sql.py \
	serverware/authority_store/authorization_records.py \
	serverware/authority_store/completed_v9_schema_source.py \
	serverware/authority_store/counted_hash_sql.py \
	serverware/authority_store/counted_installation.py \
	serverware/authority_store/counted_projection_sql.py \
	serverware/authority_store/counted_store_sql.py \
	serverware/authority_store/counted_path_sql.py \
	serverware/authority_store/counted_maintenance_sql.py \
	serverware/authority_store/metadata_schema_source.py \
	serverware/authority_store/mutation_sql.py \
	serverware/authority_store/planner_connection.py \
	serverware/authority_store/planner_writer_sql.py \
	serverware/authority_store/postgres_trigger_manifest.py \
	serverware/authority_store/primary_tree_sql.py \
	serverware/authority_store/revocation_capability.py \
	serverware/authority_store/revocation_capability_sql.py \
	serverware/authority_store/revocation_counted_sql.py \
	serverware/authority_store/revocation_execution.py \
	serverware/authority_store/revocation_writer_request.py \
	serverware/authority_store/revocation_writer_acknowledgment.py \
	serverware/authority_store/revocation_custody_read.py \
	serverware/authority_store/revocation_retained_sql.py \
	serverware/authority_store/revocation_retention.py \
	serverware/authority_store/webauthn_evidence_retention.py \
	serverware/authority_store/webauthn_evidence_entrypoints.py \
	serverware/authority_store/root_transition_sql.py \
	serverware/authority_store/schema.py \
	serverware/authority_store/v9_schema_source.py \
	serverware/authority_store/verifier_read_sql.py \
	serverware/authority_store/webauthn_trust_sql.py \
	serverware/authority_store/wire_json_sql.py \
	serverware/authority_transition_core.py \
	serverware/authority_successor_programs.py \
	serverware/authority_webauthn_transition_planning.py \
	serverware/authority_webauthn_transition_inputs.py \
	serverware/authority_webauthn_registration_replay.py \
	serverware/authority_webauthn_stage_replay.py \
	serverware/authority_webauthn_completion_replay.py \
	serverware/authority_webauthn_complete_proofs.py \
	serverware/authority_webauthn_completion_proofs.py \
	serverware/authority_webauthn_transition_proof_contract.py \
	serverware/authority_webauthn_transition_proof_wire.py \
	serverware/authority_webauthn_transition_proof.py \
	serverware/authority_webauthn_transition_proof_production.py \
	serverware/authority_transition_policy.py \
	serverware/authority_transition_webauthn.py \
	serverware/authority_transition_webauthn_registration.py \
	serverware/authority_transition_webauthn_registration_admission.py \
	serverware/authority_transition_webauthn_installation_admission.py \
	serverware/authority_transition_webauthn_completion.py \
	serverware/authority_transition_webauthn_trust_stage.py \
	serverware/authority_transport.py \
	serverware/authority_webauthn_assertion.py \
	serverware/authority_webauthn_evidence.py \
	serverware/authority_webauthn_evidence_acquisition.py \
	serverware/authority_webauthn_evidence_roots.py \
	serverware/authority_webauthn_evidence_root_reader.py \
	serverware/authority_webauthn_evidence_root_configuration.py \
	serverware/authority_webauthn_evidence_computation.py \
	serverware/authority_webauthn_evidence_custody_configuration.py \
	serverware/authority_webauthn_evidence_custody_actions.py \
	serverware/authority_webauthn_evidence_custody_transport.py \
	serverware/authority_webauthn_evidence_custody_read_request.py \
	serverware/authority_webauthn_evidence_custody_read_actions.py \
	serverware/authority_webauthn_evidence_custody_read_transport.py \
	serverware/authority_webauthn_evidence_custody_wire.py \
	serverware/authority_webauthn_evidence_custody_intent.py \
	serverware/authority_webauthn_evidence_custody_relay.py \
	serverware/authority_webauthn_evidence_custody_persistence.py \
	serverware/authority_webauthn_evidence_kernel.py \
	serverware/authority_webauthn_evidence_planning.py \
	serverware/authority_webauthn_evidence_policy.py \
	serverware/authority_webauthn_evidence_configuration.py \
	serverware/authority_webauthn_evidence_input_wire.py \
	serverware/authority_webauthn_evidence_replay.py \
	serverware/authority_webauthn_evidence_plan.py \
	serverware/authority_webauthn_evidence_plan_request.py \
	serverware/authority_webauthn_evidence_plan_response.py \
	serverware/authority_webauthn_evidence_plan_transport.py \
	serverware/authority_webauthn_evidence_plan_live.py \
	serverware/authority_webauthn_evidence_plan_actions.py \
	serverware/authority_webauthn_evidence_plan_admission.py \
	serverware/authority_webauthn_evidence_plan_clock.py \
	serverware/authority_webauthn_evidence_plan_configuration.py \
	serverware/authority_webauthn_evidence_plan_context.py \
	serverware/authority_webauthn_evidence_plan_contract.py \
	serverware/authority_webauthn_evidence_plan_owner.py \
	serverware/authority_webauthn_evidence_plan_persistence.py \
	serverware/authority_webauthn_evidence_plan_production.py \
	serverware/authority_webauthn_evidence_plan_reads.py \
	serverware/authority_webauthn_evidence_plan_retention.py \
	serverware/authority_webauthn_evidence_plan_verifier.py \
	serverware/authority_webauthn_evidence_plan_verifier_configuration.py \
	serverware/authority_webauthn_evidence_plan_writer_configuration.py \
	serverware/authority_webauthn_evidence_proofs.py \
	serverware/authority_webauthn_registration_inputs.py \
	serverware/authority_webauthn_installation_inputs.py \
	serverware/authority_webauthn_registration_production.py \
	serverware/authority_webauthn_registration_admission.py \
	serverware/authority_webauthn_installation_admission.py \
	serverware/authority_webauthn_trust_candidate.py \
	serverware/authority_webauthn_installation_production.py \
	serverware/authority_webauthn_trust.py \
	serverware/webauthn_attestation_core.py \
	serverware/webauthn_credential_trust.py \
	serverware/webauthn_trust.py \
	serverware/webauthn_trust_core.py \
	schemas/webauthn-trust-bundle.v1.schema.json \
	serverware/db.py \
	serverware/native_postgres_inventory.py \
	serverware/native_postgres_results.py
CODER_TIMEOUT ?= timeout
CODER_BUILD_TIMEOUT ?= 3600s
CODER_RUST_TEST_BUILD_TIMEOUT ?= 7200s
CODER_RUST_TEST_TIMEOUT ?= 3600s
CODER_START_TIMEOUT ?= 300s
CODER_PER_TEST_TIMEOUT ?= 900s
CODER_ISOLATED_TEST_TIMEOUT ?= 1800s
CODER_LAUNCHER_ADVERSARIAL_BUILD_TIMEOUT ?= 1800s
CODER_LAUNCHER_ADVERSARIAL_TEST_TIMEOUT ?= 900s
CODER_E2E_TIMEOUT ?= 1800s
CODER_CLEANUP_TIMEOUT ?= 180s
CODER_INSPECT_TIMEOUT ?= 60s
CODER_KILL_AFTER ?= 30s
override CODER_RUST_TEST_CPUS := 4
override CODER_RUST_TEST_MEMORY := 4g
override CODER_RUST_TEST_PIDS := 256
override CODER_RUST_TEST_TMPFS_SIZE := 1g
override CODER_RUST_TEST_LOG_MAX_SIZE := 32m
override CODER_ISOLATED_TEST_CPUS := 4
override CODER_ISOLATED_TEST_MEMORY := 4g
override CODER_ISOLATED_TEST_PIDS := 256
override CODER_ISOLATED_TEST_TMPFS_SIZE := 1g
override CODER_ISOLATED_TEST_LOG_MAX_SIZE := 32m
override CODER_LAUNCHER_ADVERSARIAL_CPUS := 4
override CODER_LAUNCHER_ADVERSARIAL_MEMORY := 4g
override CODER_LAUNCHER_ADVERSARIAL_PIDS := 256
override CODER_LAUNCHER_ADVERSARIAL_TMPFS_SIZE := 1g
override CODER_LAUNCHER_ADVERSARIAL_LOG_MAX_SIZE := 32m
override CODER_GRANT_STORE_HEALTH_RETRIES := 60
override CODER_SERVICE_CPUS := 4
override CODER_SERVICE_MEMORY := 2g
override CODER_SERVICE_PIDS := 512
override CODER_SERVICE_TMPFS_SIZE := 32m
override CODER_SERVERWARE_TMPFS_SIZE := 64m
override CODER_GRANT_STORE_RUN_TMPFS_SIZE := 8m
override CODER_BUILDKIT_CPUS := 8
override CODER_BUILDKIT_MEMORY := 16g
override CODER_BUILDKIT_PIDS := 1024
override CODER_BUILD_FILE_BLOCKS := 524288
override CODER_TEST_FILE_BLOCKS := 262144
override CODER_TASK_IMAGE_TAGS := $(CODER_SHARED_PYTHON_IMAGE) $(CODER_AUDIT_ANCHOR_IMAGE) $(CODER_DEMO_UPSTREAM_IMAGE) $(CODER_DECISION_GATE_IMAGE) $(CODER_RUST_TEST_IMAGE) $(CODER_PROXY_TEST_IMAGE) $(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE) $(CODER_LAUNCHER_ADVERSARIAL_IMAGE)
override CODER_HOST_TOOL_NAMES := basename bash cat chmod cmp curl dirname docker env flock git grep id ln make mkdir openssl python3 readlink rm sed seq sh sha256sum sleep sort stat tail tar timeout uniq
override CODER_DOCKER_ENV = env -i PATH="/usr/local/bin:/usr/bin:/bin" HOME="$${HOME:?}" XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}" DOCKER_CONFIG="$(CODER_DOCKER_CONFIG_DIR)" DOCKER_HOST="$(CODER_DOCKER_HOST)" BUILDX_CONFIG="$(CODER_BUILDX_CONFIG_DIR)"
override CODER_DOCKER = $(CODER_DOCKER_ENV) docker
override CODER_COMPOSE_ENV = $(CODER_DOCKER_ENV) COMPOSE_PROJECT_NAME="$(CODER_COMPOSE_PROJECT_NAME)" COMPOSE_PARALLEL_LIMIT=1 SERVERWARE_DECISION_GATE_DEV_IMAGE="$(CODER_DECISION_GATE_IMAGE)"
override CODER_PREP_COMPOSE = $(CODER_COMPOSE_ENV) docker compose --ansi never --project-directory "$(CODER_FROZEN_SOURCE_DIR)" --file "$(CODER_FROZEN_SOURCE_DIR)/docker-compose.yml" --file "$(CODER_COMPOSE_LIMITS_FILE)"
override CODER_COMPOSE = $(CODER_COMPOSE_ENV) docker compose --ansi never --project-directory "$(CODER_FROZEN_SOURCE_DIR)" --file "$(CODER_FROZEN_SOURCE_DIR)/docker-compose.yml" --file "$(CODER_COMPOSE_LIMITS_FILE)" --file "$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)" --file "$(CODER_COMPOSE_IMAGE_OVERRIDE_FILE)"
override CODER_TEST_COMPOSE = $(CODER_COMPOSE_ENV) docker compose --ansi never --project-directory "$(CODER_FROZEN_SOURCE_DIR)" --file "$(CODER_OUTPUT_DIR)/compose-config.yaml"

define CODER_MUTATION_GUARD_FUNCTIONS
coder_require_mutation_daemon() { \
	test "$(CODER_DOCKER_HOST)" = "unix://$(SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)" || return 2; \
	test "$(SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)" = "/run/serverware/controller-docker-proxy.sock" || return 2; \
	test -d "$(CODER_DOCKER_CONFIG_DIR)" && test ! -L "$(CODER_DOCKER_CONFIG_DIR)" || return 2; \
	test "$$(stat -Lc '%u:%a:%F' "$(CODER_DOCKER_CONFIG_DIR)")" = "$$(id -u):700:directory" || return 2; \
	test -d "$(CODER_BUILDX_CONFIG_DIR)" && test ! -L "$(CODER_BUILDX_CONFIG_DIR)" || return 2; \
	test "$$(stat -Lc '%u:%a:%F' "$(CODER_BUILDX_CONFIG_DIR)")" = "$$(id -u):700:directory" || return 2; \
	for docker_config_entry in \
		"$(CODER_DOCKER_CONFIG_DIR)"/* \
		"$(CODER_DOCKER_CONFIG_DIR)"/.[!.]* \
		"$(CODER_DOCKER_CONFIG_DIR)"/..?*; do \
		test ! -e "$$docker_config_entry" && test ! -L "$$docker_config_entry" || { \
			echo "Coder Docker client configuration must remain empty: $$docker_config_entry" >&2; \
			return 2; \
		}; \
	done; \
	test -f "$(CODER_DAEMON_ID_FILE)" && test ! -L "$(CODER_DAEMON_ID_FILE)" || return 2; \
	test "$$(stat -Lc '%u:%a:%F' "$(CODER_DAEMON_ID_FILE)")" = "$$(id -u):600:regular file" || return 2; \
	recorded_daemon_id="$$(cat "$(CODER_DAEMON_ID_FILE)")" || return 2; \
	test -n "$$recorded_daemon_id" && test -z "$$(printf '%s\n' "$$recorded_daemon_id" | sed -n '2p')" || return 2; \
	printf '%s\n' "$$recorded_daemon_id" \
		| grep -Eq '^([0-9a-f]{64}|[A-Z2-7]{4}(:[A-Z2-7]{4}){11})$$' || return 2; \
	daemon_labels="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{range .Labels}}{{println .}}{{end}}' \
	)" || return 2; \
	printf '%s\n' "$$daemon_labels" | grep -Fx "$(CODER_DAEMON_DISPOSABLE_LABEL)" >/dev/null || return 2; \
	printf '%s\n' "$$daemon_labels" | grep -Fx "$(CODER_DAEMON_NETWORK_LABEL)" >/dev/null || return 2; \
	daemon_id="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.ID}}' \
	)" || return 2; \
	daemon_platform="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.OSType}}/{{.Architecture}}' \
	)" || return 2; \
	case "$$daemon_platform" in linux/amd64|linux/x86_64) ;; *) echo "Coder Docker daemon platform changed before a mutation" >&2; return 2 ;; esac; \
	test "$$daemon_id" = "$$recorded_daemon_id" || { \
		echo "Coder Docker daemon identity changed before a mutation" >&2; \
		return 2; \
	}; \
}; \
coder_mutate() { \
	mutation_timeout="$$1"; \
	shift; \
	if ! coder_require_mutation_daemon; then \
		echo "refusing Docker mutation because the disposable daemon guard failed" >&2; \
		exit 2; \
	fi; \
	$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$$mutation_timeout" "$$@"; \
};
endef

define CODER_HOST_IDENTITY_FUNCTIONS
coder_require_single_line_field() { \
	field_name="$$1"; \
	field_value="$$2"; \
	test -n "$$field_value" || { \
		echo "empty host identity field: $$field_name" >&2; \
		return 2; \
	}; \
	test -z "$$(printf '%s\n' "$$field_value" | sed -n '2p')" || { \
		echo "multiline host identity field: $$field_name" >&2; \
		return 2; \
	}; \
	if printf '%s' "$$field_value" | grep -q "$$(printf '\t')"; then \
		echo "tab in host identity field: $$field_name" >&2; \
		return 2; \
	fi; \
}; \
coder_host_tool_command() { \
	case "$$1" in \
		make) printf '%s\n' "$(firstword $(MAKE))" ;; \
		timeout) printf '%s\n' "$(CODER_TIMEOUT)" ;; \
		*) printf '%s\n' "$$1" ;; \
	esac; \
}; \
coder_record_host_tool() { \
	tool_name="$$1"; \
	tool_command="$$(coder_host_tool_command "$$tool_name")"; \
	coder_require_single_line_field "$$tool_name command" "$$tool_command"; \
	tool_path="$$(command -v "$$tool_command")" || { \
		echo "host tool disappeared: $$tool_name" >&2; \
		return 2; \
	}; \
	tool_realpath="$$(readlink -f "$$tool_path")" || return 2; \
	coder_require_single_line_field "$$tool_name realpath" "$$tool_realpath"; \
	case "$$tool_realpath" in \
		/*) ;; \
		*) echo "host tool realpath is not absolute: $$tool_name" >&2; return 2 ;; \
	esac; \
	case "$$tool_realpath" in \
		*[!A-Za-z0-9_./-]*) echo "host tool realpath is not safely serializable: $$tool_name" >&2; return 2 ;; \
	esac; \
	test -f "$$tool_realpath" && test ! -L "$$tool_realpath" && test -x "$$tool_realpath" || { \
		echo "host tool is not an executable regular file: $$tool_name" >&2; \
		return 2; \
	}; \
	tool_digest_line="$$(sha256sum "$$tool_realpath")" || return 2; \
	tool_digest="$${tool_digest_line%% *}"; \
	test "$${#tool_digest}" -eq 64 || return 2; \
	case "$$tool_digest" in *[!0-9a-f]*) return 2 ;; esac; \
	tool_version_output="$$( \
		LC_ALL=C $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			"$$tool_realpath" --version 2>&1 || true \
	)"; \
	tool_version="$$(printf '%s\n' "$$tool_version_output" | sed -n '1p')"; \
	test -n "$$tool_version" || tool_version=unavailable; \
	coder_require_single_line_field "$$tool_name version" "$$tool_version"; \
	printf 'tool\t%s\t%s\tsha256:%s\t%s\n' \
		"$$tool_name" "$$tool_realpath" "$$tool_digest" "$$tool_version"; \
}; \
coder_plugin_path() { \
	plugin_name="$$1"; \
	case "$$plugin_name" in \
		buildx) plugin_template='{{range .ClientInfo.Plugins}}{{if eq .Name "buildx"}}{{println .Path}}{{end}}{{end}}' ;; \
		compose) plugin_template='{{range .ClientInfo.Plugins}}{{if eq .Name "compose"}}{{println .Path}}{{end}}{{end}}' ;; \
		*) return 2 ;; \
	esac; \
	plugin_path="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format "$$plugin_template" \
	)" || return 2; \
	coder_require_single_line_field "$$plugin_name plugin path" "$$plugin_path"; \
	printf '%s\n' "$$plugin_path"; \
}; \
coder_record_docker_plugin() { \
	plugin_name="$$1"; \
	plugin_path="$$(coder_plugin_path "$$plugin_name")" || { \
		echo "Docker CLI plugin disappeared: $$plugin_name" >&2; \
		return 2; \
	}; \
	plugin_realpath="$$(readlink -f "$$plugin_path")" || return 2; \
	coder_require_single_line_field "$$plugin_name plugin realpath" "$$plugin_realpath"; \
	case "$$plugin_realpath" in \
		/*) ;; \
		*) echo "Docker plugin realpath is not absolute: $$plugin_name" >&2; return 2 ;; \
	esac; \
	case "$$plugin_realpath" in \
		*[!A-Za-z0-9_./-]*) echo "Docker plugin realpath is not safely serializable: $$plugin_name" >&2; return 2 ;; \
	esac; \
	test -f "$$plugin_realpath" && test ! -L "$$plugin_realpath" && test -x "$$plugin_realpath" || { \
		echo "Docker plugin is not an executable regular file: $$plugin_name" >&2; \
		return 2; \
	}; \
	plugin_digest_line="$$(sha256sum "$$plugin_realpath")" || return 2; \
	plugin_digest="$${plugin_digest_line%% *}"; \
	test "$${#plugin_digest}" -eq 64 || return 2; \
	case "$$plugin_digest" in *[!0-9a-f]*) return 2 ;; esac; \
	plugin_version_output="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) "$$plugin_name" version 2>&1 \
	)" || return 2; \
	plugin_version="$$(printf '%s\n' "$$plugin_version_output" | sed -n '1p')"; \
	coder_require_single_line_field "$$plugin_name plugin version" "$$plugin_version"; \
	printf 'docker-plugin\t%s\t%s\tsha256:%s\t%s\n' \
		"$$plugin_name" "$$plugin_realpath" "$$plugin_digest" "$$plugin_version"; \
}; \
coder_write_host_identity() { \
	host_identity_destination="$$1"; \
	host_identity_labels_unsorted="$${host_identity_destination}.labels.unsorted"; \
	host_identity_labels_sorted="$${host_identity_destination}.labels.sorted"; \
	rm -f \
		"$$host_identity_destination" \
		"$$host_identity_labels_unsorted" \
		"$$host_identity_labels_sorted"; \
	coder_require_mutation_daemon; \
	daemon_server_version="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.ServerVersion}}' \
	)" || return 2; \
	daemon_default_runtime="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.DefaultRuntime}}' \
	)" || return 2; \
	daemon_platform="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.OSType}}/{{.Architecture}}' \
	)" || return 2; \
	daemon_id="$$( \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) info --format '{{.ID}}' \
	)" || return 2; \
	$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
		$(CODER_DOCKER) info --format '{{range .Labels}}{{println .}}{{end}}' \
		> "$$host_identity_labels_unsorted"; \
	LC_ALL=C sort -u "$$host_identity_labels_unsorted" > "$$host_identity_labels_sorted"; \
	for daemon_field_name in server-version default-runtime platform id; do \
		case "$$daemon_field_name" in \
			server-version) daemon_field_value="$$daemon_server_version" ;; \
			default-runtime) daemon_field_value="$$daemon_default_runtime" ;; \
			platform) daemon_field_value="$$daemon_platform" ;; \
			id) daemon_field_value="$$daemon_id" ;; \
		esac; \
		coder_require_single_line_field "daemon $$daemon_field_name" "$$daemon_field_value"; \
	done; \
	recipe_shell_realpath="$$(readlink -f "$(SHELL)")" || return 2; \
	test "$$recipe_shell_realpath" = "$$(readlink -f /bin/sh)" || { \
		echo "Make recipe shell no longer resolves from /bin/sh" >&2; \
		return 2; \
	}; \
	recipe_shell_digest_line="$$(sha256sum "$$recipe_shell_realpath")" || return 2; \
	recipe_shell_digest="$${recipe_shell_digest_line%% *}"; \
	test "$${#recipe_shell_digest}" -eq 64 || return 2; \
	case "$$recipe_shell_digest" in *[!0-9a-f]*) return 2 ;; esac; \
	{ \
		printf 'schema\tserverware.coder-ci.hostToolDaemonIdentity/v1\n'; \
		printf 'recipe-shell\t%s\t%s\tsha256:%s\t%s\n' \
			"$(SHELL)" "$$recipe_shell_realpath" "$$recipe_shell_digest" "$(.SHELLFLAGS)"; \
		for tool_name in $(CODER_HOST_TOOL_NAMES); do \
			coder_record_host_tool "$$tool_name"; \
		done; \
		for plugin_name in buildx compose; do \
			coder_record_docker_plugin "$$plugin_name"; \
		done; \
		printf 'daemon\tserver-version\t%s\n' "$$daemon_server_version"; \
		printf 'daemon\tdefault-runtime\t%s\n' "$$daemon_default_runtime"; \
		printf 'daemon\tplatform\t%s\n' "$$daemon_platform"; \
		printf 'daemon\tid\t%s\n' "$$daemon_id"; \
		while IFS= read -r daemon_label || test -n "$$daemon_label"; do \
			coder_require_single_line_field "daemon label" "$$daemon_label"; \
			printf 'daemon-label\t%s\n' "$$daemon_label"; \
		done < "$$host_identity_labels_sorted"; \
	} > "$$host_identity_destination"; \
	chmod 0600 "$$host_identity_destination"; \
	rm -f "$$host_identity_labels_unsorted" "$$host_identity_labels_sorted"; \
	coder_require_mutation_daemon; \
};
endef

_coder-require-clean:
	@set -eu; \
		test "$(SHELL)" = /bin/sh && test "$(.SHELLFLAGS)" = "-eu -c" || { \
			echo "Coder recipe shell or flags are not the closed Makefile values" >&2; \
			exit 2; \
		}; \
		test "$$(id -u)" -ne 0 || { echo "Coder CI must run as a non-root user" >&2; exit 2; }; \
		test -n "$${HOME:-}" || { echo "Coder CI requires HOME" >&2; exit 2; }; \
		test -x /usr/bin/docker || test -x /usr/local/bin/docker || { \
			echo "Coder CI requires Docker in /usr/bin or /usr/local/bin" >&2; \
			exit 2; \
		}; \
		for command in bash basename cat chmod cmp curl dirname docker env flock git grep id ln mkdir openssl python3 readlink rm sed seq sha256sum sh sleep sort stat tail tar uniq "$(firstword $(MAKE))" "$(CODER_TIMEOUT)"; do \
			command -v "$$command" >/dev/null 2>&1 || { echo "missing required command: $$command" >&2; exit 2; }; \
		done; \
		test "$$(git rev-parse --show-toplevel)" = "$(CURDIR)" || { echo "Coder CI must run from the repository root" >&2; exit 2; }; \
		git rev-parse --verify HEAD >/dev/null; \
		dirty="$$(git status --porcelain=v1 --untracked-files=all --ignore-submodules=none)"; \
		if test -n "$$dirty"; then \
			echo "Coder CI requires a clean committed worktree for the frozen run:" >&2; \
			printf '%s\n' "$$dirty" >&2; \
			exit 2; \
		fi

_coder-require-disposable-daemon: _coder-require-clean
	@set -eu; \
		test "$(CODER_DOCKER_HOST)" = "unix://$(SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)"; \
		test "$(SERVERWARE_CONTROLLER_DOCKER_PROXY_SOCKET)" = "/run/serverware/controller-docker-proxy.sock"; \
		test "$(CODER_PLATFORM)" = "linux/amd64"; \
		if test ! -e "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; then \
			(umask 077 && mkdir "$(CODER_REPO_TMP_DIR)"); \
		fi; \
		test -d "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; \
		test "$$(stat -Lc '%u:%F' "$(CODER_REPO_TMP_DIR)")" = "$$(id -u):directory"; \
		case "$$(stat -Lc '%a' "$(CODER_REPO_TMP_DIR)")" in \
			7[0145][0145]) ;; \
			*) echo "repository .tmp must not be group- or world-writable" >&2; exit 2 ;; \
		esac; \
		for controlled_directory in "$(CODER_DOCKER_CONFIG_DIR)" "$(CODER_BUILDX_CONFIG_DIR)"; do \
			if test ! -e "$$controlled_directory" && test ! -L "$$controlled_directory"; then \
				(umask 077 && mkdir "$$controlled_directory"); \
			fi; \
			test -d "$$controlled_directory" && test ! -L "$$controlled_directory"; \
			test "$$(stat -Lc '%u:%a:%F' "$$controlled_directory")" = "$$(id -u):700:directory"; \
		done; \
		for docker_config_entry in \
			"$(CODER_DOCKER_CONFIG_DIR)"/* \
			"$(CODER_DOCKER_CONFIG_DIR)"/.[!.]* \
			"$(CODER_DOCKER_CONFIG_DIR)"/..?*; do \
			test ! -e "$$docker_config_entry" && test ! -L "$$docker_config_entry" || { \
				echo "Coder Docker client configuration must remain empty: $$docker_config_entry" >&2; \
				exit 2; \
			}; \
		done; \
		daemon_labels="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) info --format '{{range .Labels}}{{println .}}{{end}}' \
		)"; \
		printf '%s\n' "$$daemon_labels" | grep -Fx "$(CODER_DAEMON_DISPOSABLE_LABEL)" >/dev/null || { \
			echo "Docker daemon is not labeled as a disposable Serverware Coder daemon" >&2; \
			exit 2; \
		}; \
		printf '%s\n' "$$daemon_labels" | grep -Fx "$(CODER_DAEMON_NETWORK_LABEL)" >/dev/null || { \
			echo "Docker daemon does not declare the workspace-shared network contract" >&2; \
			exit 2; \
		}; \
		daemon_os="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) info --format '{{.OSType}}' \
		)"; \
		daemon_arch="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) info --format '{{.Architecture}}' \
		)"; \
		test "$$daemon_os" = linux || { echo "Coder Docker daemon must be Linux" >&2; exit 2; }; \
		case "$$daemon_arch" in amd64|x86_64) ;; *) echo "Coder Docker daemon must be amd64" >&2; exit 2 ;; esac; \
		daemon_id="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) info --format '{{.ID}}' \
		)"; \
		test -n "$$daemon_id" && test -z "$$(printf '%s\n' "$$daemon_id" | sed -n '2p')"; \
		printf '%s\n' "$$daemon_id" \
			| grep -Eq '^([0-9a-f]{64}|[A-Z2-7]{4}(:[A-Z2-7]{4}){11})$$' || { \
				echo "Coder Docker daemon ID is not canonical" >&2; \
				exit 2; \
			}; \
		daemon_id_mode="$${CODER_DAEMON_ID_MODE:-require-if-present}"; \
		case "$$daemon_id_mode" in record|require|require-if-present) ;; \
			*) echo "CODER_DAEMON_ID_MODE must be record, require, or require-if-present" >&2; exit 2 ;; \
		esac; \
		if test -e "$(CODER_DAEMON_ID_FILE)" || test -L "$(CODER_DAEMON_ID_FILE)"; then \
			test -f "$(CODER_DAEMON_ID_FILE)" && test ! -L "$(CODER_DAEMON_ID_FILE)"; \
			test "$$(cat "$(CODER_DAEMON_ID_FILE)")" = "$$daemon_id" || { \
				echo "Coder Docker daemon identity changed after the build" >&2; \
				exit 2; \
			}; \
		elif test "$$daemon_id_mode" = require; then \
			echo "recorded Coder Docker daemon identity is missing" >&2; \
			exit 2; \
		elif test "$$daemon_id_mode" = record; then \
			test -d "$(CODER_OUTPUT_DIR)" && test ! -L "$(CODER_OUTPUT_DIR)"; \
			test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)")" = "$$(id -u):700:directory"; \
			printf '%s\n' "$$daemon_id" > "$(CODER_DAEMON_ID_FILE)"; \
			chmod 0600 "$(CODER_DAEMON_ID_FILE)"; \
		fi

_coder-require-lock:
	@set -eu; \
		lock_fd="$${CODER_LOCK_FD:-}"; \
		lock_path="$${CODER_LOCK_PATH:-}"; \
		expected_lock_path="$(CODER_LOCK_DIRECTORY)"; \
		test "$$lock_fd" = 9 || { \
			echo "private Coder helper requires inherited lock descriptor 9" >&2; \
			exit 2; \
		}; \
		test "$$lock_path" = "$$expected_lock_path" || { \
			echo "private Coder helper received an unexpected lock path" >&2; \
			exit 2; \
		}; \
		test "$$(readlink "/proc/self/fd/$$lock_fd")" = "$$expected_lock_path" || { \
			echo "Coder lock descriptor does not reference the per-user lock directory" >&2; \
			exit 2; \
		}; \
		test "$$(stat -Lc '%u:%F' "/proc/self/fd/$$lock_fd")" = "0:directory" || { \
			echo "Coder lock descriptor is not the root-owned global lock directory" >&2; \
			exit 2; \
		}; \
		flock --exclusive --nonblock "$$lock_fd" || { \
			echo "Coder lock descriptor is not exclusively held" >&2; \
			exit 2; \
		}

_coder-cleanup: _coder-require-lock
	@set -eu; \
		test "$$(id -u)" -ne 0 || { echo "Coder cleanup must run as a non-root user" >&2; exit 2; }; \
		test -n "$${HOME:-}" || { echo "Coder cleanup requires HOME" >&2; exit 2; }; \
		test -x /usr/bin/docker || test -x /usr/local/bin/docker || { \
			echo "Coder cleanup requires Docker in /usr/bin or /usr/local/bin" >&2; \
			exit 2; \
		}; \
		for command in cat docker env grep id rm sed sort stat "$(CODER_TIMEOUT)"; do \
			command -v "$$command" >/dev/null 2>&1 || { echo "missing cleanup command: $$command" >&2; exit 2; }; \
		done; \
		unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CUSTOM_HEADERS DOCKER_HOST DOCKER_TLS_VERIFY BUILDX_BUILDER BUILDX_CONFIG; \
		PATH=/usr/local/bin:/usr/bin:/bin; \
		XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}"; \
		export PATH HOME XDG_RUNTIME_DIR; \
		$(CODER_MUTATION_GUARD_FUNCTIONS) \
		coder_require_mutation_daemon; \
		ulimit -f "$(CODER_TEST_FILE_BLOCKS)"; \
		case "$(CODER_REPO_TMP_DIR)" in /*) ;; *) echo "Coder artifact root must be absolute" >&2; exit 2 ;; esac; \
		test "$(CODER_REPO_TMP_DIR)" != "$(CURDIR)"; \
		case "$(CODER_REPO_TMP_DIR)/" in "$(CURDIR)/"*) echo "Coder artifact root must be outside the source tree" >&2; exit 2 ;; esac; \
		test "$(CODER_OUTPUT_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-ci"; \
		test -d "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; \
		test "$$(stat -Lc '%u:%F' "$(CODER_REPO_TMP_DIR)")" = "$$(id -u):directory"; \
		case "$$(stat -Lc '%a' "$(CODER_REPO_TMP_DIR)")" in \
			7[0145][0145]) ;; \
			*) echo "repository .tmp must not be group- or world-writable" >&2; exit 2 ;; \
		esac; \
			test -d "$(CODER_OUTPUT_DIR)" && test ! -L "$(CODER_OUTPUT_DIR)"; \
			test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)")" = "$$(id -u):700:directory"; \
			launcher_adversarial_build_tmp="$(CODER_OUTPUT_DIR)/launcher-adversarial-build-tmp"; \
			if test -e "$$launcher_adversarial_build_tmp" || test -L "$$launcher_adversarial_build_tmp"; then \
				test -d "$$launcher_adversarial_build_tmp" && \
					test ! -L "$$launcher_adversarial_build_tmp" && \
					test "$$(stat -Lc '%u:%F' "$$launcher_adversarial_build_tmp")" = "$$(id -u):directory" || { \
					echo "refusing unsafe launcher adversarial build temporary directory" >&2; \
					exit 2; \
				}; \
				rm -rf "$$launcher_adversarial_build_tmp"; \
			fi; \
			if test "$$controller_stage" = unit || test "$$controller_stage" = all; then \
			rm -f \
				"$(CODER_OUTPUT_DIR)/cleanup.log" \
			"$(CODER_OUTPUT_DIR)/builder-containers.txt" \
			"$(CODER_OUTPUT_DIR)/builder-volumes.txt" \
			"$(CODER_OUTPUT_DIR)/builder-records.txt" \
			"$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
		: > "$(CODER_OUTPUT_DIR)/cleanup.log"; \
		status=0; \
		for ownership_artifact in "$(CODER_RUN_TOKEN_FILE)" "$(CODER_RESOURCE_OWNERSHIP_FILE)"; do \
			test -f "$$ownership_artifact" && test ! -L "$$ownership_artifact" || { \
				echo "refusing cleanup without a regular ownership artifact: $$ownership_artifact" >&2; \
				exit 2; \
			}; \
			test "$$(stat -Lc '%u:%a:%F' "$$ownership_artifact")" = "$$(id -u):600:regular file" || { \
				echo "refusing cleanup with unsafe ownership artifact metadata: $$ownership_artifact" >&2; \
				exit 2; \
			}; \
		done; \
			run_owner_token="$$(cat "$(CODER_RUN_TOKEN_FILE)")"; \
			test -n "$$run_owner_token" && test -z "$$(sed -n '2p' "$(CODER_RUN_TOKEN_FILE)")"; \
				test "$${#run_owner_token}" -eq 64; \
				case "$$run_owner_token" in *[!0-9a-f]*) echo "invalid Coder run owner token" >&2; exit 2 ;; esac; \
				builder_suffix="$$(printf '%.24s' "$$run_owner_token")"; \
				builder_name="$(CODER_BUILDER_NAME_PREFIX)$$builder_suffix"; \
				builder_container="buildx_buildkit_$${builder_name}0"; \
				builder_state_volume="$${builder_container}_state"; \
				ownership_tab="$$(printf '\t')"; \
				measurement_recovery_ids="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc \
							--filter "name=^/$(CODER_DECISION_GATE_MEASURE_CONTAINER)$$" \
				)" || measurement_recovery_ids=""; \
				if test -n "$$measurement_recovery_ids"; then \
					test -z "$$(printf '%s\n' "$$measurement_recovery_ids" | sed -n '2p')" || { \
						echo "refusing ambiguous decision-gate measurement recovery" >&2; \
						status=1; \
						measurement_recovery_ids=""; \
					}; \
				fi; \
				if test -n "$$measurement_recovery_ids"; then \
					measurement_recovery_cid="$$measurement_recovery_ids"; \
					case "$$measurement_recovery_cid" in *[!0-9a-f]*) \
						echo "refusing noncanonical decision-gate measurement recovery CID" >&2; \
						status=1; \
						measurement_recovery_cid="" ;; \
					esac; \
				fi; \
				if test -n "$${measurement_recovery_cid:-}"; then \
					test "$${#measurement_recovery_cid}" -eq 64 || { \
						echo "refusing truncated decision-gate measurement recovery CID" >&2; \
						status=1; \
						measurement_recovery_cid=""; \
					}; \
				fi; \
				if test -n "$${measurement_recovery_cid:-}"; then \
					test -f "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)" && \
						test ! -L "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)" && \
						test "$$(stat -Lc '%u:%a:%F' "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)")" = "$$(id -u):600:regular file" || { \
						echo "refusing measurement recovery without its protected image binding" >&2; \
						status=1; \
						measurement_recovery_cid=""; \
					}; \
				fi; \
				if test -n "$${measurement_recovery_cid:-}"; then \
					measurement_recovery_image="$$(cat "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)")"; \
					test -n "$$measurement_recovery_image" && \
						test -z "$$(sed -n '2p' "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)")" || { \
						echo "refusing malformed measurement image binding" >&2; \
						status=1; \
						measurement_recovery_cid=""; \
					}; \
				fi; \
				if test -n "$${measurement_recovery_cid:-}"; then \
					case "$$measurement_recovery_image" in sha256:*) ;; \
						*) echo "refusing noncanonical measurement image binding" >&2; status=1; measurement_recovery_cid="" ;; \
					esac; \
					measurement_recovery_image_digest="$${measurement_recovery_image#sha256:}"; \
					case "$$measurement_recovery_image_digest" in *[!0-9a-f]*) \
						echo "refusing noncanonical measurement image digest" >&2; \
						status=1; \
						measurement_recovery_cid="" ;; \
					esac; \
					test -z "$${measurement_recovery_cid:-}" || \
						test "$${#measurement_recovery_image}" -eq 71 || { \
						echo "refusing malformed measurement image digest" >&2; \
						status=1; \
						measurement_recovery_cid=""; \
					}; \
				fi; \
				if test -n "$${measurement_recovery_cid:-}"; then \
					measurement_recovery_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$measurement_recovery_cid" 2>/dev/null \
					)" || measurement_recovery_identity=""; \
					if test "$$measurement_recovery_identity" != "$$measurement_recovery_image|/$(CODER_DECISION_GATE_MEASURE_CONTAINER)|decision-gate-measure|$$run_owner_token"; then \
						echo "refusing measurement recovery with mismatched image, name, resource, or owner" >&2; \
						status=1; \
					else \
						measurement_recovery_record="$$(printf 'container\t%s\tdecision-gate-measure\t%s\t%s' \
							"$(CODER_DECISION_GATE_MEASURE_CONTAINER)" "$$run_owner_token" "$$measurement_recovery_cid")"; \
						if ! grep -Fx "$$measurement_recovery_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
							printf '%s\n' "$$measurement_recovery_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
						fi; \
					fi; \
				fi; \
				for recovery_spec in \
					"$(CODER_RUST_TEST_CONTAINER)|rust-unit-tests|$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_codebase_attestation.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_control_plane_startup.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_launch_authority_service.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_launch_authorization.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_nitro_nsm_attest.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_production_release_proof_target.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_release_completion.cid" \
					"$(CODER_ISOLATED_TEST_CONTAINER)|isolated-test|$(CODER_OUTPUT_DIR)/test_run_production_readiness.cid" \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_CONTAINER)|production-host-preflight|$(CODER_OUTPUT_DIR)/test_production_host_preflight.cid" \
					"$(CODER_LAUNCHER_ADVERSARIAL_CONTAINER)|launcher-adversarial|$(CODER_OUTPUT_DIR)/test_production_launcher_adversarial.cid" \
					"$(CODER_PROXY_TEST_CONTAINER)|proxy-tests|$(CODER_OUTPUT_DIR)/test_credential_constraints.cid" \
				"$(CODER_PROXY_TEST_CONTAINER)|proxy-tests|$(CODER_OUTPUT_DIR)/test_credential_constraints_proxy_transport.cid" \
				"$(CODER_PROXY_TEST_CONTAINER)|proxy-tests|$(CODER_OUTPUT_DIR)/test_jit_transaction_state.cid"; do \
				recovery_name="$${recovery_spec%%|*}"; \
				recovery_rest="$${recovery_spec#*|}"; \
				recovery_resource="$${recovery_rest%%|*}"; \
				recovery_cid_file="$${recovery_rest#*|}"; \
				recovery_cid=""; \
				if test -e "$$recovery_cid_file" || test -L "$$recovery_cid_file"; then \
					test -f "$$recovery_cid_file" && test ! -L "$$recovery_cid_file" && \
						test "$$(stat -Lc '%u:%F' "$$recovery_cid_file")" = "$$(id -u):regular file" || { \
						echo "refusing unsafe recovery CID file: $$recovery_cid_file" >&2; \
						status=1; \
						continue; \
					}; \
					recovery_cid="$$(cat "$$recovery_cid_file")"; \
					test -n "$$recovery_cid" && test -z "$$(sed -n '2p' "$$recovery_cid_file")" || { \
						echo "refusing malformed recovery CID file: $$recovery_cid_file" >&2; \
						status=1; \
						continue; \
					}; \
				else \
					if ! recovery_cid="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) ps --all --quiet --no-trunc \
								--filter "name=^/$${recovery_name}$$" \
					)"; then \
						echo "could not enumerate fixed-name recovery container: $$recovery_name" >&2; \
						status=1; \
						continue; \
					fi; \
					test -n "$$recovery_cid" || continue; \
					test -z "$$(printf '%s\n' "$$recovery_cid" | sed -n '2p')" || { \
						echo "refusing ambiguous fixed-name recovery: $$recovery_name" >&2; \
						status=1; \
						continue; \
					}; \
				fi; \
				case "$$recovery_cid" in *[!0-9a-f]*) status=1; continue ;; esac; \
				test "$${#recovery_cid}" -eq 64 || { status=1; continue; }; \
				recovery_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$recovery_cid" 2>/dev/null \
				)" || continue; \
				if test "$$recovery_identity" != "/$$recovery_name|$$recovery_resource|$$run_owner_token"; then \
					echo "refusing recovery CID with mismatched name, resource, or owner: $$recovery_cid" >&2; \
					status=1; \
					continue; \
				fi; \
				rm -f "$$recovery_cid_file"; \
				(umask 077 && printf '%s\n' "$$recovery_cid" > "$$recovery_cid_file"); \
				recovery_record="$$(printf 'container\t%s\t%s\t%s\t%s' \
					"$$recovery_name" "$$recovery_resource" "$$run_owner_token" "$$recovery_cid")"; \
					if ! grep -Fx "$$recovery_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
						printf '%s\n' "$$recovery_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
					fi; \
				done; \
				compose_recovery_ids="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc \
							--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
				)" || { \
					echo "could not enumerate Compose containers for ownership recovery" >&2; \
					status=1; \
					compose_recovery_ids=""; \
				}; \
				for compose_recovery_cid in $$compose_recovery_ids; do \
					case "$$compose_recovery_cid" in *[!0-9a-f]*) \
						echo "refusing noncanonical Compose recovery CID" >&2; \
						status=1; \
						continue ;; \
					esac; \
					test "$${#compose_recovery_cid}" -eq 64 || { \
						echo "refusing truncated Compose recovery CID" >&2; \
						status=1; \
						continue; \
					}; \
					compose_recovery_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{.Name}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.oneoff"}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$compose_recovery_cid" 2>/dev/null \
					)" || compose_recovery_identity=""; \
					compose_recovery_name="$${compose_recovery_identity%%|*}"; \
					compose_recovery_rest="$${compose_recovery_identity#*|}"; \
					compose_recovery_project="$${compose_recovery_rest%%|*}"; \
					compose_recovery_rest="$${compose_recovery_rest#*|}"; \
					compose_recovery_service="$${compose_recovery_rest%%|*}"; \
					compose_recovery_rest="$${compose_recovery_rest#*|}"; \
					compose_recovery_oneoff="$${compose_recovery_rest%%|*}"; \
					compose_recovery_rest="$${compose_recovery_rest#*|}"; \
					compose_recovery_resource="$${compose_recovery_rest%%|*}"; \
					compose_recovery_owner="$${compose_recovery_rest#*|}"; \
					compose_recovery_name="$${compose_recovery_name#/}"; \
					case " $(CODER_RUNTIME_SERVICES) " in *" $$compose_recovery_service "*) ;; \
						*) echo "refusing Compose recovery outside the closed service set: $$compose_recovery_cid" >&2; status=1; continue ;; \
					esac; \
					expected_compose_recovery_name="$(CODER_COMPOSE_PROJECT_NAME)-$$compose_recovery_service-1"; \
					if test "$$compose_recovery_project" != "$(CODER_COMPOSE_PROJECT_NAME)" || \
						test "$$compose_recovery_oneoff" != "False" || \
						test "$$compose_recovery_resource" != "$$compose_recovery_service" || \
						test "$$compose_recovery_owner" != "$$run_owner_token" || \
						test "$$compose_recovery_name" != "$$expected_compose_recovery_name"; then \
						echo "refusing Compose recovery with mismatched project, service, name, resource, or owner: $$compose_recovery_cid" >&2; \
						status=1; \
						continue; \
					fi; \
					compose_recovery_record="$$(printf 'container\t%s\t%s\t%s\t%s' \
						"$$compose_recovery_name" "$$compose_recovery_service" "$$run_owner_token" "$$compose_recovery_cid")"; \
					if ! grep -Fx "$$compose_recovery_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
						printf '%s\n' "$$compose_recovery_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
					fi; \
				done; \
				while IFS="$$ownership_tab" read -r resource_kind resource_name resource_label recorded_owner resource_id resource_extra; do \
			test -n "$$resource_kind" || continue; \
			test -z "$${resource_extra:-}" && test "$$recorded_owner" = "$$run_owner_token" || { \
				echo "refusing malformed or cross-run ownership record for $$resource_name" >&2; \
				status=1; \
				continue; \
			}; \
			test "$$resource_kind" = container || continue; \
			current_name="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{.Name}}' "$$resource_id" 2>/dev/null \
			)" || continue; \
			current_resource_label="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}' "$$resource_id" \
			)" || { status=1; continue; }; \
			current_owner="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$resource_id" \
			)" || { status=1; continue; }; \
			if test "$$current_name" != "/$$resource_name" || \
				test "$$current_resource_label" != "$$resource_label" || \
				test "$$current_owner" != "$$run_owner_token"; then \
				echo "refusing to remove container with mismatched name, label, token, or recorded CID: $$resource_id" >&2; \
				status=1; \
				continue; \
			fi; \
			coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
				$(CODER_DOCKER) rm -f "$$resource_id" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || status=1; \
				done < "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				builder_container_id=""; \
				builder_record_owned=0; \
			while IFS="$$ownership_tab" read -r resource_kind resource_name resource_label recorded_owner resource_id resource_extra; do \
				if test "$$resource_kind" = buildkit-container && \
				test "$$resource_name" = "$$builder_container" && \
				test "$$resource_label" = buildx-builder && \
				test "$$recorded_owner" = "$$run_owner_token" && \
					test -z "$${resource_extra:-}"; then \
					builder_container_id="$$resource_id"; \
				elif test "$$resource_kind" = buildkit-record && \
					test "$$resource_name" = "$$builder_name" && \
					test "$$resource_label" = buildx-builder && \
					test "$$recorded_owner" = "$$run_owner_token" && \
					test -n "$$builder_container_id" && \
					test "$$resource_id" = "$$builder_container_id" && \
					test -z "$${resource_extra:-}"; then \
					builder_record_owned=1; \
					fi; \
				done < "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				if test -z "$$builder_container_id"; then \
					recovered_builder_ids="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) ps --all --quiet --no-trunc \
								--filter "name=^/$${builder_container}$$" \
					)" || recovered_builder_ids=""; \
					if test -n "$$recovered_builder_ids" && \
						test -z "$$(printf '%s\n' "$$recovered_builder_ids" | sed -n '2p')"; then \
						case "$$recovered_builder_ids" in *[!0-9a-f]*) recovered_builder_ids="" ;; esac; \
						test -z "$$recovered_builder_ids" || test "$${#recovered_builder_ids}" -eq 64 || recovered_builder_ids=""; \
					else \
						recovered_builder_ids=""; \
					fi; \
					if test -n "$$recovered_builder_ids"; then \
						recovered_builder_label="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) container inspect --format '{{index .Config.Labels "com.docker.buildx.builder"}}' "$$recovered_builder_ids" \
						)" || recovered_builder_label=""; \
						recovered_builder_owner="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$$recovered_builder_ids" \
								| grep -Fx "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" \
						)" || recovered_builder_owner=""; \
						recovered_builder_volume="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) container inspect \
									--format '{{range .Mounts}}{{if eq .Destination "/var/lib/buildkit"}}{{.Name}}{{end}}{{end}}' \
									"$$recovered_builder_ids" \
						)" || recovered_builder_volume=""; \
						if test "$$recovered_builder_label" = "$$builder_name" && \
							test "$$recovered_builder_owner" = "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" && \
							test "$$recovered_builder_volume" = "$$builder_state_volume"; then \
							builder_container_id="$$recovered_builder_ids"; \
							printf 'buildkit-container\t%s\tbuildx-builder\t%s\t%s\n' \
								"$$builder_container" "$$run_owner_token" "$$builder_container_id" \
								>> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
						else \
							echo "refusing to recover a BuildKit container without exact builder and owner identities" >&2; \
							status=1; \
						fi; \
					fi; \
				fi; \
			if test -n "$$builder_container_id"; then \
				current_builder_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$${builder_container}$$" \
				)" || current_builder_id=""; \
				if test -n "$$current_builder_id" && test "$$current_builder_id" != "$$builder_container_id"; then \
					echo "refusing to remove an unowned same-name BuildKit container" >&2; \
					status=1; \
				elif test "$$current_builder_id" = "$$builder_container_id"; then \
					current_builder_label="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{index .Config.Labels "com.docker.buildx.builder"}}' "$$current_builder_id" \
					)" || current_builder_label=""; \
					current_builder_owner="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$$current_builder_id" \
							| grep -Fx "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" \
					)" || current_builder_owner=""; \
					current_builder_volume="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{range .Mounts}}{{if eq .Destination "/var/lib/buildkit"}}{{.Name}}{{end}}{{end}}' \
								"$$current_builder_id" \
					)" || current_builder_volume=""; \
					if test "$$current_builder_label" != "$$builder_name" || \
						test "$$current_builder_owner" != "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" || \
						test "$$current_builder_volume" != "$$builder_state_volume"; then \
						echo "refusing to remove a BuildKit container without matching builder and owner identities" >&2; \
						status=1; \
					else \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) rm -f "$$current_builder_id" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || status=1; \
					fi; \
				fi; \
				elif $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$${builder_container}$$" | grep -q .; then \
					echo "refusing to remove an unrecorded same-name BuildKit container" >&2; \
					status=1; \
				elif test "$$builder_record_owned" = 1; then \
					if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) buildx ls --format '{{.Name}}' \
						> "$(CODER_OUTPUT_DIR)/builder-records.txt" 2>> "$(CODER_OUTPUT_DIR)/cleanup.log"; then \
						if grep -Fx "$$builder_name" "$(CODER_OUTPUT_DIR)/builder-records.txt" >/dev/null; then \
							echo "owned Buildx registration remains in the private client config after container cleanup" >&2; \
						fi; \
					else \
						status=1; \
					fi; \
				fi; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume inspect "$$builder_state_volume" >/dev/null 2>&1; then \
					builder_volume_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) volume inspect \
								--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
								"$$builder_state_volume" \
					)" || builder_volume_identity=""; \
					builder_volume_record="$$(printf 'volume\t%s\tbuildkit-state\t%s\t%s' \
						"$$builder_state_volume" "$$run_owner_token" "$$builder_state_volume")"; \
					if test "$$builder_volume_identity" != "$$builder_state_volume|buildkit-state|$$run_owner_token"; then \
						echo "refusing to remove an unowned BuildKit state volume" >&2; \
						status=1; \
					else \
						grep -Fx "$$builder_volume_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || \
							printf '%s\n' "$$builder_volume_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) volume rm "$$builder_state_volume" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || status=1; \
					fi; \
				fi; \
				test "$(CODER_BUILDX_CONFIG_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-buildx-config"; \
				test -d "$(CODER_BUILDX_CONFIG_DIR)" && test ! -L "$(CODER_BUILDX_CONFIG_DIR)" && \
					test "$$(stat -Lc '%u:%a:%F' "$(CODER_BUILDX_CONFIG_DIR)")" = "$$(id -u):700:directory" || { \
						echo "refusing unsafe Buildx client configuration cleanup" >&2; \
						exit 2; \
					}; \
				rm -rf "$(CODER_BUILDX_CONFIG_DIR)"; \
				(umask 077 && mkdir "$(CODER_BUILDX_CONFIG_DIR)"); \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; then \
			echo "could not inspect task-owned containers after Compose cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		fi; \
		if test -n "$$remaining"; then \
			echo "refusing to remove unrecorded or ownership-mismatched Compose containers: $$remaining" >&2; \
			status=1; \
		fi; \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; then \
			echo "could not verify task-owned container absence" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		fi; \
		if test -n "$$remaining"; then \
			echo "task-owned containers remain after cleanup: $$remaining" >&2; \
			status=1; \
		fi; \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$(CODER_RUST_TEST_CONTAINER)$$" \
			)"; then \
			echo "could not verify task-owned Rust test container absence" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		fi; \
			if test -n "$$remaining"; then \
				echo "task-owned Rust test containers remain after cleanup: $$remaining" >&2; \
				status=1; \
			fi; \
			remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$(CODER_PROXY_TEST_CONTAINER)$$" \
			)"; then \
				echo "could not verify task-owned proxy test container absence" \
					>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
				status=1; \
			fi; \
			if test -n "$$remaining"; then \
				echo "task-owned proxy test containers remain after cleanup: $$remaining" >&2; \
				status=1; \
			fi; \
			remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$(CODER_ISOLATED_TEST_CONTAINER)$$" \
			)"; then \
				echo "could not verify task-owned isolated test container absence" \
					>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
				status=1; \
			fi; \
				if test -n "$$remaining"; then \
					echo "task-owned isolated test containers remain after cleanup: $$remaining" >&2; \
					status=1; \
				fi; \
				remaining=""; \
				if ! remaining="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$(CODER_LAUNCHER_ADVERSARIAL_CONTAINER)$$" \
				)"; then \
					echo "could not verify launcher adversarial container absence" \
						>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
					status=1; \
				fi; \
				if test -n "$$remaining"; then \
					echo "launcher adversarial containers remain after cleanup: $$remaining" >&2; \
					status=1; \
				fi; \
				remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$(CODER_DECISION_GATE_MEASURE_CONTAINER)$$" \
			)"; then \
				echo "could not verify decision-gate measurement container absence" \
					>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
				status=1; \
			fi; \
			if test -n "$$remaining"; then \
				echo "decision-gate measurement containers remain after cleanup: $$remaining" >&2; \
				status=1; \
			fi; \
			compose_recovery_networks="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) network ls -q \
						--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)" || compose_recovery_networks=""; \
			for recovery_network_id in $$compose_recovery_networks; do \
				recovery_network_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) network inspect \
							--format '{{.Id}}|{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
							"$$recovery_network_id" \
				)" || recovery_network_identity=""; \
				if test "$$recovery_network_identity" != "$$recovery_network_id|$(CODER_COMPOSE_PROJECT_NAME)_default|compose-default-network|$$run_owner_token"; then \
					echo "refusing unsafe partial Compose network recovery" >&2; \
					status=1; \
					continue; \
				fi; \
				recovery_network_record="$$(printf 'network\t%s\tcompose-default-network\t%s\t%s' \
					"$(CODER_COMPOSE_PROJECT_NAME)_default" "$$run_owner_token" "$$recovery_network_id")"; \
				grep -Fx "$$recovery_network_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || \
					printf '%s\n' "$$recovery_network_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
			done; \
			compose_recovery_volumes="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume ls -q \
						--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)" || compose_recovery_volumes=""; \
			for recovery_volume in $$compose_recovery_volumes; do \
				recovery_volume_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume inspect \
							--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
							"$$recovery_volume" \
				)" || recovery_volume_identity=""; \
				recovery_volume_resource="$$(printf '%s\n' "$$recovery_volume_identity" | sed 's/^[^|]*|\\([^|]*\\)|.*$$/\\1/')"; \
				case "$$recovery_volume_resource" in \
					serverware-data|serverware-audit-anchors|serverware-grant-store|serverware-custody-socket|serverware-custody-trust|serverware-custody-state|serverware-response-signing-private) ;; \
					*) echo "refusing unsafe partial Compose volume recovery" >&2; status=1; continue ;; \
				esac; \
				if test "$$recovery_volume_identity" != "$$recovery_volume|$$recovery_volume_resource|$$run_owner_token" || \
					test "$$recovery_volume" != "$(CODER_COMPOSE_PROJECT_NAME)_$$recovery_volume_resource"; then \
					echo "refusing mismatched partial Compose volume recovery" >&2; \
					status=1; \
					continue; \
				fi; \
				recovery_volume_record="$$(printf 'volume\t%s\t%s\t%s\t%s' \
					"$$recovery_volume" "$$recovery_volume_resource" "$$run_owner_token" "$$recovery_volume")"; \
				grep -Fx "$$recovery_volume_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || \
					printf '%s\n' "$$recovery_volume_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
			done; \
			while IFS="$$ownership_tab" read -r resource_kind resource_name resource_label recorded_owner resource_id resource_extra; do \
				test -z "$${resource_extra:-}" && test "$$recorded_owner" = "$$run_owner_token" || continue; \
				case "$$resource_kind" in \
					network) \
						test "$$resource_name" = "$(CODER_COMPOSE_PROJECT_NAME)_default" && \
							test "$$resource_label" = compose-default-network || { \
								echo "refusing undeclared network ownership record" >&2; status=1; continue; \
							}; \
						network_identity="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) network inspect \
									--format '{{.Id}}|{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
									"$$resource_id" 2>/dev/null \
						)" || continue; \
						if test "$$network_identity" != "$$resource_id|$$resource_name|$$resource_label|$$run_owner_token"; then \
							echo "refusing to remove network with mismatched exact ownership: $$resource_name" >&2; \
							status=1; \
							continue; \
						fi; \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) network rm "$$resource_id" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || status=1 \
						;; \
					volume) \
						test "$$resource_label" != buildkit-state || continue; \
						case "$$resource_label" in \
							serverware-data|serverware-audit-anchors|serverware-grant-store|serverware-custody-socket|serverware-custody-trust|serverware-custody-state|serverware-response-signing-private) ;; \
							*) echo "refusing undeclared volume ownership record" >&2; status=1; continue ;; \
						esac; \
						test "$$resource_name" = "$(CODER_COMPOSE_PROJECT_NAME)_$$resource_label" || { status=1; continue; }; \
						volume_identity="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) volume inspect \
									--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
									"$$resource_name" 2>/dev/null \
						)" || continue; \
						if test "$$resource_id" != "$$resource_name" || \
							test "$$volume_identity" != "$$resource_name|$$resource_label|$$run_owner_token"; then \
							echo "refusing to remove volume with mismatched exact ownership: $$resource_name" >&2; \
							status=1; \
							continue; \
						fi; \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) volume rm "$$resource_name" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || status=1 \
						;; \
				esac; \
			done < "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
			remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) network ls -q \
						--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
						--filter "label=$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
			)"; then \
			echo "could not inspect task-owned networks after Compose cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		fi; \
			if test -n "$$remaining"; then \
				echo "unrecorded task-labeled networks remain after exact cleanup: $$remaining" >&2; \
				status=1; \
			fi; \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) network ls -q --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; then \
			status=1; \
		elif test -n "$$remaining"; then \
			echo "task-owned networks remain after cleanup: $$remaining" >&2; \
			status=1; \
		fi; \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume ls -q \
						--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
						--filter "label=$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
			)"; then \
			echo "could not inspect task-owned volumes after Compose cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		fi; \
			if test -n "$$remaining"; then \
				echo "unrecorded task-labeled volumes remain after exact cleanup: $$remaining" >&2; \
				status=1; \
			fi; \
		remaining=""; \
			if ! remaining="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume ls -q --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; then \
			status=1; \
		elif test -n "$$remaining"; then \
			echo "task-owned volumes remain after cleanup: $$remaining" >&2; \
			status=1; \
		fi; \
			if ! $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) ps -a --format '{{.Names}}' \
				> "$(CODER_OUTPUT_DIR)/builder-containers.txt"; then \
			echo "could not enumerate containers after Buildx cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		elif grep -Fx "$$builder_container" "$(CODER_OUTPUT_DIR)/builder-containers.txt" >/dev/null; then \
			echo "task-owned Buildx container remains after cleanup: $$builder_container" >&2; \
			status=1; \
			fi; \
			if ! $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) volume ls --format '{{.Name}}' \
				> "$(CODER_OUTPUT_DIR)/builder-volumes.txt"; then \
			echo "could not enumerate volumes after Buildx cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		elif grep -Fx "$$builder_state_volume" "$(CODER_OUTPUT_DIR)/builder-volumes.txt" >/dev/null; then \
			echo "task-owned Buildx state volume remains after cleanup: $$builder_state_volume" >&2; \
			status=1; \
			fi; \
			if ! $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) buildx ls --format '{{.Name}}' \
				> "$(CODER_OUTPUT_DIR)/builder-records.txt"; then \
			echo "could not enumerate Buildx builder records after cleanup" \
				>> "$(CODER_OUTPUT_DIR)/cleanup.log"; \
			status=1; \
		elif grep -Fx "$$builder_name" "$(CODER_OUTPUT_DIR)/builder-records.txt" >/dev/null; then \
			echo "the private Buildx registration remains after cleanup" >&2; \
			status=1; \
		fi; \
		if test "$${CODER_REMOVE_IMAGES:-0}" = 1; then \
			: > "$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
			if test -f "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" && test ! -L "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; then \
				for recovery_image_spec in \
					"$(CODER_RUST_TEST_IMAGE)|$(CODER_OUTPUT_DIR)/rust-test-image.iid" \
					"$(CODER_PROXY_TEST_IMAGE)|$(CODER_OUTPUT_DIR)/proxy-test-image.iid" \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)|$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" \
					"$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)|$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)"; do \
					recovery_image_ref="$${recovery_image_spec%%|*}"; \
					recovery_iid_file="$${recovery_image_spec#*|}"; \
					test -e "$$recovery_iid_file" || test -L "$$recovery_iid_file" || continue; \
					test -f "$$recovery_iid_file" && test ! -L "$$recovery_iid_file" || { status=1; continue; }; \
					recovery_image_id="$$(cat "$$recovery_iid_file")"; \
					case "$$recovery_image_id" in sha256:[0-9a-f]*) ;; *) status=1; continue ;; esac; \
					test "$${#recovery_image_id}" -eq 71 || { status=1; continue; }; \
					recovery_image_digest="$${recovery_image_id#sha256:}"; \
					case "$$recovery_image_digest" in *[!0-9a-f]*) status=1; continue ;; esac; \
					printf '%s\n' "$$recovery_image_id" >> "$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
					current_recovery_image_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$recovery_image_ref" 2>/dev/null \
					)" || current_recovery_image_id=""; \
					if test -n "$$current_recovery_image_id" && \
						test "$$current_recovery_image_id" != "$$recovery_image_id"; then \
						echo "refusing partial-build recovery of foreign same-name image tag: $$recovery_image_ref" >&2; \
						status=1; \
						continue; \
					fi; \
					test "$$current_recovery_image_id" = "$$recovery_image_id" || continue; \
					recovery_image_record="$$(printf 'task-image\t%s\t%s\t%s' \
						"$$recovery_image_ref" "$$recovery_image_id" "$$run_owner_token")"; \
					if ! grep -F "$$(printf 'task-image\t%s\t' "$$recovery_image_ref")" \
						"$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" >/dev/null; then \
						printf '%s\n' "$$recovery_image_record" >> "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
					fi; \
				done; \
				shared_recovery_id="$$(sed -n \
					"s|^task-image	$(CODER_SHARED_PYTHON_IMAGE)	\\([^	]*\\)	$$run_owner_token$$|\\1|p" \
					"$(CODER_TASK_IMAGE_OWNERSHIP_FILE)")"; \
				if test -n "$$shared_recovery_id" && test -z "$$(printf '%s\n' "$$shared_recovery_id" | sed -n '2p')"; then \
					for alias_ref in "$(CODER_AUDIT_ANCHOR_IMAGE)" "$(CODER_DEMO_UPSTREAM_IMAGE)"; do \
						alias_current_id="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$alias_ref" 2>/dev/null \
						)" || alias_current_id=""; \
						test "$$alias_current_id" = "$$shared_recovery_id" || continue; \
						alias_record="$$(printf 'task-image\t%s\t%s\t%s' "$$alias_ref" "$$shared_recovery_id" "$$run_owner_token")"; \
						grep -F "$$(printf 'task-image\t%s\t' "$$alias_ref")" \
							"$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" >/dev/null || \
							printf '%s\n' "$$alias_record" >> "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
					done; \
				fi; \
			fi; \
			if test -f "$(CODER_OUTPUT_DIR)/task-image-ids.txt" && \
				test ! -L "$(CODER_OUTPUT_DIR)/task-image-ids.txt"; then \
				cat "$(CODER_OUTPUT_DIR)/task-image-ids.txt" \
					>> "$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
			fi; \
			LC_ALL=C sort -u \
				"$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt" \
				-o "$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
				if test -f "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" && test ! -L "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; then \
				while IFS="$$ownership_tab" read -r image_kind image recorded_image_id image_owner image_extra; do \
					test "$$image_kind" = task-image && test "$$image_owner" = "$$run_owner_token" && \
						test -z "$${image_extra:-}" || { \
							echo "refusing malformed task image ownership record" >&2; \
							status=1; \
							continue; \
						}; \
					case " $(CODER_TASK_IMAGE_TAGS) " in *" $$image "*) ;; \
						*) echo "refusing undeclared task image cleanup reference: $$image" >&2; status=1; continue ;; \
					esac; \
					current_image_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$image" 2>/dev/null \
					)" || current_image_id=""; \
					test -z "$$current_image_id" && continue; \
					if test "$$current_image_id" != "$$recorded_image_id"; then \
						echo "refusing to remove foreign same-name image tag: $$image ($$current_image_id)" >&2; \
						status=1; \
						continue; \
					fi; \
					coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
						$(CODER_DOCKER) image rm "$$image" \
						>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || true; \
				done < "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
				fi; \
			while IFS= read -r image_id; do \
				test -n "$$image_id" || continue; \
				case "$$image_id" in sha256:*) ;; *) echo "invalid task image ID during cleanup" >&2; status=1; continue ;; esac; \
				image_digest="$${image_id#sha256:}"; \
				case "$$image_digest" in \
					*[!0-9a-f]*) echo "invalid task image digest during cleanup" >&2; status=1; continue ;; \
				esac; \
				test "$${#image_digest}" -eq 64 || { \
					echo "invalid task image digest length during cleanup" >&2; \
					status=1; \
					continue; \
					}; \
					coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
						$(CODER_DOCKER) image rm "$$image_id" \
						>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || true; \
					if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect "$$image_id" >/dev/null 2>&1; then \
					echo "task-built image ID remains after cleanup: $$image_id" >&2; \
					status=1; \
				fi; \
				done < "$(CODER_OUTPUT_DIR)/cleanup-image-ids.txt"; \
				if test -f "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" && test ! -L "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; then \
				while IFS="$$ownership_tab" read -r image_kind image recorded_image_id image_owner image_extra; do \
					test "$$image_kind" = task-image && test "$$image_owner" = "$$run_owner_token" && \
						test -z "$${image_extra:-}" || continue; \
					if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect "$$image" >/dev/null 2>&1; then \
					echo "task-owned image tag remains after cleanup: $$image" >&2; \
					status=1; \
				fi; \
				done < "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
				fi; \
				if test -f "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)" && \
					test ! -L "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; then \
					while IFS="$$ownership_tab" read -r dependency_kind dependency_ref dependency_id dependency_introduction dependency_owner dependency_extra; do \
						test "$$dependency_kind" = dependency-image && \
							test "$$dependency_owner" = "$$run_owner_token" && \
							test -z "$${dependency_extra:-}" || { status=1; continue; }; \
						case "$$dependency_ref" in "$(CODER_BUILDKIT_IMAGE)"|"$(CODER_POSTGRES_IMAGE)") ;; \
							*) echo "refusing undeclared dependency cleanup reference" >&2; status=1; continue ;; \
						esac; \
						case "$$dependency_introduction" in \
							preexisting-reference) \
								current_dependency_id="$$( \
									$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
										$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$dependency_ref" 2>/dev/null \
								)" || current_dependency_id=""; \
								if test "$$current_dependency_id" != "$$dependency_id"; then \
									echo "pre-existing dependency reference was not preserved: $$dependency_ref" >&2; \
									status=1; \
								fi; \
								continue ;; \
							introduced-reference|introduced-image) ;; \
							*) echo "invalid dependency introduction classification" >&2; status=1; continue ;; \
						esac; \
						current_dependency_id="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$dependency_ref" 2>/dev/null \
						)" || current_dependency_id=""; \
						if test -n "$$current_dependency_id" && \
							test "$$current_dependency_id" != "$$dependency_id"; then \
							echo "refusing to remove a rebound dependency reference: $$dependency_ref" >&2; \
							status=1; \
						elif test "$$current_dependency_id" = "$$dependency_id"; then \
							if ! coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
								$(CODER_DOCKER) image rm "$$dependency_ref" \
								>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1; then \
								echo "failed to remove introduced dependency reference: $$dependency_ref" >&2; \
								status=1; \
							fi; \
						fi; \
						remaining_dependency_ref_id="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$dependency_ref" 2>/dev/null \
						)" || remaining_dependency_ref_id=""; \
						if test -n "$$remaining_dependency_ref_id"; then \
							if test "$$remaining_dependency_ref_id" = "$$dependency_id"; then \
								echo "introduced dependency reference remains after cleanup: $$dependency_ref" >&2; \
							else \
								echo "dependency reference rebound during cleanup: $$dependency_ref" >&2; \
							fi; \
							status=1; \
						fi; \
						if test "$$dependency_introduction" = introduced-reference; then \
							if ! $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) image inspect "$$dependency_id" >/dev/null 2>&1; then \
								echo "pre-existing dependency image disappeared during reference cleanup: $$dependency_id" >&2; \
								status=1; \
							fi; \
							continue; \
						fi; \
						if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect "$$dependency_id" >/dev/null 2>&1; then \
							if ! coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
								$(CODER_DOCKER) image rm "$$dependency_id" \
								>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1; then \
								echo "failed to remove introduced dependency image ID: $$dependency_id" >&2; \
								status=1; \
							fi; \
						fi; \
						if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect "$$dependency_id" >/dev/null 2>&1; then \
							echo "introduced dependency image ID remains after cleanup: $$dependency_id" >&2; \
							status=1; \
						fi; \
					done < "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; \
				fi; \
		elif test "$${CODER_REMOVE_IMAGES:-0}" != 0; then \
			echo "CODER_REMOVE_IMAGES must be 0 or 1" >&2; \
			status=1; \
		fi; \
		exit "$$status"

# SECURITY BOUNDARY: this is cooperative capacity diagnostics only. Repository
# Make/Python/E2E and same-UID output are neither immutable nor contained from
# the Docker socket. The lane is valid only under a trusted orchestrator with an
# exclusive disposable DinD sidecar whose destruction is terminal cleanup. It
# is never hostile-source containment, provenance, or attestation, and it never
# calls production watchdog, promotion, signing, publication, or launch targets.
coder-build-all: _coder-require-clean
	@set -eu; \
		lock_dir="$(CODER_LOCK_DIRECTORY)"; \
		test -d "$$lock_dir" && test ! -L "$$lock_dir"; \
		test "$$(stat -Lc '%u:%F' "$$lock_dir")" = "0:directory"; \
		exec 9<"$$lock_dir"; \
		flock --exclusive --nonblock 9; \
		exec env CODER_LOCK_FD=9 CODER_LOCK_PATH="$$lock_dir" $(MAKE) --no-print-directory _coder-build-all-locked

_coder-build-all-locked: _coder-require-lock _coder-require-clean
	@set -eu; \
		unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CUSTOM_HEADERS DOCKER_HOST DOCKER_TLS_VERIFY BUILDX_BUILDER BUILDX_CONFIG; \
		PATH=/usr/local/bin:/usr/bin:/bin; \
		XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}"; \
		export PATH HOME XDG_RUNTIME_DIR; \
		test "$${CODER_COMBINED_CI:-0}" = 0 || test "$${CODER_COMBINED_CI:-0}" = 1; \
		test "$${CODER_PARENT_CLEANUP:-0}" = 0 || test "$${CODER_PARENT_CLEANUP:-0}" = 1; \
		case "$(CODER_REPO_TMP_DIR)" in /*) ;; *) echo "Coder artifact root must be absolute" >&2; exit 2 ;; esac; \
		test "$(CODER_REPO_TMP_DIR)" != "$(CURDIR)"; \
		case "$(CODER_REPO_TMP_DIR)/" in "$(CURDIR)/"*) echo "Coder artifact root must be outside the source tree" >&2; exit 2 ;; esac; \
		test "$(CODER_OUTPUT_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-ci"; \
		if test ! -e "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; then \
			(umask 077 && mkdir "$(CODER_REPO_TMP_DIR)"); \
		fi; \
		test -d "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; \
		test "$$(stat -Lc '%u:%F' "$(CODER_REPO_TMP_DIR)")" = "$$(id -u):directory"; \
		case "$$(stat -Lc '%a' "$(CODER_REPO_TMP_DIR)")" in \
			7[0145][0145]) ;; \
			*) echo "repository .tmp must not be group- or world-writable" >&2; exit 2 ;; \
		esac; \
		if test -e "$(CODER_OUTPUT_DIR)" || test -L "$(CODER_OUTPUT_DIR)"; then \
			test -d "$(CODER_OUTPUT_DIR)" && test ! -L "$(CODER_OUTPUT_DIR)"; \
			test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)")" = "$$(id -u):700:directory"; \
			env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup; \
			rm -rf "$(CODER_OUTPUT_DIR)"; \
		fi; \
		(umask 077 && mkdir "$(CODER_OUTPUT_DIR)"); \
		test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)")" = "$$(id -u):700:directory"; \
		for controlled_directory in "$(CODER_DOCKER_CONFIG_DIR)" "$(CODER_BUILDX_CONFIG_DIR)"; do \
			if test ! -e "$$controlled_directory" && test ! -L "$$controlled_directory"; then \
				(umask 077 && mkdir "$$controlled_directory"); \
			fi; \
			test -d "$$controlled_directory" && test ! -L "$$controlled_directory"; \
			test "$$(stat -Lc '%u:%a:%F' "$$controlled_directory")" = "$$(id -u):700:directory"; \
		done; \
			test "$(CODER_BUILDX_CONFIG_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-buildx-config"; \
			rm -rf "$(CODER_BUILDX_CONFIG_DIR)"; \
			(umask 077 && mkdir "$(CODER_BUILDX_CONFIG_DIR)"); \
			if test "$${CODER_PARENT_CLEANUP:-0}" = 1; then \
				parent_cleanup_token="$${CODER_PARENT_CLEANUP_TOKEN:?}"; \
				test -n "$$parent_cleanup_token" && \
					test -z "$$(printf '%s\n' "$$parent_cleanup_token" | sed -n '2p')"; \
			printf '%s\n' "$$parent_cleanup_token" > "$(CODER_PARENT_CLEANUP_MARKER_FILE)"; \
			chmod 0600 "$(CODER_PARENT_CLEANUP_MARKER_FILE)"; \
			else \
				rm -f "$(CODER_PARENT_CLEANUP_MARKER_FILE)"; \
			fi; \
			env CODER_DAEMON_ID_MODE=record $(MAKE) --no-print-directory _coder-require-disposable-daemon; \
			$(CODER_MUTATION_GUARD_FUNCTIONS) \
		$(CODER_HOST_IDENTITY_FUNCTIONS) \
		coder_require_mutation_daemon; \
			test -f /proc/sys/kernel/random/uuid && test ! -L /proc/sys/kernel/random/uuid || { \
				echo "Coder requires the Linux kernel UUID source for a fresh run token" >&2; \
				exit 2; \
			}; \
			run_token_nonce="$$(cat /proc/sys/kernel/random/uuid)"; \
			printf '%s\n' "$$run_token_nonce" \
				| grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$$' || { \
					echo "Coder received a malformed kernel run nonce" >&2; \
					exit 2; \
				}; \
			run_token_material="$$(cat "$(CODER_DAEMON_ID_FILE)"):$${CODER_PARENT_CLEANUP_TOKEN:-standalone}:$$$$:$$run_token_nonce"; \
		run_token_digest_line="$$(printf '%s' "$$run_token_material" | sha256sum)"; \
		run_owner_token="$${run_token_digest_line%% *}"; \
		test "$${#run_owner_token}" -eq 64; \
		case "$$run_owner_token" in *[!0-9a-f]*) echo "could not generate a canonical Coder run token" >&2; exit 2 ;; esac; \
		printf '%s\n' "$$run_owner_token" > "$(CODER_RUN_TOKEN_FILE)"; \
		: > "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
		chmod 0600 "$(CODER_RUN_TOKEN_FILE)" "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
		ulimit -f "$(CODER_BUILD_FILE_BLOCKS)"; \
		: > "$(CODER_OUTPUT_DIR)/cleanup.log"; \
		: > "$(CODER_OUTPUT_DIR)/dependency-pull.log"; \
			: > "$(CODER_OUTPUT_DIR)/buildkit-pull.log"; \
			: > "$(CODER_OUTPUT_DIR)/builder.log"; \
			: > "$(CODER_OUTPUT_DIR)/build.log"; \
			: > "$(CODER_OUTPUT_DIR)/rust-test-build.log"; \
			: > "$(CODER_OUTPUT_DIR)/proxy-test-build.log"; \
			: > "$(CODER_OUTPUT_DIR)/launcher-adversarial-build.log"; \
		{ \
			printf '%s\n' \
				'services:' \
				'  grant-store:' \
				"    cpus: \"$(CODER_SERVICE_CPUS)\"" \
					"    mem_limit: $(CODER_SERVICE_MEMORY)" \
					"    memswap_limit: $(CODER_SERVICE_MEMORY)" \
					"    pids_limit: $(CODER_SERVICE_PIDS)" \
					'    tmpfs: !override' \
					"      - /tmp:rw,noexec,nosuid,nodev,size=$(CODER_SERVICE_TMPFS_SIZE)" \
					"      - /var/run/postgresql:rw,noexec,nosuid,nodev,size=$(CODER_GRANT_STORE_RUN_TMPFS_SIZE),uid=70,gid=70,mode=3775" \
					'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): grant-store" \
				'    logging:' \
				'      driver: local' \
				'      options:' \
				'        max-size: "32m"' \
				'        max-file: "1"' \
				'  audit-anchor:' \
				"    cpus: \"$(CODER_SERVICE_CPUS)\"" \
					"    mem_limit: $(CODER_SERVICE_MEMORY)" \
					"    memswap_limit: $(CODER_SERVICE_MEMORY)" \
					"    pids_limit: $(CODER_SERVICE_PIDS)" \
					'    tmpfs: !override' \
					"      - /tmp:rw,noexec,nosuid,nodev,size=$(CODER_SERVICE_TMPFS_SIZE)" \
					'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): audit-anchor" \
				'    logging:' \
				'      driver: local' \
				'      options:' \
				'        max-size: "32m"' \
				'        max-file: "1"' \
				'  demo-upstream:' \
				"    cpus: \"$(CODER_SERVICE_CPUS)\"" \
					"    mem_limit: $(CODER_SERVICE_MEMORY)" \
					"    memswap_limit: $(CODER_SERVICE_MEMORY)" \
					"    pids_limit: $(CODER_SERVICE_PIDS)" \
					'    tmpfs: !override' \
					"      - /tmp:rw,noexec,nosuid,nodev,size=$(CODER_SERVICE_TMPFS_SIZE)" \
					'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): demo-upstream" \
				'    logging:' \
				'      driver: local' \
				'      options:' \
				'        max-size: "32m"' \
				'        max-file: "1"' \
				'  serverware:' \
				"    cpus: \"$(CODER_SERVICE_CPUS)\"" \
					"    mem_limit: $(CODER_SERVICE_MEMORY)" \
					"    memswap_limit: $(CODER_SERVICE_MEMORY)" \
					"    pids_limit: $(CODER_SERVICE_PIDS)" \
					'    tmpfs: !override' \
					"      - /tmp:rw,noexec,nosuid,nodev,size=$(CODER_SERVERWARE_TMPFS_SIZE)" \
					'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware" \
				'    logging:' \
				'      driver: local' \
				'      options:' \
				'        max-size: "32m"' \
				'        max-file: "1"' \
				'  decision-gate-rs:' \
				"    cpus: \"$(CODER_SERVICE_CPUS)\"" \
					"    mem_limit: $(CODER_SERVICE_MEMORY)" \
					"    memswap_limit: $(CODER_SERVICE_MEMORY)" \
					"    pids_limit: $(CODER_SERVICE_PIDS)" \
					'    tmpfs: !override' \
					"      - /tmp:rw,noexec,nosuid,nodev,size=$(CODER_SERVICE_TMPFS_SIZE)" \
					'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): decision-gate-rs" \
				'    logging:' \
				'      driver: local' \
				'      options:' \
				'        max-size: "32m"' \
				'        max-file: "1"' \
				'networks:' \
				'  default:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): compose-default-network" \
				'volumes:' \
				'  serverware-data:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-data" \
				'  serverware-audit-anchors:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-audit-anchors" \
				'  serverware-grant-store:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-grant-store" \
				'  serverware-custody-socket:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-custody-socket" \
				'  serverware-custody-trust:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-custody-trust" \
				'  serverware-custody-state:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-custody-state" \
				'  serverware-response-signing-private:' \
				'    labels:' \
				"      $(CODER_OWNER_LABEL_KEY): \"$$run_owner_token\"" \
				"      $(CODER_RESOURCE_LABEL_KEY): serverware-response-signing-private"; \
		} > "$(CODER_COMPOSE_LIMITS_FILE)"; \
		rm -f \
			"$(CODER_OUTPUT_DIR)/build-commit.txt" \
			"$(CODER_BUILD_PARENT_COMMIT_FILE)" \
			"$(CODER_BUILD_BASE_TREE_FILE)" \
			"$(CODER_OUTPUT_DIR)/build-tree.txt" \
			"$(CODER_OUTPUT_DIR)/build-source-tree-sha256.txt" \
			"$(CODER_OUTPUT_DIR)/source-archive-sha256.txt" \
			"$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt" \
			"$(CODER_OUTPUT_DIR)/task-image-ids.txt" \
			"$(CODER_OUTPUT_DIR)/image-digests.txt" \
				"$(CODER_OUTPUT_DIR)/image-references.txt" \
				"$(CODER_OUTPUT_DIR)/rust-test-image-binding.txt" \
				"$(CODER_OUTPUT_DIR)/rust-test-image.iid" \
				"$(CODER_OUTPUT_DIR)/proxy-test-image-binding.txt" \
				"$(CODER_OUTPUT_DIR)/proxy-test-image.iid" \
				"$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)" \
				"$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" \
				"$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)" \
				"$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" \
				"$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)" \
				"$(CODER_BUILDKIT_IMAGE_BINDING_FILE)" \
				"$(CODER_DECISION_GATE_BINARY_DIGEST_FILE)" \
				"$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)" \
				"$(CODER_COMPOSE_DIGEST_OVERRIDE_SHA256_FILE)" \
				"$(CODER_COMPOSE_IMAGE_OVERRIDE_FILE)" \
				"$(CODER_HOST_IDENTITY_FILE)" \
				"$(CODER_HOST_IDENTITY_SHA256_FILE)" \
				"$(CODER_CURRENT_HOST_IDENTITY_FILE)" \
				"$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest-sha256.txt" \
				"$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)" \
				"$(CODER_CHANGED_TESTS_FILE)" \
				"$(CODER_PREPARED_TESTS_FILE)" \
				"$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)" \
				"$(CODER_EXCLUDED_TESTS_FILE)" \
				"$(CODER_CHANGED_EXCLUDED_TESTS_FILE)" \
				"$(CODER_CHANGED_BLOCKED_PREREQUISITE_TESTS_FILE)" \
				"$(CODER_OUTPUT_DIR)/compose-config.yaml" \
				"$(CODER_OUTPUT_DIR)/compose-config-sha256.txt"; \
		coder_write_host_identity "$(CODER_HOST_IDENTITY_FILE)"; \
		host_identity_digest_line="$$(sha256sum "$(CODER_HOST_IDENTITY_FILE)")"; \
		host_identity_digest="$${host_identity_digest_line%% *}"; \
		test "$${#host_identity_digest}" -eq 64; \
		case "$$host_identity_digest" in *[!0-9a-f]*) exit 2 ;; esac; \
		printf '%s\n' "$$host_identity_digest" > "$(CODER_HOST_IDENTITY_SHA256_FILE)"; \
		chmod 0600 "$(CODER_HOST_IDENTITY_SHA256_FILE)"; \
		source_tree_digest() { \
			snapshot_file="$(CODER_OUTPUT_DIR)/source-tree-normalized.tar"; \
			rm -f "$$snapshot_file"; \
			tar \
				--sort=name \
				--mtime=@0 \
				--owner=0 \
				--group=0 \
				--numeric-owner \
				--format=posix \
				--pax-option=delete=atime,delete=ctime \
				-cf "$$snapshot_file" \
				-C "$(CODER_FROZEN_SOURCE_DIR)" .; \
			digest_line="$$(sha256sum "$$snapshot_file")"; \
			rm -f "$$snapshot_file"; \
			printf '%s\n' "$${digest_line%% *}"; \
		}; \
		frozen_file_digest() { \
			digest_line="$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/$$1")"; \
			printf '%s\n' "$${digest_line%% *}"; \
			}; \
			coder_require_mutation_daemon; \
			on_exit() { \
				status=$$?; \
				trap - EXIT HUP INT TERM; \
				if test "$${CODER_PARENT_CLEANUP:-0}" = 1; then \
					exit "$$status"; \
				fi; \
				if test "$${CODER_COMBINED_CI:-0}" = 1; then \
					if test "$$status" -ne 0; then \
						env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup || status=1; \
					fi; \
					exit "$$status"; \
				fi; \
			remove_images=0; \
			test "$$status" -eq 0 || remove_images=1; \
			env CODER_REMOVE_IMAGES="$$remove_images" $(MAKE) --no-print-directory _coder-cleanup || status=1; \
			exit "$$status"; \
		}; \
			on_signal() { \
				trap - EXIT HUP INT TERM; \
				if test "$${CODER_PARENT_CLEANUP:-0}" = 1; then \
					exit 130; \
				fi; \
				cleanup_status=0; \
				env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup || cleanup_status=$$?; \
			test "$$cleanup_status" -eq 0 || exit "$$cleanup_status"; \
			exit 130; \
			}; \
				trap on_exit EXIT; \
				trap on_signal HUP INT TERM; \
				env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup; \
		source_commit="$$(git rev-parse --verify 'HEAD^{commit}')"; \
		source_tree="$$(git rev-parse --verify "$$source_commit^{tree}")"; \
		source_parent_line="$$(git rev-list --parents -n 1 "$$source_commit")"; \
		set -- $$source_parent_line; \
		test "$$#" -ge 1 && test "$$1" = "$$source_commit"; \
		if test "$$#" -eq 1; then \
			source_parent=ROOT; \
			source_base_tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904; \
		else \
			source_parent="$$2"; \
			source_base_tree="$$(git rev-parse --verify "$$source_parent^{tree}")"; \
		fi; \
		printf '%s\n' "$$source_parent" > "$(CODER_BUILD_PARENT_COMMIT_FILE)"; \
		printf '%s\n' "$$source_base_tree" > "$(CODER_BUILD_BASE_TREE_FILE)"; \
		chmod 0600 "$(CODER_BUILD_PARENT_COMMIT_FILE)" "$(CODER_BUILD_BASE_TREE_FILE)"; \
		rm -rf "$(CODER_FROZEN_SOURCE_DIR)"; \
		(umask 077 && mkdir "$(CODER_FROZEN_SOURCE_DIR)"); \
		git archive --format=tar --output="$(CODER_OUTPUT_DIR)/source.tar" "$$source_commit"; \
		tar -xf "$(CODER_OUTPUT_DIR)/source.tar" -C "$(CODER_FROZEN_SOURCE_DIR)"; \
		source_archive_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/source.tar")"; \
		source_archive_digest="$${source_archive_digest_line%% *}"; \
		frozen_source_digest="$$(source_tree_digest)"; \
			for required_source_file in \
				Makefile \
				docker-compose.yml \
				Dockerfile \
				Dockerfile.production \
				requirements.lock \
				requirements.browser.lock \
				requirements.proxy-test.lock \
				serverware_agent_trust/requirements.lock \
				serverware/authority_counted_root_transition.py \
				serverware/authority_store/counted_installation.py \
				serverware/authority_complete_query_batch.py \
				serverware/authority_complete_acquisition.py \
				serverware/authority_index_heads.py \
				serverware/authority_index_trace.py \
				serverware/authority_complete_read_write.py \
				serverware/authority_revocation_read_write.py \
				serverware/authority_revocation_proof_bundle.py \
				serverware/authority_revocation_bundle_contract.py \
				serverware/authority_revocation_semantics.py \
				serverware/authority_revocation_plan_contract.py \
				serverware/authority_revocation_plan.py \
				serverware/authority_revocation_plan_production.py \
				serverware/authority_revocation_wire.py \
				serverware/authority_revocation_retention.py \
				serverware/authority_revocation_capability.py \
				serverware/authority_revocation_capability_production.py \
				serverware/authority_revocation_configuration.py \
				serverware/authority_revocation_roots.py \
				serverware/authority_revocation_root_reader.py \
				serverware/authority_revocation_observed.py \
				serverware/authority_revocation_handoff.py \
				serverware/authority_revocation_verifier.py \
				serverware/authority_revocation_planning.py \
				serverware/authority_revocation_planning_request.py \
				serverware/authority_revocation_planning_transport.py \
				serverware/authority_revocation_planning_client.py \
				serverware/authority_revocation_planning_receiver.py \
				serverware/authority_revocation_planner_custody_transport.py \
				serverware/authority_revocation_planner_custody_client.py \
				serverware/authority_revocation_planner_custody_receiver.py \
				serverware/authority_revocation_custody_read.py \
				serverware/authority_revocation_custody_read_client.py \
				serverware/authority_revocation_custody_read_transport.py \
				serverware/authority_revocation_planner_configuration.py \
				serverware/authority_transport.py \
				serverware/authority_revocation_invocation.py \
				serverware/authority_revocation_issuance.py \
				serverware/authority_revocation_persistence.py \
				serverware/authority_revocation_writer_connection.py \
				serverware/authority_revocation_writer_configuration.py \
				serverware/authority_revocation_writer_action.py \
				serverware/authority_revocation_writer_commitment.py \
				serverware/authority_revocation_writer_composition.py \
				serverware/authority_revocation_writer_signer.py \
				serverware/authority_revocation_writer_acknowledgment.py \
				serverware/authority_revocation_writer_transport.py \
				serverware/authority_revocation_writer_ack_expectation.py \
				serverware/authority_revocation_writer_client.py \
				serverware/authority_revocation_writer_producers.py \
				serverware/authority_revocation_coordinator.py \
				serverware/authority_store/planner_connection.py \
				serverware/authority_store/authorization_records.py \
				serverware/authority_store/revocation_capability.py \
				serverware/authority_store/revocation_capability_sql.py \
				serverware/authority_store/revocation_retention.py \
				serverware/authority_store/webauthn_evidence_retention.py \
				serverware/authority_store/webauthn_evidence_entrypoints.py \
				serverware/authority_store/revocation_counted_sql.py \
				serverware/authority_store/revocation_execution.py \
				serverware/authority_store/revocation_writer_request.py \
				serverware/authority_store/revocation_writer_acknowledgment.py \
				serverware/authority_store/revocation_custody_read.py \
				serverware/authority_store/revocation_retained_sql.py \
				serverware/authority_store/executor_v9.py \
				serverware/authority_revocation_write_trace.py \
				serverware/authority_webauthn_trust.py \
				serverware/authority_request_commitment.py \
				serverware/authority_planner.py \
				serverware/authority_successor_programs.py \
				serverware/authority_webauthn_transition_planning.py \
				serverware/authority_webauthn_transition_inputs.py \
				serverware/authority_webauthn_registration_replay.py \
				serverware/authority_webauthn_stage_replay.py \
				serverware/authority_webauthn_completion_replay.py \
				serverware/authority_webauthn_complete_proofs.py \
				serverware/authority_webauthn_completion_proofs.py \
				serverware/authority_webauthn_transition_proof_contract.py \
				serverware/authority_webauthn_transition_proof_wire.py \
				serverware/authority_webauthn_transition_proof.py \
				serverware/authority_webauthn_transition_proof_production.py \
				serverware/authority_webauthn_assertion.py \
				serverware/authority_webauthn_evidence.py \
				serverware/authority_webauthn_evidence_acquisition.py \
				serverware/authority_webauthn_evidence_roots.py \
				serverware/authority_webauthn_evidence_root_reader.py \
				serverware/authority_webauthn_evidence_root_configuration.py \
				serverware/authority_webauthn_evidence_computation.py \
				serverware/authority_webauthn_evidence_custody_configuration.py \
				serverware/authority_webauthn_evidence_custody_actions.py \
				serverware/authority_webauthn_evidence_custody_transport.py \
				serverware/authority_webauthn_evidence_custody_read_request.py \
				serverware/authority_webauthn_evidence_custody_read_actions.py \
				serverware/authority_webauthn_evidence_custody_read_transport.py \
				serverware/authority_webauthn_evidence_custody_wire.py \
				serverware/authority_webauthn_evidence_custody_intent.py \
				serverware/authority_webauthn_evidence_custody_relay.py \
				serverware/authority_webauthn_evidence_custody_persistence.py \
				serverware/authority_webauthn_evidence_kernel.py \
				serverware/authority_webauthn_evidence_planning.py \
				serverware/authority_webauthn_evidence_policy.py \
				serverware/authority_webauthn_evidence_configuration.py \
				serverware/authority_webauthn_evidence_input_wire.py \
				serverware/authority_webauthn_evidence_replay.py \
				serverware/authority_webauthn_evidence_plan.py \
				serverware/authority_webauthn_evidence_plan_request.py \
				serverware/authority_webauthn_evidence_plan_response.py \
				serverware/authority_webauthn_evidence_plan_transport.py \
				serverware/authority_webauthn_evidence_plan_live.py \
				serverware/authority_webauthn_evidence_plan_actions.py \
				serverware/authority_webauthn_evidence_plan_admission.py \
				serverware/authority_webauthn_evidence_plan_clock.py \
				serverware/authority_webauthn_evidence_plan_configuration.py \
				serverware/authority_webauthn_evidence_plan_context.py \
				serverware/authority_webauthn_evidence_plan_contract.py \
				serverware/authority_webauthn_evidence_plan_owner.py \
				serverware/authority_webauthn_evidence_plan_persistence.py \
				serverware/authority_webauthn_evidence_plan_production.py \
				serverware/authority_webauthn_evidence_plan_reads.py \
				serverware/authority_webauthn_evidence_plan_retention.py \
				serverware/authority_webauthn_evidence_plan_verifier.py \
				serverware/authority_webauthn_evidence_plan_verifier_configuration.py \
				serverware/authority_webauthn_evidence_plan_writer_configuration.py \
				serverware/authority_webauthn_evidence_proofs.py \
				serverware/authority_webauthn_registration_inputs.py \
				serverware/authority_webauthn_installation_inputs.py \
				serverware/authority_webauthn_registration_production.py \
				serverware/authority_webauthn_registration_admission.py \
				serverware/authority_webauthn_installation_admission.py \
				serverware/authority_webauthn_trust_candidate.py \
				serverware/authority_webauthn_installation_production.py \
				serverware/webauthn_attestation_core.py \
				serverware/webauthn_credential_trust.py \
				serverware/webauthn_trust.py \
				serverware/webauthn_trust_core.py \
				schemas/webauthn-trust-bundle.v1.schema.json \
				serverware/authority_transition_webauthn.py \
				serverware/authority_transition_webauthn_registration.py \
				serverware/authority_transition_webauthn_registration_admission.py \
				serverware/authority_transition_webauthn_installation_admission.py \
				serverware/authority_transition_webauthn_completion.py \
				serverware/authority_transition_webauthn_trust_stage.py \
				scripts/authority_revocation_observation_fixture.py \
				scripts/authority_revocation_semantics_fixture.py \
				scripts/authority_revocation_trust_fixture.py \
				serverware/authority_index_frontier.py \
				data-plane/decision-gate-rs/Dockerfile \
				data-plane/decision-gate-rs/Dockerfile.production \
				data-plane/decision-gate-rs/Cargo.lock \
				data-plane/decision-gate-rs/coder-test-runner.sh \
				ops/systemd/serverware-launch-authority-relay.service \
				ops/systemd/serverware-launch-authority-relay.socket \
				schemas/production-launch-manifest.v3.schema.json \
				schemas/release-completion-verification.v1.schema.json \
				schemas/release-completion-result-signing-request.v1.schema.json \
				schemas/release-completion-result-signing-response.v1.schema.json \
				production-dependencies/prefetch.py \
				scripts/discard_headers_parity.v1.json \
				scripts/oci_lane_entrypoint.py \
				scripts/verify_agent_trust_same_journey.py \
				policies/credential-limits.examples.json \
				scripts/test_credential_constraints.py \
				scripts/test_jit_transaction_state.py \
				scripts/e2e.sh \
				$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT) \
				$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT) \
				$(CODER_COUNTED_NATIVE_SOURCE_DEPENDENCIES) \
				$(CODER_TEST_SCRIPTS) \
				$(CODER_ISOLATED_TEST_SCRIPTS) \
				$(CODER_BLOCKED_PREREQUISITE_TEST_SCRIPTS) \
				$(CODER_EXCLUDED_TEST_SCRIPTS); do \
			test -f "$(CODER_FROZEN_SOURCE_DIR)/$$required_source_file" && \
				test ! -L "$(CODER_FROZEN_SOURCE_DIR)/$$required_source_file" || { \
					echo "required frozen build input is missing or a symlink: $$required_source_file" >&2; \
					exit 2; \
				}; \
		done; \
		git ls-tree -r --name-only "$$source_commit" -- \
				':(glob)scripts/test_*' scripts/e2e.sh \
			| LC_ALL=C sort > "$(CODER_OUTPUT_DIR)/test-inventory.git.txt"; \
		: > "$(CODER_OUTPUT_DIR)/test-inventory.untracked.txt"; \
		tar -tf "$(CODER_OUTPUT_DIR)/source.tar" \
			| grep -E '^scripts/(e2e\.sh|test_[A-Za-z0-9_.-]+)$$' \
			| LC_ALL=C sort > "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt"; \
		cmp "$(CODER_OUTPUT_DIR)/test-inventory.git.txt" "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt" || { \
			echo "bounded Git and frozen-archive test inventories differ" >&2; \
			exit 2; \
		}; \
		printf '%s\n' \
			$(CODER_TEST_SCRIPTS) \
			$(CODER_ISOLATED_TEST_SCRIPTS) \
			scripts/test_credential_constraints.py \
			scripts/test_jit_transaction_state.py \
			"$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)" \
			"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)" \
			scripts/e2e.sh \
			| LC_ALL=C sort > "$(CODER_PREPARED_TESTS_FILE)"; \
		{ \
			for blocked_test_path in $(CODER_BLOCKED_PREREQUISITE_TEST_SCRIPTS); do \
				printf '%s\n' "$$blocked_test_path"; \
			done; \
		} | LC_ALL=C sort > "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
		{ \
			for excluded_test_path in $(CODER_EXCLUDED_TEST_SCRIPTS); do \
				printf '%s\n' "$$excluded_test_path"; \
			done; \
		} | LC_ALL=C sort > "$(CODER_EXCLUDED_TESTS_FILE)"; \
		{ \
			cat "$(CODER_PREPARED_TESTS_FILE)"; \
			cat "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
			cat "$(CODER_EXCLUDED_TESTS_FILE)"; \
		} \
			| LC_ALL=C sort > "$(CODER_OUTPUT_DIR)/test-inventory.classified.txt"; \
		LC_ALL=C uniq -d "$(CODER_OUTPUT_DIR)/test-inventory.classified.txt" \
			> "$(CODER_OUTPUT_DIR)/test-inventory.duplicates.txt"; \
		test ! -s "$(CODER_OUTPUT_DIR)/test-inventory.duplicates.txt" || { \
			echo "a Coder test appears in more than one prepared/blocked/excluded inventory" >&2; \
			exit 2; \
		}; \
		cmp "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt" "$(CODER_OUTPUT_DIR)/test-inventory.classified.txt" || { \
			echo "a frozen test is omitted from or duplicated across prepared/blocked/excluded coverage" >&2; \
			exit 2; \
		}; \
		if test "$$source_parent" = ROOT; then \
			git ls-tree -r --name-only "$$source_commit" -- \
					':(glob)scripts/test_*' scripts/e2e.sh \
				| LC_ALL=C sort -u > "$(CODER_CHANGED_TESTS_FILE)"; \
		else \
			git diff --name-only --diff-filter=AM --no-renames \
					"$$source_parent" "$$source_commit" -- \
					':(glob)scripts/test_*' scripts/e2e.sh \
				| LC_ALL=C sort -u > "$(CODER_CHANGED_TESTS_FILE)"; \
		fi; \
		: > "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)"; \
		: > "$(CODER_CHANGED_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
		while IFS= read -r changed_test_path; do \
			test -n "$$changed_test_path" || continue; \
			if grep -Fx "$$changed_test_path" "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)" >/dev/null; then \
				printf '%s\n' "$$changed_test_path" >> "$(CODER_CHANGED_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
			elif ! grep -Fx "$$changed_test_path" "$(CODER_PREPARED_TESTS_FILE)" >/dev/null; then \
				printf '%s\n' "$$changed_test_path" >> "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)"; \
			fi; \
		done < "$(CODER_CHANGED_TESTS_FILE)"; \
		if test -s "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)"; then \
			echo "changed or added tests lack prepared no-build execution artifacts:" >&2; \
			sed 's/^/  /' "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)" >&2; \
			echo "prepare those exact tests in the sequential no-build lane before coder-build-all can proceed" >&2; \
			exit 2; \
		fi; \
		if test -s "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; then \
			blocked_prerequisite_count=0; \
			while IFS= read -r blocked_test_path; do \
				test -n "$$blocked_test_path" || continue; \
				blocked_prerequisite_count=$$((blocked_prerequisite_count + 1)); \
			done < "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
			echo "the closed Coder batch has $$blocked_prerequisite_count tests blocked on external prerequisites unavailable to this closed lane:" >&2; \
			while IFS= read -r blocked_test_path; do \
				case "$$blocked_test_path" in \
					scripts/test_agent_trust_clean_room.py) \
						blocked_detail="requires a reviewed privileged OCI launcher plus a signed exact clean-room payload; ordinary Docker injects mounts forbidden by the test" ;; \
					scripts/test_portal_browser_oauth.py) \
						blocked_detail="requires a digest-bound Chromium executable with its complete shared-library, font, and runtime closure; a digest-bound Node executable with its npm CLI, package manifest, package-manager dependencies, and offline package/cache closure; corrected Candidate Manifest v6 same-journey callback inputs binding the promotion receipt, launcher lease/capability, browser result, and npm request/result; and a trusted one-use npm companion broker with no Docker authority in the browser container" ;; \
					scripts/test_response_proof_capture.sh) \
						blocked_detail="requires an externally installed root-owned fixed-command coder-test-controller that alone owns the exclusive disposable DinD socket and implements the frozen response-proof stage protocol" ;; \
					*) blocked_detail="unknown closed external prerequisite"; exit 2 ;; \
				esac; \
				printf '  %s: %s\n' "$$blocked_test_path" "$$blocked_detail" >&2; \
			done < "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
			echo "refusing pulls or builds until these prerequisites are supplied and their runners are reviewed into the closed lane" >&2; \
			exit 2; \
		fi; \
		printf '%s\n' "$$(frozen_file_digest "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)")" \
			> "$(CODER_OUTPUT_DIR)/launcher-adversarial-script-sha256.txt"; \
		printf '%s\n' "$$(frozen_file_digest scripts/e2e.sh)" \
			> "$(CODER_OUTPUT_DIR)/e2e-script-sha256.txt"; \
		chmod 0600 \
			"$(CODER_OUTPUT_DIR)/launcher-adversarial-script-sha256.txt" \
			"$(CODER_OUTPUT_DIR)/e2e-script-sha256.txt"; \
		{ \
			echo "classification=untrusted-diagnostics-only"; \
			echo "attestation=false"; \
			echo "publication=false"; \
				echo "hostile_source_containment=false"; \
				echo "provenance=false"; \
				echo "orchestrator_trust=cooperative-trusted-required"; \
				echo "docker_daemon=exclusive-disposable-dind-required"; \
				echo "docker_socket_containment=false"; \
				echo "repository_and_same_uid_output_immutability=false"; \
				echo "terminal_cleanup_requirement=trusted-orchestrator-destroys-exclusive-dind-sidecar"; \
				echo "compose_project=$(CODER_COMPOSE_PROJECT_NAME)"; \
				echo "daemon_id=$$(cat "$(CODER_DAEMON_ID_FILE)")"; \
				echo "daemon_guard_labels=$(CODER_DAEMON_DISPOSABLE_LABEL),$(CODER_DAEMON_NETWORK_LABEL)"; \
				echo "daemon_guard_attestation=false"; \
				echo "platform=$(CODER_PLATFORM)"; \
				echo "commit=$$source_commit"; \
				echo "parent=$$source_parent"; \
				echo "base_tree=$$source_base_tree"; \
				echo "tree=$$source_tree"; \
				echo "git_toolchain=$$(git --version)"; \
				echo "bash_toolchain=$$(bash --version | sed -n '1p')"; \
				echo "curl_toolchain=$$(curl --version | sed -n '1p')"; \
				echo "openssl_toolchain=$$(openssl version)"; \
				echo "python_toolchain=$$(python3 --version)"; \
				echo "tar_toolchain=$$(tar --version | sed -n '1p')"; \
				echo "sha256sum_toolchain=$$(sha256sum --version | sed -n '1p')"; \
				echo "timeout_toolchain=$$($(CODER_TIMEOUT) --version | sed -n '1p')"; \
				echo "docker_toolchain=$$($(CODER_DOCKER) --version)"; \
				echo "compose_toolchain=$$($(CODER_DOCKER) compose version)"; \
				echo "buildx_toolchain=$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) buildx version \
				)"; \
				echo "build_log=$(CODER_OUTPUT_DIR)/build.log"; \
				echo "rust_test_build_log=$(CODER_OUTPUT_DIR)/rust-test-build.log"; \
				echo "proxy_test_build_log=$(CODER_OUTPUT_DIR)/proxy-test-build.log"; \
				echo "production_host_preflight_build_log=$(CODER_OUTPUT_DIR)/production-host-preflight-build.log"; \
				echo "launcher_adversarial_build_log=$(CODER_OUTPUT_DIR)/launcher-adversarial-build.log"; \
				echo "rust_test_log=$(CODER_OUTPUT_DIR)/rust-unit-tests.log"; \
				echo "batch_coverage_manifest=$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv"; \
				echo "builder_log=$(CODER_OUTPUT_DIR)/builder.log"; \
				echo "dependency_pull_log=$(CODER_OUTPUT_DIR)/dependency-pull.log"; \
				echo "buildkit_pull_log=$(CODER_OUTPUT_DIR)/buildkit-pull.log"; \
				echo "buildkit_image=$(CODER_BUILDKIT_IMAGE)"; \
				echo "host_identity=$(CODER_HOST_IDENTITY_FILE)"; \
				echo "host_identity_sha256=sha256:$$host_identity_digest"; \
				echo "test_log_root=$(CODER_OUTPUT_DIR)"; \
			sed -n 's/^FROM /declared_base=/p' \
				"$(CODER_FROZEN_SOURCE_DIR)/Dockerfile" \
				"$(CODER_FROZEN_SOURCE_DIR)/data-plane/decision-gate-rs/Dockerfile"; \
		} > "$(CODER_OUTPUT_DIR)/diagnostics.txt"; \
		: > "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
		: > "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; \
		: > "$(CODER_OUTPUT_DIR)/task-image-ids.txt"; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_DOCKER) image ls --all --no-trunc --quiet \
			| LC_ALL=C sort -u > "$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)"; \
		while IFS= read -r preexisting_image_id; do \
			test -n "$$preexisting_image_id" || continue; \
			case "$$preexisting_image_id" in sha256:[0-9a-f]*) ;; \
				*) echo "Docker returned a noncanonical pre-existing image ID" >&2; exit 2 ;; \
			esac; \
			test "$${#preexisting_image_id}" -eq 71; \
			preexisting_image_digest="$${preexisting_image_id#sha256:}"; \
			case "$$preexisting_image_digest" in *[!0-9a-f]*) exit 2 ;; esac; \
		done < "$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)"; \
		chmod 0600 \
			"$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" \
			"$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)" \
			"$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)" \
			"$(CODER_OUTPUT_DIR)/task-image-ids.txt"; \
		for task_image_ref in $(CODER_TASK_IMAGE_TAGS); do \
			if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect "$$task_image_ref" >/dev/null 2>&1; then \
				echo "refusing to build over a pre-existing task image reference: $$task_image_ref" >&2; \
				exit 2; \
			fi; \
		done; \
		buildkit_preexisting=0; \
		buildkit_preexisting_id=""; \
		if buildkit_preexisting_id="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_BUILDKIT_IMAGE)" 2>/dev/null \
		)"; then \
			buildkit_preexisting=1; \
		fi; \
		printf '%s\n' "pulling the pinned BuildKit driver during build preparation; log: $(CODER_OUTPUT_DIR)/buildkit-pull.log"; \
		buildkit_pull_status=0; \
		coder_mutate "$(CODER_START_TIMEOUT)" \
			$(CODER_DOCKER) pull --platform "$(CODER_PLATFORM)" "$(CODER_BUILDKIT_IMAGE)" \
			> "$(CODER_OUTPUT_DIR)/buildkit-pull.log" 2>&1 || buildkit_pull_status=$$?; \
		buildkit_image_id="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_BUILDKIT_IMAGE)" 2>/dev/null \
		)" || { \
			test "$$buildkit_pull_status" -ne 0 && exit "$$buildkit_pull_status"; \
			echo "BuildKit pull completed without an observable pinned image" >&2; \
			exit 2; \
		}; \
		case "$$buildkit_image_id" in sha256:*) ;; *) echo "BuildKit image ID is not canonical" >&2; exit 2 ;; esac; \
		buildkit_image_digest="$${buildkit_image_id#sha256:}"; \
		test "$${#buildkit_image_digest}" -eq 64; \
		case "$$buildkit_image_digest" in *[!0-9a-f]*) echo "BuildKit image ID is not lowercase hexadecimal" >&2; exit 2 ;; esac; \
		if test "$$buildkit_preexisting" = 1; then \
			test "$$buildkit_preexisting_id" = "$$buildkit_image_id" || { \
				echo "pinned BuildKit reference changed identity during pull" >&2; \
				exit 2; \
			}; \
			buildkit_introduction=preexisting-reference; \
		elif grep -Fx "$$buildkit_image_id" "$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)" >/dev/null; then \
			buildkit_introduction=introduced-reference; \
		else \
			buildkit_introduction=introduced-image; \
		fi; \
		printf 'dependency-image\t%s\t%s\t%s\t%s\n' \
			"$(CODER_BUILDKIT_IMAGE)" "$$buildkit_image_id" "$$buildkit_introduction" "$$run_owner_token" \
			>> "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; \
		test "$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$buildkit_image_id" \
		)" = "linux/amd64" || { echo "BuildKit dependency platform is not linux/amd64" >&2; exit 2; }; \
		buildkit_repo_digests="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$(CODER_BUILDKIT_IMAGE)" \
		)"; \
		printf '%s\n' "$$buildkit_repo_digests" | grep -Fx "$(CODER_BUILDKIT_REPO_DIGEST)" >/dev/null || { \
			echo "loaded BuildKit image does not expose the pinned digest reference" >&2; \
			exit 2; \
		}; \
		printf '%s %s\n' "$(CODER_BUILDKIT_IMAGE)" "$$buildkit_image_id" \
			> "$(CODER_BUILDKIT_IMAGE_BINDING_FILE)"; \
		test "$$buildkit_pull_status" -eq 0 || exit "$$buildkit_pull_status"; \
		postgres_preexisting=0; \
		postgres_preexisting_id=""; \
		if postgres_preexisting_id="$$( \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_POSTGRES_IMAGE)" 2>/dev/null \
		)"; then \
			postgres_preexisting=1; \
		fi; \
		printf '%s\n' "pulling the external runtime dependency; log: $(CODER_OUTPUT_DIR)/dependency-pull.log"; \
			postgres_pull_status=0; \
			coder_mutate "$(CODER_START_TIMEOUT)" \
				$(CODER_PREP_COMPOSE) pull --policy missing grant-store \
				> "$(CODER_OUTPUT_DIR)/dependency-pull.log" 2>&1 || postgres_pull_status=$$?; \
			postgres_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_POSTGRES_IMAGE)" 2>/dev/null \
			)" || { \
				test "$$postgres_pull_status" -ne 0 && exit "$$postgres_pull_status"; \
				echo "Postgres pull completed without an observable pinned image" >&2; \
				exit 2; \
			}; \
			if test "$$postgres_preexisting" = 1; then \
				test "$$postgres_preexisting_id" = "$$postgres_image_id" || { \
					echo "pinned Postgres reference changed identity during pull" >&2; \
					exit 2; \
				}; \
				postgres_introduction=preexisting-reference; \
			elif grep -Fx "$$postgres_image_id" "$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)" >/dev/null; then \
				postgres_introduction=introduced-reference; \
			else \
				postgres_introduction=introduced-image; \
			fi; \
			printf 'dependency-image\t%s\t%s\t%s\t%s\n' \
				"$(CODER_POSTGRES_IMAGE)" "$$postgres_image_id" "$$postgres_introduction" "$$run_owner_token" \
				>> "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$postgres_image_id" \
			)" = "linux/amd64" || { echo "Postgres dependency platform is not linux/amd64" >&2; exit 2; }; \
			test "$$postgres_pull_status" -eq 0 || exit "$$postgres_pull_status"; \
				builder_suffix="$$(printf '%.24s' "$$run_owner_token")"; \
				builder_name="$(CODER_BUILDER_NAME_PREFIX)$$builder_suffix"; \
				builder_container="buildx_buildkit_$${builder_name}0"; \
				builder_state_volume="$${builder_container}_state"; \
				case "$$builder_name$$builder_container$$builder_state_volume" in *[!A-Za-z0-9_.-]*) \
					echo "derived Buildx resource name is unsafe" >&2; exit 2 ;; \
				esac; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) buildx inspect "$$builder_name" >/dev/null 2>&1; then \
					echo "derived Buildx registration already exists: $$builder_name" >&2; \
					exit 2; \
				fi; \
				test -z "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$${builder_container}$$" \
				)" || { echo "derived BuildKit container already exists" >&2; exit 2; }; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume inspect "$$builder_state_volume" >/dev/null 2>&1; then \
					echo "derived BuildKit state volume already exists" >&2; \
					exit 2; \
				fi; \
				created_builder_volume="$$( \
					coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume create \
							--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
							--label "$(CODER_RESOURCE_LABEL_KEY)=buildkit-state" \
							"$$builder_state_volume" \
				)"; \
				test "$$created_builder_volume" = "$$builder_state_volume" && \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) volume inspect \
								--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
								"$$builder_state_volume" \
					)" = "$$builder_state_volume|buildkit-state|$$run_owner_token" || { \
						echo "BuildKit state volume identity validation failed" >&2; \
						exit 2; \
					}; \
				printf 'volume\t%s\tbuildkit-state\t%s\t%s\n' \
					"$$builder_state_volume" "$$run_owner_token" "$$builder_state_volume" \
					>> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				printf '%s\n' "creating a disposable Buildx builder; log: $(CODER_OUTPUT_DIR)/builder.log"; \
					builder_create_status=0; \
					coder_mutate "$(CODER_START_TIMEOUT)" \
						$(CODER_DOCKER) buildx create \
						--name "$$builder_name" \
					--driver docker-container \
					--platform "$(CODER_PLATFORM)" \
					--driver-opt "image=$(CODER_BUILDKIT_IMAGE)" \
					--driver-opt "memory=$(CODER_BUILDKIT_MEMORY)" \
					--driver-opt "memory-swap=$(CODER_BUILDKIT_MEMORY)" \
					--driver-opt "cpu-period=100000" \
						--driver-opt "cpu-quota=$$((100000 * $(CODER_BUILDKIT_CPUS)))" \
						--driver-opt "env.SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" \
						--driver-opt env.BUILDKIT_STEP_LOG_MAX_SIZE=33554432 \
						--driver-opt env.BUILDKIT_STEP_LOG_MAX_SPEED=1048576 \
					> "$(CODER_OUTPUT_DIR)/builder.log" 2>&1 || builder_create_status=$$?; \
					test "$$builder_create_status" -eq 0 || exit "$$builder_create_status"; \
					builder_bootstrap_status=0; \
				coder_mutate "$(CODER_START_TIMEOUT)" \
					$(CODER_DOCKER) buildx inspect --bootstrap "$$builder_name" \
					>> "$(CODER_OUTPUT_DIR)/builder.log" 2>&1 || builder_bootstrap_status=$$?; \
					builder_container_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "name=^/$${builder_container}$$" \
					)"; \
				test -n "$$builder_container_id" && test -z "$$(printf '%s\n' "$$builder_container_id" | sed -n '2p')" || { \
					echo "Buildx did not create exactly one expected builder container" >&2; \
					test "$$builder_bootstrap_status" -eq 0 || exit "$$builder_bootstrap_status"; \
					exit 2; \
				}; \
				case "$$builder_container_id" in *[!0-9a-f]*) echo "Buildx container CID is not lowercase hexadecimal" >&2; exit 2 ;; esac; \
				test "$${#builder_container_id}" -eq 64 || { echo "Buildx container CID has the wrong length" >&2; exit 2; }; \
				test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{index .Config.Labels "com.docker.buildx.builder"}}' "$$builder_container_id" \
			)" = "$$builder_name" || { \
				echo "Buildx container does not expose the expected builder label" >&2; \
					exit 2; \
				}; \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$$builder_container_id" \
					| grep -Fx "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" >/dev/null || { \
							echo "Buildx container does not expose the run owner token" >&2; \
							exit 2; \
						}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect \
							--format '{{range .Mounts}}{{if eq .Destination "/var/lib/buildkit"}}{{.Name}}{{end}}{{end}}' \
							"$$builder_container_id" \
				)" = "$$builder_state_volume" || { \
					echo "BuildKit container is not mounted on the exact owned state volume" >&2; \
					exit 2; \
				}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume inspect \
							--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
							"$$builder_state_volume" \
				)" = "$$builder_state_volume|buildkit-state|$$run_owner_token" || { \
					echo "Buildx replaced or relabeled the owned BuildKit state volume" >&2; \
					exit 2; \
				}; \
				printf 'buildkit-container\t%s\tbuildx-builder\t%s\t%s\n' \
					"$$builder_container" "$$run_owner_token" "$$builder_container_id" \
					>> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				test "$$builder_bootstrap_status" -eq 0 || exit "$$builder_bootstrap_status"; \
					coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) update --pids-limit "$(CODER_BUILDKIT_PIDS)" "$$builder_container_id" \
					>> "$(CODER_OUTPUT_DIR)/builder.log" 2>&1; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.PidsLimit}}' "$$builder_container_id" \
				)" = "17179869184|17179869184|800000|100000|$(CODER_BUILDKIT_PIDS)" || { \
					echo "BuildKit container does not expose the required CPU, memory, swap, and PID bounds" >&2; \
					exit 2; \
				}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Config.Image}}|{{.Image}}' "$$builder_container_id" \
				)" = "$(CODER_BUILDKIT_IMAGE)|$$buildkit_image_id" || { \
					echo "BuildKit container image binding is not exact" >&2; \
					exit 2; \
				}; \
				builder_registration="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) buildx inspect \
							--format '{{.Name}}|{{.Driver}}|{{range .Nodes}}{{.Name}}={{.Endpoint}};{{end}}' \
							"$$builder_name" \
				)"; \
				test "$$builder_registration" = "$$builder_name|docker-container|$${builder_name}0=$(CODER_DOCKER_HOST);" || { \
					echo "Buildx registration does not resolve to the exact owned node and daemon endpoint" >&2; \
					exit 2; \
				}; \
				printf 'builder\t%s\tdocker-container\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
					"$$builder_name" "$${builder_name}0" "$(CODER_DOCKER_HOST)" "$$builder_container_id" \
					"$$builder_state_volume" "$$(cat "$(CODER_DAEMON_ID_FILE)")" "$$buildkit_image_id" \
					"$$run_owner_token" "17179869184|17179869184|800000|100000|$(CODER_BUILDKIT_PIDS)" \
					> "$(CODER_BUILDER_BINDING_FILE)"; \
				chmod 0600 "$(CODER_BUILDER_BINDING_FILE)"; \
				printf 'buildkit-record\t%s\tbuildx-builder\t%s\t%s\n' \
					"$$builder_name" "$$run_owner_token" "$$builder_container_id" \
					>> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				coder_record_task_iid() { \
					record_image_id="$$1"; \
					case "$$record_image_id" in sha256:[0-9a-f]*) ;; *) return 2 ;; esac; \
					test "$${#record_image_id}" -eq 71 || return 2; \
					record_image_digest="$${record_image_id#sha256:}"; \
					case "$$record_image_digest" in *[!0-9a-f]*) return 2 ;; esac; \
					if ! grep -Fx "$$record_image_id" "$(CODER_OUTPUT_DIR)/task-image-ids.txt" >/dev/null; then \
						printf '%s\n' "$$record_image_id" >> "$(CODER_OUTPUT_DIR)/task-image-ids.txt"; \
					fi; \
				}; \
				coder_record_task_image() { \
					record_image_ref="$$1"; \
					record_image_id="$$2"; \
					case "$$record_image_id" in sha256:[0-9a-f]*) ;; \
						*) echo "task image ID is not canonical: $$record_image_ref" >&2; return 2 ;; \
					esac; \
					test "$${#record_image_id}" -eq 71 || return 2; \
					record_image_digest="$${record_image_id#sha256:}"; \
					case "$$record_image_digest" in *[!0-9a-f]*) return 2 ;; esac; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$record_image_ref" \
					)" = "$$record_image_id" || { \
						echo "task image reference does not resolve to its exact IID: $$record_image_ref" >&2; \
						return 2; \
					}; \
					record_line="$$(printf 'task-image\t%s\t%s\t%s' "$$record_image_ref" "$$record_image_id" "$$run_owner_token")"; \
					if grep -F "$$(printf 'task-image\t%s\t' "$$record_image_ref")" "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" >/dev/null; then \
						grep -Fx "$$record_line" "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" >/dev/null || { \
							echo "task image reference was rebound after ownership capture: $$record_image_ref" >&2; \
							return 2; \
						}; \
					else \
						printf '%s\n' "$$record_line" >> "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
					fi; \
					coder_record_task_iid "$$record_image_id"; \
				}; \
				printf '%s\n' "building application services once; log: $(CODER_OUTPUT_DIR)/build.log"; \
			for build_service in $(CODER_BUILD_SERVICES); do \
				case "$$build_service" in \
					serverware) built_image="$(CODER_SHARED_PYTHON_IMAGE)" ;; \
					decision-gate-rs) built_image="$(CODER_DECISION_GATE_IMAGE)" ;; \
					*) echo "unexpected Coder build service: $$build_service" >&2; exit 2 ;; \
				esac; \
				compose_build_status=0; \
				coder_mutate "$(CODER_BUILD_TIMEOUT)" \
					$(CODER_COMPOSE_ENV) BUILDX_BUILDER="$$builder_name" docker compose \
						--ansi never \
						--project-directory "$(CODER_FROZEN_SOURCE_DIR)" \
						--file "$(CODER_FROZEN_SOURCE_DIR)/docker-compose.yml" \
						--file "$(CODER_COMPOSE_LIMITS_FILE)" \
						build --progress plain "$$build_service" \
					>> "$(CODER_OUTPUT_DIR)/build.log" 2>&1 || compose_build_status=$$?; \
				if built_image_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$built_image" 2>/dev/null \
				)"; then \
					coder_record_task_image "$$built_image" "$$built_image_id"; \
				elif test "$$compose_build_status" -eq 0; then \
					echo "successful Compose build did not expose its task image: $$built_image" >&2; \
					exit 2; \
				fi; \
				test "$$compose_build_status" -eq 0 || exit "$$compose_build_status"; \
			done; \
			printf '%s\n' "compiling Rust unit-test harnesses once; log: $(CODER_OUTPUT_DIR)/rust-test-build.log"; \
			rust_test_build_status=0; \
			coder_mutate "$(CODER_RUST_TEST_BUILD_TIMEOUT)" \
				$(CODER_DOCKER) buildx build \
					--builder "$$builder_name" \
					--platform "$(CODER_PLATFORM)" \
					--file "$(CODER_FROZEN_SOURCE_DIR)/data-plane/decision-gate-rs/Dockerfile" \
				--target coder-test-runtime \
				--tag "$(CODER_RUST_TEST_IMAGE)" \
				--iidfile "$(CODER_OUTPUT_DIR)/rust-test-image.iid" \
				--load \
					--progress plain \
					"$(CODER_FROZEN_SOURCE_DIR)" \
			> "$(CODER_OUTPUT_DIR)/rust-test-build.log" 2>&1 || rust_test_build_status=$$?; \
			if test -s "$(CODER_OUTPUT_DIR)/rust-test-image.iid"; then \
				rust_test_image_id="$$(cat "$(CODER_OUTPUT_DIR)/rust-test-image.iid")"; \
				rust_test_tag_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_RUST_TEST_IMAGE)" 2>/dev/null \
				)" || rust_test_tag_id=""; \
				if test "$$rust_test_tag_id" = "$$rust_test_image_id"; then \
					coder_record_task_image "$(CODER_RUST_TEST_IMAGE)" "$$rust_test_image_id"; \
				fi; \
			elif rust_test_observable_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_RUST_TEST_IMAGE)" 2>/dev/null \
			)"; then \
				coder_record_task_image "$(CODER_RUST_TEST_IMAGE)" "$$rust_test_observable_id"; \
			fi; \
			test "$$rust_test_build_status" -eq 0 || exit "$$rust_test_build_status"; \
			printf '%s\n' "building the isolated proxy test runtime once; log: $(CODER_OUTPUT_DIR)/proxy-test-build.log"; \
				proxy_test_build_status=0; \
				coder_mutate "$(CODER_BUILD_TIMEOUT)" \
					$(CODER_DOCKER) buildx build \
						--builder "$$builder_name" \
					--platform "$(CODER_PLATFORM)" \
					--file "$(CODER_FROZEN_SOURCE_DIR)/Dockerfile" \
					--target coder-proxy-test-runtime \
					--tag "$(CODER_PROXY_TEST_IMAGE)" \
					--iidfile "$(CODER_OUTPUT_DIR)/proxy-test-image.iid" \
					--load \
					--progress plain \
						"$(CODER_FROZEN_SOURCE_DIR)" \
					> "$(CODER_OUTPUT_DIR)/proxy-test-build.log" 2>&1 || proxy_test_build_status=$$?; \
				if test -s "$(CODER_OUTPUT_DIR)/proxy-test-image.iid"; then \
					proxy_test_image_id="$$(cat "$(CODER_OUTPUT_DIR)/proxy-test-image.iid")"; \
					proxy_test_tag_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PROXY_TEST_IMAGE)" 2>/dev/null \
					)" || proxy_test_tag_id=""; \
					if test "$$proxy_test_tag_id" = "$$proxy_test_image_id"; then \
						coder_record_task_image "$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_image_id"; \
					fi; \
				elif proxy_test_observable_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PROXY_TEST_IMAGE)" 2>/dev/null \
				)"; then \
					coder_record_task_image "$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_observable_id"; \
				fi; \
				test "$$proxy_test_build_status" -eq 0 || exit "$$proxy_test_build_status"; \
				printf '%s\n' "building the socketless production-host-preflight runtime once; log: $(CODER_OUTPUT_DIR)/production-host-preflight-build.log"; \
				production_host_preflight_build_status=0; \
				coder_mutate "$(CODER_BUILD_TIMEOUT)" \
					$(CODER_DOCKER) buildx build \
						--builder "$$builder_name" \
						--platform "$(CODER_PLATFORM)" \
						--file "$(CODER_FROZEN_SOURCE_DIR)/Dockerfile" \
						--target coder-production-host-preflight-runtime \
						--tag "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" \
						--iidfile "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" \
						--load \
						--progress plain \
						"$(CODER_FROZEN_SOURCE_DIR)" \
					> "$(CODER_OUTPUT_DIR)/production-host-preflight-build.log" 2>&1 || \
						production_host_preflight_build_status=$$?; \
				if test -s "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid"; then \
					production_host_preflight_image_id="$$(cat "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")"; \
					production_host_preflight_tag_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" 2>/dev/null \
					)" || production_host_preflight_tag_id=""; \
					if test "$$production_host_preflight_tag_id" = "$$production_host_preflight_image_id"; then \
						coder_record_task_image "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_image_id"; \
					fi; \
				elif production_host_preflight_observable_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" 2>/dev/null \
				)"; then \
					coder_record_task_image "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_observable_id"; \
				fi; \
				test "$$production_host_preflight_build_status" -eq 0 || exit "$$production_host_preflight_build_status"; \
				coder_require_launcher_builder_identity() { \
					coder_require_mutation_daemon || return 1; \
					current_launcher_builder_container_id="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) ps --all --quiet --no-trunc \
								--filter "name=^/$${builder_container}$$" \
					)" || return 1; \
					test "$$current_launcher_builder_container_id" = "$$builder_container_id" || { \
						echo "launcher preparation builder container identity changed" >&2; \
						return 1; \
					}; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{index .Config.Labels "com.docker.buildx.builder"}}' \
								"$$current_launcher_builder_container_id" \
					)" = "$$builder_name" || { \
						echo "launcher preparation builder label changed" >&2; \
						return 1; \
					}; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{.State.Running}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.CpuQuota}}|{{.HostConfig.CpuPeriod}}|{{.HostConfig.PidsLimit}}' \
								"$$current_launcher_builder_container_id" \
					)" = "true|17179869184|17179869184|800000|100000|$(CODER_BUILDKIT_PIDS)" || { \
						echo "launcher preparation builder state or resource bounds changed" >&2; \
						return 1; \
					}; \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect \
							--format '{{range .Config.Env}}{{println .}}{{end}}' \
							"$$current_launcher_builder_container_id" \
						| grep -Fx "SERVERWARE_CODER_OWNER_TOKEN=$$run_owner_token" >/dev/null || { \
							echo "launcher preparation builder owner identity changed" >&2; \
							return 1; \
						}; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{.Config.Image}}|{{.Image}}' \
								"$$current_launcher_builder_container_id" \
					)" = "$(CODER_BUILDKIT_IMAGE)|$$buildkit_image_id" || return 1; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{range .Mounts}}{{if eq .Destination "/var/lib/buildkit"}}{{.Name}}{{end}}{{end}}' \
								"$$current_launcher_builder_container_id" \
					)" = "$$builder_state_volume" || return 1; \
					current_builder_registration="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) buildx inspect \
								--format '{{.Name}}|{{.Driver}}|{{range .Nodes}}{{.Name}}={{.Endpoint}};{{end}}' \
								"$$builder_name" \
					)" || return 1; \
					test "$$current_builder_registration" = "$$builder_name|docker-container|$${builder_name}0=$(CODER_DOCKER_HOST);" || return 1; \
					current_builder_binding="$(CODER_OUTPUT_DIR)/buildx-builder-binding.current.tsv"; \
					printf 'builder\t%s\tdocker-container\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
						"$$builder_name" "$${builder_name}0" "$(CODER_DOCKER_HOST)" \
						"$$current_launcher_builder_container_id" "$$builder_state_volume" \
						"$$(cat "$(CODER_DAEMON_ID_FILE)")" "$$buildkit_image_id" \
						"$$run_owner_token" "17179869184|17179869184|800000|100000|$(CODER_BUILDKIT_PIDS)" \
						> "$$current_builder_binding"; \
					chmod 0600 "$$current_builder_binding"; \
					cmp "$(CODER_BUILDER_BINDING_FILE)" "$$current_builder_binding" || return 1; \
					rm -f "$$current_builder_binding"; \
				}; \
				coder_require_launcher_builder_identity || { \
					echo "mutation daemon or builder identity is invalid before launcher adversarial image preparation" >&2; \
					exit 2; \
				}; \
				printf '%s\n' "preparing the launcher adversarial fixture image exactly once; log: $(CODER_OUTPUT_DIR)/launcher-adversarial-build.log"; \
				launcher_adversarial_build_tmp="$(CODER_OUTPUT_DIR)/launcher-adversarial-build-tmp"; \
				rm -rf "$$launcher_adversarial_build_tmp"; \
				(umask 077 && mkdir "$$launcher_adversarial_build_tmp"); \
				launcher_command_bin="$$launcher_adversarial_build_tmp/command-bin"; \
				(umask 077 && mkdir "$$launcher_command_bin"); \
				launcher_real_docker="$$(readlink -f "$$(command -v docker)")"; \
				launcher_python="$$(readlink -f "$$(command -v python3)")"; \
				{ \
					printf '%s\n' \
						'#!/bin/sh' \
						'set -eu' \
						"real_docker=$$launcher_real_docker" \
						'case "$${1:-}:$${2:-}" in' \
						'  version:--format|buildx:build|image:inspect) ;;' \
						'  *) echo "launcher Docker shim denied command" >&2; exit 2 ;;' \
						'esac' \
						'exec "$$real_docker" "$$@"'; \
				} > "$$launcher_command_bin/docker"; \
				chmod 0500 "$$launcher_command_bin/docker"; \
				if grep -En '(/usr/(local/)?bin/docker|/var/run/docker\.sock|unix:///var/run/docker\.sock)' \
					"$(CODER_FROZEN_SOURCE_DIR)/$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)" >/dev/null; then \
					echo "launcher harness contains an absolute Docker client or socket bypass" >&2; \
					exit 2; \
				fi; \
				launcher_harness_digest_before="$$(frozen_file_digest "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)")"; \
				test "$$launcher_harness_digest_before" = "$$(cat "$(CODER_OUTPUT_DIR)/launcher-adversarial-script-sha256.txt")" || { \
					echo "launcher adversarial harness changed immediately before execution" >&2; \
					exit 2; \
				}; \
				launcher_adversarial_prepare_status=0; \
				coder_mutate "$(CODER_LAUNCHER_ADVERSARIAL_BUILD_TIMEOUT)" \
					env -i \
						PATH="$$launcher_command_bin" \
						HOME="$$HOME" \
						XDG_RUNTIME_DIR="$$XDG_RUNTIME_DIR" \
						DOCKER_CONFIG="$(CODER_DOCKER_CONFIG_DIR)" \
						DOCKER_HOST="$(CODER_DOCKER_HOST)" \
						BUILDX_CONFIG="$(CODER_BUILDX_CONFIG_DIR)" \
						TMPDIR="$$launcher_adversarial_build_tmp" \
						"$$launcher_python" "$(CODER_FROZEN_SOURCE_DIR)/$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)" \
							--prepare-image \
							--builder "$$builder_name" \
							--image-ref "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" \
							--image-id-out "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" \
							--context-manifest-out "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" \
					> "$(CODER_OUTPUT_DIR)/launcher-adversarial-build.log" 2>&1 || \
						launcher_adversarial_prepare_status=$$?; \
				launcher_harness_digest_after="$$(frozen_file_digest "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)")"; \
				test "$$launcher_harness_digest_after" = "$$launcher_harness_digest_before" || { \
					echo "launcher adversarial harness changed during execution" >&2; \
					exit 2; \
				}; \
				rm -rf "$$launcher_adversarial_build_tmp"; \
				coder_require_launcher_builder_identity || { \
					echo "mutation daemon or builder identity changed during launcher adversarial image preparation" >&2; \
					exit 2; \
				}; \
				launcher_adversarial_tag_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" 2>/dev/null \
				)" || launcher_adversarial_tag_id=""; \
				if test -s "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)"; then \
					launcher_adversarial_iid="$$(cat "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")"; \
					if test "$$launcher_adversarial_tag_id" = "$$launcher_adversarial_iid"; then \
						coder_record_task_image "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_iid"; \
					fi; \
				elif test -n "$$launcher_adversarial_tag_id"; then \
					coder_record_task_image "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_tag_id"; \
				fi; \
				if test -n "$$launcher_adversarial_tag_id"; then \
					case "$$launcher_adversarial_tag_id" in sha256:*) ;; \
						*) echo "prepared launcher adversarial image ID is not canonical" >&2; exit 2 ;; \
					esac; \
					launcher_adversarial_tag_digest="$${launcher_adversarial_tag_id#sha256:}"; \
					test "$${#launcher_adversarial_tag_digest}" -eq 64 || { \
						echo "prepared launcher adversarial image digest has the wrong length" >&2; \
						exit 2; \
					}; \
					case "$$launcher_adversarial_tag_digest" in *[!0-9a-f]*) \
						echo "prepared launcher adversarial image digest is not lowercase hexadecimal" >&2; \
						exit 2 ;; \
					esac; \
				fi; \
				if test "$$launcher_adversarial_prepare_status" -ne 0; then \
					tail -n 200 "$(CODER_OUTPUT_DIR)/launcher-adversarial-build.log" >&2 || true; \
					exit "$$launcher_adversarial_prepare_status"; \
				fi; \
				test -s "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" && \
					test -f "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" && \
					test ! -L "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" && \
					test "$$(stat -Lc '%u:%a:%F' "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)")" = "$$(id -u):600:regular file" || { \
						echo "launcher adversarial build-input manifest is missing or unsafe" >&2; \
						exit 2; \
					}; \
			test -s "$(CODER_OUTPUT_DIR)/rust-test-image.iid" || { \
			echo "Rust test image build did not produce an image ID" >&2; \
			exit 2; \
		}; \
		test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/rust-test-image.iid")" || { \
			echo "Rust test image ID file contains multiple lines" >&2; \
			exit 2; \
		}; \
		rust_test_image_id="$$(cat "$(CODER_OUTPUT_DIR)/rust-test-image.iid")"; \
		case "$$rust_test_image_id" in \
			sha256:*) ;; \
			*) echo "Rust test image ID is not canonical: $$rust_test_image_id" >&2; exit 2 ;; \
		esac; \
		rust_test_image_digest="$${rust_test_image_id#sha256:}"; \
		test "$${#rust_test_image_digest}" -eq 64 || { \
			echo "Rust test image digest has the wrong length" >&2; \
			exit 2; \
		}; \
		case "$$rust_test_image_digest" in \
			*[!0-9a-f]*) echo "Rust test image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
		esac; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_RUST_TEST_IMAGE)" \
			)" = "$$rust_test_image_id" || { \
			echo "loaded Rust test image tag does not resolve to the Buildx image ID" >&2; \
				exit 2; \
			}; \
			coder_record_task_image "$(CODER_RUST_TEST_IMAGE)" "$$rust_test_image_id"; \
			test -s "$(CODER_OUTPUT_DIR)/proxy-test-image.iid" || { \
				echo "proxy test image build did not produce an image ID" >&2; \
				exit 2; \
			}; \
			test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/proxy-test-image.iid")" || { \
				echo "proxy test image ID file contains multiple lines" >&2; \
				exit 2; \
			}; \
			proxy_test_image_id="$$(cat "$(CODER_OUTPUT_DIR)/proxy-test-image.iid")"; \
			case "$$proxy_test_image_id" in \
				sha256:*) ;; \
				*) echo "proxy test image ID is not canonical: $$proxy_test_image_id" >&2; exit 2 ;; \
			esac; \
			proxy_test_image_digest="$${proxy_test_image_id#sha256:}"; \
			test "$${#proxy_test_image_digest}" -eq 64 || { \
				echo "proxy test image digest has the wrong length" >&2; \
				exit 2; \
			}; \
			case "$$proxy_test_image_digest" in \
				*[!0-9a-f]*) echo "proxy test image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
			esac; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PROXY_TEST_IMAGE)" \
			)" = "$$proxy_test_image_id" || { \
				echo "loaded proxy test image tag does not resolve to the Buildx image ID" >&2; \
					exit 2; \
				}; \
				coder_record_task_image "$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_image_id"; \
				test -s "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" || { \
					echo "production-host-preflight image build did not produce an image ID" >&2; \
					exit 2; \
				}; \
				test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")" || { \
					echo "production-host-preflight image ID file contains multiple lines" >&2; \
					exit 2; \
				}; \
				production_host_preflight_image_id="$$(cat "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")"; \
				case "$$production_host_preflight_image_id" in \
					sha256:*) ;; \
					*) echo "production-host-preflight image ID is not canonical" >&2; exit 2 ;; \
				esac; \
				production_host_preflight_image_digest="$${production_host_preflight_image_id#sha256:}"; \
				test "$${#production_host_preflight_image_digest}" -eq 64 || { \
					echo "production-host-preflight image digest has the wrong length" >&2; \
					exit 2; \
				}; \
				case "$$production_host_preflight_image_digest" in \
					*[!0-9a-f]*) echo "production-host-preflight image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
				esac; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" \
				)" = "$$production_host_preflight_image_id" || { \
					echo "loaded production-host-preflight image tag does not resolve to the Buildx image ID" >&2; \
					exit 2; \
				}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$production_host_preflight_image_id" \
				)" = "linux/amd64" || { \
					echo "production-host-preflight image does not match the required linux/amd64 platform" >&2; \
					exit 2; \
				}; \
				coder_record_task_image "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_image_id"; \
				test -f "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" && \
					test ! -L "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" || { \
					echo "production-host-preflight image ID file is unsafe" >&2; \
					exit 2; \
				}; \
				chmod 0600 "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid"; \
				test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")" = "$$(id -u):600:regular file"; \
				test -f "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" && \
					test ! -L "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" || { \
					echo "launcher adversarial preparation did not produce a safe image ID file" >&2; \
					exit 2; \
				}; \
				chmod 0600 "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)"; \
				test "$$(stat -Lc '%u:%a:%F' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")" = "$$(id -u):600:regular file"; \
				test -z "$$(sed -n '2p' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")" || { \
					echo "launcher adversarial image ID file contains multiple lines" >&2; \
					exit 2; \
				}; \
				launcher_adversarial_image_id="$$(cat "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")"; \
				case "$$launcher_adversarial_image_id" in \
					sha256:*) ;; \
					*) echo "launcher adversarial image ID is not canonical" >&2; exit 2 ;; \
				esac; \
				launcher_adversarial_image_digest="$${launcher_adversarial_image_id#sha256:}"; \
				test "$${#launcher_adversarial_image_digest}" -eq 64 || { \
					echo "launcher adversarial image digest has the wrong length" >&2; \
					exit 2; \
				}; \
				case "$$launcher_adversarial_image_digest" in \
					*[!0-9a-f]*) echo "launcher adversarial image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
				esac; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" \
				)" = "$$launcher_adversarial_image_id" || { \
					echo "launcher adversarial image tag does not resolve to its prepared exact ID" >&2; \
					exit 2; \
				}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$launcher_adversarial_image_id" \
				)" = "linux/amd64" || { \
					echo "launcher adversarial image does not match the required linux/amd64 platform" >&2; \
					exit 2; \
				}; \
				coder_record_task_image "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_image_id"; \
				shared_python_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_SHARED_PYTHON_IMAGE)" \
			)"; \
			coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image tag "$$shared_python_id" "$(CODER_AUDIT_ANCHOR_IMAGE)"; \
			coder_record_task_image "$(CODER_AUDIT_ANCHOR_IMAGE)" "$$shared_python_id"; \
			coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) image tag "$$shared_python_id" "$(CODER_DEMO_UPSTREAM_IMAGE)"; \
			coder_record_task_image "$(CODER_DEMO_UPSTREAM_IMAGE)" "$$shared_python_id"; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_BUILDKIT_IMAGE)" \
			)" = "$$buildkit_image_id" || { \
				echo "the loaded BuildKit image ID changed during build preparation" >&2; \
				exit 2; \
			}; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{.Config.Image}}' "$$builder_container_id" \
			)" = "$(CODER_BUILDKIT_IMAGE)" || { \
				echo "the Buildx builder does not use the pinned BuildKit reference" >&2; \
				exit 2; \
			}; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect --format '{{.Image}}' "$$builder_container_id" \
			)" = "$$buildkit_image_id" || { \
				echo "the Buildx builder does not use the recorded BuildKit image ID" >&2; \
				exit 2; \
			}; \
				decision_gate_image_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_DECISION_GATE_IMAGE)" \
				)"; \
					printf '%s\n' "$$decision_gate_image_id" \
						> "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)"; \
					chmod 0600 "$(CODER_DECISION_GATE_MEASURE_IMAGE_ID_FILE)"; \
					decision_gate_measure_cid="$(CODER_OUTPUT_DIR)/decision-gate-measure.cid"; \
					test ! -L "$$decision_gate_measure_cid"; \
					rm -f "$$decision_gate_measure_cid"; \
					measurement_create_status=0; \
					measurement_container_id="$$( \
						coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) create \
							--name "$(CODER_DECISION_GATE_MEASURE_CONTAINER)" \
							--cidfile "$$decision_gate_measure_cid" \
							--label "$(CODER_DECISION_GATE_MEASURE_CONTAINER_LABEL)" \
						--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
						--platform "$(CODER_PLATFORM)" \
							--entrypoint /usr/local/bin/serverware-decision-gate \
							"$$decision_gate_image_id" --help \
				)" || measurement_create_status=$$?; \
					if test -z "$$measurement_container_id" && \
						test -f "$$decision_gate_measure_cid" && test ! -L "$$decision_gate_measure_cid" && \
						test "$$(stat -Lc '%u:%F' "$$decision_gate_measure_cid")" = "$$(id -u):regular file"; then \
						measurement_cid_candidate="$$(cat "$$decision_gate_measure_cid")"; \
						if test -n "$$measurement_cid_candidate" && \
							test -z "$$(sed -n '2p' "$$decision_gate_measure_cid)"; then \
							case "$$measurement_cid_candidate" in *[!0-9a-f]*) measurement_cid_candidate="" ;; esac; \
							test -z "$$measurement_cid_candidate" || \
								test "$${#measurement_cid_candidate}" -eq 64 || measurement_cid_candidate=""; \
						else \
							measurement_cid_candidate=""; \
						fi; \
						measurement_container_id="$$measurement_cid_candidate"; \
					fi; \
					if test -z "$$measurement_container_id"; then \
						measurement_container_id="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) ps --all --quiet --no-trunc \
									--filter "name=^/$(CODER_DECISION_GATE_MEASURE_CONTAINER)$$" \
						)" || measurement_container_id=""; \
						if test -n "$$measurement_container_id" && \
							test -z "$$(printf '%s\n' "$$measurement_container_id" | sed -n '2p')" && \
							test "$$( \
								$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
									$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$measurement_container_id" \
							)" = "$$decision_gate_image_id|/$(CODER_DECISION_GATE_MEASURE_CONTAINER)|decision-gate-measure|$$run_owner_token"; then \
							if test -e "$$decision_gate_measure_cid" || test -L "$$decision_gate_measure_cid"; then \
								test -f "$$decision_gate_measure_cid" && test ! -L "$$decision_gate_measure_cid" && \
									test "$$(stat -Lc '%u:%F' "$$decision_gate_measure_cid")" = "$$(id -u):regular file" || { \
									echo "refusing unsafe decision-gate measurement CID recovery file" >&2; \
									exit 2; \
								}; \
								rm -f "$$decision_gate_measure_cid"; \
							fi; \
							(umask 077 && printf '%s\n' "$$measurement_container_id" > "$$decision_gate_measure_cid"); \
						fi; \
					fi; \
					test -n "$$measurement_container_id" || { \
						echo "decision-gate measurement container was not created" >&2; \
						test "$$measurement_create_status" -eq 0 || exit "$$measurement_create_status"; \
						exit 2; \
					}; \
				case "$$measurement_container_id" in *[!0-9a-f]*) \
					echo "decision-gate measurement CID is not lowercase hexadecimal" >&2; \
					exit 2 ;; \
				esac; \
				test "$${#measurement_container_id}" -eq 64 && \
					test -f "$$decision_gate_measure_cid" && test ! -L "$$decision_gate_measure_cid" && \
					test "$$(cat "$$decision_gate_measure_cid")" = "$$measurement_container_id" && \
					test -z "$$(sed -n '2p' "$$decision_gate_measure_cid")" || { \
					echo "decision-gate measurement CID file does not match docker create output" >&2; \
					exit 2; \
				}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$measurement_container_id" \
				)" = "$$decision_gate_image_id|/$(CODER_DECISION_GATE_MEASURE_CONTAINER)|decision-gate-measure|$$run_owner_token" || { \
					echo "decision-gate measurement container ownership validation failed" >&2; \
					exit 2; \
				}; \
				printf 'container\t%s\tdecision-gate-measure\t%s\t%s\n' \
					"$(CODER_DECISION_GATE_MEASURE_CONTAINER)" "$$run_owner_token" "$$measurement_container_id" \
					>> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				test "$$measurement_create_status" -eq 0 || exit "$$measurement_create_status"; \
			coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) cp \
					"$$measurement_container_id:/usr/local/bin/serverware-decision-gate" \
					"$(CODER_OUTPUT_DIR)/serverware-decision-gate.measured"; \
				coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
					$(CODER_DOCKER) rm -f "$$measurement_container_id" \
					>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1; \
				rm -f "$$decision_gate_measure_cid"; \
			decision_gate_binary_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/serverware-decision-gate.measured")"; \
			decision_gate_binary_digest="sha256:$${decision_gate_binary_digest_line%% *}"; \
			rm -f "$(CODER_OUTPUT_DIR)/serverware-decision-gate.measured"; \
			case "$$decision_gate_binary_digest" in sha256:*) ;; *) echo "measured decision-gate binary digest is not canonical" >&2; exit 2 ;; esac; \
			decision_gate_binary_hex="$${decision_gate_binary_digest#sha256:}"; \
			test "$${#decision_gate_binary_hex}" -eq 64; \
			case "$$decision_gate_binary_hex" in *[!0-9a-f]*) echo "measured decision-gate binary digest is not lowercase hexadecimal" >&2; exit 2 ;; esac; \
			printf '%s\n' "$$decision_gate_binary_digest" \
				> "$(CODER_DECISION_GATE_BINARY_DIGEST_FILE)"; \
			{ \
				printf '%s\n' \
					'services:' \
					'  serverware:' \
					'    environment:' \
					"      SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST: \"$$decision_gate_binary_digest\""; \
			} > "$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)"; \
			compose_override_digest_line="$$(sha256sum "$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)")"; \
			printf '%s\n' "$${compose_override_digest_line%% *}" \
				> "$(CODER_COMPOSE_DIGEST_OVERRIDE_SHA256_FILE)"; \
			grant_store_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$(CODER_POSTGRES_IMAGE)" \
			)"; \
			test "$$grant_store_image_id" = "$$postgres_image_id" || { \
				echo "pinned Postgres image identity changed after dependency recording" >&2; \
				exit 2; \
			}; \
			{ \
				printf '%s\n' \
					'services:' \
					'  grant-store:' \
					"    image: \"$$grant_store_image_id\"" \
					'    pull_policy: never' \
					'  audit-anchor:' \
					"    image: \"$$shared_python_id\"" \
					'    pull_policy: never' \
					'  demo-upstream:' \
					"    image: \"$$shared_python_id\"" \
					'    pull_policy: never' \
					'  serverware:' \
					"    image: \"$$shared_python_id\"" \
					'    pull_policy: never' \
					'  decision-gate-rs:' \
					"    image: \"$$decision_gate_image_id\"" \
					'    pull_policy: never'; \
			} > "$(CODER_COMPOSE_IMAGE_OVERRIDE_FILE)"; \
		$(MAKE) --no-print-directory _coder-require-clean; \
		test "$$(git rev-parse HEAD)" = "$$source_commit" || { \
			echo "HEAD changed while the frozen Coder build was running" >&2; \
			exit 2; \
		}; \
		test "$$(git rev-parse 'HEAD^{tree}')" = "$$source_tree" || { \
			echo "the committed tree changed while the frozen Coder build was running" >&2; \
			exit 2; \
		}; \
		test "$$(source_tree_digest)" = "$$frozen_source_digest" || { \
			echo "the extracted frozen source changed while the Coder build was running" >&2; \
			exit 2; \
		}; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_COMPOSE) config \
			> "$(CODER_OUTPUT_DIR)/compose-config.yaml"; \
		test "$$(grep -Ec '^    cpus: (4|4\\.0)$$' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 5 || { \
			echo "resolved Compose configuration does not contain five Coder CPU limits" >&2; \
			exit 2; \
		}; \
		test "$$(grep -Ec '^    mem_limit: \"?2147483648\"?$$' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 5 || { \
			echo "resolved Compose configuration does not contain five 2 GiB memory limits" >&2; \
			exit 2; \
		}; \
		test "$$(grep -Ec '^    memswap_limit: \"?2147483648\"?$$' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 5 || { \
			echo "resolved Compose configuration does not contain five swap-equals-memory limits" >&2; \
			exit 2; \
		}; \
		test "$$(grep -c '^    pids_limit: 512$$' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 5 || { \
			echo "resolved Compose configuration does not contain five Coder PID limits" >&2; \
			exit 2; \
		}; \
		test "$$(grep -c '^      $(CODER_OWNER_LABEL_KEY): $$run_owner_token$$' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -ge 13 || { \
			echo "resolved Compose configuration is missing run ownership labels" >&2; \
			exit 2; \
		}; \
			test "$$(grep -Ec 'size=$(CODER_SERVICE_TMPFS_SIZE)(,|$$)' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 4 && \
				test "$$(grep -Ec 'size=$(CODER_SERVERWARE_TMPFS_SIZE)(,|$$)' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 1 && \
				test "$$(grep -Ec 'size=$(CODER_GRANT_STORE_RUN_TMPFS_SIZE)(,|$$)' "$(CODER_OUTPUT_DIR)/compose-config.yaml")" -eq 1 || { \
				echo "resolved Compose configuration does not contain the exact six Coder tmpfs bounds" >&2; \
				exit 2; \
			}; \
		compose_config_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/compose-config.yaml")"; \
		printf '%s\n' "$${compose_config_digest_line%% *}" \
			> "$(CODER_OUTPUT_DIR)/compose-config-sha256.txt"; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_COMPOSE) config --images \
			> "$(CODER_OUTPUT_DIR)/image-references.unsorted.txt"; \
		LC_ALL=C sort -u \
			"$(CODER_OUTPUT_DIR)/image-references.unsorted.txt" \
			> "$(CODER_OUTPUT_DIR)/image-references.txt"; \
		rm -f "$(CODER_OUTPUT_DIR)/image-references.unsorted.txt"; \
		test -s "$(CODER_OUTPUT_DIR)/image-references.txt" || { \
			echo "Compose returned no image references after the build" >&2; \
			exit 2; \
		}; \
		: > "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
		while IFS= read -r image; do \
			test -n "$$image" || continue; \
				image_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$image" \
				)"; \
				repo_digests="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$image" \
				)"; \
			printf 'image=%s id=%s repo_digests=%s\n' "$$image" "$$image_id" "$$repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
		done < "$(CODER_OUTPUT_DIR)/image-references.txt"; \
			rust_test_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$rust_test_image_id" \
			)"; \
		printf 'image=%s id=%s repo_digests=%s\n' \
				"$(CODER_RUST_TEST_IMAGE)" "$$rust_test_image_id" "$$rust_test_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
			proxy_test_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$proxy_test_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_image_id" "$$proxy_test_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
			production_host_preflight_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$production_host_preflight_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_image_id" "$$production_host_preflight_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
			launcher_adversarial_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$launcher_adversarial_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_image_id" "$$launcher_adversarial_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/image-digests.txt"; \
		test -s "$(CODER_OUTPUT_DIR)/image-digests.txt" || { \
			echo "no image digests were recorded after the build" >&2; \
			exit 2; \
		}; \
		: > "$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt"; \
		printf '%s %s %s\n' \
			grant-store "$(CODER_POSTGRES_IMAGE)" "$$grant_store_image_id" \
			audit-anchor "$(CODER_AUDIT_ANCHOR_IMAGE)" "$$shared_python_id" \
			demo-upstream "$(CODER_DEMO_UPSTREAM_IMAGE)" "$$shared_python_id" \
			serverware "$(CODER_SHARED_PYTHON_IMAGE)" "$$shared_python_id" \
			decision-gate-rs "$(CODER_DECISION_GATE_IMAGE)" "$$decision_gate_image_id" \
			> "$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt"; \
			printf '%s %s\n' "$(CODER_RUST_TEST_IMAGE)" "$$rust_test_image_id" \
				> "$(CODER_OUTPUT_DIR)/rust-test-image-binding.txt"; \
			printf '%s %s\n' "$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_image_id" \
				> "$(CODER_OUTPUT_DIR)/proxy-test-image-binding.txt"; \
			printf '%s %s\n' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_image_id" \
				> "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)"; \
			{ \
				for python_test_path in $(CODER_ISOLATED_TEST_SCRIPTS); do \
					python_test_image_id="$$shared_python_id"; \
					if test "$$python_test_path" = scripts/test_production_release_proof_target.py; then \
						python_test_image_id="$$proxy_test_image_id"; \
					fi; \
					printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
						"$$python_test_path" "$$python_test_image_id" \
						"$(CODER_IMAGE_PYTHON_INTERPRETER)" "$$python_test_path"; \
				done; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					scripts/test_credential_constraints.py \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_credential_constraints.py; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\t%s\n' \
					'scripts/test_credential_constraints.py#proxy-transport-only' \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_credential_constraints.py \
					--proxy-transport-only; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					scripts/test_jit_transaction_state.py \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_jit_transaction_state.py; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)" \
					"$$production_host_preflight_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)"; \
			} | LC_ALL=C sort > "$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)"; \
			printf '%s %s\n' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_image_id" \
				> "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)"; \
			chmod 0600 \
				"$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)" \
				"$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)" \
				"$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)"; \
			printf '%s\n' "$$shared_python_id" "$$decision_gate_image_id" "$$rust_test_image_id" "$$proxy_test_image_id" "$$production_host_preflight_image_id" "$$launcher_adversarial_image_id" \
				| LC_ALL=C sort -u > "$(CODER_OUTPUT_DIR)/task-image-ids.txt"; \
			{ \
				printf 'schema\tserverware.coder-ci.batch-coverage.v2\n'; \
				printf 'classification\tuntrusted-capacity-diagnostics-not-attestation\n'; \
				printf 'boundary\tcooperative-trusted-orchestrator\texclusive-disposable-dind-required\n'; \
				printf 'boundary\thostile-source-containment\tfalse\n'; \
				printf 'boundary\tdocker-socket-containment\tfalse\n'; \
				printf 'boundary\trepository-and-same-uid-output-immutable\tfalse\n'; \
				printf 'boundary\tterminal-cleanup-requirement\ttrusted-orchestrator-destroys-exclusive-dind-sidecar\n'; \
				printf 'source\tcommit\t%s\n' "$$source_commit"; \
				printf 'source\tfirst-parent\t%s\n' "$$source_parent"; \
				printf 'source\tbase-tree\t%s\n' "$$source_base_tree"; \
				printf 'source\ttree\t%s\n' "$$source_tree"; \
				printf 'source\tfrozen-tree-sha256\t%s\n' "$$frozen_source_digest"; \
				printf 'source\tarchive-sha256\t%s\n' "$$source_archive_digest"; \
				printf 'daemon\tid\t%s\n' "$$(cat "$(CODER_DAEMON_ID_FILE)")"; \
				printf 'build-host\ttool-daemon-identity\tsha256:%s\thost-tool-daemon-identity.tsv\n' "$$host_identity_digest"; \
				printf 'build-host\tbuildx-builder-binding\t%s\tbuildx-builder-binding.tsv\n' "$$(sha256sum "$(CODER_BUILDER_BINDING_FILE)" | sed 's/ .*//')"; \
				printf 'build-dependency\tbuildkit-driver\t%s\t%s\n' "$(CODER_BUILDKIT_IMAGE)" "$$buildkit_image_id"; \
				printf 'build-input\tlauncher-adversarial-rust-slim-base\t%s\t%s\n' "$(CODER_LAUNCHER_ADVERSARIAL_RUST_SLIM_BASE)" "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)"; \
				printf 'build-input\tlauncher-adversarial-rust-alpine-base\t%s\t%s\n' "$(CODER_LAUNCHER_ADVERSARIAL_RUST_ALPINE_BASE)" "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)"; \
				printf 'build-input\tlauncher-adversarial-python-slim-base\t%s\t%s\n' "$(CODER_LAUNCHER_ADVERSARIAL_PYTHON_SLIM_BASE)" "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)"; \
				printf 'build-input\tlauncher-adversarial-harness\t%s\t%s\n' "$$(cat "$(CODER_OUTPUT_DIR)/launcher-adversarial-script-sha256.txt")" "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)"; \
				printf 'build-input\tlauncher-adversarial-context\t%s\tlauncher-adversarial-build-inputs.json\n' "$$(sha256sum "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\te2e-host-script\t%s\tscripts/e2e.sh\n' "$$(cat "$(CODER_OUTPUT_DIR)/e2e-script-sha256.txt")"; \
				for e2e_child in scripts/install_verified_ca.sh scripts/wait_for_serverware.sh scripts/wait_for_demo_upstream.sh scripts/wait_for_decision_gate.sh; do \
					printf 'build-input\te2e-host-child\t%s\t%s\n' "$$(frozen_file_digest "$$e2e_child")" "$$e2e_child"; \
				done; \
				printf 'build-input\ttest-inventory-git\t%s\ttest-inventory.git.txt\n' "$$(sha256sum "$(CODER_OUTPUT_DIR)/test-inventory.git.txt" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-frozen-archive\t%s\ttest-inventory.archive.txt\n' "$$(sha256sum "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-outside-frozen-commit\t%s\ttest-inventory.untracked.txt\n' "$$(sha256sum "$(CODER_OUTPUT_DIR)/test-inventory.untracked.txt" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-changed-from-recorded-base\t%s\ttest-inventory.changed.txt\n' "$$(sha256sum "$(CODER_CHANGED_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-prepared\t%s\ttest-inventory.prepared.txt\n' "$$(sha256sum "$(CODER_PREPARED_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-blocked-prerequisite\t%s\ttest-inventory.blocked-prerequisite.txt\n' "$$(sha256sum "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-excluded\t%s\ttest-inventory.excluded.txt\n' "$$(sha256sum "$(CODER_EXCLUDED_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-changed-excluded\t%s\ttest-inventory.changed-excluded.txt\n' "$$(sha256sum "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\ttest-inventory-changed-blocked-prerequisite\t%s\ttest-inventory.changed-blocked-prerequisite.txt\n' "$$(sha256sum "$(CODER_CHANGED_BLOCKED_PREREQUISITE_TESTS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\tdependency-preexisting-image-ids\t%s\tdependency-image-preexisting-ids.txt\n' "$$(sha256sum "$(CODER_DEPENDENCY_PREEXISTING_IDS_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\tpython-test-argv-bindings\t%s\tpython-test-argv-bindings.tsv\n' "$$(sha256sum "$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)" | sed 's/ .*//')"; \
				printf 'build-input\tproduction-python-lock\t%s\trequirements.lock\n' "$$(frozen_file_digest requirements.lock)"; \
				printf 'build-input\tbrowser-python-lock\t%s\trequirements.browser.lock\n' "$$(frozen_file_digest requirements.browser.lock)"; \
				printf 'build-input\tproxy-python-lock\t%s\trequirements.proxy-test.lock\n' "$$(frozen_file_digest requirements.proxy-test.lock)"; \
				printf 'build-input\tclean-room-python-lock\t%s\tserverware_agent_trust/requirements.lock\n' "$$(frozen_file_digest serverware_agent_trust/requirements.lock)"; \
				printf 'build-input\tconsolidated-oci-entrypoint\t%s\tscripts/oci_lane_entrypoint.py\n' "$$(frozen_file_digest scripts/oci_lane_entrypoint.py)"; \
				printf 'build-input\tsame-journey-verifier\t%s\tscripts/verify_agent_trust_same_journey.py\n' "$$(frozen_file_digest scripts/verify_agent_trust_same_journey.py)"; \
				printf 'build-input\trust-lock\t%s\tdata-plane/decision-gate-rs/Cargo.lock\n' "$$(frozen_file_digest data-plane/decision-gate-rs/Cargo.lock)"; \
				printf 'build-input\trust-discard-header-parity\t%s\tscripts/discard_headers_parity.v1.json\n' "$$(frozen_file_digest scripts/discard_headers_parity.v1.json)"; \
				printf 'build-input\tcredential-policy-examples\t%s\tpolicies/credential-limits.examples.json\n' "$$(frozen_file_digest policies/credential-limits.examples.json)"; \
				printf 'built-artifact\tproduction-python-image\t%s\t%s\n' "$(CODER_SHARED_PYTHON_IMAGE)" "$$shared_python_id"; \
				printf 'built-artifact\tdecision-gate-runtime-image\t%s\t%s\n' "$(CODER_DECISION_GATE_IMAGE)" "$$decision_gate_image_id"; \
				printf 'built-artifact\tdecision-gate-runtime-binary\t%s\t/usr/local/bin/serverware-decision-gate\n' "$$decision_gate_binary_digest"; \
				printf 'built-artifact\trust-test-runtime-image\t%s\t%s\n' "$(CODER_RUST_TEST_IMAGE)" "$$rust_test_image_id"; \
				printf 'built-artifact\tproxy-test-runtime-image\t%s\t%s\n' "$(CODER_PROXY_TEST_IMAGE)" "$$proxy_test_image_id"; \
				printf 'built-artifact\tproduction-host-preflight-runtime-image\t%s\t%s\n' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" "$$production_host_preflight_image_id"; \
				printf 'built-artifact\tproduction-host-preflight-runtime-iid\t%s\tproduction-host-preflight-image.iid\n' "$$production_host_preflight_image_id"; \
				printf 'built-artifact\tlauncher-adversarial-runtime-image\t%s\t%s\n' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" "$$launcher_adversarial_image_id"; \
				printf 'build-ownership\ttask-images\t%s\ttask-image-ownership.tsv\n' "$$(sha256sum "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" | sed 's/ .*//')"; \
				printf 'build-ownership\tdependency-images\t%s\tdependency-image-ownership.tsv\n' "$$(sha256sum "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)" | sed 's/ .*//')"; \
				printf 'built-artifact\tcompose-digest-override\t%s\tcompose-digest-override.yaml\n' "$$(cat "$(CODER_COMPOSE_DIGEST_OVERRIDE_SHA256_FILE)")"; \
				printf 'runtime-dependency\tgrant-store\t%s\n' "$(CODER_POSTGRES_IMAGE)"; \
				for test_path in $(CODER_ISOLATED_TEST_SCRIPTS); do \
					if test "$$test_path" = scripts/test_production_release_proof_target.py; then \
						printf 'test\tprepared\t%s\tpython-isolated-proxy-test-image\texact image-bound /usr/local/bin/python3.11 plus frozen /app script argv, frozen root inputs, and fresh tmpfs state\n' "$$test_path"; \
					else \
						printf 'test\tprepared\t%s\tpython-isolated-production-image\texact image-bound /usr/local/bin/python3.11 plus frozen /app script argv and fresh tmpfs state\n' "$$test_path"; \
					fi; \
				done; \
				printf 'test\tprepared\t%s\tproduction-host-preflight-runtime\texact image-bound /usr/local/bin/python3.11 plus frozen /app script argv, frozen Docker and Compose executable bindings, nonexistent socket, and cooperative diagnostics only\n' "$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)"; \
				printf 'test\tprepared\t%s\tlauncher-adversarial-runtime\texact prebuilt image entrypoint with managed container lifecycle\n' "$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)"; \
				printf 'test\tprepared\tscripts/test_credential_constraints.py\tproxy-test-runtime\texact image-bound /usr/local/bin/python3.11 plus frozen /app script argv; full fixtures\n'; \
				printf 'test\tprepared\tscripts/test_credential_constraints.py#proxy-transport-only\tproxy-test-runtime\texact image-bound /usr/local/bin/python3.11 plus frozen /app script and --proxy-transport-only argv\n'; \
				printf 'test\tprepared\tscripts/test_jit_transaction_state.py\tproxy-test-runtime\texact image-bound /usr/local/bin/python3.11 plus frozen /app script argv; full fixtures\n'; \
				printf 'test\tprepared\trust-unit-harnesses\trust-test-runtime\tprecompiled closed harness inventory\n'; \
				for test_path in $(CODER_TEST_SCRIPTS); do \
					printf 'test\tprepared\t%s\tcompose-shared-service-group\tsequential group with one fresh stack\n' "$$test_path"; \
				done; \
				printf 'test\tprepared\tscripts/e2e.sh\tcompose-fresh-e2e-group\tuntrusted host diagnostics with reviewed digest and exact-image stack; not attestation\n'; \
				while IFS= read -r test_path; do \
					test -n "$$test_path" || continue; \
					case "$$test_path" in \
						scripts/test_agent_trust_clean_room.py) prerequisite_detail="reviewed privileged exact-mount OCI launcher and signed exact clean-room payload required; ordinary Docker is contract-incompatible" ;; \
						scripts/test_portal_browser_oauth.py) prerequisite_detail="digest-bound Chromium executable with complete shared-library, font, and runtime closure; digest-bound Node executable with npm CLI, package manifest, package-manager dependencies, and offline package/cache closure; corrected Candidate Manifest v6 same-journey callback inputs binding promotion receipt, launcher lease/capability, browser result, and npm request/result; and trusted one-use npm companion broker with no Docker authority in the browser container required" ;; \
						scripts/test_response_proof_capture.sh) prerequisite_detail="external root-owned fixed-command coder-test-controller owning the exclusive disposable DinD socket and frozen response-proof stage protocol required" ;; \
						*) echo "unknown blocked-prerequisite test: $$test_path" >&2; exit 2 ;; \
					esac; \
					printf 'test\tblocked-prerequisite\t%s\tnot-run\t%s\n' "$$test_path" "$$prerequisite_detail"; \
				done < "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; \
				while IFS= read -r test_path; do \
					test -n "$$test_path" || continue; \
					exclusion_detail="tracked historical harness outside the bounded changed-source build-once Coder batch"; \
					printf 'test\texcluded\t%s\tnot-run\t%s\n' "$$test_path" "$$exclusion_detail"; \
				done < "$(CODER_EXCLUDED_TESTS_FILE)"; \
			} > "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv"; \
			: > "$(CODER_OUTPUT_DIR)/batch-coverage-test-ids.txt"; \
			coverage_tab="$$(printf '\t')"; \
			coverage_test_count=0; \
			while IFS="$$coverage_tab" read -r record disposition test_id runner detail; do \
				test "$$record" = test || continue; \
				test -n "$$test_id" && test -n "$$disposition" && test -n "$$runner" || { \
					echo "batch coverage manifest contains an incomplete test record" >&2; \
					exit 2; \
				}; \
				case "$$disposition" in prepared|blocked-prerequisite|excluded) ;; *) echo "invalid test disposition: $$disposition" >&2; exit 2 ;; esac; \
				if grep -Fx "$$test_id" "$(CODER_OUTPUT_DIR)/batch-coverage-test-ids.txt" >/dev/null; then \
					echo "duplicate canonical test ID in batch coverage manifest: $$test_id" >&2; \
					exit 2; \
				fi; \
				printf '%s\n' "$$test_id" >> "$(CODER_OUTPUT_DIR)/batch-coverage-test-ids.txt"; \
				coverage_test_count=$$((coverage_test_count + 1)); \
			done < "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv"; \
			test "$$coverage_test_count" -gt 0; \
			rm -f "$(CODER_OUTPUT_DIR)/batch-coverage-test-ids.txt"; \
			batch_coverage_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv")"; \
			printf '%s\n' "$${batch_coverage_digest_line%% *}" \
				> "$(CODER_OUTPUT_DIR)/batch-coverage-manifest-sha256.txt"; \
			printf '%s\n' "$$source_commit" > "$(CODER_OUTPUT_DIR)/build-commit.txt"; \
		printf '%s\n' "$$source_tree" > "$(CODER_OUTPUT_DIR)/build-tree.txt"; \
		printf '%s\n' "$$frozen_source_digest" > "$(CODER_OUTPUT_DIR)/build-source-tree-sha256.txt"; \
		printf '%s\n' "$$source_archive_digest" > "$(CODER_OUTPUT_DIR)/source-archive-sha256.txt"; \
		echo "image_digests=$(CODER_OUTPUT_DIR)/image-digests.txt" >> "$(CODER_OUTPUT_DIR)/diagnostics.txt"; \
		printf '%s\n' "untrusted image diagnostics: $(CODER_OUTPUT_DIR)/image-digests.txt"

coder-test-no-build:
	@set -eu; \
		lock_dir="$(CODER_LOCK_DIRECTORY)"; \
		test -d "$$lock_dir" && test ! -L "$$lock_dir"; \
		test "$$(stat -Lc '%u:%F' "$$lock_dir")" = "0:directory"; \
		exec 9<"$$lock_dir"; \
		flock --exclusive --nonblock 9; \
		finalize_state=0; \
		finalize_once() { \
			test "$$finalize_state" -eq 0 || return 0; \
			finalize_state=1; \
			finalize_status=0; \
			if test -e "$(CODER_OUTPUT_DIR)" || test -L "$(CODER_OUTPUT_DIR)"; then \
				env \
					CODER_LOCK_FD=9 \
					CODER_LOCK_PATH="$$lock_dir" \
					CODER_REMOVE_IMAGES=1 \
					$(MAKE) --no-print-directory _coder-cleanup || finalize_status=$$?; \
			fi; \
			finalize_state=2; \
			return "$$finalize_status"; \
		}; \
		on_exit() { \
			status=$$?; \
			trap - EXIT HUP INT TERM; \
			finalize_once || status=1; \
			exit "$$status"; \
		}; \
		on_signal() { \
			trap - EXIT HUP INT TERM; \
			finalize_status=0; \
			finalize_once || finalize_status=$$?; \
			test "$$finalize_status" -eq 0 || exit "$$finalize_status"; \
			exit 130; \
		}; \
		trap on_exit EXIT; \
		trap on_signal HUP INT TERM; \
		env \
			CODER_LOCK_FD=9 \
			CODER_LOCK_PATH="$$lock_dir" \
			CODER_PARENT_CLEANUP=1 \
			$(MAKE) --no-print-directory _coder-test-no-build-locked

_coder-test-no-build-locked: _coder-require-lock _coder-require-clean
	@set -eu; \
		controller_stage="$${CODER_CONTROLLER_STAGE:-all}"; \
		case "$$controller_stage" in unit|integration|e2e|attestation|all) ;; *) echo "invalid fixed Coder stage" >&2; exit 2 ;; esac; \
		stage_marker="$(CODER_OUTPUT_DIR)/controller-stage-$$controller_stage.passed"; \
		test ! -L "$$stage_marker"; \
		case "$$controller_stage" in \
			integration) predecessor_marker="$(CODER_OUTPUT_DIR)/controller-stage-unit.passed" ;; \
			e2e) predecessor_marker="$(CODER_OUTPUT_DIR)/controller-stage-integration.passed" ;; \
			attestation) predecessor_marker="$(CODER_OUTPUT_DIR)/controller-stage-e2e.passed" ;; \
			*) predecessor_marker="" ;; \
		esac; \
		if test -n "$$predecessor_marker"; then \
			test -f "$$predecessor_marker" && test ! -L "$$predecessor_marker" || { echo "required predecessor stage is absent" >&2; exit 2; }; \
		fi; \
		unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONFIG DOCKER_CONTEXT DOCKER_CUSTOM_HEADERS DOCKER_HOST DOCKER_TLS_VERIFY BUILDX_BUILDER BUILDX_CONFIG; \
		PATH=/usr/local/bin:/usr/bin:/bin; \
		XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}"; \
			export PATH HOME XDG_RUNTIME_DIR; \
			test "$${CODER_COMBINED_CI:-0}" = 0 || test "$${CODER_COMBINED_CI:-0}" = 1; \
			test "$${CODER_PARENT_CLEANUP:-0}" = 0 || test "$${CODER_PARENT_CLEANUP:-0}" = 1; \
		case "$(CODER_REPO_TMP_DIR)" in /*) ;; *) echo "Coder artifact root must be absolute" >&2; exit 2 ;; esac; \
		test "$(CODER_REPO_TMP_DIR)" != "$(CURDIR)"; \
		case "$(CODER_REPO_TMP_DIR)/" in "$(CURDIR)/"*) echo "Coder artifact root must be outside the source tree" >&2; exit 2 ;; esac; \
		test "$(CODER_OUTPUT_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-ci"; \
		test -d "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; \
		test "$$(stat -Lc '%u:%F' "$(CODER_REPO_TMP_DIR)")" = "$$(id -u):directory"; \
		case "$$(stat -Lc '%a' "$(CODER_REPO_TMP_DIR)")" in \
			7[0145][0145]) ;; \
			*) echo "repository .tmp must not be group- or world-writable" >&2; exit 2 ;; \
		esac; \
			test -d "$(CODER_OUTPUT_DIR)" && test ! -L "$(CODER_OUTPUT_DIR)"; \
			test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)")" = "$$(id -u):700:directory"; \
			ulimit -f "$(CODER_TEST_FILE_BLOCKS)"; \
			$(CODER_MUTATION_GUARD_FUNCTIONS) \
			$(CODER_HOST_IDENTITY_FUNCTIONS) \
			coder_require_mutation_daemon; \
			for host_identity_artifact in \
				"$(CODER_HOST_IDENTITY_FILE)" \
				"$(CODER_HOST_IDENTITY_SHA256_FILE)"; do \
				test -f "$$host_identity_artifact" && test ! -L "$$host_identity_artifact"; \
				test "$$(stat -Lc '%u:%a:%F' "$$host_identity_artifact")" = "$$(id -u):600:regular file"; \
			done; \
			recorded_host_identity_digest="$$(cat "$(CODER_HOST_IDENTITY_SHA256_FILE)")"; \
			test -n "$$recorded_host_identity_digest" && \
				test -z "$$(sed -n '2p' "$(CODER_HOST_IDENTITY_SHA256_FILE)")"; \
			test "$${#recorded_host_identity_digest}" -eq 64; \
			case "$$recorded_host_identity_digest" in *[!0-9a-f]*) exit 2 ;; esac; \
			host_identity_digest_line="$$(sha256sum "$(CODER_HOST_IDENTITY_FILE)")"; \
			test "$${host_identity_digest_line%% *}" = "$$recorded_host_identity_digest" || { \
				echo "the recorded host tool/daemon identity artifact changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			coder_write_host_identity "$(CODER_CURRENT_HOST_IDENTITY_FILE)"; \
			current_host_identity_digest_line="$$(sha256sum "$(CODER_CURRENT_HOST_IDENTITY_FILE)")"; \
			test "$${current_host_identity_digest_line%% *}" = "$$recorded_host_identity_digest" || { \
				echo "host tool, Docker plugin, or daemon identity drifted after coder-build-all" >&2; \
				exit 2; \
			}; \
			cmp -s "$(CODER_HOST_IDENTITY_FILE)" "$(CODER_CURRENT_HOST_IDENTITY_FILE)" || { \
				echo "host tool/daemon identity bytes drifted after coder-build-all" >&2; \
				exit 2; \
			}; \
			host_record_tab="$$(printf '\t')"; \
			recorded_docker_path=""; \
			recorded_docker_digest=""; \
			recorded_docker_count=0; \
			recorded_compose_plugin_path=""; \
			recorded_compose_plugin_digest=""; \
			recorded_compose_plugin_count=0; \
			while IFS="$$host_record_tab" read -r record_kind record_name record_path record_digest record_version; do \
				if test "$$record_kind" = tool && test "$$record_name" = docker; then \
					recorded_docker_count=$$((recorded_docker_count + 1)); \
					recorded_docker_path="$$record_path"; \
					recorded_docker_digest="$$record_digest"; \
				elif test "$$record_kind" = docker-plugin && test "$$record_name" = compose; then \
					recorded_compose_plugin_count=$$((recorded_compose_plugin_count + 1)); \
					recorded_compose_plugin_path="$$record_path"; \
					recorded_compose_plugin_digest="$$record_digest"; \
				fi; \
			done < "$(CODER_HOST_IDENTITY_FILE)"; \
			test "$$recorded_docker_count" -eq 1; \
			test "$$recorded_compose_plugin_count" -eq 1; \
			test -n "$$recorded_docker_path" && test -n "$$recorded_docker_digest"; \
			test -n "$$recorded_compose_plugin_path" && test -n "$$recorded_compose_plugin_digest"; \
			case "$$recorded_docker_path" in /*) ;; *) exit 2 ;; esac; \
			case "$$recorded_compose_plugin_path" in /*) ;; *) exit 2 ;; esac; \
			case "$$recorded_docker_digest" in sha256:*) ;; *) exit 2 ;; esac; \
			case "$$recorded_compose_plugin_digest" in sha256:*) ;; *) exit 2 ;; esac; \
			recorded_docker_hex="$${recorded_docker_digest#sha256:}"; \
			recorded_compose_plugin_hex="$${recorded_compose_plugin_digest#sha256:}"; \
			test "$${#recorded_docker_hex}" -eq 64; \
			test "$${#recorded_compose_plugin_hex}" -eq 64; \
			case "$$recorded_docker_hex" in *[!0-9a-f]*) exit 2 ;; esac; \
			case "$$recorded_compose_plugin_hex" in *[!0-9a-f]*) exit 2 ;; esac; \
			on_exit() { \
				status=$$?; \
				trap - EXIT HUP INT TERM; \
				if test "$${CODER_PARENT_CLEANUP:-0}" = 1; then \
					exit "$$status"; \
				fi; \
			if test "$${CODER_COMBINED_CI:-0}" = 1; then \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_CLEANUP_TIMEOUT)" \
					$(CODER_TEST_COMPOSE) logs --no-color > "$(CODER_OUTPUT_DIR)/compose.log" 2>&1 || true; \
				env CODER_REMOVE_IMAGES=0 $(MAKE) --no-print-directory _coder-cleanup || status=1; \
				exit "$$status"; \
			fi; \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_CLEANUP_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) logs --no-color > "$(CODER_OUTPUT_DIR)/compose.log" 2>&1 || true; \
			env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup || status=1; \
			exit "$$status"; \
		}; \
			on_signal() { \
				trap - EXIT HUP INT TERM; \
				if test "$${CODER_PARENT_CLEANUP:-0}" = 1; then \
					exit 130; \
				fi; \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_CLEANUP_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) logs --no-color > "$(CODER_OUTPUT_DIR)/compose.log" 2>&1 || true; \
			cleanup_status=0; \
			env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup || cleanup_status=$$?; \
			test "$$cleanup_status" -eq 0 || exit "$$cleanup_status"; \
				exit 130; \
			}; \
			trap on_exit EXIT; \
			trap on_signal HUP INT TERM; \
			if test "$${CODER_COMBINED_CI:-0}" = 0; then \
				env CODER_REMOVE_IMAGES=0 $(MAKE) --no-print-directory _coder-cleanup; \
			fi; \
			source_tree_digest() { \
			snapshot_file="$(CODER_OUTPUT_DIR)/source-tree-normalized.tar"; \
			rm -f "$$snapshot_file"; \
			tar \
				--sort=name \
				--mtime=@0 \
				--owner=0 \
				--group=0 \
				--numeric-owner \
				--format=posix \
				--pax-option=delete=atime,delete=ctime \
				-cf "$$snapshot_file" \
				-C "$(CODER_FROZEN_SOURCE_DIR)" .; \
			digest_line="$$(sha256sum "$$snapshot_file")"; \
			rm -f "$$snapshot_file"; \
			printf '%s\n' "$${digest_line%% *}"; \
		}; \
		verify_frozen_source() { \
			test "$$(source_tree_digest)" = "$$(cat "$(CODER_OUTPUT_DIR)/build-source-tree-sha256.txt")" || { \
				echo "the frozen source changed after coder-build-all" >&2; \
				exit 2; \
			}; \
		}; \
		for artifact in \
			build-commit.txt \
			build-parent-commit.txt \
			build-base-tree.txt \
			build-tree.txt \
			build-source-tree-sha256.txt \
			source-archive-sha256.txt \
			source.tar \
			image-references.txt \
			image-digests.txt \
				runtime-image-bindings.txt \
				task-image-ids.txt \
				daemon-id.txt \
				run-owner-token.txt \
				resource-ownership.tsv \
				task-image-ownership.tsv \
				dependency-image-ownership.tsv \
				dependency-image-preexisting-ids.txt \
				rust-test-image-binding.txt \
				proxy-test-image-binding.txt \
				production-host-preflight-image-binding.txt \
				production-host-preflight-image.iid \
				python-test-argv-bindings.tsv \
				launcher-adversarial-image.id \
				launcher-adversarial-image-binding.txt \
				launcher-adversarial-build-inputs.json \
				launcher-adversarial-script-sha256.txt \
				e2e-script-sha256.txt \
				buildkit-image-binding.txt \
				buildx-builder-binding.tsv \
				decision-gate-binary-digest.txt \
				compose-digest-override.yaml \
				compose-digest-override-sha256.txt \
				compose-image-override.yaml \
				host-tool-daemon-identity.tsv \
				host-tool-daemon-identity-sha256.txt \
				batch-coverage-manifest.tsv \
				batch-coverage-manifest-sha256.txt \
				test-inventory.git.txt \
				test-inventory.archive.txt \
				test-inventory.untracked.txt \
				test-inventory.classified.txt \
				test-inventory.duplicates.txt \
				test-inventory.changed.txt \
				test-inventory.prepared.txt \
				test-inventory.blocked-prerequisite.txt \
				test-inventory.excluded.txt \
				test-inventory.changed-excluded.txt \
				test-inventory.changed-blocked-prerequisite.txt \
				compose-limits.yaml \
			compose-config.yaml \
			compose-config-sha256.txt; do \
			test -f "$(CODER_OUTPUT_DIR)/$$artifact" && test ! -L "$(CODER_OUTPUT_DIR)/$$artifact" || { \
				echo "unsafe or missing Coder build artifact: $$artifact" >&2; \
				exit 2; \
			}; \
		done; \
		for transient_directory in e2e e2e-command-bin; do \
			transient_path="$(CODER_OUTPUT_DIR)/$$transient_directory"; \
			if test -e "$$transient_path" || test -L "$$transient_path"; then \
				test -d "$$transient_path" && test ! -L "$$transient_path"; \
				rm -rf "$$transient_path"; \
			fi; \
			(umask 077 && mkdir "$$transient_path"); \
		done; \
		run_owner_token="$$(cat "$(CODER_RUN_TOKEN_FILE)")"; \
		test -n "$$run_owner_token" && test -z "$$(sed -n '2p' "$(CODER_RUN_TOKEN_FILE)")"; \
		test "$${#run_owner_token}" -eq 64; \
		case "$$run_owner_token" in *[!0-9a-f]*) echo "invalid persisted Coder run owner token" >&2; exit 2 ;; esac; \
		test "$$(stat -Lc '%u:%a:%F' "$(CODER_RUN_TOKEN_FILE)")" = "$$(id -u):600:regular file"; \
		test "$$(stat -Lc '%u:%a:%F' "$(CODER_RESOURCE_OWNERSHIP_FILE)")" = "$$(id -u):600:regular file"; \
		test "$$(stat -Lc '%u:%a:%F' "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)")" = "$$(id -u):600:regular file"; \
		test "$$(stat -Lc '%u:%a:%F' "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)")" = "$$(id -u):600:regular file"; \
		ownership_tab="$$(printf '\t')"; \
		task_image_record_count=0; \
		while IFS="$$ownership_tab" read -r image_kind image_ref image_id image_owner image_extra; do \
			test "$$image_kind" = task-image && test "$$image_owner" = "$$run_owner_token" && \
				test -z "$${image_extra:-}" || { echo "malformed task image ownership record" >&2; exit 2; }; \
			case " $(CODER_TASK_IMAGE_TAGS) " in *" $$image_ref "*) ;; \
				*) echo "task image ownership contains an undeclared reference" >&2; exit 2 ;; \
			esac; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$image_ref" \
			)" = "$$image_id" || { echo "task image ownership binding drifted: $$image_ref" >&2; exit 2; }; \
			task_image_record_count=$$((task_image_record_count + 1)); \
		done < "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)"; \
		expected_task_image_record_count=0; \
		for expected_task_image_ref in $(CODER_TASK_IMAGE_TAGS); do \
			test "$$(grep -Fc "$$(printf 'task-image\t%s\t' "$$expected_task_image_ref")" \
				"$(CODER_TASK_IMAGE_OWNERSHIP_FILE)")" -eq 1 || { \
				echo "task image ownership does not contain exactly one expected reference" >&2; \
				exit 2; \
			}; \
			expected_task_image_record_count=$$((expected_task_image_record_count + 1)); \
		done; \
		test "$$task_image_record_count" -eq "$$expected_task_image_record_count" || { \
			echo "task image ownership ledger does not match the closed task reference set" >&2; \
			exit 2; \
		}; \
		dependency_image_record_count=0; \
		while IFS="$$ownership_tab" read -r dependency_kind dependency_ref dependency_id dependency_introduction dependency_owner dependency_extra; do \
			test "$$dependency_kind" = dependency-image && \
				test "$$dependency_owner" = "$$run_owner_token" && \
				test -z "$${dependency_extra:-}" || { echo "malformed dependency image ownership record" >&2; exit 2; }; \
			case "$$dependency_ref" in "$(CODER_BUILDKIT_IMAGE)"|"$(CODER_POSTGRES_IMAGE)") ;; \
				*) echo "dependency ownership contains an undeclared reference" >&2; exit 2 ;; \
			esac; \
			case "$$dependency_introduction" in \
				preexisting-reference|introduced-reference|introduced-image) ;; \
				*) echo "dependency ownership has an invalid introduction classification" >&2; exit 2 ;; \
			esac; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$dependency_ref" \
			)" = "$$dependency_id" || { echo "dependency image binding drifted: $$dependency_ref" >&2; exit 2; }; \
			dependency_image_record_count=$$((dependency_image_record_count + 1)); \
		done < "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)"; \
		test "$$dependency_image_record_count" -eq 2 || { \
			echo "dependency image ownership ledger does not contain exactly two references" >&2; \
			exit 2; \
		}; \
		for expected_dependency_ref in "$(CODER_BUILDKIT_IMAGE)" "$(CODER_POSTGRES_IMAGE)"; do \
			test "$$(grep -Fc "$$(printf 'dependency-image\t%s\t' "$$expected_dependency_ref")" \
				"$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)")" -eq 1 || { \
				echo "dependency ownership does not contain exactly one expected reference" >&2; \
				exit 2; \
			}; \
		done; \
		real_docker_path="$$recorded_docker_path"; \
		real_docker_digest="$$recorded_docker_digest"; \
		test "$$(readlink -f "$$real_docker_path")" = "$$real_docker_path"; \
		real_docker_digest_line="$$(sha256sum "$$real_docker_path")"; \
		test "sha256:$${real_docker_digest_line%% *}" = "$$real_docker_digest"; \
		test "$$(readlink -f "$$recorded_compose_plugin_path")" = "$$recorded_compose_plugin_path"; \
		test -f "$$recorded_compose_plugin_path" && test ! -L "$$recorded_compose_plugin_path" && \
			test -x "$$recorded_compose_plugin_path"; \
		compose_plugin_digest_line="$$(sha256sum "$$recorded_compose_plugin_path")"; \
		test "sha256:$${compose_plugin_digest_line%% *}" = "$$recorded_compose_plugin_digest"; \
		{ \
			printf '%s\n' \
					'#!/bin/sh' \
					'set -eu' \
					"real_docker=$$real_docker_path" \
					"real_docker_digest=$$real_docker_digest" \
					"DOCKER_CONFIG=$(CODER_DOCKER_CONFIG_DIR)" \
					"DOCKER_HOST=$(CODER_DOCKER_HOST)" \
					"BUILDX_CONFIG=$(CODER_BUILDX_CONFIG_DIR)" \
					"daemon_id_file=$(CODER_DAEMON_ID_FILE)" \
					"disposable_label=$(CODER_DAEMON_DISPOSABLE_LABEL)" \
					"network_label=$(CODER_DAEMON_NETWORK_LABEL)" \
					"owner_token=$$run_owner_token" \
					"owner_label=$(CODER_OWNER_LABEL_KEY)" \
					"resource_label=$(CODER_RESOURCE_LABEL_KEY)" \
					'export DOCKER_CONFIG DOCKER_HOST BUILDX_CONFIG' \
					'compose_file=$${SERVERWARE_CODER_COMPOSE_FILE:?}' \
				'project_directory=$${SERVERWARE_CODER_PROJECT_DIRECTORY:?}' \
				'case "$$real_docker" in /*) ;; *) echo "invalid real Docker path" >&2; exit 2 ;; esac' \
				'test -f "$$real_docker" && test ! -L "$$real_docker" && test -x "$$real_docker"' \
				'test "$$(readlink -f "$$real_docker")" = "$$real_docker"' \
				'test -f "$$compose_file" && test ! -L "$$compose_file"' \
				'test -d "$$project_directory" && test ! -L "$$project_directory"' \
				'guard_daemon() {' \
				'  docker_digest_line="$$(sha256sum "$$real_docker")"' \
				'  test "sha256:$${docker_digest_line%% *}" = "$$real_docker_digest" || { echo "Docker executable identity drifted" >&2; exit 2; }' \
				'  test "$$DOCKER_HOST" = "unix:///var/run/docker.sock"' \
				'  test -d "$$DOCKER_CONFIG" && test ! -L "$$DOCKER_CONFIG"' \
				'  test "$$(stat -Lc "%u:%a:%F" "$$DOCKER_CONFIG")" = "$$(id -u):700:directory"' \
				'  test -d "$$BUILDX_CONFIG" && test ! -L "$$BUILDX_CONFIG"' \
				'  test "$$(stat -Lc "%u:%a:%F" "$$BUILDX_CONFIG")" = "$$(id -u):700:directory"' \
				'  for entry in "$$DOCKER_CONFIG"/* "$$DOCKER_CONFIG"/.[!.]* "$$DOCKER_CONFIG"/..?*; do' \
				'    test ! -e "$$entry" && test ! -L "$$entry" || { echo "Docker client configuration drifted" >&2; exit 2; }' \
				'  done' \
				'  test -f "$$daemon_id_file" && test ! -L "$$daemon_id_file"' \
				'  test "$$(stat -Lc "%u:%a:%F" "$$daemon_id_file")" = "$$(id -u):600:regular file"' \
				'  recorded_daemon_id="$$(cat "$$daemon_id_file")"' \
				'  test -n "$$recorded_daemon_id" && test -z "$$(printf "%s\n" "$$recorded_daemon_id" | sed -n "2p")"' \
				'  printf "%s\n" "$$recorded_daemon_id" | grep -Eq "^([0-9a-f]{64}|[A-Z2-7]{4}(:[A-Z2-7]{4}){11})$$"' \
				'  daemon_labels="$$(timeout --kill-after=$(CODER_KILL_AFTER) $(CODER_INSPECT_TIMEOUT) "$$real_docker" info --format "{{range .Labels}}{{println .}}{{end}}")"' \
				'  printf "%s\n" "$$daemon_labels" | grep -Fx "$$disposable_label" >/dev/null' \
				'  printf "%s\n" "$$daemon_labels" | grep -Fx "$$network_label" >/dev/null' \
				'  current_daemon_id="$$(timeout --kill-after=$(CODER_KILL_AFTER) $(CODER_INSPECT_TIMEOUT) "$$real_docker" info --format "{{.ID}}")"' \
				'  daemon_platform="$$(timeout --kill-after=$(CODER_KILL_AFTER) $(CODER_INSPECT_TIMEOUT) "$$real_docker" info --format "{{.OSType}}/{{.Architecture}}")"' \
				'  case "$$daemon_platform" in linux/amd64|linux/x86_64) ;; *) echo "Docker daemon platform changed before E2E mutation" >&2; exit 2 ;; esac' \
				'  test "$$current_daemon_id" = "$$recorded_daemon_id" || { echo "Docker daemon identity changed before E2E mutation" >&2; exit 2; }' \
				'}' \
				'guard_service() {' \
				'  service=$$1' \
				'  cid="$$(timeout --kill-after=$(CODER_KILL_AFTER) $(CODER_INSPECT_TIMEOUT) "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" ps -q "$$service")"' \
				'  test -n "$$cid" && test -z "$$(printf "%s\n" "$$cid" | sed -n "2p")"' \
				'  identity="$$(timeout --kill-after=$(CODER_KILL_AFTER) $(CODER_INSPECT_TIMEOUT) "$$real_docker" container inspect --format "{{.Name}}|{{index .Config.Labels \"$$resource_label\"}}|{{index .Config.Labels \"$$owner_label\"}}" "$$cid")"' \
				'  test "$$identity" = "/$(CODER_COMPOSE_PROJECT_NAME)-$$service-1|$$service|$$owner_token" || { echo "E2E service ownership changed: $$service" >&2; exit 2; }' \
				'}' \
				'test "$${1-}" = compose || { echo "only Docker Compose is allowed in the frozen E2E journey" >&2; exit 2; }' \
				'shift' \
				'case "$${1-}" in' \
				'  stop)' \
				'    test "$$#" -eq 2 && test "$${2-}" = serverware' \
				'    guard_daemon' \
				'    guard_service serverware' \
				'    exec "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" stop serverware' \
				'    ;;' \
				'  start)' \
				'    test "$$#" -eq 2 && test "$${2-}" = serverware' \
				'    guard_daemon' \
				'    guard_service serverware' \
				'    exec "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" start serverware' \
				'    ;;' \
				'  exec)' \
				'    test "$$#" -ge 4 && test "$${2-}" = -T' \
				'    case "$${3-}:$${4-}" in' \
				'      demo-upstream:python)' \
				'        service=$$3' \
				'        executable=$$4' \
				'        shift 4' \
				'        guard_daemon' \
				'        guard_service "$$service"' \
				'        exec "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" exec -T "$$service" "$$executable" "$$@"' \
				'        ;;' \
				'      serverware:python)' \
				'        test "$$#" -eq 11' \
				'        test "$${5-}" = scripts/verify_attestation.py' \
				'        test "$${6-}" = --base && test "$${7-}" = http://localhost:3000' \
				'        test "$${8-}" = --admin-token && test "$${9-}" = dev-admin-token' \
				'        test "$${10-}" = --ca-out && test "$${11-}" = /tmp/serverware-verified-ca.pem' \
				'        guard_daemon' \
				'        guard_service serverware' \
				'        exec "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" exec -T serverware python scripts/verify_attestation.py --base http://localhost:3000 --admin-token dev-admin-token --ca-out /tmp/serverware-verified-ca.pem' \
				'        ;;' \
				'      serverware:cat)' \
				'        test "$$#" -eq 5 && test "$${5-}" = /tmp/serverware-verified-ca.pem' \
				'        guard_daemon' \
				'        guard_service serverware' \
				'        exec "$$real_docker" compose --ansi never --project-directory "$$project_directory" --file "$$compose_file" exec -T serverware cat /tmp/serverware-verified-ca.pem' \
				'        ;;' \
				'      *) exit 2 ;;' \
				'    esac' \
				'    ;;' \
				'  *)' \
				'    echo "Docker build, pull, create, and unrestricted Compose commands are denied during E2E" >&2' \
				'    exit 2' \
				'    ;;' \
				'esac'; \
		} > "$(CODER_OUTPUT_DIR)/e2e-command-bin/docker"; \
		chmod 0500 "$(CODER_OUTPUT_DIR)/e2e-command-bin/docker"; \
		for e2e_command in bash cat chmod curl dirname grep id mkdir python3 readlink sed seq sh sha256sum sleep stat timeout; do \
			case "$$e2e_command" in \
				timeout) e2e_command_path="$$(command -v "$(CODER_TIMEOUT)")" ;; \
				*) e2e_command_path="$$(command -v "$$e2e_command")" ;; \
			esac; \
			e2e_command_realpath="$$(readlink -f "$$e2e_command_path")"; \
			test -f "$$e2e_command_realpath" && test ! -L "$$e2e_command_realpath" && \
				test -x "$$e2e_command_realpath" || exit 2; \
			ln -s "$$e2e_command_realpath" "$(CODER_OUTPUT_DIR)/e2e-command-bin/$$e2e_command"; \
		done; \
		for reviewed_host_script in \
			scripts/e2e.sh \
			scripts/install_verified_ca.sh \
			scripts/wait_for_serverware.sh \
			scripts/wait_for_demo_upstream.sh \
			scripts/wait_for_decision_gate.sh; do \
			if grep -En '(/usr/(local/)?bin/docker|/var/run/docker\.sock|unix:///var/run/docker\.sock)' \
				"$(CODER_FROZEN_SOURCE_DIR)/$$reviewed_host_script" >/dev/null; then \
				echo "reviewed host script contains an absolute Docker client or socket bypass: $$reviewed_host_script" >&2; \
				exit 2; \
			fi; \
		done; \
		rm -f \
			"$(CODER_OUTPUT_DIR)/startup.log" \
			"$(CODER_OUTPUT_DIR)/compose.log" \
			"$(CODER_OUTPUT_DIR)/rust-unit-tests.log" \
				"$(CODER_OUTPUT_DIR)/rust-unit-tests.exit-code" \
				"$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints.log" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints.exit-code" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints.cid" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints_proxy_transport.log" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints_proxy_transport.exit-code" \
				"$(CODER_OUTPUT_DIR)/test_credential_constraints_proxy_transport.cid" \
				"$(CODER_OUTPUT_DIR)/test_jit_transaction_state.log" \
				"$(CODER_OUTPUT_DIR)/test_jit_transaction_state.exit-code" \
				"$(CODER_OUTPUT_DIR)/test_jit_transaction_state.cid" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-results.actual.sorted.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.sorted.tsv" \
				"$(CODER_OUTPUT_DIR)/e2e.log" \
			"$(CODER_OUTPUT_DIR)/current-compose-config.yaml" \
			"$(CODER_OUTPUT_DIR)/current-image-digests.txt" \
			"$(CODER_OUTPUT_DIR)/current-runtime-image-bindings.txt" \
			"$(CODER_OUTPUT_DIR)/current-image-references.txt" \
			"$(CODER_OUTPUT_DIR)/current-image-references.unsorted.txt"; \
			: > "$(CODER_OUTPUT_DIR)/startup.log"; \
			: > "$(CODER_OUTPUT_DIR)/compose.log"; \
			: > "$(CODER_OUTPUT_DIR)/rust-unit-tests.log"; \
			{ \
				printf 'schema\tserverware.coder-ci.batch-coverage-results.v2\n'; \
			} > "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
			else \
				test -f "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv" && \
					test ! -L "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv" || { \
						echo "prior no-build result ledger is absent" >&2; \
						exit 2; \
					}; \
			fi; \
			test -s "$(CODER_OUTPUT_DIR)/build-commit.txt" || { \
			echo "build identity is absent; run coder-build-all first" >&2; \
			exit 2; \
		}; \
			test -s "$(CODER_OUTPUT_DIR)/source.tar" || { \
				echo "the frozen source archive is absent; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			compose_override_digest_line="$$(sha256sum "$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)")"; \
			test "$${compose_override_digest_line%% *}" = "$$(cat "$(CODER_COMPOSE_DIGEST_OVERRIDE_SHA256_FILE)")" || { \
				echo "the measured-binary Compose override changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			decision_gate_binary_digest="$$(cat "$(CODER_DECISION_GATE_BINARY_DIGEST_FILE)")"; \
			test -n "$$decision_gate_binary_digest" && \
				test -z "$$(sed -n '2p' "$(CODER_DECISION_GATE_BINARY_DIGEST_FILE)")"; \
			grep -Fx \
				"      SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST: \"$$decision_gate_binary_digest\"" \
				"$(CODER_COMPOSE_DIGEST_OVERRIDE_FILE)" >/dev/null || { \
					echo "the Compose override is not bound to the measured decision-gate digest" >&2; \
					exit 2; \
				}; \
			read -r buildkit_image buildkit_image_id buildkit_binding_extra \
				< "$(CODER_BUILDKIT_IMAGE_BINDING_FILE)"; \
			test -z "$${buildkit_binding_extra:-}" && test "$$buildkit_image" = "$(CODER_BUILDKIT_IMAGE)" || { \
				echo "the recorded BuildKit image binding is invalid" >&2; \
				exit 2; \
			}; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$buildkit_image" \
			)" = "$$buildkit_image_id" || { \
				echo "the pinned BuildKit image ID changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			buildkit_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$$buildkit_image" \
			)"; \
			printf '%s\n' "$$buildkit_repo_digests" | grep -Fx "$(CODER_BUILDKIT_REPO_DIGEST)" >/dev/null || { \
				echo "the pinned BuildKit digest reference is no longer loaded" >&2; \
				exit 2; \
			}; \
			test -s "$(CODER_OUTPUT_DIR)/rust-test-image-binding.txt" || { \
				echo "Rust test image identity is absent; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			test -s "$(CODER_OUTPUT_DIR)/proxy-test-image-binding.txt" || { \
				echo "proxy test image identity is absent; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			test -s "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)" || { \
				echo "production-host-preflight image identity is absent; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			test -f "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" && \
				test ! -L "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" && \
				test "$$(stat -Lc '%u:%a:%F' "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")" = "$$(id -u):600:regular file" || { \
				echo "production-host-preflight IID file is unsafe; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			test -s "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid" && \
				test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")" || { \
				echo "production-host-preflight IID file is empty or contains multiple lines" >&2; \
				exit 2; \
			}; \
			test -s "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" && \
				test -s "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)" || { \
				echo "launcher adversarial image identity is absent; run coder-build-all first" >&2; \
				exit 2; \
			}; \
			batch_coverage_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv")"; \
			test "$${batch_coverage_digest_line%% *}" = "$$(cat "$(CODER_OUTPUT_DIR)/batch-coverage-manifest-sha256.txt")" || { \
				echo "the batch coverage manifest changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			grep -Fx \
				"build-host	tool-daemon-identity	sha256:$$recorded_host_identity_digest	host-tool-daemon-identity.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
					echo "the batch coverage manifest is not bound to the recorded host tool/daemon identity" >&2; \
					exit 2; \
				}; \
			builder_binding_digest="$$(sha256sum "$(CODER_BUILDER_BINDING_FILE)" | sed 's/ .*//')"; \
			grep -Fx \
				"build-host	buildx-builder-binding	$$builder_binding_digest	buildx-builder-binding.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
					echo "coverage manifest is not bound to the exact Buildx builder identity" >&2; \
					exit 2; \
				}; \
			launcher_context_digest="$$(sha256sum "$(CODER_LAUNCHER_ADVERSARIAL_CONTEXT_MANIFEST_FILE)" | sed 's/ .*//')"; \
			grep -Fx \
				"build-input	launcher-adversarial-context	$$launcher_context_digest	launcher-adversarial-build-inputs.json" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
					echo "coverage manifest is not bound to the launcher build-input context" >&2; \
					exit 2; \
				}; \
			task_image_ownership_digest="$$(sha256sum "$(CODER_TASK_IMAGE_OWNERSHIP_FILE)" | sed 's/ .*//')"; \
			dependency_image_ownership_digest="$$(sha256sum "$(CODER_DEPENDENCY_IMAGE_OWNERSHIP_FILE)" | sed 's/ .*//')"; \
			grep -Fx \
				"build-ownership	task-images	$$task_image_ownership_digest	task-image-ownership.tsv" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null && \
				grep -Fx \
					"build-ownership	dependency-images	$$dependency_image_ownership_digest	dependency-image-ownership.tsv" \
					"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
						echo "image ownership ledgers changed after the build phase" >&2; \
						exit 2; \
					}; \
			cmp "$(CODER_OUTPUT_DIR)/test-inventory.git.txt" "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt" && \
				cmp "$(CODER_OUTPUT_DIR)/test-inventory.archive.txt" "$(CODER_OUTPUT_DIR)/test-inventory.classified.txt" && \
				test ! -s "$(CODER_OUTPUT_DIR)/test-inventory.untracked.txt" && \
				test ! -s "$(CODER_OUTPUT_DIR)/test-inventory.duplicates.txt" && \
				test ! -s "$(CODER_CHANGED_EXCLUDED_TESTS_FILE)" || { \
					echo "recorded Coder test inventory is not closed one-to-one" >&2; \
					exit 2; \
				}; \
			while IFS= read -r changed_test_path; do \
				test -n "$$changed_test_path" || continue; \
				grep -Fx "$$changed_test_path" "$(CODER_PREPARED_TESTS_FILE)" >/dev/null || \
					grep -Fx "$$changed_test_path" "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)" >/dev/null || { \
					echo "a changed test is neither prepared nor bound to a closed prerequisite: $$changed_test_path" >&2; \
					exit 2; \
				}; \
			done < "$(CODER_CHANGED_TESTS_FILE)"; \
			if test -s "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)"; then \
				echo "refusing partial behavioral execution while closed external prerequisites remain:" >&2; \
				sed 's/^/  /' "$(CODER_BLOCKED_PREREQUISITE_TESTS_FILE)" >&2; \
				echo "rerun coder-build-all only after the prerequisite gate is empty and all four tests have reviewed exact runners" >&2; \
				exit 2; \
			fi; \
			for inventory_binding in \
				"test-inventory-git|test-inventory.git.txt" \
				"test-inventory-frozen-archive|test-inventory.archive.txt" \
				"test-inventory-outside-frozen-commit|test-inventory.untracked.txt" \
				"test-inventory-changed-from-recorded-base|test-inventory.changed.txt" \
				"test-inventory-prepared|test-inventory.prepared.txt" \
				"test-inventory-blocked-prerequisite|test-inventory.blocked-prerequisite.txt" \
				"test-inventory-excluded|test-inventory.excluded.txt" \
				"test-inventory-changed-excluded|test-inventory.changed-excluded.txt" \
				"test-inventory-changed-blocked-prerequisite|test-inventory.changed-blocked-prerequisite.txt" \
				"dependency-preexisting-image-ids|dependency-image-preexisting-ids.txt" \
				"python-test-argv-bindings|python-test-argv-bindings.tsv"; do \
				inventory_label="$${inventory_binding%%|*}"; \
				inventory_file="$${inventory_binding#*|}"; \
				inventory_digest="$$(sha256sum "$(CODER_OUTPUT_DIR)/$$inventory_file" | sed 's/ .*//')"; \
				grep -Fx \
					"build-input	$$inventory_label	$$inventory_digest	$$inventory_file" \
					"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
						echo "coverage manifest is not bound to $$inventory_file" >&2; \
						exit 2; \
					}; \
			done; \
		source_archive_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/source.tar")"; \
		test "$${source_archive_digest_line%% *}" = "$$(cat "$(CODER_OUTPUT_DIR)/source-archive-sha256.txt")" || { \
			echo "the frozen source archive changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		if test -e "$(CODER_FROZEN_SOURCE_DIR)" || test -L "$(CODER_FROZEN_SOURCE_DIR)"; then \
			test -d "$(CODER_FROZEN_SOURCE_DIR)" && test ! -L "$(CODER_FROZEN_SOURCE_DIR)"; \
			rm -rf "$(CODER_FROZEN_SOURCE_DIR)"; \
		fi; \
		(umask 077 && mkdir "$(CODER_FROZEN_SOURCE_DIR)"); \
		tar -xf "$(CODER_OUTPUT_DIR)/source.tar" -C "$(CODER_FROZEN_SOURCE_DIR)"; \
		verify_frozen_source; \
		for frozen_source_binding in \
			"production-python-lock|requirements.lock" \
			"browser-python-lock|requirements.browser.lock" \
			"proxy-python-lock|requirements.proxy-test.lock" \
			"clean-room-python-lock|serverware_agent_trust/requirements.lock" \
			"consolidated-oci-entrypoint|scripts/oci_lane_entrypoint.py" \
			"same-journey-verifier|scripts/verify_agent_trust_same_journey.py"; do \
			frozen_source_label="$${frozen_source_binding%%|*}"; \
			frozen_source_path="$${frozen_source_binding#*|}"; \
			frozen_source_digest="$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/$$frozen_source_path" | sed 's/ .*//')"; \
			grep -Fx \
				"build-input	$$frozen_source_label	$$frozen_source_digest	$$frozen_source_path" \
				"$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
					echo "coverage manifest is not bound to frozen source input: $$frozen_source_path" >&2; \
					exit 2; \
				}; \
		done; \
		test "$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)" | sed 's/ .*//')" = \
			"$$(cat "$(CODER_OUTPUT_DIR)/launcher-adversarial-script-sha256.txt")" || { \
				echo "frozen launcher harness differs from the reviewed build-time digest" >&2; \
				exit 2; \
			}; \
		test "$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/scripts/e2e.sh" | sed 's/ .*//')" = \
			"$$(cat "$(CODER_OUTPUT_DIR)/e2e-script-sha256.txt")" || { \
				echo "frozen E2E script differs from the reviewed build-time digest" >&2; \
				exit 2; \
			}; \
		for required_test_file in \
			docker-compose.yml \
			scripts/wait_for_serverware.sh \
			scripts/wait_for_demo_upstream.sh \
			scripts/wait_for_decision_gate.sh \
			scripts/install_verified_ca.sh \
			scripts/e2e.sh; do \
			test -f "$(CODER_FROZEN_SOURCE_DIR)/$$required_test_file" && \
			test ! -L "$(CODER_FROZEN_SOURCE_DIR)/$$required_test_file" || { \
				echo "required frozen test input is missing or a symlink: $$required_test_file" >&2; \
				exit 2; \
			}; \
		done; \
		recorded_source_commit="$$(cat "$(CODER_OUTPUT_DIR)/build-commit.txt")"; \
		test -n "$$recorded_source_commit" && \
			test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/build-commit.txt")"; \
		git cat-file -e "$$recorded_source_commit^{commit}"; \
		recorded_source_tree="$$(git rev-parse --verify "$$recorded_source_commit^{tree}")"; \
		test "$$(cat "$(CODER_OUTPUT_DIR)/build-tree.txt")" = "$$recorded_source_tree" || { \
			echo "recorded frozen commit and tree metadata disagree" >&2; \
			exit 2; \
		}; \
		recorded_parent_line="$$(git rev-list --parents -n 1 "$$recorded_source_commit")"; \
		set -- $$recorded_parent_line; \
		test "$$#" -ge 1 && test "$$1" = "$$recorded_source_commit"; \
		if test "$$#" -eq 1; then \
			recorded_source_parent=ROOT; \
			recorded_base_tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904; \
		else \
			recorded_source_parent="$$2"; \
			recorded_base_tree="$$(git rev-parse --verify "$$recorded_source_parent^{tree}")"; \
		fi; \
		test "$$(cat "$(CODER_BUILD_PARENT_COMMIT_FILE)")" = "$$recorded_source_parent" && \
			test "$$(cat "$(CODER_BUILD_BASE_TREE_FILE)")" = "$$recorded_base_tree" || { \
				echo "recorded frozen commit parent/base metadata disagree" >&2; \
				exit 2; \
			}; \
		grep -Fx "source	commit	$$recorded_source_commit" "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null && \
			grep -Fx "source	first-parent	$$recorded_source_parent" "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null && \
			grep -Fx "source	base-tree	$$recorded_base_tree" "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null && \
			grep -Fx "source	tree	$$recorded_source_tree" "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv" >/dev/null || { \
				echo "coverage manifest is not bound to exact frozen commit/base/tree metadata" >&2; \
				exit 2; \
			}; \
		current_changed_tests="$(CODER_OUTPUT_DIR)/test-inventory.changed.current.txt"; \
		if test "$$recorded_source_parent" = ROOT; then \
			git ls-tree -r --name-only "$$recorded_source_commit" -- \
					':(glob)scripts/test_*' scripts/e2e.sh \
				| LC_ALL=C sort -u > "$$current_changed_tests"; \
		else \
			git diff --name-only --diff-filter=AM --no-renames \
					"$$recorded_source_parent" "$$recorded_source_commit" -- \
					':(glob)scripts/test_*' scripts/e2e.sh \
				| LC_ALL=C sort -u > "$$current_changed_tests"; \
		fi; \
		cmp "$(CODER_CHANGED_TESTS_FILE)" "$$current_changed_tests" || { \
			echo "changed-test inventory differs from the exact frozen commit base" >&2; \
			exit 2; \
		}; \
		rm -f "$$current_changed_tests"; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_COMPOSE) config \
			> "$(CODER_OUTPUT_DIR)/current-compose-config.yaml"; \
		current_compose_config_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/current-compose-config.yaml")"; \
		test "$${current_compose_config_digest_line%% *}" = "$$(cat "$(CODER_OUTPUT_DIR)/compose-config-sha256.txt")" || { \
			echo "the resolved Compose configuration changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		cmp -s "$(CODER_OUTPUT_DIR)/compose-config.yaml" "$(CODER_OUTPUT_DIR)/current-compose-config.yaml" || { \
			echo "the resolved Compose configuration bytes changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
			$(CODER_COMPOSE) config --images \
			> "$(CODER_OUTPUT_DIR)/current-image-references.unsorted.txt"; \
		LC_ALL=C sort -u \
			"$(CODER_OUTPUT_DIR)/current-image-references.unsorted.txt" \
			> "$(CODER_OUTPUT_DIR)/current-image-references.txt"; \
		rm -f "$(CODER_OUTPUT_DIR)/current-image-references.unsorted.txt"; \
		cmp -s "$(CODER_OUTPUT_DIR)/image-references.txt" "$(CODER_OUTPUT_DIR)/current-image-references.txt" || { \
			echo "the Compose image set changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		: > "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
			while IFS= read -r image; do \
				test -n "$$image" || continue; \
				image_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$image" \
				)" || { echo "required prebuilt image is absent: $$image" >&2; exit 2; }; \
				repo_digests="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$image" \
				)"; \
			printf 'image=%s id=%s repo_digests=%s\n' "$$image" "$$image_id" "$$repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
		done < "$(CODER_OUTPUT_DIR)/image-references.txt"; \
		read -r rust_test_image rust_test_image_id rust_test_binding_extra \
			< "$(CODER_OUTPUT_DIR)/rust-test-image-binding.txt"; \
		test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/rust-test-image-binding.txt")" || { \
			echo "Rust test image binding contains multiple lines" >&2; \
			exit 2; \
		}; \
		test -z "$${rust_test_binding_extra:-}" || { \
			echo "Rust test image binding is malformed" >&2; \
			exit 2; \
		}; \
		test "$$rust_test_image" = "$(CODER_RUST_TEST_IMAGE)" || { \
			echo "Rust test image reference changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		case "$$rust_test_image_id" in \
			sha256:*) ;; \
			*) echo "recorded Rust test image ID is not canonical" >&2; exit 2 ;; \
		esac; \
		rust_test_image_digest="$${rust_test_image_id#sha256:}"; \
		test "$${#rust_test_image_digest}" -eq 64 || { \
			echo "recorded Rust test image digest has the wrong length" >&2; \
			exit 2; \
		}; \
		case "$$rust_test_image_digest" in \
			*[!0-9a-f]*) echo "recorded Rust test image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
		esac; \
			current_rust_test_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$rust_test_image" \
			)" || { \
			echo "required prebuilt Rust test image is absent" >&2; \
			exit 2; \
		}; \
		test "$$current_rust_test_image_id" = "$$rust_test_image_id" || { \
			echo "the Rust test image ID changed after coder-build-all" >&2; \
			exit 2; \
		}; \
			rust_test_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$rust_test_image_id" \
			)"; \
		printf 'image=%s id=%s repo_digests=%s\n' \
				"$$rust_test_image" "$$rust_test_image_id" "$$rust_test_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
			read -r proxy_test_image proxy_test_image_id proxy_test_binding_extra \
				< "$(CODER_OUTPUT_DIR)/proxy-test-image-binding.txt"; \
			test -z "$$(sed -n '2p' "$(CODER_OUTPUT_DIR)/proxy-test-image-binding.txt")" || { \
				echo "proxy test image binding contains multiple lines" >&2; \
				exit 2; \
			}; \
			test -z "$${proxy_test_binding_extra:-}" || { \
				echo "proxy test image binding is malformed" >&2; \
				exit 2; \
			}; \
			test "$$proxy_test_image" = "$(CODER_PROXY_TEST_IMAGE)" || { \
				echo "proxy test image reference changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			case "$$proxy_test_image_id" in \
				sha256:*) ;; \
				*) echo "recorded proxy test image ID is not canonical" >&2; exit 2 ;; \
			esac; \
			proxy_test_image_digest="$${proxy_test_image_id#sha256:}"; \
			test "$${#proxy_test_image_digest}" -eq 64 || { \
				echo "recorded proxy test image digest has the wrong length" >&2; \
				exit 2; \
			}; \
			case "$$proxy_test_image_digest" in \
				*[!0-9a-f]*) echo "recorded proxy test image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
			esac; \
			current_proxy_test_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$proxy_test_image" \
			)" || { \
				echo "required prebuilt proxy test image is absent" >&2; \
				exit 2; \
			}; \
			test "$$current_proxy_test_image_id" = "$$proxy_test_image_id" || { \
				echo "the proxy test image ID changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			proxy_test_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$proxy_test_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$$proxy_test_image" "$$proxy_test_image_id" "$$proxy_test_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
			read -r production_host_preflight_image production_host_preflight_image_id production_host_preflight_binding_extra \
				< "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)"; \
			test -z "$$(sed -n '2p' "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE_BINDING_FILE)")" || { \
				echo "production-host-preflight image binding contains multiple lines" >&2; \
				exit 2; \
			}; \
			test -z "$${production_host_preflight_binding_extra:-}" || { \
				echo "production-host-preflight image binding is malformed" >&2; \
				exit 2; \
			}; \
			test "$$production_host_preflight_image" = "$(CODER_PRODUCTION_HOST_PREFLIGHT_IMAGE)" || { \
				echo "production-host-preflight image reference changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			test "$$(cat "$(CODER_OUTPUT_DIR)/production-host-preflight-image.iid")" = "$$production_host_preflight_image_id" || { \
				echo "production-host-preflight IID and frozen image binding disagree" >&2; \
				exit 2; \
			}; \
			case "$$production_host_preflight_image_id" in \
				sha256:*) ;; \
				*) echo "recorded production-host-preflight image ID is not canonical" >&2; exit 2 ;; \
			esac; \
			production_host_preflight_image_digest="$${production_host_preflight_image_id#sha256:}"; \
			test "$${#production_host_preflight_image_digest}" -eq 64 || { \
				echo "recorded production-host-preflight image digest has the wrong length" >&2; \
				exit 2; \
			}; \
			case "$$production_host_preflight_image_digest" in \
				*[!0-9a-f]*) echo "recorded production-host-preflight image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
			esac; \
			current_production_host_preflight_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$production_host_preflight_image" \
			)" || { \
				echo "required prebuilt production-host-preflight image is absent" >&2; \
				exit 2; \
			}; \
			test "$$current_production_host_preflight_image_id" = "$$production_host_preflight_image_id" || { \
				echo "the production-host-preflight image ID changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$production_host_preflight_image_id" \
			)" = "linux/amd64" || { \
				echo "the production-host-preflight image platform changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			production_host_preflight_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$production_host_preflight_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$$production_host_preflight_image" "$$production_host_preflight_image_id" "$$production_host_preflight_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
			test -f "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" && \
				test ! -L "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)" && \
				test "$$(stat -Lc '%u:%a:%F' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")" = "$$(id -u):600:regular file" || { \
				echo "launcher adversarial image ID file is unsafe" >&2; \
				exit 2; \
			}; \
			test -z "$$(sed -n '2p' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")" || { \
				echo "launcher adversarial image ID file contains multiple lines" >&2; \
				exit 2; \
			}; \
			test -f "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)" && \
				test ! -L "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)" && \
				test "$$(stat -Lc '%u:%a:%F' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)")" = "$$(id -u):600:regular file" || { \
				echo "launcher adversarial image binding file is unsafe" >&2; \
				exit 2; \
			}; \
			read -r launcher_adversarial_image launcher_adversarial_image_id launcher_adversarial_binding_extra \
				< "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)"; \
			test -z "$$(sed -n '2p' "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_BINDING_FILE)")" || { \
				echo "launcher adversarial image binding contains multiple lines" >&2; \
				exit 2; \
			}; \
			test -z "$${launcher_adversarial_binding_extra:-}" || { \
				echo "launcher adversarial image binding is malformed" >&2; \
				exit 2; \
			}; \
			test "$$launcher_adversarial_image" = "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE)" || { \
				echo "launcher adversarial image reference changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			test "$$launcher_adversarial_image_id" = "$$(cat "$(CODER_LAUNCHER_ADVERSARIAL_IMAGE_ID_FILE)")" || { \
				echo "launcher adversarial image ID file and binding disagree" >&2; \
				exit 2; \
			}; \
			case "$$launcher_adversarial_image_id" in \
				sha256:*) ;; \
				*) echo "recorded launcher adversarial image ID is not canonical" >&2; exit 2 ;; \
			esac; \
			launcher_adversarial_image_digest="$${launcher_adversarial_image_id#sha256:}"; \
			test "$${#launcher_adversarial_image_digest}" -eq 64 || { \
				echo "recorded launcher adversarial image digest has the wrong length" >&2; \
				exit 2; \
			}; \
			case "$$launcher_adversarial_image_digest" in \
				*[!0-9a-f]*) echo "recorded launcher adversarial image digest is not lowercase hexadecimal" >&2; exit 2 ;; \
			esac; \
			current_launcher_adversarial_image_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$launcher_adversarial_image" \
			)" || { \
				echo "required prebuilt launcher adversarial image is absent" >&2; \
				exit 2; \
			}; \
			test "$$current_launcher_adversarial_image_id" = "$$launcher_adversarial_image_id" || { \
				echo "the launcher adversarial image ID changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			test "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{.Os}}/{{.Architecture}}' "$$launcher_adversarial_image_id" \
			)" = "linux/amd64" || { \
				echo "the launcher adversarial image platform changed after coder-build-all" >&2; \
				exit 2; \
			}; \
			launcher_adversarial_repo_digests="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) image inspect --format '{{json .RepoDigests}}' "$$launcher_adversarial_image_id" \
			)"; \
			printf 'image=%s id=%s repo_digests=%s\n' \
				"$$launcher_adversarial_image" "$$launcher_adversarial_image_id" "$$launcher_adversarial_repo_digests" \
				>> "$(CODER_OUTPUT_DIR)/current-image-digests.txt"; \
			cmp -s "$(CODER_OUTPUT_DIR)/image-digests.txt" "$(CODER_OUTPUT_DIR)/current-image-digests.txt" || { \
			echo "a prebuilt image digest changed after coder-build-all" >&2; \
			exit 2; \
		}; \
		: > "$(CODER_OUTPUT_DIR)/current-runtime-image-bindings.txt"; \
		for binding in $(CODER_RUNTIME_IMAGE_BINDINGS); do \
			service="$${binding%%=*}"; \
			image="$${binding#*=}"; \
				image_id="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) image inspect --format '{{.Id}}' "$$image" \
				)"; \
			printf '%s %s %s\n' "$$service" "$$image" "$$image_id" \
				>> "$(CODER_OUTPUT_DIR)/current-runtime-image-bindings.txt"; \
		done; \
				cmp -s \
					"$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt" \
					"$(CODER_OUTPUT_DIR)/current-runtime-image-bindings.txt" || { \
						echo "the exact five-service runtime image binding changed after coder-build-all" >&2; \
						exit 2; \
					}; \
				env CODER_REMOVE_IMAGES=0 $(MAKE) --no-print-directory _coder-cleanup; \
				: > "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				chmod 0600 "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				record_owned_container() { \
					record_container_id="$$1"; \
					record_container_name="$$2"; \
					record_container_resource="$$3"; \
					record_container_image_id="$$4"; \
					record_container_cid_file="$$5"; \
					case "$$record_container_id" in *[!0-9a-f]*) \
						echo "container CID is not lowercase hexadecimal: $$record_container_name" >&2; \
						return 2 ;; \
					esac; \
					test "$${#record_container_id}" -eq 64 || { \
						echo "container CID has the wrong length: $$record_container_name" >&2; \
						return 2; \
					}; \
					case "$$record_container_name" in ""|*[!a-z0-9_-]*) \
						echo "container name is not closed: $$record_container_name" >&2; \
						return 2 ;; \
					esac; \
					case "$$record_container_resource" in ""|*[!a-z0-9_-]*) \
						echo "container resource label is not closed: $$record_container_resource" >&2; \
						return 2 ;; \
					esac; \
					test -f "$$record_container_cid_file" && test ! -L "$$record_container_cid_file" && \
						test "$$(cat "$$record_container_cid_file")" = "$$record_container_id" && \
						test -z "$$(sed -n '2p' "$$record_container_cid_file")" || { \
						echo "container CID file does not match the recorded CID: $$record_container_name" >&2; \
						return 2; \
					}; \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$record_container_id" \
					)" = "$$record_container_image_id|/$$record_container_name|$$record_container_resource|$$run_owner_token" || { \
						echo "container image, name, label, owner token, or recorded CID is invalid: $$record_container_name" >&2; \
						return 2; \
					}; \
					ownership_record="$$(printf 'container\t%s\t%s\t%s\t%s' \
						"$$record_container_name" "$$record_container_resource" "$$run_owner_token" "$$record_container_id")"; \
						if ! grep -Fx "$$ownership_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
							printf '%s\n' "$$ownership_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
						fi; \
					}; \
					recover_failed_run_cid() { \
						recovery_container_name="$$1"; \
						recovery_container_resource="$$2"; \
						recovery_container_image_id="$$3"; \
						recovery_container_cid_file="$$4"; \
						test ! -L "$$recovery_container_cid_file" || { \
							echo "refusing symlinked failed-run CID file: $$recovery_container_cid_file" >&2; \
							return 2; \
						}; \
						recovery_existing_cid=""; \
						recovery_existing_valid=0; \
						if test -f "$$recovery_container_cid_file"; then \
							recovery_existing_cid="$$(cat "$$recovery_container_cid_file")"; \
							case "$$recovery_existing_cid" in *[!0-9a-f]*) ;; \
								*) \
									if test "$${#recovery_existing_cid}" -eq 64 && \
										test -z "$$(sed -n '2p' "$$recovery_container_cid_file")"; then \
										recovery_existing_valid=1; \
									fi ;; \
							esac; \
						elif test -e "$$recovery_container_cid_file"; then \
							echo "refusing non-regular failed-run CID file: $$recovery_container_cid_file" >&2; \
							return 2; \
						fi; \
						test "$$recovery_existing_valid" -eq 0 || return 0; \
						if ! recovered_container_cid="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) ps --all --quiet --no-trunc \
									--filter "name=^/$$recovery_container_name$$" \
						)"; then \
							echo "could not enumerate the fixed-name container after a failed run: $$recovery_container_name" >&2; \
							return 2; \
						fi; \
						if test -z "$$recovered_container_cid"; then \
							rm -f "$$recovery_container_cid_file"; \
							return 0; \
						fi; \
						test -z "$$(printf '%s\n' "$$recovered_container_cid" | sed -n '2p')" || { \
							echo "ambiguous fixed-name container recovery: $$recovery_container_name" >&2; \
							return 2; \
						}; \
						case "$$recovered_container_cid" in *[!0-9a-f]*) \
							echo "recovered container CID is not lowercase hexadecimal: $$recovery_container_name" >&2; \
							return 2 ;; \
						esac; \
						test "$${#recovered_container_cid}" -eq 64 || { \
							echo "recovered container CID has the wrong length: $$recovery_container_name" >&2; \
							return 2; \
						}; \
						test "$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$recovered_container_cid" \
						)" = "$$recovery_container_image_id|/$$recovery_container_name|$$recovery_container_resource|$$run_owner_token" || { \
							echo "refusing fixed-name recovery with mismatched image, name, resource, or owner: $$recovery_container_name" >&2; \
							return 2; \
						}; \
						rm -f "$$recovery_container_cid_file"; \
						(umask 077 && printf '%s\n' "$$recovered_container_cid" > "$$recovery_container_cid_file"); \
					}; \
					run_isolated_container_test() { \
				selected_test_id="$$1"; \
				isolated_test_artifact_name="$$2"; \
				selected_test_container="$$3"; \
					selected_test_label="$$4"; \
					selected_test_image_id="$$5"; \
					selected_test_timeout="$$6"; \
					selected_test_profile="$$7"; \
					shift 7; \
					selected_python_script=""; \
					case "$$selected_test_profile" in \
						python-isolated) \
							case "$$selected_test_id" in \
								'scripts/test_credential_constraints.py#proxy-transport-only') \
									test "$$#" -eq 2 && \
										test "$$1" = scripts/test_credential_constraints.py && \
										test "$$2" = --proxy-transport-only || { \
										echo "proxy-transport Python argv is outside the closed frozen argument set" >&2; \
										exit 2; \
									}; \
									selected_python_script="/app/$$1"; \
									set -- "$$selected_python_script" --proxy-transport-only ;; \
								*) \
									test "$$#" -eq 1 || { \
										echo "isolated Python test received unexpected arguments" >&2; \
										exit 2; \
									}; \
									case "$$1" in scripts/test_*.py) ;; \
										*) echo "isolated Python test path is outside the closed frozen script set" >&2; exit 2 ;; \
									esac; \
									selected_python_script="/app/$$1"; \
									set -- "$$selected_python_script" ;; \
							esac ;; \
						production-host-preflight) \
							test "$$#" -eq 0; \
							selected_python_script="/app/$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)"; \
							set -- "$$selected_python_script" ;; \
						launcher-adversarial) test "$$#" -eq 0 ;; \
						*) echo "isolated test execution profile is invalid" >&2; exit 2 ;; \
					esac; \
				case "$$selected_test_label" in "$(CODER_RESOURCE_LABEL_KEY)="*) ;; \
					*) echo "isolated test resource label is invalid" >&2; exit 2 ;; \
				esac; \
				selected_test_resource="$${selected_test_label#*=}"; \
				case "$$selected_test_image_id" in sha256:*) ;; \
					*) echo "isolated test image ID is not canonical" >&2; exit 2 ;; \
				esac; \
				test "$${#selected_test_image_id}" -eq 71 || { \
					echo "isolated test image ID has the wrong length" >&2; \
					exit 2; \
				}; \
				selected_test_image_digest="$${selected_test_image_id#sha256:}"; \
				case "$$selected_test_image_digest" in *[!0-9a-f]*) \
					echo "isolated test image digest is not lowercase hexadecimal" >&2; \
					exit 2 ;; \
				esac; \
				if test -n "$$selected_python_script"; then \
					python_argv_tab="$$(printf '\t')"; \
					expected_python_argv_binding="$$(printf 'python-argv\t%s\t%s\t%s' \
						"$$selected_test_id" "$$selected_test_image_id" \
						"$(CODER_IMAGE_PYTHON_INTERPRETER)")"; \
					for selected_python_arg in "$$@"; do \
						expected_python_argv_binding="$$expected_python_argv_binding$$python_argv_tab$$selected_python_arg"; \
					done; \
					test "$$(grep -Fxc "$$expected_python_argv_binding" "$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)")" -eq 1 || { \
						echo "isolated Python interpreter/image/argv binding is absent or ambiguous: $$selected_test_id" >&2; \
						exit 2; \
					}; \
				fi; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect "$$selected_test_container" >/dev/null 2>&1; then \
					echo "refusing to create over a pre-existing isolated test container: $$selected_test_container" >&2; \
					exit 2; \
				fi; \
				isolated_test_log="$(CODER_OUTPUT_DIR)/$$isolated_test_artifact_name.log"; \
				isolated_test_exit_code="$(CODER_OUTPUT_DIR)/$$isolated_test_artifact_name.exit-code"; \
				isolated_test_cid="$(CODER_OUTPUT_DIR)/$$isolated_test_artifact_name.cid"; \
				for test_artifact in \
					"$$isolated_test_log" \
					"$$isolated_test_exit_code" \
					"$$isolated_test_cid"; do \
					test ! -L "$$test_artifact" || { \
						echo "refusing unsafe isolated test artifact: $$test_artifact" >&2; \
						exit 2; \
					}; \
					rm -f "$$test_artifact"; \
					done; \
					(umask 077 && : > "$$isolated_test_log"); \
					isolated_test_run_status=0; \
					if test "$$selected_test_profile" = python-isolated; then \
						isolated_test_container_id="$$( \
							coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) run --detach \
							--pull never \
							--no-healthcheck \
							--name "$$selected_test_container" \
							--cidfile "$$isolated_test_cid" \
							--label "$$selected_test_label" \
							--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
							--platform "$(CODER_PLATFORM)" \
							--network none \
							--ipc none \
							--read-only \
							--cap-drop ALL \
							--security-opt no-new-privileges=true \
								--pids-limit "$(CODER_ISOLATED_TEST_PIDS)" \
								--memory "$(CODER_ISOLATED_TEST_MEMORY)" \
								--memory-swap "$(CODER_ISOLATED_TEST_MEMORY)" \
								--cpus "$(CODER_ISOLATED_TEST_CPUS)" \
									--mount "type=bind,src=$(CODER_FROZEN_SOURCE_DIR)/Makefile,dst=/app/Makefile,readonly" \
									--mount "type=bind,src=$(CODER_FROZEN_SOURCE_DIR)/Dockerfile.production,dst=/app/Dockerfile.production,readonly" \
									--mount "type=bind,src=$(CODER_FROZEN_SOURCE_DIR)/data-plane,dst=/app/data-plane,readonly" \
									--mount "type=bind,src=$(CODER_FROZEN_SOURCE_DIR)/ops,dst=/app/ops,readonly" \
									--mount "type=bind,src=$(CODER_FROZEN_SOURCE_DIR)/production-dependencies,dst=/app/production-dependencies,readonly" \
								--env HOME=/tmp \
								--env TMPDIR=/run/serverware-test-tmp \
								--env SERVERWARE_DATA_DIR=/data \
									--tmpfs "/tmp:rw,noexec,nosuid,nodev,size=$(CODER_ISOLATED_TEST_TMPFS_SIZE),mode=0700,uid=10001,gid=10001" \
									--tmpfs "/data:rw,noexec,nosuid,nodev,size=$(CODER_ISOLATED_TEST_TMPFS_SIZE),mode=0700,uid=10001,gid=10001" \
									--tmpfs "/app/.tmp:rw,exec,nosuid,nodev,size=$(CODER_ISOLATED_TEST_TMPFS_SIZE),mode=0700,uid=10001,gid=10001" \
									--tmpfs "/run/serverware-test-tmp:rw,exec,nosuid,nodev,size=$(CODER_ISOLATED_TEST_TMPFS_SIZE),mode=0700,uid=10001,gid=10001" \
							--user 10001:10001 \
							--workdir /app \
							--hostname isolated-tests \
							--ulimit core=0:0 \
							--ulimit nofile=1024:1024 \
							--log-driver local \
								--log-opt "max-size=$(CODER_ISOLATED_TEST_LOG_MAX_SIZE)" \
								--log-opt max-file=1 \
								--entrypoint "$(CODER_IMAGE_PYTHON_INTERPRETER)" \
								"$$selected_test_image_id" "$$@" \
									2>> "$$isolated_test_log" \
						)" || isolated_test_run_status=$$?; \
					elif test "$$selected_test_profile" = production-host-preflight; then \
						isolated_test_container_id="$$( \
							coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) run --detach \
									--pull never \
									--no-healthcheck \
									--name "$$selected_test_container" \
									--cidfile "$$isolated_test_cid" \
									--label "$$selected_test_label" \
									--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
									--platform "$(CODER_PLATFORM)" \
									--network none \
									--ipc none \
									--read-only \
									--cap-drop ALL \
									--security-opt no-new-privileges=true \
									--pids-limit "$(CODER_ISOLATED_TEST_PIDS)" \
									--memory "$(CODER_ISOLATED_TEST_MEMORY)" \
									--memory-swap "$(CODER_ISOLATED_TEST_MEMORY)" \
									--cpus "$(CODER_ISOLATED_TEST_CPUS)" \
									--mount "type=bind,src=$$recorded_docker_path,dst=/opt/serverware/host-tools/docker,readonly" \
									--mount "type=bind,src=$$recorded_compose_plugin_path,dst=/opt/serverware/host-tools/docker-compose,readonly" \
									--env HOME=/tmp \
									--env TMPDIR=/tmp \
									--env SERVERWARE_CODER_PREFLIGHT_DOCKER_EXECUTABLE=/opt/serverware/host-tools/docker \
									--env SERVERWARE_CODER_PREFLIGHT_COMPOSE_PLUGIN_EXECUTABLE=/opt/serverware/host-tools/docker-compose \
									--env SERVERWARE_CODER_PREFLIGHT_DOCKER_UNIX_SOCKET=/run/serverware-no-docker.sock \
									--env "SERVERWARE_CODER_PREFLIGHT_DOCKER_DAEMON_ID=$$(cat "$(CODER_DAEMON_ID_FILE)")" \
									--tmpfs "/tmp:rw,exec,nosuid,nodev,size=$(CODER_ISOLATED_TEST_TMPFS_SIZE),mode=0700,uid=10001,gid=10001" \
									--user 10001:10001 \
									--workdir /app \
									--hostname production-host-preflight \
									--ulimit core=0:0 \
									--ulimit nofile=1024:1024 \
									--log-driver local \
									--log-opt "max-size=$(CODER_ISOLATED_TEST_LOG_MAX_SIZE)" \
									--log-opt max-file=1 \
									--entrypoint "$(CODER_IMAGE_PYTHON_INTERPRETER)" \
									"$$selected_test_image_id" "$$@" \
									2>> "$$isolated_test_log" \
						)" || isolated_test_run_status=$$?; \
					else \
						isolated_test_container_id="$$( \
							coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) run --detach \
									--pull never \
									--no-healthcheck \
									--name "$$selected_test_container" \
									--cidfile "$$isolated_test_cid" \
									--label "$$selected_test_label" \
									--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
									--platform "$(CODER_PLATFORM)" \
									--network none \
									--ipc none \
									--security-opt no-new-privileges=true \
									--pids-limit "$(CODER_LAUNCHER_ADVERSARIAL_PIDS)" \
									--memory "$(CODER_LAUNCHER_ADVERSARIAL_MEMORY)" \
									--memory-swap "$(CODER_LAUNCHER_ADVERSARIAL_MEMORY)" \
									--cpus "$(CODER_LAUNCHER_ADVERSARIAL_CPUS)" \
									--tmpfs "/tmp:rw,exec,nosuid,nodev,size=$(CODER_LAUNCHER_ADVERSARIAL_TMPFS_SIZE),mode=1777" \
									--hostname launcher-adversarial \
									--ulimit core=0:0 \
									--ulimit nofile=1024:1024 \
									--log-driver local \
									--log-opt "max-size=$(CODER_LAUNCHER_ADVERSARIAL_LOG_MAX_SIZE)" \
									--log-opt max-file=1 \
									"$$selected_test_image_id" \
									2>> "$$isolated_test_log" \
						)" || isolated_test_run_status=$$?; \
					fi; \
						if test "$$isolated_test_run_status" -ne 0; then \
							recover_failed_run_cid \
								"$$selected_test_container" \
								"$$selected_test_resource" \
								"$$selected_test_image_id" \
								"$$isolated_test_cid" || exit 2; \
						if test -f "$$isolated_test_cid" && test ! -L "$$isolated_test_cid"; then \
							isolated_test_container_id="$$(cat "$$isolated_test_cid")"; \
							record_owned_container \
								"$$isolated_test_container_id" \
								"$$selected_test_container" \
								"$$selected_test_resource" \
								"$$selected_test_image_id" \
								"$$isolated_test_cid" || exit 2; \
						fi; \
						echo "could not start prebuilt isolated test: $$selected_test_id" >&2; \
						tail -n 200 "$$isolated_test_log" >&2 || true; \
						exit "$$isolated_test_run_status"; \
					fi; \
					test -n "$$isolated_test_container_id" || { \
						echo "docker run returned no isolated test container ID" >&2; \
						exit 2; \
					}; \
					record_owned_container \
						"$$isolated_test_container_id" \
						"$$selected_test_container" \
						"$$selected_test_resource" \
						"$$selected_test_image_id" \
						"$$isolated_test_cid"; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Image}}' "$$isolated_test_container_id" \
				)" = "$$selected_test_image_id" || { \
					echo "isolated test container does not use the selected recorded image ID" >&2; \
					exit 2; \
				}; \
				if test -n "$$selected_python_script"; then \
					selected_process_binding="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{.Path}}{{range .Args}}{{printf "\t%s" .}}{{end}}' \
								"$$isolated_test_container_id" \
					)"; \
					expected_process_binding="$(CODER_IMAGE_PYTHON_INTERPRETER)"; \
					for selected_python_arg in "$$@"; do \
						expected_process_binding="$$expected_process_binding$$python_argv_tab$$selected_python_arg"; \
					done; \
					test "$$selected_process_binding" = "$$expected_process_binding" || { \
						echo "isolated Python container process argv drifted: $$selected_test_id" >&2; \
						exit 2; \
					}; \
				fi; \
				if test "$$selected_test_profile" = production-host-preflight; then \
					test "$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect \
								--format '{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.IpcMode}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.PidsLimit}}' \
								"$$isolated_test_container_id" \
					)" = "true|none|none|4294967296|4294967296|4000000000|$(CODER_ISOLATED_TEST_PIDS)" || { \
						echo "production-host-preflight resource or isolation contract drifted" >&2; \
						exit 2; \
					}; \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{json .HostConfig.CapDrop}}' "$$isolated_test_container_id" \
						| grep -Fx '["ALL"]' >/dev/null || { \
							echo "production-host-preflight capability drop contract drifted" >&2; \
							exit 2; \
						}; \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{range .HostConfig.SecurityOpt}}{{println .}}{{end}}' "$$isolated_test_container_id" \
						| grep -E '^no-new-privileges(:true)?$$' >/dev/null || { \
							echo "production-host-preflight no-new-privileges contract drifted" >&2; \
							exit 2; \
						}; \
					preflight_bind_mounts="$(CODER_OUTPUT_DIR)/production-host-preflight.bind-mounts"; \
					preflight_expected_bind_mounts="$(CODER_OUTPUT_DIR)/production-host-preflight.bind-mounts.expected"; \
					for preflight_mount_artifact in "$$preflight_bind_mounts" "$$preflight_expected_bind_mounts"; do \
						test ! -L "$$preflight_mount_artifact" || { \
							echo "refusing unsafe production-host-preflight mount artifact" >&2; \
							exit 2; \
						}; \
						rm -f "$$preflight_mount_artifact"; \
					done; \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect \
							--format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}}={{.Source}}:{{.RW}}{{println}}{{end}}{{end}}' \
							"$$isolated_test_container_id" \
						| LC_ALL=C sort > "$$preflight_bind_mounts"; \
					printf '%s\n' \
						"/opt/serverware/host-tools/docker=$$recorded_docker_path:false" \
						"/opt/serverware/host-tools/docker-compose=$$recorded_compose_plugin_path:false" \
						| LC_ALL=C sort > "$$preflight_expected_bind_mounts"; \
					cmp "$$preflight_expected_bind_mounts" "$$preflight_bind_mounts" || { \
						echo "production-host-preflight immutable host-tool mount contract drifted" >&2; \
						exit 2; \
					}; \
					rm -f "$$preflight_bind_mounts" "$$preflight_expected_bind_mounts"; \
				fi; \
				isolated_test_wait_status=0; \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$$selected_test_timeout" \
					$(CODER_DOCKER) wait "$$isolated_test_container_id" \
					> "$$isolated_test_exit_code" 2>> "$$isolated_test_log" || isolated_test_wait_status=$$?; \
				isolated_test_logs_status=0; \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) logs --timestamps "$$isolated_test_container_id" \
					> "$$isolated_test_log" 2>&1 || isolated_test_logs_status=$$?; \
					coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
						$(CODER_DOCKER) rm -f "$$isolated_test_container_id" \
						>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || { \
						echo "could not remove isolated test container: $$selected_test_id" >&2; \
						exit 2; \
					}; \
					coder_require_mutation_daemon || { \
						echo "Docker daemon identity changed while removing isolated test container: $$selected_test_id" >&2; \
						exit 2; \
					}; \
					if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect "$$isolated_test_container_id" >/dev/null 2>&1; then \
						echo "isolated test container remains after removal: $$selected_test_id" >&2; \
						exit 2; \
					fi; \
					rm -f "$$isolated_test_cid"; \
					if test "$$isolated_test_wait_status" -ne 0; then \
					tail -n 200 "$$isolated_test_log" >&2 || true; \
					exit "$$isolated_test_wait_status"; \
				fi; \
				if test "$$isolated_test_logs_status" -ne 0; then \
					echo "could not collect bounded isolated test log: $$selected_test_id" >&2; \
					exit "$$isolated_test_logs_status"; \
				fi; \
				isolated_test_status="$$(cat "$$isolated_test_exit_code")"; \
				case "$$isolated_test_status" in \
					""|*[!0-9]*) echo "isolated test container returned an invalid exit status" >&2; exit 2 ;; \
				esac; \
				test "$$isolated_test_status" -le 255 || { \
					echo "isolated test container exit status is out of range" >&2; \
					exit 2; \
				}; \
				if test "$$isolated_test_status" -ne 0; then \
					tail -n 200 "$$isolated_test_log" >&2 || true; \
					exit "$$isolated_test_status"; \
				fi; \
				printf 'passed\t%s\n' "$$selected_test_id" \
					>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
			}; \
			production_test_image_id=""; \
			production_binding_count=0; \
			while read -r runtime_service runtime_image runtime_image_id runtime_extra; do \
				if test "$$runtime_service" = serverware; then \
					production_binding_count=$$((production_binding_count + 1)); \
					test -z "$${runtime_extra:-}" && test "$$runtime_image" = "$(CODER_SHARED_PYTHON_IMAGE)" || { \
						echo "frozen serverware runtime image binding is malformed" >&2; \
						exit 2; \
					}; \
					production_test_image_id="$$runtime_image_id"; \
				fi; \
			done < "$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt"; \
			test "$$production_binding_count" -eq 1 && test -n "$$production_test_image_id" || { \
				echo "frozen runtime bindings do not contain exactly one serverware image ID" >&2; \
				exit 2; \
			}; \
			current_python_argv_bindings="$(CODER_OUTPUT_DIR)/python-test-argv-bindings.current.tsv"; \
			test ! -L "$$current_python_argv_bindings"; \
			rm -f "$$current_python_argv_bindings"; \
			{ \
				for python_test_path in $(CODER_ISOLATED_TEST_SCRIPTS); do \
					python_test_image_id="$$production_test_image_id"; \
					if test "$$python_test_path" = scripts/test_production_release_proof_target.py; then \
						python_test_image_id="$$proxy_test_image_id"; \
					fi; \
					printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
						"$$python_test_path" "$$python_test_image_id" \
						"$(CODER_IMAGE_PYTHON_INTERPRETER)" "$$python_test_path"; \
				done; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					scripts/test_credential_constraints.py \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_credential_constraints.py; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\t%s\n' \
					'scripts/test_credential_constraints.py#proxy-transport-only' \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_credential_constraints.py \
					--proxy-transport-only; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					scripts/test_jit_transaction_state.py \
					"$$proxy_test_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					scripts/test_jit_transaction_state.py; \
				printf 'python-argv\t%s\t%s\t%s\t/app/%s\n' \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)" \
					"$$production_host_preflight_image_id" \
					"$(CODER_IMAGE_PYTHON_INTERPRETER)" \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)"; \
			} | LC_ALL=C sort > "$$current_python_argv_bindings"; \
			cmp "$(CODER_PYTHON_TEST_ARGV_BINDING_FILE)" "$$current_python_argv_bindings" || { \
				echo "isolated Python interpreter/image/argv inventory drifted after coder-build-all" >&2; \
				exit 2; \
			}; \
			rm -f "$$current_python_argv_bindings"; \
				if test "$$controller_stage" = unit || test "$$controller_stage" = all; then \
				printf '%s\n' "running production host preflight in its exact prebuilt socketless diagnostics image"; \
				run_isolated_container_test \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_TEST_SCRIPT)" \
					test_production_host_preflight \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_CONTAINER)" \
					"$(CODER_PRODUCTION_HOST_PREFLIGHT_CONTAINER_LABEL)" \
					"$$production_host_preflight_image_id" \
					"$(CODER_ISOLATED_TEST_TIMEOUT)" \
					production-host-preflight; \
					for isolated_test_path in $(CODER_ISOLATED_TEST_SCRIPTS); do \
						isolated_test_name="$$(basename "$$isolated_test_path" .py)"; \
						isolated_test_image_id="$$production_test_image_id"; \
						isolated_test_runtime=production-image; \
						if test "$$isolated_test_path" = scripts/test_production_release_proof_target.py; then \
							isolated_test_image_id="$$proxy_test_image_id"; \
							isolated_test_runtime=proxy-test-image; \
							printf '%s\n' "using the prebuilt proxy-test image for the release-proof harness's standard checksum utility and source package"; \
						fi; \
						printf '%s\n' "running $$isolated_test_path in a fresh prebuilt $$isolated_test_runtime container"; \
						run_isolated_container_test \
							"$$isolated_test_path" \
						"$$isolated_test_name" \
						"$(CODER_ISOLATED_TEST_CONTAINER)" \
							"$(CODER_ISOLATED_TEST_CONTAINER_LABEL)" \
							"$$isolated_test_image_id" \
							"$(CODER_ISOLATED_TEST_TIMEOUT)" \
							python-isolated \
							"$$isolated_test_path"; \
					done; \
				printf '%s\n' "running the launcher adversarial fixture from its exact prebuilt image ID with a managed container lifecycle"; \
				run_isolated_container_test \
					"$(CODER_LAUNCHER_ADVERSARIAL_TEST_SCRIPT)" \
					test_production_launcher_adversarial \
					"$(CODER_LAUNCHER_ADVERSARIAL_CONTAINER)" \
					"$(CODER_LAUNCHER_ADVERSARIAL_CONTAINER_LABEL)" \
					"$$launcher_adversarial_image_id" \
					"$(CODER_LAUNCHER_ADVERSARIAL_TEST_TIMEOUT)" \
					launcher-adversarial; \
			printf '%s\n' "running full credential-constraint fixtures from the prebuilt proxy runtime"; \
			run_isolated_container_test \
				scripts/test_credential_constraints.py \
				test_credential_constraints \
				"$(CODER_PROXY_TEST_CONTAINER)" \
				"$(CODER_PROXY_TEST_CONTAINER_LABEL)" \
				"$$proxy_test_image_id" \
				"$(CODER_PER_TEST_TIMEOUT)" \
				python-isolated \
				scripts/test_credential_constraints.py; \
			printf '%s\n' "running proxy-transport credential fixtures from the same prebuilt proxy runtime"; \
			run_isolated_container_test \
				"scripts/test_credential_constraints.py#proxy-transport-only" \
				test_credential_constraints_proxy_transport \
				"$(CODER_PROXY_TEST_CONTAINER)" \
				"$(CODER_PROXY_TEST_CONTAINER_LABEL)" \
				"$$proxy_test_image_id" \
				"$(CODER_PER_TEST_TIMEOUT)" \
				python-isolated \
				scripts/test_credential_constraints.py --proxy-transport-only; \
			printf '%s\n' "running JIT transaction-state fixtures from the same prebuilt proxy runtime"; \
			run_isolated_container_test \
				scripts/test_jit_transaction_state.py \
				test_jit_transaction_state \
				"$(CODER_PROXY_TEST_CONTAINER)" \
				"$(CODER_PROXY_TEST_CONTAINER_LABEL)" \
				"$$proxy_test_image_id" \
				"$(CODER_PER_TEST_TIMEOUT)" \
				python-isolated \
				scripts/test_jit_transaction_state.py; \
			printf '%s\n' "running prebuilt Rust unit-test harnesses; log: $(CODER_OUTPUT_DIR)/rust-unit-tests.log"; \
				rust_test_run_status=0; \
				rust_test_container_id="$$( \
					coder_mutate "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) run --detach \
					--pull never \
					--no-healthcheck \
					--name "$(CODER_RUST_TEST_CONTAINER)" \
					--cidfile "$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" \
					--label "$(CODER_RUST_TEST_CONTAINER_LABEL)" \
					--label "$(CODER_OWNER_LABEL_KEY)=$$run_owner_token" \
					--platform "$(CODER_PLATFORM)" \
				--network none \
				--ipc none \
				--read-only \
				--cap-drop ALL \
				--security-opt no-new-privileges=true \
				--pids-limit "$(CODER_RUST_TEST_PIDS)" \
				--memory "$(CODER_RUST_TEST_MEMORY)" \
					--memory-swap "$(CODER_RUST_TEST_MEMORY)" \
					--cpus "$(CODER_RUST_TEST_CPUS)" \
					--env TMPDIR=/run/serverware-test-tmp \
					--tmpfs "/tmp:rw,noexec,nosuid,nodev,size=$(CODER_RUST_TEST_TMPFS_SIZE),mode=1777" \
					--tmpfs "/run/serverware-test-tmp:rw,exec,nosuid,nodev,size=$(CODER_RUST_TEST_TMPFS_SIZE),mode=0700,uid=65532,gid=65532" \
					--user 65532:65532 \
				--workdir /tmp \
				--hostname rust-unit-tests \
				--ulimit core=0:0 \
				--ulimit nofile=1024:1024 \
				--log-driver local \
				--log-opt "max-size=$(CODER_RUST_TEST_LOG_MAX_SIZE)" \
				--log-opt max-file=1 \
					"$$rust_test_image_id" \
					2>> "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" \
				)" || rust_test_run_status=$$?; \
				if test "$$rust_test_run_status" -ne 0; then \
					recover_failed_run_cid \
						"$(CODER_RUST_TEST_CONTAINER)" \
						rust-unit-tests \
						"$$rust_test_image_id" \
						"$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" || exit 2; \
				if test -f "$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" && \
					test ! -L "$(CODER_OUTPUT_DIR)/rust-unit-tests.cid"; then \
					rust_test_container_id="$$(cat "$(CODER_OUTPUT_DIR)/rust-unit-tests.cid")"; \
					record_owned_container \
						"$$rust_test_container_id" \
						"$(CODER_RUST_TEST_CONTAINER)" \
						rust-unit-tests \
						"$$rust_test_image_id" \
						"$(CODER_OUTPUT_DIR)/rust-unit-tests.cid" || exit 2; \
				fi; \
				echo "could not start the prebuilt Rust test image" >&2; \
				tail -n 200 "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" >&2 || true; \
				exit "$$rust_test_run_status"; \
			fi; \
			test -n "$$rust_test_container_id" || { \
				echo "docker run returned no Rust test container ID" >&2; \
				exit 2; \
			}; \
			record_owned_container \
				"$$rust_test_container_id" \
				"$(CODER_RUST_TEST_CONTAINER)" \
				rust-unit-tests \
				"$$rust_test_image_id" \
				"$(CODER_OUTPUT_DIR)/rust-unit-tests.cid"; \
			rust_test_wait_status=0; \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_RUST_TEST_TIMEOUT)" \
				$(CODER_DOCKER) wait "$$rust_test_container_id" \
			> "$(CODER_OUTPUT_DIR)/rust-unit-tests.exit-code" \
			2>> "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" || rust_test_wait_status=$$?; \
			rust_test_logs_status=0; \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) logs --timestamps "$$rust_test_container_id" \
				> "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" 2>&1 || rust_test_logs_status=$$?; \
			coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
				$(CODER_DOCKER) rm -f "$$rust_test_container_id" \
			>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 || { \
				echo "could not remove the Rust test container" >&2; \
				exit 2; \
			}; \
		if test "$$rust_test_wait_status" -ne 0; then \
			tail -n 200 "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" >&2 || true; \
			exit "$$rust_test_wait_status"; \
		fi; \
		if test "$$rust_test_logs_status" -ne 0; then \
			echo "could not collect the bounded Rust test log" >&2; \
			exit "$$rust_test_logs_status"; \
		fi; \
		rust_test_status="$$(cat "$(CODER_OUTPUT_DIR)/rust-unit-tests.exit-code")"; \
		case "$$rust_test_status" in \
			""|*[!0-9]*) \
				echo "Rust test container returned an invalid exit status" >&2; \
				exit 2 \
				;; \
		esac; \
		test "$$rust_test_status" -le 255 || { \
			echo "Rust test container exit status is out of range" >&2; \
			exit 2; \
		}; \
			if test "$$rust_test_status" -ne 0; then \
				tail -n 200 "$(CODER_OUTPUT_DIR)/rust-unit-tests.log" >&2 || true; \
				exit "$$rust_test_status"; \
			fi; \
				printf 'passed\trust-unit-harnesses\n' \
					>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
				fi; \
			verify_compose_storage_ownership() { \
			compose_network="$(CODER_COMPOSE_PROJECT_NAME)_default"; \
			network_identity="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) network inspect \
						--format '{{.Id}}|{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
						"$$compose_network" \
			)" || { echo "expected Compose network is absent: $$compose_network" >&2; exit 2; }; \
			network_id="$${network_identity%%|*}"; \
			test "$$network_identity" = "$$network_id|$$compose_network|compose-default-network|$$run_owner_token" || { \
				echo "refusing unowned same-name Compose network: $$compose_network" >&2; \
				exit 2; \
			}; \
			network_record="$$(printf 'network\t%s\tcompose-default-network\t%s\t%s' \
				"$$compose_network" "$$run_owner_token" "$$network_id")"; \
			if ! grep -Fx "$$network_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
				printf '%s\n' "$$network_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
			fi; \
			for volume_suffix in \
				serverware-data \
				serverware-audit-anchors \
				serverware-grant-store \
				serverware-custody-socket \
				serverware-custody-trust \
				serverware-response-signing-private; do \
				compose_volume="$(CODER_COMPOSE_PROJECT_NAME)_$$volume_suffix"; \
				volume_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume inspect \
							--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
							"$$compose_volume" \
				)" || { echo "expected Compose volume is absent: $$compose_volume" >&2; exit 2; }; \
				test "$$volume_identity" = "$$compose_volume|$$volume_suffix|$$run_owner_token" || { \
					echo "refusing unowned same-name Compose volume: $$compose_volume" >&2; \
					exit 2; \
				}; \
				volume_record="$$(printf 'volume\t%s\t%s\t%s\t%s' \
					"$$compose_volume" "$$volume_suffix" "$$run_owner_token" "$$compose_volume")"; \
				if ! grep -Fx "$$volume_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
					printf '%s\n' "$$volume_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				fi; \
			done; \
			project_network_ids="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) network ls -q --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; \
			for project_network_id in $$project_network_ids; do \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) network inspect --format '{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$project_network_id" \
				)" = "$$run_owner_token" || { \
					echo "refusing a Compose project containing an unowned network: $$project_network_id" >&2; \
					exit 2; \
				}; \
			done; \
			project_volumes="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume ls -q --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; \
			for project_volume in $$project_volumes; do \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume inspect --format '{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$project_volume" \
				)" = "$$run_owner_token" || { \
					echo "refusing a Compose project containing an unowned volume: $$project_volume" >&2; \
					exit 2; \
				}; \
			done; \
		}; \
		destroy_owned_compose_stack() { \
			compose_container_ids="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)"; \
			for compose_container_id in $$compose_container_ids; do \
				compose_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$compose_container_id" \
				)"; \
				compose_name="$${compose_identity%%|*}"; \
				compose_identity_rest="$${compose_identity#*|}"; \
				compose_resource="$${compose_identity_rest%%|*}"; \
				compose_owner="$${compose_identity_rest#*|}"; \
				compose_name="$${compose_name#/}"; \
				test "$$compose_owner" = "$$run_owner_token" || { \
					echo "refusing to destroy an unowned Compose container: $$compose_container_id" >&2; \
					exit 2; \
				}; \
				ownership_record="$$(printf 'container\t%s\t%s\t%s\t%s' "$$compose_name" "$$compose_resource" "$$run_owner_token" "$$compose_container_id")"; \
				grep -Fx "$$ownership_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || { \
					echo "refusing to destroy an unrecorded Compose container: $$compose_container_id" >&2; \
					exit 2; \
				}; \
				coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
					$(CODER_DOCKER) rm -f "$$compose_container_id" \
					>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1; \
			done; \
			ownership_tab="$$(printf '\t')"; \
			while IFS="$$ownership_tab" read -r storage_kind storage_name storage_resource storage_owner storage_id storage_extra; do \
				test "$$storage_owner" = "$$run_owner_token" && test -z "$${storage_extra:-}" || continue; \
				case "$$storage_kind" in \
					network) \
						test "$$storage_resource" = compose-default-network || continue; \
						storage_identity="$$( \
							$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
								$(CODER_DOCKER) network inspect \
									--format '{{.Id}}|{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
									"$$storage_id" 2>/dev/null \
						)" || continue; \
						test "$$storage_identity" = "$$storage_id|$$storage_name|$$storage_resource|$$run_owner_token" || exit 2; \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) network rm "$$storage_id" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 \
						;; \
					volume) \
						test "$$storage_resource" != buildkit-state || continue; \
						case "$$storage_resource" in \
							serverware-data|serverware-audit-anchors|serverware-grant-store|serverware-custody-socket|serverware-custody-trust|serverware-custody-state|serverware-response-signing-private) ;; \
							*) echo "refusing undeclared Compose volume record" >&2; exit 2 ;; \
						esac; \
						test "$$storage_name" = "$(CODER_COMPOSE_PROJECT_NAME)_$$storage_resource" || exit 2; \
						test "$$storage_id" = "$$storage_name" && \
							test "$$( \
								$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
									$(CODER_DOCKER) volume inspect \
										--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
										"$$storage_name" \
							)" = "$$storage_name|$$storage_resource|$$run_owner_token" || exit 2; \
						coder_mutate "$(CODER_CLEANUP_TIMEOUT)" \
							$(CODER_DOCKER) volume rm "$$storage_name" \
							>> "$(CODER_OUTPUT_DIR)/cleanup.log" 2>&1 \
						;; \
				esac; \
			done < "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
			test -z "$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) ps --all --quiet --no-trunc \
						--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
			)" || { echo "Compose containers remain after exact teardown" >&2; exit 2; }; \
		}; \
		create_and_start_compose_stack() { \
		current_compose_config_digest_line="$$(sha256sum "$(CODER_OUTPUT_DIR)/compose-config.yaml")"; \
		test "$${current_compose_config_digest_line%% *}" = "$$(cat "$(CODER_OUTPUT_DIR)/compose-config-sha256.txt")" || { \
			echo "the recorded Compose configuration changed before container creation" >&2; \
			exit 2; \
			}; \
			for compose_service in $(CODER_RUNTIME_SERVICES); do \
				compose_container_name="$(CODER_COMPOSE_PROJECT_NAME)-$${compose_service}-1"; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) container inspect "$$compose_container_name" >/dev/null 2>&1; then \
					echo "refusing to create over a pre-existing Compose container: $$compose_container_name" >&2; \
					exit 2; \
				fi; \
			done; \
			compose_network="$(CODER_COMPOSE_PROJECT_NAME)_default"; \
			if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
				$(CODER_DOCKER) network inspect "$$compose_network" >/dev/null 2>&1; then \
				echo "refusing to create over a pre-existing Compose network: $$compose_network" >&2; \
				exit 2; \
			fi; \
			for volume_suffix in \
				serverware-data \
				serverware-audit-anchors \
				serverware-grant-store \
				serverware-custody-socket \
				serverware-custody-trust \
				serverware-custody-state \
				serverware-response-signing-private; do \
				compose_volume="$(CODER_COMPOSE_PROJECT_NAME)_$$volume_suffix"; \
				if $(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_DOCKER) volume inspect "$$compose_volume" >/dev/null 2>&1; then \
					echo "refusing to create over a pre-existing Compose volume: $$compose_volume" >&2; \
					exit 2; \
				fi; \
			done; \
			printf '%s\n' "creating only prebuilt services for image verification; log: $(CODER_OUTPUT_DIR)/startup.log"; \
			compose_create_status=0; \
			coder_mutate "$(CODER_START_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) create --no-build --pull never $(CODER_RUNTIME_SERVICES) \
				> "$(CODER_OUTPUT_DIR)/startup.log" 2>&1 || compose_create_status=$$?; \
				created_compose_ids="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) ps --all --quiet --no-trunc --filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
				)" || created_compose_ids=""; \
				for created_compose_id in $$created_compose_ids; do \
					created_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) container inspect --format '{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$created_compose_id" \
					)" || continue; \
					created_name="$${created_identity%%|*}"; \
					created_rest="$${created_identity#*|}"; \
					created_resource="$${created_rest%%|*}"; \
					created_owner="$${created_rest#*|}"; \
					test "$$created_owner" = "$$run_owner_token" || continue; \
					created_name="$${created_name#/}"; \
					case "$$created_compose_id" in *[!0-9a-f]*) continue ;; esac; \
					test "$${#created_compose_id}" -eq 64 || continue; \
					case "$$created_name:$$created_resource" in \
						""|:*|*:|*:*[!a-z0-9_-]*|*[!a-z0-9_-]*:*) continue ;; \
					esac; \
					created_ownership_record="$$(printf 'container\t%s\t%s\t%s\t%s' \
						"$$created_name" "$$created_resource" "$$run_owner_token" "$$created_compose_id")"; \
					if ! grep -Fx "$$created_ownership_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
						printf '%s\n' "$$created_ownership_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
					fi; \
				done; \
				created_network_ids="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) network ls -q \
							--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
				)" || created_network_ids=""; \
				for created_network_id in $$created_network_ids; do \
					created_network_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) network inspect \
								--format '{{.Id}}|{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
								"$$created_network_id" \
					)"; \
					test "$$created_network_identity" = "$$created_network_id|$(CODER_COMPOSE_PROJECT_NAME)_default|compose-default-network|$$run_owner_token" || { \
						echo "refusing unexpected network in partial Compose creation" >&2; exit 2; \
					}; \
					created_network_record="$$(printf 'network\t%s\tcompose-default-network\t%s\t%s' \
						"$(CODER_COMPOSE_PROJECT_NAME)_default" "$$run_owner_token" "$$created_network_id")"; \
					grep -Fx "$$created_network_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || \
						printf '%s\n' "$$created_network_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				done; \
				created_volumes="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) volume ls -q \
							--filter "label=com.docker.compose.project=$(CODER_COMPOSE_PROJECT_NAME)" \
				)" || created_volumes=""; \
				for created_volume in $$created_volumes; do \
					created_volume_identity="$$( \
						$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
							$(CODER_DOCKER) volume inspect \
								--format '{{.Name}}|{{index .Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Labels "$(CODER_OWNER_LABEL_KEY)"}}' \
								"$$created_volume" \
					)"; \
					created_volume_resource="$$(printf '%s\n' "$$created_volume_identity" | sed 's/^[^|]*|\\([^|]*\\)|.*$$/\\1/')"; \
					case "$$created_volume_resource" in \
						serverware-data|serverware-audit-anchors|serverware-grant-store|serverware-custody-socket|serverware-custody-trust|serverware-custody-state|serverware-response-signing-private) ;; \
						*) echo "refusing unexpected volume in partial Compose creation" >&2; exit 2 ;; \
					esac; \
					test "$$created_volume_identity" = "$$created_volume|$$created_volume_resource|$$run_owner_token" && \
						test "$$created_volume" = "$(CODER_COMPOSE_PROJECT_NAME)_$$created_volume_resource" || exit 2; \
					created_volume_record="$$(printf 'volume\t%s\t%s\t%s\t%s' \
						"$$created_volume" "$$created_volume_resource" "$$run_owner_token" "$$created_volume")"; \
					grep -Fx "$$created_volume_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null || \
						printf '%s\n' "$$created_volume_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				done; \
				if test "$$compose_create_status" -ne 0; then \
					echo "Compose could not create the complete prebuilt service group" >&2; \
					exit "$$compose_create_status"; \
				fi; \
			while read -r service image expected_image_id; do \
			test -n "$$service" || continue; \
			container_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_TEST_COMPOSE) ps -q "$$service" \
			)"; \
			test -n "$$container_id" || { \
				echo "Compose did not create the expected service container: $$service" >&2; \
				exit 2; \
			}; \
				compose_identity="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Image}}|{{.Name}}|{{index .Config.Labels "$(CODER_RESOURCE_LABEL_KEY)"}}|{{index .Config.Labels "$(CODER_OWNER_LABEL_KEY)"}}' "$$container_id" \
				)"; \
			actual_image_id="$${compose_identity%%|*}"; \
			test "$$actual_image_id" = "$$expected_image_id" || { \
				echo "service $$service was created from $$actual_image_id, expected $$expected_image_id ($$image)" >&2; \
				exit 2; \
				}; \
			compose_identity_rest="$${compose_identity#*|}"; \
			compose_name="$${compose_identity_rest%%|*}"; \
			compose_identity_rest="$${compose_identity_rest#*|}"; \
			compose_resource="$${compose_identity_rest%%|*}"; \
			compose_owner="$${compose_identity_rest#*|}"; \
			compose_name="$${compose_name#/}"; \
			test "$$compose_resource" = "$$service" && test "$$compose_owner" = "$$run_owner_token" || { \
				echo "Compose service ownership validation failed: $$service" >&2; \
				exit 2; \
			}; \
				compose_ownership_record="$$(printf 'container\t%s\t%s\t%s\t%s' \
					"$$compose_name" "$$compose_resource" "$$run_owner_token" "$$container_id")"; \
				if ! grep -Fx "$$compose_ownership_record" "$(CODER_RESOURCE_OWNERSHIP_FILE)" >/dev/null; then \
					printf '%s\n' "$$compose_ownership_record" >> "$(CODER_RESOURCE_OWNERSHIP_FILE)"; \
				fi; \
				done < "$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt"; \
			verify_compose_storage_ownership; \
			printf '%s\n' "starting grant-store before its dependants"; \
			coder_mutate "$(CODER_START_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) start grant-store \
				>> "$(CODER_OUTPUT_DIR)/startup.log" 2>&1; \
			grant_store_container_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
					$(CODER_TEST_COMPOSE) ps -q grant-store \
			)"; \
			test -n "$$grant_store_container_id" || { \
				echo "grant-store container disappeared during startup" >&2; \
				exit 2; \
			}; \
			grant_store_healthy=0; \
			grant_store_attempt=1; \
			while test "$$grant_store_attempt" -le "$(CODER_GRANT_STORE_HEALTH_RETRIES)"; do \
				grant_store_health="$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect \
							--format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
							"$$grant_store_container_id" \
				)"; \
				case "$$grant_store_health" in \
					healthy) grant_store_healthy=1; break ;; \
					starting) ;; \
					unhealthy|missing) \
						echo "grant-store health check failed: $$grant_store_health" >&2; \
						exit 2 \
						;; \
					*) echo "unexpected grant-store health state: $$grant_store_health" >&2; exit 2 ;; \
				esac; \
				sleep 1; \
				grant_store_attempt=$$((grant_store_attempt + 1)); \
			done; \
			test "$$grant_store_healthy" = 1 || { \
				echo "grant-store did not become healthy within $(CODER_GRANT_STORE_HEALTH_RETRIES) seconds" >&2; \
				exit 2; \
			}; \
			printf '%s\n' "starting audit-anchor, demo-upstream, and serverware from prebuilt images"; \
			coder_mutate "$(CODER_START_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) start audit-anchor demo-upstream serverware \
				>> "$(CODER_OUTPUT_DIR)/startup.log" 2>&1; \
			verify_frozen_source; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_START_TIMEOUT)" \
			env -i \
				PATH="$(CODER_OUTPUT_DIR)/e2e-command-bin" \
				HOME="$${HOME:-/tmp}" \
				XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}" \
				COMPOSE_PROJECT_NAME="$(CODER_COMPOSE_PROJECT_NAME)" \
				SERVERWARE_CODER_COMPOSE_FILE="$(CODER_OUTPUT_DIR)/compose-config.yaml" \
				SERVERWARE_CODER_PROJECT_DIRECTORY="$(CODER_FROZEN_SOURCE_DIR)" \
				BASE=http://localhost:3000 \
				sh -c 'cd "$$1" && exec ./scripts/wait_for_serverware.sh' \
				sh "$(CODER_FROZEN_SOURCE_DIR)"; \
		verify_frozen_source; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_START_TIMEOUT)" \
			env -i \
				PATH="$(CODER_OUTPUT_DIR)/e2e-command-bin" \
				HOME="$${HOME:-/tmp}" \
				XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}" \
				COMPOSE_PROJECT_NAME="$(CODER_COMPOSE_PROJECT_NAME)" \
				SERVERWARE_CODER_COMPOSE_FILE="$(CODER_OUTPUT_DIR)/compose-config.yaml" \
				SERVERWARE_CODER_PROJECT_DIRECTORY="$(CODER_FROZEN_SOURCE_DIR)" \
					sh -c 'cd "$$1" && exec ./scripts/wait_for_demo_upstream.sh' \
					sh "$(CODER_FROZEN_SOURCE_DIR)"; \
			verify_frozen_source; \
			printf '%s\n' "starting decision-gate only after serverware is ready"; \
			coder_mutate "$(CODER_START_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) start decision-gate-rs \
				>> "$(CODER_OUTPUT_DIR)/startup.log" 2>&1; \
			$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_START_TIMEOUT)" \
			env -i \
				PATH="$(CODER_OUTPUT_DIR)/e2e-command-bin" \
				HOME="$${HOME:-/tmp}" \
				XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}" \
				COMPOSE_PROJECT_NAME="$(CODER_COMPOSE_PROJECT_NAME)" \
				SERVERWARE_CODER_COMPOSE_FILE="$(CODER_OUTPUT_DIR)/compose-config.yaml" \
				SERVERWARE_CODER_PROJECT_DIRECTORY="$(CODER_FROZEN_SOURCE_DIR)" \
				DECISION_GATE_BASE=http://localhost:9091 \
				sh -c 'cd "$$1" && exec ./scripts/wait_for_decision_gate.sh' \
				sh "$(CODER_FROZEN_SOURCE_DIR)"; \
		verify_frozen_source; \
		}; \
		if test "$$controller_stage" = integration || test "$$controller_stage" = all; then \
		: > "$(CODER_OUTPUT_DIR)/startup.log"; \
		: > "$(CODER_OUTPUT_DIR)/compose.log"; \
		create_and_start_compose_stack; \
		for test_path in $(CODER_TEST_SCRIPTS); do \
			test_name="$$(basename "$$test_path" .py)"; \
			test_log="$(CODER_OUTPUT_DIR)/$$test_name.log"; \
			rm -f "$$test_log"; \
			printf '%s\n' "running $$test_path without a build; log: $$test_log"; \
			status=0; \
			coder_mutate "$(CODER_PER_TEST_TIMEOUT)" \
				$(CODER_TEST_COMPOSE) exec -T serverware python "$$test_path" \
				> "$$test_log" 2>&1 || status=$$?; \
				if test "$$status" -ne 0; then \
					tail -n 200 "$$test_log" >&2 || true; \
					exit "$$status"; \
				fi; \
				printf 'passed\t%s\n' "$$test_path" \
					>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
			done; \
			if test "$$controller_stage" = integration; then destroy_owned_compose_stack; fi; \
			fi; \
			if test "$$controller_stage" = e2e || test "$$controller_stage" = all; then \
			printf '%s\n' "recreating exact-image Compose services and volumes before the E2E group"; \
			if test "$$controller_stage" = all; then destroy_owned_compose_stack; fi; \
			create_and_start_compose_stack; \
			printf '%s\n' "running the existing end-to-end journey without an internal compose build; log: $(CODER_OUTPUT_DIR)/e2e.log"; \
		verify_frozen_source; \
		e2e_script_digest_before="$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/scripts/e2e.sh" | sed 's/ .*//')"; \
		test "$$e2e_script_digest_before" = "$$(cat "$(CODER_OUTPUT_DIR)/e2e-script-sha256.txt")" || { \
			echo "E2E script differs from its reviewed build-time digest immediately before execution" >&2; \
			exit 2; \
		}; \
		status=0; \
		$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_E2E_TIMEOUT)" \
			env -i \
				PATH="$(CODER_OUTPUT_DIR)/e2e-command-bin" \
				HOME="$${HOME:-/tmp}" \
				XDG_RUNTIME_DIR="$${XDG_RUNTIME_DIR:-/run/user/$$(id -u)}" \
				COMPOSE_PROJECT_NAME="$(CODER_COMPOSE_PROJECT_NAME)" \
				SERVERWARE_CODER_COMPOSE_FILE="$(CODER_OUTPUT_DIR)/compose-config.yaml" \
				SERVERWARE_CODER_PROJECT_DIRECTORY="$(CODER_FROZEN_SOURCE_DIR)" \
				BASE=http://localhost:3000 \
				PROXY=http://localhost:8080 \
				DECISION_GATE_BASE=http://localhost:9091 \
				SERVERWARE_ADMIN_TOKEN=dev-admin-token \
				SERVERWARE_START_DECISION_GATE=0 \
				TMP_DIR="$(CODER_OUTPUT_DIR)/e2e" \
				sh -c 'cd "$$1" && exec ./scripts/e2e.sh' \
				sh "$(CODER_FROZEN_SOURCE_DIR)" \
				> "$(CODER_OUTPUT_DIR)/e2e.log" 2>&1 || status=$$?; \
			e2e_script_digest_after="$$(sha256sum "$(CODER_FROZEN_SOURCE_DIR)/scripts/e2e.sh" | sed 's/ .*//')"; \
			test "$$e2e_script_digest_after" = "$$e2e_script_digest_before" || { \
				echo "E2E script changed during host execution" >&2; \
				exit 2; \
			}; \
			verify_frozen_source; \
			if test "$$status" -ne 0; then \
				tail -n 200 "$(CODER_OUTPUT_DIR)/e2e.log" >&2 || true; \
				exit "$$status"; \
			fi; \
			printf 'passed\tscripts/e2e.sh\n' \
				>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
			fi; \
			if test "$$controller_stage" = attestation || test "$$controller_stage" = all; then \
		while read -r service image expected_image_id; do \
			test -n "$$service" || continue; \
			container_id="$$( \
				$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_TEST_COMPOSE) ps -q "$$service" \
			)"; \
			test -n "$$container_id" || { \
				echo "expected service container disappeared during tests: $$service" >&2; \
				exit 2; \
			}; \
				test "$$( \
					$(CODER_TIMEOUT) --kill-after="$(CODER_KILL_AFTER)" "$(CODER_INSPECT_TIMEOUT)" \
						$(CODER_DOCKER) container inspect --format '{{.Image}}' "$$container_id" \
				)" = "$$expected_image_id" || { \
				echo "service $$service changed image identity during tests ($$image)" >&2; \
				exit 2; \
			}; \
		done < "$(CODER_OUTPUT_DIR)/runtime-image-bindings.txt"; \
			while IFS= read -r test_path; do \
				test -n "$$test_path" || continue; \
				printf 'excluded\t%s\n' "$$test_path"; \
			done < "$(CODER_EXCLUDED_TESTS_FILE)" \
				>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv"; \
		printf 'schema\tserverware.coder-ci.batch-coverage-results.v2\n' \
			> "$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.tsv"; \
		coverage_tab="$$(printf '\t')"; \
		while IFS="$$coverage_tab" read -r record disposition test_id runner detail; do \
			test "$$record" = test || continue; \
			case "$$disposition" in \
				prepared) result_status=passed ;; \
				excluded) result_status=excluded ;; \
				*) echo "invalid disposition while reconciling coverage: $$disposition" >&2; exit 2 ;; \
			esac; \
			printf '%s\t%s\n' "$$result_status" "$$test_id" \
				>> "$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.tsv"; \
		done < "$(CODER_OUTPUT_DIR)/batch-coverage-manifest.tsv"; \
		LC_ALL=C sort "$(CODER_OUTPUT_DIR)/batch-coverage-results.tsv" \
			> "$(CODER_OUTPUT_DIR)/batch-coverage-results.actual.sorted.tsv"; \
		LC_ALL=C sort "$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.tsv" \
			> "$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.sorted.tsv"; \
		cmp -s \
			"$(CODER_OUTPUT_DIR)/batch-coverage-results.expected.sorted.tsv" \
			"$(CODER_OUTPUT_DIR)/batch-coverage-results.actual.sorted.tsv" || { \
				echo "coverage results do not reconcile one-to-one with the canonical manifest" >&2; \
				exit 2; \
			}; \
			$(MAKE) --no-print-directory _coder-require-clean; \
			printf '%s\n' "all selected no-build tests passed; logs: $(CODER_OUTPUT_DIR)"; \
			fi; \
			printf '%s\n' "$$controller_stage" > "$$stage_marker"; \
			chmod 0600 "$$stage_marker"

coder-ci: _coder-require-clean
	@set -eu; \
		lock_dir="$(CODER_LOCK_DIRECTORY)"; \
		test -d "$$lock_dir" && test ! -L "$$lock_dir"; \
		test "$$(stat -Lc '%u:%F' "$$lock_dir")" = "0:directory"; \
		exec 9<"$$lock_dir"; \
		flock --exclusive --nonblock 9; \
		exec env CODER_LOCK_FD=9 CODER_LOCK_PATH="$$lock_dir" $(MAKE) --no-print-directory _coder-ci-locked

_coder-ci-locked: _coder-require-lock _coder-require-clean
	@set -eu; \
		case "$(CODER_REPO_TMP_DIR)" in /*) ;; *) echo "Coder artifact root must be absolute" >&2; exit 2 ;; esac; \
		test "$(CODER_REPO_TMP_DIR)" != "$(CURDIR)"; \
		case "$(CODER_REPO_TMP_DIR)/" in "$(CURDIR)/"*) echo "Coder artifact root must be outside the source tree" >&2; exit 2 ;; esac; \
		test "$(CODER_OUTPUT_DIR)" = "$(CODER_REPO_TMP_DIR)/coder-ci"; \
		if test ! -e "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; then \
			(umask 077 && mkdir "$(CODER_REPO_TMP_DIR)"); \
		fi; \
		test -d "$(CODER_REPO_TMP_DIR)" && test ! -L "$(CODER_REPO_TMP_DIR)"; \
		test "$$(stat -Lc '%u:%F' "$(CODER_REPO_TMP_DIR)")" = "$$(id -u):directory"; \
		case "$$(stat -Lc '%a' "$(CODER_REPO_TMP_DIR)")" in \
			7[0145][0145]) ;; \
			*) echo "repository .tmp must not be group- or world-writable" >&2; exit 2 ;; \
		esac; \
		parent_cleanup_token="$(CODER_REPO_TMP_DIR)/coder-ci-parent-$$$$"; \
		test ! -e "$$parent_cleanup_token" && test ! -L "$$parent_cleanup_token"; \
		(umask 077 && mkdir "$$parent_cleanup_token"); \
		test "$$(stat -Lc '%u:%a:%F' "$$parent_cleanup_token")" = "$$(id -u):700:directory"; \
		cleanup_state=0; \
		parent_cleanup_once() { \
			test "$$cleanup_state" -eq 0 || return 0; \
			cleanup_state=1; \
			cleanup_status=0; \
			if test -e "$(CODER_PARENT_CLEANUP_MARKER_FILE)" || \
				test -L "$(CODER_PARENT_CLEANUP_MARKER_FILE)"; then \
				test -f "$(CODER_PARENT_CLEANUP_MARKER_FILE)" && \
					test ! -L "$(CODER_PARENT_CLEANUP_MARKER_FILE)" && \
					test "$$(stat -Lc '%u:%a:%F' "$(CODER_PARENT_CLEANUP_MARKER_FILE)")" = "$$(id -u):600:regular file" && \
					test "$$(cat "$(CODER_PARENT_CLEANUP_MARKER_FILE)")" = "$$parent_cleanup_token" || { \
						echo "refusing parent cleanup because its ownership token is invalid" >&2; \
						cleanup_state=2; \
						return 2; \
					}; \
				if test ! -e "$(CODER_DAEMON_ID_FILE)" && test ! -L "$(CODER_DAEMON_ID_FILE)"; then \
					cleanup_state=2; \
					return 0; \
				fi; \
				test -f "$(CODER_DAEMON_ID_FILE)" && \
					test ! -L "$(CODER_DAEMON_ID_FILE)" && \
					test "$$(stat -Lc '%u:%a:%F' "$(CODER_DAEMON_ID_FILE)")" = "$$(id -u):600:regular file" || { \
						echo "refusing parent cleanup because the recorded daemon ID is unsafe" >&2; \
						cleanup_state=2; \
						return 2; \
					}; \
				env CODER_REMOVE_IMAGES=1 $(MAKE) --no-print-directory _coder-cleanup || cleanup_status=$$?; \
			fi; \
			cleanup_state=2; \
			return "$$cleanup_status"; \
		}; \
		on_exit() { \
			status=$$?; \
			trap - EXIT HUP INT TERM; \
			if test "$$status" -ne 0; then \
				parent_cleanup_once || status=1; \
			fi; \
			rm -rf "$$parent_cleanup_token"; \
			exit "$$status"; \
		}; \
		on_signal() { \
			trap - EXIT HUP INT TERM; \
			cleanup_status=0; \
			parent_cleanup_once || cleanup_status=$$?; \
			rm -rf "$$parent_cleanup_token"; \
			test "$$cleanup_status" -eq 0 || exit "$$cleanup_status"; \
			exit 130; \
		}; \
		trap on_exit EXIT; \
		trap on_signal HUP INT TERM; \
		env \
			CODER_COMBINED_CI=1 \
			CODER_PARENT_CLEANUP=1 \
			CODER_PARENT_CLEANUP_TOKEN="$$parent_cleanup_token" \
			$(MAKE) --no-print-directory _coder-build-all-locked; \
		env CODER_REMOVE_IMAGES=0 $(MAKE) --no-print-directory _coder-cleanup; \
		env \
			CODER_COMBINED_CI=1 \
			CODER_PARENT_CLEANUP=1 \
			CODER_PARENT_CLEANUP_TOKEN="$$parent_cleanup_token" \
			$(MAKE) --no-print-directory _coder-test-no-build-locked; \
		parent_cleanup_once; \
		rm -f "$(CODER_PARENT_CLEANUP_MARKER_FILE)"

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
		--reproducible-build-signature "$(REPRODUCIBLE_BUILD_VERIFICATION_SIGNATURE)" \
		--reproducible-build-trusted-public-key "$(REPRODUCIBLE_BUILD_VERIFICATION_TRUSTED_PUBLIC_KEY)" \
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

# Build orchestration is intentionally non-attesting. GNU Make parses the live
# Makefile and only requests one externally supervised candidate-build lease.
# The privileged build watchdog exclusively owns daemon access and cleanup.
build-consolidated-test-artifacts:
	@set -eu; for value in \
		"$(CONSOLIDATED_BUILD_PYTHON)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT_SHA256)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT_SHA256)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256)" \
		"$(CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256)" \
		"$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		"$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		"$(CONSOLIDATED_SOURCE_GIT_INVENTORY_PUBLIC_KEY)" \
		"$(CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_SPKI_SHA256)" \
		"$(CONSOLIDATED_SOURCE_GIT_INVENTORY_KEY_RAW_SHA256)" \
		"$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_PUBLIC_KEY)" \
		"$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_SPKI_SHA256)" \
		"$(CONSOLIDATED_SOURCE_UNTRACKED_APPROVAL_KEY_RAW_SHA256)" \
		"$(CONSOLIDATED_DEPENDENCY_BUNDLE_ROOT)" \
		"$(CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST)" \
		"$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_PUBLIC_KEY)" \
		"$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_SPKI_SHA256)" \
		"$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_RAW_SHA256)" \
		"$(CONSOLIDATED_APPARMOR_PROFILE)" \
		"$(CONSOLIDATED_SECCOMP_PROFILE)"; do \
		test -n "$$value" || { echo "all consolidated OCI build inputs are required" >&2; exit 2; }; \
	done
	"$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT)" supervise-build-lease-v4 \
		--socket "$(CONSOLIDATED_BUILD_WATCHDOG_SOCKET)" \
		--expected-client-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT_SHA256)" \
		--contract "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		--expected-contract-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT_SHA256)" \
		--public-key "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY)" \
		--expected-public-key-spki-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256)" \
		--expected-public-key-raw-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256)" \
		--expected-challenge-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256)" \
		--expected-capability-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS) \
		--handshake-out "$(CONSOLIDATED_BUILD_WATCHDOG_HANDSHAKE)" \
		--workspace "$(CURDIR)" \
		--output-root "$(abspath $(CONSOLIDATED_OUTPUT_ROOT))" \
		-- "$(MAKE)" --no-print-directory _build-consolidated-test-artifacts-locked

verify-consolidated-no-build:
	@printf '%s\n' "NON-ATTESTING CONVENIENCE ONLY: this alias requires an externally promoted, signed, read-only verification root."
	PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(CONSOLIDATED_PYTHON)" -I "$(CONSOLIDATED_TRUSTED_LAUNCHER)" verify \
		--capability-authority-public-key "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_PUBLIC_KEY)" \
		--expected-capability-authority-public-key-spki-sha256 "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_SPKI_SHA256)" \
		--expected-capability-authority-public-key-raw-sha256 "$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_KEY_RAW_SHA256)" \
		--promotion-receipt "$(CONSOLIDATED_PROMOTION_RECEIPT)" \
		--expected-promotion-receipt-sha256 "$(CONSOLIDATED_PROMOTION_RECEIPT_SHA256)" \
		--promotion-public-key "$(CONSOLIDATED_PROMOTION_PUBLIC_KEY)" \
		--expected-promotion-public-key-spki-sha256 "$(CONSOLIDATED_PROMOTION_PUBLIC_KEY_SPKI_SHA256)" \
		--expected-promotion-public-key-raw-sha256 "$(CONSOLIDATED_PROMOTION_PUBLIC_KEY_RAW_SHA256)" \
		--expected-promotion-acceptance-sha256 "$(CONSOLIDATED_PROMOTION_ACCEPTANCE_SHA256)" \
		--expected-candidate-index-sha256 "$(CONSOLIDATED_CANDIDATE_INDEX_SHA256)" \
		--expected-candidate-file-sha256 "$(CONSOLIDATED_CANDIDATE_FILE_SHA256)" \
		--expected-candidate-payload-sha256 "$(CONSOLIDATED_CANDIDATE_PAYLOAD_SHA256)" \
		--expected-manifest-sha256 "$(CONSOLIDATED_PROMOTED_MANIFEST_SHA256)" \
		--expected-manifest-file-sha256 "$(CONSOLIDATED_PROMOTED_MANIFEST_FILE_SHA256)" \
		--expected-launcher-sha256 "$(CONSOLIDATED_TRUSTED_LAUNCHER_SHA256)" \
		--trusted-runtime-manifest "$(CONSOLIDATED_TRUSTED_RUNTIME_MANIFEST)" \
		--expected-runtime-manifest-sha256 "$(CONSOLIDATED_TRUSTED_RUNTIME_MANIFEST_SHA256)" \
		--expected-base-measurement "$(CONSOLIDATED_TRUSTED_BASE_MEASUREMENT)" \
		--expected-python-path "$(CONSOLIDATED_PYTHON)" \
		--expected-python-sha256 "$(CONSOLIDATED_PYTHON_SHA256)" \
		--manifest "$(CONSOLIDATED_PROMOTED_MANIFEST)" \
		$(CONSOLIDATED_ALLOWED_READ_ONLY_MOUNT_ID_ARGS)

# Promotion is deliberately absent: Make can prepare a candidate but cannot
# create acceptance evidence for itself. The externally installed promoter must
# freeze/sign the candidate before this convenience alias is usable.
verify-consolidated: build-consolidated-test-artifacts
	@printf '%s\n' "Candidate prepared; external privileged promotion is required. This Make target is non-attesting and cannot accept the candidate." >&2
	@exit 2

# These compatibility names intentionally prepare the complete frozen batch.
build-agent-enrollment-wheel: build-consolidated-test-artifacts

build-portal-browser-artifacts: build-consolidated-test-artifacts

_verify-consolidated-source-snapshot-locked:
	$(CONSOLIDATED_FROZEN_VERIFIER_RUN) verify-source-snapshot \
		--snapshot-root "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--manifest "$(CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS)

# This target runs only inside supervise-build-lease-v4. Dependency resolution
# has already produced the frozen dependency bundle. The build watchdog builds
# every image before returning, exports deterministic OCI archives, removes all
# exact build resources, and supplies three absence observations. No behavioral
# lane or compatibility probe is permitted in this phase.
_build-consolidated-test-artifacts-locked:
	@set -eu; \
		test -n "$${SERVERWARE_BUILD_WATCHDOG_LEASE_ID:-}" || { echo "external build-watchdog lease is missing" >&2; exit 2; }; \
		test -n "$${SERVERWARE_BUILD_WATCHDOG_CAPABILITY_FD:-}" || { echo "external build-watchdog capability FD is missing" >&2; exit 2; }
	PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(CONSOLIDATED_BUILD_PYTHON)" -I "$(AGENT_TRUST_SAME_JOURNEY_VERIFIER)" reset-outputs \
		--source-root "$(CURDIR)" \
		--path "$(CONSOLIDATED_OUTPUT_ROOT)"
	PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(CONSOLIDATED_BUILD_PYTHON)" -I "$(AGENT_TRUST_SAME_JOURNEY_VERIFIER)" snapshot-source \
		--source-root "$(CURDIR)" \
		--snapshot-root "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--manifest "$(CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS)
	"$(MAKE)" --no-print-directory _verify-consolidated-source-snapshot-locked
	$(CONSOLIDATED_FROZEN_VERIFIER_RUN) record-oci-build-plan \
		--source-snapshot "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--source-manifest "$(CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS) \
		--dependency-bundle-manifest "$(CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST)" \
		$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_ARGS) \
		--build-watchdog-contract "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		--apparmor-profile "$(CONSOLIDATED_APPARMOR_PROFILE)" \
		--seccomp-profile "$(CONSOLIDATED_SECCOMP_PROFILE)" \
		--out "$(CONSOLIDATED_OCI_BUILD_PLAN)"
	"$(MAKE)" --no-print-directory _verify-consolidated-source-snapshot-locked
	"$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT)" build-all-oci-v4 \
		--socket "$(CONSOLIDATED_BUILD_WATCHDOG_SOCKET)" \
		--expected-client-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CLIENT_SHA256)" \
		--contract "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		--expected-contract-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT_SHA256)" \
		--public-key "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY)" \
		--expected-public-key-spki-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256)" \
		--expected-public-key-raw-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256)" \
		--expected-challenge-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256)" \
		--expected-capability-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256)" \
		--lease-id "$$SERVERWARE_BUILD_WATCHDOG_LEASE_ID" \
		--lease-capability-fd "$$SERVERWARE_BUILD_WATCHDOG_CAPABILITY_FD" \
		--plan "$(CONSOLIDATED_OCI_BUILD_PLAN)" \
		--source-snapshot "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS) \
		--dependency-bundle-root "$(CONSOLIDATED_DEPENDENCY_BUNDLE_ROOT)" \
		--dependency-bundle-manifest "$(CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST)" \
		$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_ARGS) \
		--oci-root "$(CONSOLIDATED_OCI_ROOT)" \
		--bundle-out "$(CONSOLIDATED_OCI_BUILD_BUNDLE)" \
		--receipt-out "$(CONSOLIDATED_BUILD_WATCHDOG_RECEIPT)" \
		--platform linux/amd64 \
		--network none \
		--all-images-before-return \
		--deterministic-oci-archives \
		--no-behavioral-probes
	"$(MAKE)" --no-print-directory _verify-consolidated-source-snapshot-locked
	$(CONSOLIDATED_FROZEN_VERIFIER_RUN) record-candidate-manifest \
		--build-plan "$(CONSOLIDATED_OCI_BUILD_PLAN)" \
		--build-watchdog-receipt "$(CONSOLIDATED_BUILD_WATCHDOG_RECEIPT)" \
		--build-watchdog-public-key "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY)" \
		--expected-build-watchdog-key-spki-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256)" \
		--expected-build-watchdog-key-raw-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256)" \
		--expected-build-watchdog-challenge-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256)" \
		--expected-build-watchdog-capability-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256)" \
		--build-watchdog-contract "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		--source-snapshot "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--source-manifest "$(CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS) \
		--dependency-bundle-manifest "$(CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST)" \
		$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_ARGS) \
		--apparmor-profile "$(CONSOLIDATED_APPARMOR_PROFILE)" \
		--seccomp-profile "$(CONSOLIDATED_SECCOMP_PROFILE)" \
		--oci-bundle-manifest "$(CONSOLIDATED_OCI_BUILD_BUNDLE)" \
		--oci-root "$(CONSOLIDATED_OCI_ROOT)" \
		--candidate-file-out "$(CONSOLIDATED_CANDIDATE_FILE)" \
		--out "$(CONSOLIDATED_TEST_ARTIFACTS_FILE)"
	$(CONSOLIDATED_FROZEN_VERIFIER_RUN) verify-candidate-manifest \
		--manifest "$(CONSOLIDATED_TEST_ARTIFACTS_FILE)" \
		--candidate-file "$(CONSOLIDATED_CANDIDATE_FILE)" \
		--build-plan "$(CONSOLIDATED_OCI_BUILD_PLAN)" \
		--build-watchdog-receipt "$(CONSOLIDATED_BUILD_WATCHDOG_RECEIPT)" \
		--build-watchdog-public-key "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY)" \
		--expected-build-watchdog-key-spki-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_SPKI_SHA256)" \
		--expected-build-watchdog-key-raw-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_PUBLIC_KEY_RAW_SHA256)" \
		--expected-build-watchdog-challenge-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CHALLENGE_SHA256)" \
		--expected-build-watchdog-capability-sha256 "$(CONSOLIDATED_BUILD_WATCHDOG_CAPABILITY_SHA256)" \
		--build-watchdog-contract "$(CONSOLIDATED_BUILD_WATCHDOG_CONTRACT)" \
		--source-snapshot "$(CONSOLIDATED_SOURCE_SNAPSHOT)" \
		--source-manifest "$(CONSOLIDATED_SOURCE_SNAPSHOT_MANIFEST)" \
		--source-input-manifest "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST)" \
		--expected-source-input-manifest-sha256 "$(CONSOLIDATED_SOURCE_INPUT_MANIFEST_SHA256)" \
		$(CONSOLIDATED_SOURCE_EVIDENCE_ARGS) \
		--dependency-bundle-manifest "$(CONSOLIDATED_DEPENDENCY_BUNDLE_MANIFEST)" \
		$(CONSOLIDATED_DEPENDENCY_CAPABILITY_AUTHORITY_ARGS) \
		--apparmor-profile "$(CONSOLIDATED_APPARMOR_PROFILE)" \
		--seccomp-profile "$(CONSOLIDATED_SECCOMP_PROFILE)" \
		--oci-bundle-manifest "$(CONSOLIDATED_OCI_BUILD_BUNDLE)" \
		--oci-root "$(CONSOLIDATED_OCI_ROOT)"
	"$(MAKE)" --no-print-directory _verify-consolidated-source-snapshot-locked
# Clean-room and browser compatibility names enter the same promoted OCI
# sequence. Neither has a host-side preparation or callback implementation.
verify-agent-enrollment-wheel-clean-room: verify-consolidated-no-build

fetch-production-dependency-cache:
	python3 production-dependencies/prefetch.py fetch

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

# This convenience target is outside the production trust boundary. The root
# launcher must supply a manifest measured from the live operation driver and
# atomically install the resulting generation before starting the units.
render-policy-custody-assets:
	@test "$$(id -u)" = 0 || { echo "render-policy-custody-assets must run as the trusted root launcher" >&2; exit 2; }
	@test -n "$(POLICY_CUSTODY_RENDER_MANIFEST)"
	@test -n "$(POLICY_CUSTODY_RENDER_OUTPUT)"
	@test -f "$(POLICY_CUSTODY_RENDER_MANIFEST)" && test ! -L "$(POLICY_CUSTODY_RENDER_MANIFEST)"
	@test ! -e "$(POLICY_CUSTODY_RENDER_OUTPUT)"
	python3 ops/policy-custody/render-assets.py \
		"$(POLICY_CUSTODY_RENDER_MANIFEST)" \
		"$(POLICY_CUSTODY_RENDER_OUTPUT)"

verify-policy-custody-host-ready:
	@test "$$(id -u)" = 0 || { echo "verify-policy-custody-host-ready must run as root on the production Linux host" >&2; exit 2; }
	@set -eu; \
		root="$(POLICY_CUSTODY_SOCKET_ROOT)"; \
		config_root="$(POLICY_CUSTODY_RUNTIME_CONFIG_ROOT)"; \
		test -d "$$root" && test ! -L "$$root"; \
		test "$$(stat -Lc '%U:%G:%a' "$$root")" = "root:$(POLICY_CUSTODY_DRIVER_GROUP):750"; \
		test -d "$$config_root"; \
		if test -L "$$config_root"; then test "$$(stat -c '%U:%G' "$$config_root")" = root:root; fi; \
		resolved_config_root=$$(readlink -f "$$config_root"); \
		test -n "$$resolved_config_root" && test -d "$$resolved_config_root" && test ! -L "$$resolved_config_root"; \
		test "$$(stat -Lc '%U:%G:%a' "$$resolved_config_root")" = root:root:700; \
		for binding in \
			'durable-recovery-store:swpc-store' \
			'cleanup-authorization-consumer:swpc-consume' \
			'recovery-target-provider:swpc-target' \
			'current-signature-authority:swpc-signature' \
			'bounded-cleanup-helper:swpc-cleanup'; do \
			role=$${binding%%:*}; account=$${binding#*:}; \
			service="serverware-policy-custody@$$role.service"; \
			socket="serverware-policy-custody@$$role.socket"; \
			path="$$root/$$role.sock"; \
			config="$$resolved_config_root/serverware-policy-custody-$$role.json"; \
			test -f "$$config" && test ! -L "$$config"; \
			test "$$(stat -Lc '%U:%G:%a' "$$config")" = root:root:400; \
			systemctl is-active --quiet "$$socket"; \
			systemctl is-active --quiet "$$service"; \
			test -S "$$path" && test ! -L "$$path"; \
			test "$$(stat -Lc '%U:%G:%a' "$$path")" = "root:$(POLICY_CUSTODY_DRIVER_GROUP):660"; \
			test "$$(systemctl show --property=User --value "$$service")" = "$$account"; \
			test "$$(systemctl show --property=Group --value "$$service")" = "$$account"; \
			test "$$(systemctl show --property=PrivateNetwork --value "$$service")" = yes; \
			test "$$(systemctl show --property=NoNewPrivileges --value "$$service")" = yes; \
			test "$$(systemctl show --property=ProtectSystem --value "$$service")" = strict; \
			memory_max=$$(systemctl show --property=MemoryMax --value "$$service"); \
			tasks_max=$$(systemctl show --property=TasksMax --value "$$service"); \
			case "$$memory_max" in ''|infinity|*[!0-9]*) exit 2 ;; esac; \
			case "$$tasks_max" in ''|infinity|*[!0-9]*) exit 2 ;; esac; \
			test "$$memory_max" -gt 0 && test "$$tasks_max" -gt 0; \
		done; \
		systemctl is-active --quiet serverware-policy-custody-sockets.target; \
		systemctl is-active --quiet serverware-policy-custody.target

# Run on the production Linux host before Compose is allowed to create the
# decision gate. The key remains root-owned but is group-readable by the
# container's fixed primary GID; no ingress material may be writable.
verify-production-proxy-ingress-materials:
	@test "$$(id -u)" = 0 || { echo "verify-production-proxy-ingress-materials must run as root on the production Linux host" >&2; exit 2; }
	@set -eu; \
		test "$(SERVERWARE_PROXY_INGRESS_MODE)" = mtls; \
		for path in "$(SERVERWARE_PROXY_TLS_CERT_FILE)" "$(SERVERWARE_PROXY_CLIENT_CA_BUNDLE_FILE)"; do \
			test -n "$$path" && test -f "$$path" && test ! -L "$$path"; \
			test "$$(stat -Lc '%u:%g:%a' "$$path")" = 0:0:444; \
		done; \
		key="$(SERVERWARE_PROXY_TLS_KEY_FILE)"; \
		test -n "$$key" && test -f "$$key" && test ! -L "$$key"; \
		test "$$(stat -Lc '%u:%g:%a' "$$key")" = 0:65532:440

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
	@test ! -e "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" || { echo "PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY must not already exist" >&2; exit 2; }
	mkdir -p "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)"
	docker buildx build --network=none --platform "$(PRODUCTION_PLATFORM)" --target production-python-runtime-artifact --output "type=local,dest=$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" -f Dockerfile.production .
	test -x "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/bin/python3"
	test -d "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/lib/python3.11/lib-dynload"
	test -f "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/runtime/python/lib/libpython3.11.so.1.0"
	test -d "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)/vendor"

build-production-launcher: verify-production-dependency-cache
	@test -n "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" && test "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" != / || { echo "PRODUCTION_LAUNCHER_BUILD_DIRECTORY is unsafe" >&2; exit 2; }
	@test ! -e "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" || { echo "PRODUCTION_LAUNCHER_BUILD_DIRECTORY must not already exist" >&2; exit 2; }
	mkdir -p "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)"
	python3 scripts/build_production_images.py --network=none --platform "$(PRODUCTION_PLATFORM)" --target production-launcher-artifact --output "type=local,dest=$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" --dockerfile data-plane/decision-gate-rs/Dockerfile.production
	test -x "$(PRODUCTION_LAUNCHER_BUILD_PATH)"

install-production-launcher:
	@test "$$(id -u)" = 0 || { echo "install-production-launcher must run as root on the production host" >&2; exit 2; }
	@test -x "$(PRODUCTION_LAUNCHER_BUILD_PATH)" || { echo "build-production-launcher must produce $(PRODUCTION_LAUNCHER_BUILD_PATH) first" >&2; exit 2; }
	@set -eu; set -- $$(sha256sum "$(PRODUCTION_LAUNCHER_BUILD_PATH)"); digest="$$1"; expected=$$(python3 -c 'import json,sys; document=json.load(open(sys.argv[1], encoding="utf-8")); matches=[item.get("launcher_binary_digest") for item in document.get("images", []) if item.get("service") == "serverware-decision-gate"]; len(matches) == 1 or sys.exit("production build must contain exactly one decision-gate launcher digest"); print(matches[0])' "$(PRODUCTION_IMAGES_BUILD_FILE)"); test "sha256:$$digest" = "$$expected" || { echo "production launcher artifact does not match the independently reproducible production image" >&2; exit 2; }; destination="/opt/serverware/launchers/sha256-$$digest/serverware-production-launcher"; install -d -o root -g root -m 0755 "$${destination%/*}"; install -o root -g root -m 0500 "$(PRODUCTION_LAUNCHER_BUILD_PATH)" "$$destination"; mkdir -p "$$(dirname "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)")"; printf '%s\n' "$$destination" > "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"; chmod 0600 "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"

# This is a direct frozen-verifier lane. It is intentionally independent of
# run-production-readiness-final, the readiness systemd unit, and all coder-* targets.
_production-final-v1-input-preflight:
	@set -eu; \
		LC_ALL=C; export LC_ALL; \
		fail() { echo "$$1" >&2; exit 2; }; \
		require_normalized_path() { \
			label="$$1"; path="$$2"; \
			test -n "$$path" && test "$${#path}" -le 4096 || fail "$$label is required and must be a bounded absolute path"; \
			case "$$path" in /*) ;; *) fail "$$label must be absolute" ;; esac; \
			case "$$path" in /|*/|*//*|*/./*|*/../*|*/.|*/..) fail "$$label must be normalized and contain no dot components" ;; esac; \
		}; \
		require_file() { \
			label="$$1"; path="$$2"; \
			require_normalized_path "$$label" "$$path"; \
			test -f "$$path" && test ! -L "$$path" || fail "$$label must be a non-symlink regular file"; \
		}; \
		require_sha256() { \
			label="$$1"; value="$$2"; \
			test "$${#value}" -eq 71 && printf '%s' "$$value" | grep -Eq '^sha256:[0-9a-f]{64}$$' || fail "$$label is required and must be sha256:<64 lowercase hex>"; \
		}; \
		require_identifier() { \
			label="$$1"; value="$$2"; \
			test -n "$$value" && test "$${#value}" -le 256 || fail "$$label is required and must use the closed final-v1 identifier grammar"; \
			case "$$value" in [A-Za-z0-9]*) ;; *) fail "$$label must use the closed final-v1 identifier grammar" ;; esac; \
			case "$$value" in *[!A-Za-z0-9_.:@+-]*) fail "$$label must use the closed final-v1 identifier grammar" ;; esac; \
		}; \
		test "$$(id -u)" = 0 || fail "production final-v1 targets must run as root on the production verifier host"; \
		require_normalized_path "PRODUCTION_RELEASE_ROOT" "$(PRODUCTION_RELEASE_ROOT)"; \
		test -d "$(PRODUCTION_RELEASE_ROOT)" && test ! -L "$(PRODUCTION_RELEASE_ROOT)" || fail "PRODUCTION_RELEASE_ROOT must be a non-symlink directory"; \
		require_normalized_path "PRODUCTION_RELEASE_PYTHON" "$(PRODUCTION_RELEASE_PYTHON)"; \
		test -f "$(PRODUCTION_RELEASE_PYTHON)" && test -x "$(PRODUCTION_RELEASE_PYTHON)" && test ! -L "$(PRODUCTION_RELEASE_PYTHON)" || fail "PRODUCTION_RELEASE_PYTHON must be an executable non-symlink file"; \
		for import_root in \
			"$(PRODUCTION_RELEASE_ROOT)/scripts" \
			"$(PRODUCTION_RELEASE_ROOT)" \
			"$(PRODUCTION_RELEASE_PYTHON_STDLIB)" \
			"$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" \
			"$(PRODUCTION_RELEASE_PYTHON_VENDOR)"; do \
			require_normalized_path "production final-v1 Python import root" "$$import_root"; \
			test -d "$$import_root" && test ! -L "$$import_root" || fail "production final-v1 Python import roots must be non-symlink directories"; \
		done; \
		require_file "the frozen release-completion verifier" "$(PRODUCTION_RELEASE_ROOT)/scripts/verify_release_completion.py"; \
		require_file "the frozen public-Nitro verifier" "$(PRODUCTION_RELEASE_ROOT)/scripts/verify_nitro_tee.py"; \
		require_file "the frozen Sigstore JSON helper" "$(PRODUCTION_RELEASE_ROOT)/scripts/sigstore_json.py"; \
		require_file "the frozen exact latency helper" "$(PRODUCTION_RELEASE_ROOT)/scripts/exact_latency.py"; \
		test "$(PRODUCTION_STATE_DIRECTORY)" = "/var/lib/serverware/production-proof" || fail "PRODUCTION_STATE_DIRECTORY must remain the fixed durable final-proof directory /var/lib/serverware/production-proof"; \
		require_file "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE)"; \
		require_file "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS)"; \
		require_file "PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_TRUST_ROOTS_SHA256" "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_TRUST_ROOTS_SHA256)"; \
		require_file "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT)"; \
		require_file "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY)"; \
		require_identifier "PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_PROVIDER" "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_PROVIDER)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_KEY_ID" "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_KEY_ID)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_SPKI_SHA256" "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_SPKI_SHA256)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_GLOBAL_ROLE_REGISTRY_SHA256" "$(PRODUCTION_FINAL_V1_EXPECTED_GLOBAL_ROLE_REGISTRY_SHA256)"; \
		require_file "PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY)"; \
		require_identifier "PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_PROVIDER" "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_PROVIDER)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_KEY_ID" "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_KEY_ID)"; \
		require_sha256 "PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_SPKI_SHA256" "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_SPKI_SHA256)"

prepare-production-final-v1: _production-final-v1-input-preflight
	@set -eu; \
		LC_ALL=C; export LC_ALL; umask 077; \
		fail() { echo "$$1" >&2; exit 2; }; \
		require_output_path() { \
			label="$$1"; path="$$2"; \
			test -n "$$path" && test "$${#path}" -le 4096 || fail "$$label is required and must be a bounded absolute path"; \
			case "$$path" in "$(PRODUCTION_STATE_DIRECTORY)"/*) ;; *) fail "$$label must be below the fixed durable PRODUCTION_STATE_DIRECTORY" ;; esac; \
			case "$$path" in */|*//*|*/./*|*/../*|*/.|*/..) fail "$$label must be normalized and contain no dot components" ;; esac; \
			if test -e "$$path" || test -L "$$path"; then \
				test -f "$$path" && test ! -L "$$path" || fail "$$label must be absent or a regular non-symlink file"; \
			fi; \
		}; \
		reject_collision() { \
			output_label="$$1"; output_path="$$2"; input_label="$$3"; input_path="$$4"; \
			output_canonical="$$(readlink -m -- "$$output_path")" || fail "$$output_label could not be normalized"; \
			input_canonical="$$(readlink -m -- "$$input_path")" || fail "$$input_label could not be normalized"; \
			test "$$output_canonical" != "$$input_canonical" || fail "$$output_label must not collide with $$input_label"; \
			if test -e "$$output_path" && test -e "$$input_path"; then \
				test ! "$$output_path" -ef "$$input_path" || fail "$$output_label must not share file identity with $$input_label"; \
			fi; \
		}; \
		require_output_path "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)"; \
		require_output_path "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY)"; \
		reject_collision "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" "PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY)"; \
		env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(PRODUCTION_RELEASE_PYTHON)" -I -S -B -u -c 'import runpy,sys; roots=sys.argv[1:6]; script=sys.argv[6]; sys.path[:]=roots; sys.path_importer_cache.clear(); sys.argv=sys.argv[6:]; runpy.run_path(script,run_name="__main__")' \
			"$(PRODUCTION_RELEASE_ROOT)/scripts" \
			"$(PRODUCTION_RELEASE_ROOT)" \
			"$(PRODUCTION_RELEASE_PYTHON_STDLIB)" \
			"$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" \
			"$(PRODUCTION_RELEASE_PYTHON_VENDOR)" \
			"$(PRODUCTION_RELEASE_ROOT)/scripts/verify_release_completion.py" \
			--verification-mode final \
			--final-result-phase prepare \
			--public-nitro-evidence-bundle "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE)" \
			--public-nitro-expectations "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS)" \
			--public-nitro-trust-roots "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS)" \
			--expected-public-nitro-trust-roots-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_TRUST_ROOTS_SHA256)" \
			--public-nitro-verification-result "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT)" \
			--public-nitro-verification-result-public-key "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY)" \
			--expected-public-nitro-verification-result-provider "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_PROVIDER)" \
			--expected-public-nitro-verification-result-key-id "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_KEY_ID)" \
			--expected-public-nitro-verification-result-spki-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_SPKI_SHA256)" \
			--expected-final-role-registry-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_GLOBAL_ROLE_REGISTRY_SHA256)" \
			--release-completion-result-public-key "$(PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY)" \
			--expected-release-completion-result-provider "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_PROVIDER)" \
			--expected-release-completion-result-key-id "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_KEY_ID)" \
			--expected-release-completion-result-spki-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_SPKI_SHA256)" \
			--out "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)" >/dev/null

finalize-production-final-v1: _production-final-v1-input-preflight
	@set -eu; \
		LC_ALL=C; export LC_ALL; umask 077; \
		fail() { echo "$$1" >&2; exit 2; }; \
		require_normalized_file() { \
			label="$$1"; path="$$2"; \
			test -n "$$path" && test "$${#path}" -le 4096 || fail "$$label is required and must be a bounded absolute path"; \
			case "$$path" in /*) ;; *) fail "$$label must be absolute" ;; esac; \
			case "$$path" in /|*/|*//*|*/./*|*/../*|*/.|*/..) fail "$$label must be normalized and contain no dot components" ;; esac; \
			test -f "$$path" && test ! -L "$$path" || fail "$$label must be a non-symlink regular file"; \
		}; \
		require_output_path() { \
			label="$$1"; path="$$2"; \
			test -n "$$path" && test "$${#path}" -le 4096 || fail "$$label is required and must be a bounded absolute path"; \
			case "$$path" in "$(PRODUCTION_STATE_DIRECTORY)"/*) ;; *) fail "$$label must be below the fixed durable PRODUCTION_STATE_DIRECTORY" ;; esac; \
			case "$$path" in */|*//*|*/./*|*/../*|*/.|*/..) fail "$$label must be normalized and contain no dot components" ;; esac; \
			if test -e "$$path" || test -L "$$path"; then \
				test -f "$$path" && test ! -L "$$path" || fail "$$label must be absent or a regular non-symlink file"; \
			fi; \
		}; \
		reject_collision() { \
			output_label="$$1"; output_path="$$2"; input_label="$$3"; input_path="$$4"; \
			output_canonical="$$(readlink -m -- "$$output_path")" || fail "$$output_label could not be normalized"; \
			input_canonical="$$(readlink -m -- "$$input_path")" || fail "$$input_label could not be normalized"; \
			test "$$output_canonical" != "$$input_canonical" || fail "$$output_label must not collide with $$input_label"; \
			if test -e "$$output_path" && test -e "$$input_path"; then \
				test ! "$$output_path" -ef "$$input_path" || fail "$$output_label must not share file identity with $$input_label"; \
			fi; \
		}; \
		require_output_path "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)"; \
		require_normalized_file "PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST" "$(PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST)"; \
		require_normalized_file "PRODUCTION_FINAL_V1_SIGNING_RESPONSE" "$(PRODUCTION_FINAL_V1_SIGNING_RESPONSE)"; \
		require_output_path "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT" "$(PRODUCTION_FINAL_V1_SIGNING_REQUEST_OUT)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST" "$(PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_SIGNING_RESPONSE" "$(PRODUCTION_FINAL_V1_SIGNING_RESPONSE)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY)"; \
		reject_collision "PRODUCTION_FINAL_V1_RESULT_OUT" "$(PRODUCTION_FINAL_V1_RESULT_OUT)" "PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY" "$(PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY)"; \
		reject_collision "PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST" "$(PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST)" "PRODUCTION_FINAL_V1_SIGNING_RESPONSE" "$(PRODUCTION_FINAL_V1_SIGNING_RESPONSE)"; \
		env PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "$(PRODUCTION_RELEASE_PYTHON)" -I -S -B -u -c 'import runpy,sys; roots=sys.argv[1:6]; script=sys.argv[6]; sys.path[:]=roots; sys.path_importer_cache.clear(); sys.argv=sys.argv[6:]; runpy.run_path(script,run_name="__main__")' \
			"$(PRODUCTION_RELEASE_ROOT)/scripts" \
			"$(PRODUCTION_RELEASE_ROOT)" \
			"$(PRODUCTION_RELEASE_PYTHON_STDLIB)" \
			"$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" \
			"$(PRODUCTION_RELEASE_PYTHON_VENDOR)" \
			"$(PRODUCTION_RELEASE_ROOT)/scripts/verify_release_completion.py" \
			--verification-mode final \
			--final-result-phase finalize \
			--public-nitro-evidence-bundle "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EVIDENCE_BUNDLE)" \
			--public-nitro-expectations "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_EXPECTATIONS)" \
			--public-nitro-trust-roots "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_TRUST_ROOTS)" \
			--expected-public-nitro-trust-roots-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_TRUST_ROOTS_SHA256)" \
			--public-nitro-verification-result "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT)" \
			--public-nitro-verification-result-public-key "$(PRODUCTION_FINAL_V1_PUBLIC_NITRO_VERIFICATION_RESULT_PUBLIC_KEY)" \
			--expected-public-nitro-verification-result-provider "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_PROVIDER)" \
			--expected-public-nitro-verification-result-key-id "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_KEY_ID)" \
			--expected-public-nitro-verification-result-spki-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_PUBLIC_NITRO_VERIFICATION_RESULT_SPKI_SHA256)" \
			--expected-final-role-registry-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_GLOBAL_ROLE_REGISTRY_SHA256)" \
			--release-completion-result-signing-request "$(PRODUCTION_FINAL_V1_RETAINED_SIGNING_REQUEST)" \
			--release-completion-result-signature "$(PRODUCTION_FINAL_V1_SIGNING_RESPONSE)" \
			--release-completion-result-public-key "$(PRODUCTION_FINAL_V1_RELEASE_COMPLETION_RESULT_PUBLIC_KEY)" \
			--expected-release-completion-result-provider "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_PROVIDER)" \
			--expected-release-completion-result-key-id "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_KEY_ID)" \
			--expected-release-completion-result-spki-sha256 "$(PRODUCTION_FINAL_V1_EXPECTED_RELEASE_COMPLETION_RESULT_SPKI_SHA256)" \
			--out "$(PRODUCTION_FINAL_V1_RESULT_OUT)" >/dev/null

generate-production-launch-manifest:
	@test "$$(id -u)" = 0 || { echo "generate-production-launch-manifest must run as root on the production host" >&2; exit 2; }
	@test -n "$(PRODUCTION_RELEASE_ROOT)" || { echo "PRODUCTION_RELEASE_ROOT is required" >&2; exit 2; }
	@test "$(PRODUCTION_STATE_DIRECTORY)" = /var/lib/serverware/production-proof || { echo "PRODUCTION_STATE_DIRECTORY must be the fixed native launch locator /var/lib/serverware/production-proof" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_SOURCE_TREE_DIGEST)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_SOURCE_TREE_DIGEST must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_DEPLOYMENT_AUDIENCE)" | grep -Eq '^[a-z0-9][a-z0-9._:-]{0,127}$$' || { echo "PRODUCTION_DEPLOYMENT_AUDIENCE is invalid" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_DEPLOYMENT_IDENTITY_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_DEPLOYMENT_IDENTITY_SHA256 must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_RELEASE_SEQUENCE)" | grep -Eq '^[1-9][0-9]*$$' || { echo "PRODUCTION_RELEASE_SEQUENCE must be a positive integer" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_ROLLBACK_EPOCH)" | grep -Eq '^(0|[1-9][0-9]*)$$' || { echo "PRODUCTION_ROLLBACK_EPOCH must be a nonnegative integer" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_KEY_ID)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_KEY_ID is required and must be an independently supplied sha256:<64 lowercase hex> key ID" >&2; exit 2; }
	@test -n "$(PRODUCTION_GLOBAL_ROLE_REGISTRY)" || { echo "PRODUCTION_GLOBAL_ROLE_REGISTRY is required" >&2; exit 2; }
	@case "$(PRODUCTION_GLOBAL_ROLE_REGISTRY)" in /etc/serverware/*) ;; *) echo "PRODUCTION_GLOBAL_ROLE_REGISTRY must be below /etc/serverware" >&2; exit 2 ;; esac
	@test -f "$(PRODUCTION_GLOBAL_ROLE_REGISTRY)" && test ! -L "$(PRODUCTION_GLOBAL_ROLE_REGISTRY)" || { echo "PRODUCTION_GLOBAL_ROLE_REGISTRY must be a non-symlink regular file" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_EXPECTED_GLOBAL_ROLE_REGISTRY_PINS_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_EXPECTED_GLOBAL_ROLE_REGISTRY_PINS_SHA256 is required and must be the independently pinned registry file digest as sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_SIGNING_PUBLIC_KEY_SPKI_BASE64URL)" | grep -Eq '^[A-Za-z0-9_-]+$$' || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_SIGNING_PUBLIC_KEY_SPKI_BASE64URL is required and must be canonical unpadded base64url" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_KEY_ID)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_KEY_ID is required and must be an independently supplied sha256:<64 lowercase hex> key ID" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_IDENTITY_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_IDENTITY_SHA256 is required and must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_ADMINISTRATIVE_DOMAIN_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_ADMINISTRATIVE_DOMAIN_SHA256 is required and must be sha256:<64 lowercase hex>" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_SHA256 is required and must be an independently supplied sha256:<64 lowercase hex> digest" >&2; exit 2; }
	@test -n "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE is required" >&2; exit 2; }
	@case "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" in /*) ;; *) echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE must be absolute" >&2; exit 2 ;; esac
	@test -f "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" && test ! -L "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE must be a non-symlink regular file" >&2; exit 2; }
	@test "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" != "$(PRODUCTION_LAUNCH_MANIFEST)" && test "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" != "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" && test "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" != "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" && test "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" != "$(PRODUCTION_SYSTEMD_UNIT_OUT)" || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE must not overlap a generated output" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_PUBLIC_KEY_SPKI_BASE64URL)" | grep -Eq '^[A-Za-z0-9_-]+$$' || { echo "PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_PUBLIC_KEY_SPKI_BASE64URL is required and must be canonical unpadded base64url" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_KEY_ID)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_KEY_ID is required and must be an independently supplied sha256:<64 lowercase hex> key ID" >&2; exit 2; }
	@test -n "$(PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS)" || { echo "PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS is required" >&2; exit 2; }
	@case "$(PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS)" in /etc/serverware/*) ;; *) echo "PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS must be below /etc/serverware" >&2; exit 2 ;; esac
	@test -f "$(PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS)" && test ! -L "$(PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS)" || { echo "PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS must be a non-symlink regular file" >&2; exit 2; }
	@printf '%s' "$(PRODUCTION_EXPECTED_NONCE_ROLLBACK_ASSURANCE_PINS_SHA256)" | grep -Eq '^sha256:[0-9a-f]{64}$$' || { echo "PRODUCTION_EXPECTED_NONCE_ROLLBACK_ASSURANCE_PINS_SHA256 must be an independently supplied sha256:<64 lowercase hex> digest" >&2; exit 2; }
	@case "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" in /*) ;; *) echo "PRODUCTION_LAUNCH_PIPELINE_METADATA must be absolute" >&2; exit 2 ;; esac
	@case "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" in /*) ;; *) echo "PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE must be absolute" >&2; exit 2 ;; esac
	@test "$(PRODUCTION_SYSTEMD_UNIT_OUT)" = "/etc/systemd/system/$(PRODUCTION_SYSTEMD_UNIT_NAME)" || { echo "PRODUCTION_SYSTEMD_UNIT_OUT must exactly match /etc/systemd/system/PRODUCTION_SYSTEMD_UNIT_NAME" >&2; exit 2; }
	@test "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" != "$(PRODUCTION_LAUNCH_MANIFEST)" && test "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" != "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" && test "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" != "$(PRODUCTION_LAUNCH_MANIFEST)" || { echo "launch manifest, pipeline metadata, and metadata digest outputs must be distinct" >&2; exit 2; }
	@test -x "$(PRODUCTION_RELEASE_PYTHON)" || { echo "production release Python executable is missing or not executable: $(PRODUCTION_RELEASE_PYTHON)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_STDLIB)" || { echo "production release Python stdlib is missing: $(PRODUCTION_RELEASE_PYTHON_STDLIB)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" || { echo "production release Python lib-dynload is missing: $(PRODUCTION_RELEASE_PYTHON_LIB_DYNLOAD)" >&2; exit 2; }
	@test -d "$(PRODUCTION_RELEASE_PYTHON_VENDOR)" || { echo "production release Python vendor root is missing: $(PRODUCTION_RELEASE_PYTHON_VENDOR)" >&2; exit 2; }
	@set -eu; \
		launcher_path=$$(cat "$(PRODUCTION_LAUNCHER_INSTALL_PATH_FILE)"); \
		install -d -o root -g root -m 0700 "$(PRODUCTION_STATE_DIRECTORY)" /run/serverware; \
		if test -e "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" || test -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; then \
			test -f "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" && \
				test ! -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" && \
				test "$$(stat -Lc '%u:%g:%a:%F' "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)")" = "0:0:400:regular file" || { \
				echo "refusing to replace an unsafe launch pipeline metadata digest file" >&2; \
				exit 2; \
			}; \
			rm -f "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; \
		fi; \
		python3 scripts/generate_production_launch_manifest.py \
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
		--expected-launch-authority-key-id "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_KEY_ID)" \
		--global-role-registry "$(PRODUCTION_GLOBAL_ROLE_REGISTRY)" \
		--expected-global-role-registry-pins-sha256 "$(PRODUCTION_EXPECTED_GLOBAL_ROLE_REGISTRY_PINS_SHA256)" \
		--launch-authority-witness-signing-public-key-spki-base64url "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_SIGNING_PUBLIC_KEY_SPKI_BASE64URL)" \
		--expected-launch-authority-witness-key-id "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_KEY_ID)" \
		--launch-authority-witness-identity-sha256 "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_IDENTITY_SHA256)" \
		--launch-authority-witness-administrative-domain-sha256 "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_ADMINISTRATIVE_DOMAIN_SHA256)" \
		--launch-authority-witness-store-assurance-sha256 "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_SHA256)" \
		--launch-authority-witness-store-assurance "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE)" \
		--launch-authority-witness-store-assurance-issuer-public-key-spki-base64url "$(PRODUCTION_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_PUBLIC_KEY_SPKI_BASE64URL)" \
		--expected-launch-authority-witness-store-assurance-issuer-key-id "$(PRODUCTION_EXPECTED_LAUNCH_AUTHORITY_WITNESS_STORE_ASSURANCE_ISSUER_KEY_ID)" \
		--nonce-rollback-assurance-pins "$(PRODUCTION_NONCE_ROLLBACK_ASSURANCE_PINS)" \
		--expected-nonce-rollback-assurance-pins-sha256 "$(PRODUCTION_EXPECTED_NONCE_ROLLBACK_ASSURANCE_PINS_SHA256)" \
		--pipeline-metadata-out "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" \
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
		--print-sha256; \
		test -f "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" && test ! -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)"; \
		test "$$(stat -Lc '%u:%g:%a:%F' "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)")" = "0:0:400:regular file"; \
		test ! -e "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" && test ! -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; \
		metadata_digest_line=$$(sha256sum "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)"); \
		metadata_digest="sha256:$${metadata_digest_line%% *}"; \
		(umask 077 && printf '%s\n' "$$metadata_digest" > "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"); \
		chown root:root "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; \
		chmod 0400 "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; \
		printf 'launch_pipeline_metadata_sha256=%s\n' "$$metadata_digest"
	/usr/bin/systemctl daemon-reload

run-production-readiness-final:
	@test "$$(id -u)" = 0 || { echo "run-production-readiness-final must run as root on the production host" >&2; exit 2; }
	@set -eu; \
		fail() { echo "$$1" >&2; exit 2; }; \
		state_directory="$(PRODUCTION_STATE_DIRECTORY)"; \
		manifest="$(PRODUCTION_LAUNCH_MANIFEST)"; \
		unit="$(PRODUCTION_SYSTEMD_UNIT_NAME)"; \
		receipt="$(PRODUCTION_READINESS_INVOCATION_RECEIPT)"; \
		invocation_lock="$(PRODUCTION_READINESS_INVOCATION_LOCK)"; \
		test "$$state_directory" = "/var/lib/serverware/production-proof" || fail "production readiness state directory is not the fixed trusted locator"; \
		test "$$unit" = "serverware-production-release-proof.service" || fail "production readiness unit name is not the fixed audited service"; \
		for directory in /var /var/lib /var/lib/serverware "$$state_directory"; do \
			test -d "$$directory" && test ! -L "$$directory" || fail "production readiness state path contains a non-directory or symlink: $$directory"; \
		done; \
		test -d "$$state_directory" && test ! -L "$$state_directory" || fail "production readiness state directory must be a non-symlink directory"; \
		test "$$(stat -Lc '%u:%g:%a:%F' "$$state_directory")" = "0:0:700:directory" || fail "production readiness state directory must be root:root mode 0700"; \
		if test ! -e "$$invocation_lock" && test ! -L "$$invocation_lock"; then \
			(umask 077; set -C; : > "$$invocation_lock") 2>/dev/null || true; \
		fi; \
		test -f "$$invocation_lock" && test ! -L "$$invocation_lock" || fail "readiness invocation lock must be a regular non-symlink file"; \
		test "$$(stat -Lc '%u:%g:%a:%h:%F' "$$invocation_lock")" = "0:0:600:1:regular file" || fail "readiness invocation lock identity is unsafe"; \
		invocation_lock_identity=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%F' "$$invocation_lock"); \
		exec 9<> "$$invocation_lock"; \
		flock --exclusive --nonblock 9 || fail "another production readiness invocation owns the execution lock"; \
		test "$$(stat -Lc '%d:%i:%u:%g:%a:%h:%F' "/proc/$$$$/fd/9")" = "$$invocation_lock_identity" || fail "readiness invocation lock descriptor identity changed"; \
		test "$$(stat -Lc '%d:%i:%u:%g:%a:%h:%F' "$$invocation_lock")" = "$$invocation_lock_identity" || fail "readiness invocation lock path identity changed"; \
		test -f "$$manifest" && test ! -L "$$manifest" || fail "production launch manifest must be a regular non-symlink file"; \
		test "$$(stat -Lc '%u:%g:%a:%h:%F' "$$manifest")" = "0:0:400:1:regular file" || fail "production launch manifest identity is unsafe"; \
		manifest_identity_before=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$manifest"); \
		manifest_digest_line=$$(sha256sum "$$manifest"); \
		manifest_sha256="sha256:$${manifest_digest_line%% *}"; \
		manifest_identity_after=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$manifest"); \
		test "$$manifest_identity_before" = "$$manifest_identity_after" || fail "production launch manifest changed while establishing invocation identity"; \
		test -f "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)" && test ! -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)"; \
		test "$$(stat -Lc '%u:%g:%a:%F' "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)")" = "0:0:400:regular file"; \
		test -f "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)" && test ! -L "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"; \
		test "$$(stat -Lc '%u:%g:%a:%F' "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)")" = "0:0:400:regular file"; \
		recorded_metadata_digest=$$(cat "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)"); \
		test -n "$$recorded_metadata_digest" && test -z "$$(sed -n '2p' "$(PRODUCTION_LAUNCH_PIPELINE_METADATA_SHA256_FILE)")"; \
		printf '%s' "$$recorded_metadata_digest" | grep -Eq '^sha256:[0-9a-f]{64}$$'; \
		metadata_digest_line=$$(sha256sum "$(PRODUCTION_LAUNCH_PIPELINE_METADATA)"); \
		test "sha256:$${metadata_digest_line%% *}" = "$$recorded_metadata_digest" || { \
			echo "production launch pipeline metadata changed after manifest generation" >&2; \
			exit 2; \
		}; \
		previous_invocation_id=$$(/usr/bin/systemctl show --property=InvocationID --value "$$unit"); \
		if test -n "$$previous_invocation_id"; then \
			printf '%s\n' "$$previous_invocation_id" | grep -Eq '^[0-9a-f]{32}$$' || fail "systemd returned a malformed previous InvocationID"; \
		fi; \
		/usr/bin/systemctl stop "$$unit"; \
		test "$$(/usr/bin/systemctl show --property=ActiveState --value "$$unit")" = inactive || fail "previous readiness invocation did not become inactive"; \
		for output in $(PRODUCTION_READINESS_EXPECTED_OUTPUTS) "$$receipt"; do \
			case "$$output" in "$$state_directory"/*) ;; *) fail "refusing readiness output outside the fixed state directory: $$output" ;; esac; \
			test "$${output#$$state_directory/}" = "$$(basename "$$output")" || fail "readiness output must be a direct state-directory child: $$output"; \
			if test -e "$$output" || test -L "$$output"; then \
				test -f "$$output" && test ! -L "$$output" || fail "refusing unsafe stale readiness output: $$output"; \
				test "$$(stat -Lc '%u:%g:%h:%F' "$$output")" = "0:0:1:regular file" || fail "refusing stale readiness output with unsafe ownership or links: $$output"; \
				case "$$(stat -Lc '%a' "$$output")" in 400|600) ;; *) fail "refusing stale readiness output with unsafe mode: $$output" ;; esac; \
				/usr/bin/rm -- "$$output"; \
			fi; \
			test ! -e "$$output" && test ! -L "$$output" || fail "stale readiness output survived pre-invocation cleanup: $$output"; \
		done; \
		/usr/bin/systemctl start "$$unit"; \
		condition_result=$$(/usr/bin/systemctl show --property=ConditionResult --value "$$unit"); \
		result=$$(/usr/bin/systemctl show --property=Result --value "$$unit"); \
		exec_main_code=$$(/usr/bin/systemctl show --property=ExecMainCode --value "$$unit"); \
		exec_main_status=$$(/usr/bin/systemctl show --property=ExecMainStatus --value "$$unit"); \
		active_state=$$(/usr/bin/systemctl show --property=ActiveState --value "$$unit"); \
		sub_state=$$(/usr/bin/systemctl show --property=SubState --value "$$unit"); \
		invocation_id=$$(/usr/bin/systemctl show --property=InvocationID --value "$$unit"); \
		exec_start_monotonic=$$(/usr/bin/systemctl show --property=ExecMainStartTimestampMonotonic --value "$$unit"); \
		exec_exit_monotonic=$$(/usr/bin/systemctl show --property=ExecMainExitTimestampMonotonic --value "$$unit"); \
		test "$$condition_result" = yes || fail "systemd did not report ConditionResult=true for the readiness invocation"; \
		test "$$result" = success || fail "systemd readiness invocation Result is not success"; \
		test "$$exec_main_code" = exited || fail "systemd readiness invocation ExecMainCode is not exited"; \
		test "$$exec_main_status" = 0 || fail "systemd readiness invocation ExecMainStatus is not zero"; \
		test "$$active_state" = active || fail "systemd readiness invocation is not retained as active"; \
		test "$$sub_state" = exited || fail "systemd readiness invocation is not retained in exited state"; \
		printf '%s\n' "$$invocation_id" | grep -Eq '^[0-9a-f]{32}$$' || fail "systemd returned a malformed readiness InvocationID"; \
		test "$$invocation_id" != "$$previous_invocation_id" || fail "systemd reused the previous readiness InvocationID"; \
		printf '%s\n' "$$exec_start_monotonic" | grep -Eq '^[1-9][0-9]*$$' || fail "systemd omitted the readiness ExecMain start timestamp"; \
		printf '%s\n' "$$exec_exit_monotonic" | grep -Eq '^[1-9][0-9]*$$' || fail "systemd omitted the readiness ExecMain exit timestamp"; \
		test "$$exec_exit_monotonic" -ge "$$exec_start_monotonic" || fail "systemd readiness execution timestamps are inverted"; \
		completion_proof_identity=; \
		completion_proof_sha256=; \
		for output in $(PRODUCTION_READINESS_EXPECTED_OUTPUTS); do \
			test -f "$$output" && test ! -L "$$output" || fail "readiness invocation omitted expected output: $$output"; \
			test "$$(stat -Lc '%u:%g:%a:%h:%F' "$$output")" = "0:0:600:1:regular file" || fail "readiness invocation produced an unsafe output identity: $$output"; \
			test -s "$$output" || fail "readiness invocation produced an empty output: $$output"; \
			output_identity_before=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$output"); \
			output_digest_line=$$(sha256sum "$$output"); \
			output_sha256="sha256:$${output_digest_line%% *}"; \
			output_identity_after=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$output"); \
			test "$$output_identity_before" = "$$output_identity_after" || fail "readiness output changed while establishing invocation identity: $$output"; \
			if test "$$output" = "$$state_directory/serverware-completion-proof.json"; then \
				completion_proof_identity="$$output_identity_before"; \
				completion_proof_sha256="$$output_sha256"; \
			fi; \
		done; \
		test -n "$$completion_proof_identity" && test -n "$$completion_proof_sha256" || fail "readiness completion proof identity was not established"; \
		receipt_tmp="$${receipt}.tmp.$$$$"; \
		test ! -e "$$receipt_tmp" && test ! -L "$$receipt_tmp" || fail "refusing pre-existing readiness invocation receipt temporary"; \
		trap '/usr/bin/rm -f -- "$${receipt_tmp}"' EXIT HUP INT TERM; \
		umask 077; \
		{ \
			printf 'apiVersion=serverware.productionReadinessInvocationReceipt/v1\n'; \
			printf 'unit=%s\n' "$$unit"; \
			printf 'invocationId=%s\n' "$$invocation_id"; \
			printf 'conditionResult=yes\n'; \
			printf 'result=success\n'; \
			printf 'execMainCode=exited\n'; \
			printf 'execMainStatus=0\n'; \
			printf 'activeState=active\n'; \
			printf 'subState=exited\n'; \
			printf 'execMainStartTimestampMonotonic=%s\n' "$$exec_start_monotonic"; \
			printf 'execMainExitTimestampMonotonic=%s\n' "$$exec_exit_monotonic"; \
			printf 'manifestPath=%s\n' "$$manifest"; \
			printf 'manifestIdentity=%s\n' "$$manifest_identity_before"; \
			printf 'manifestSha256=%s\n' "$$manifest_sha256"; \
			printf 'completionProofPath=%s\n' "$$state_directory/serverware-completion-proof.json"; \
			printf 'completionProofIdentity=%s\n' "$$completion_proof_identity"; \
			printf 'completionProofSha256=%s\n' "$$completion_proof_sha256"; \
			for output in $(PRODUCTION_READINESS_EXPECTED_OUTPUTS); do \
				output_identity_before=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$output"); \
				output_digest_line=$$(sha256sum "$$output"); \
				output_sha256="sha256:$${output_digest_line%% *}"; \
				output_identity_after=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$output"); \
				test "$$output_identity_before" = "$$output_identity_after" || fail "readiness output changed while binding the invocation receipt: $$output"; \
				printf 'output=%s|%s|%s\n' "$$output" "$$output_identity_before" "$$output_sha256"; \
			done; \
		} > "$$receipt_tmp"; \
		chown root:root "$$receipt_tmp"; \
		chmod 0400 "$$receipt_tmp"; \
		/usr/bin/ln -- "$$receipt_tmp" "$$receipt"; \
		/usr/bin/rm -- "$$receipt_tmp"; \
		trap - EXIT HUP INT TERM; \
		test "$$(stat -Lc '%u:%g:%a:%h:%F' "$$receipt")" = "0:0:400:1:regular file" || fail "readiness invocation receipt identity is unsafe"; \
		receipt_identity_before=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$receipt"); \
		receipt_digest_line=$$(sha256sum "$$receipt"); \
		receipt_identity_after=$$(stat -Lc '%d:%i:%u:%g:%a:%h:%s:%Y:%Z:%F' "$$receipt"); \
		test "$$receipt_identity_before" = "$$receipt_identity_after" || fail "readiness invocation receipt changed after publication"; \
		printf 'readiness_invocation_id=%s\nreadiness_invocation_receipt_sha256=sha256:%s\n' "$$invocation_id" "$${receipt_digest_line%% *}"

# Each release stage is an explicit operation in its owner's trust domain.
# There is deliberately no aggregate target that builds, publishes, signs,
# deploys, and then calls its own output production proof. See docs/release-stages.md.
production-source-capture:
	python3 -c 'import json; from scripts.serverware_source_tree import production_source_contract; print(json.dumps(production_source_contract(), sort_keys=True))'

production-release-build:
	@test ! -e "$(PRODUCTION_IMAGES_BUILD_FILE)" || { echo "release build record already exists; use a fresh release workspace" >&2; exit 2; }
	@test ! -e "$(PRODUCTION_PYTHON_RUNTIME_ARTIFACT_DIRECTORY)" || { echo "release Python artifact already exists; use a fresh release workspace" >&2; exit 2; }
	@test ! -e "$(PRODUCTION_LAUNCHER_BUILD_DIRECTORY)" || { echo "release launcher artifact already exists; use a fresh release workspace" >&2; exit 2; }
	$(MAKE) production-source-capture
	$(MAKE) verify-production-dependency-cache
	$(MAKE) validate-production-policy-identity
	$(MAKE) build-production-images
	$(MAKE) build-production-python-runtime
	$(MAKE) build-production-launcher

production-release-publish:
	$(MAKE) publish-production-images
	$(MAKE) merge-production-images-env

production-release-sign:
	$(MAKE) production-release-provenance
	$(MAKE) sign-production-images

production-release-deploy:
	$(MAKE) verify-production-agent-enrollment-evidence
	$(MAKE) production-release-input-preflight
	$(MAKE) prepare-aws-kms-materials
	$(MAKE) deploy-production
	$(MAKE) install-production-launcher
	$(MAKE) generate-production-launch-manifest

# Consumes already produced, independently signed evidence. It never prepares
# a signing request, signs, builds, installs, deploys, or runs the legacy NSM lane.
production-release-proof:
	$(MAKE) finalize-production-final-v1

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
	python3 scripts/test_sigstore_json.py

verify-release-image-signing:
	python3 scripts/test_sign_release_images.py

verify-production-image-publish:
	python3 scripts/test_publish_production_images.py

verify-production-images-env-merge:
	python3 scripts/test_merge_production_images_env.py

verify-production-handoff:
	python3 scripts/test_production_handoff.py

verify-production-release-input-preflight:
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_production_release_input_preflight.py

verify-production-policy-identity:
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_production_policy_identity.py

verify-production-host-preflight:
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_production_host_preflight.py

verify-production-python-runtime:
	python3 scripts/test_build_production_images.py

verify-production-launch-assets: verify-production-python-runtime
	python3 -I scripts/test_production_launch_assets.py
	test -n "$(strip $(PRODUCTION_LAUNCHER_ADVERSARIAL_BUILDER))" || { \
		echo "PRODUCTION_LAUNCHER_ADVERSARIAL_BUILDER must name an explicit pre-created buildx builder" >&2; \
		exit 2; \
	}
	python3 -I scripts/test_production_launcher_adversarial.py \
		--builder "$(PRODUCTION_LAUNCHER_ADVERSARIAL_BUILDER)"
	cargo test --locked --manifest-path data-plane/decision-gate-rs/Cargo.toml --bin serverware-production-launcher

verify-launch-authorization:
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_launch_authorization.py
	$(CRYPTO_PYTHON_RUN) scripts/test_launch_authority_service.py

verify-production-release-proof: verify-production-launch-assets verify-launch-authorization verify-production-image-builds verify-production-release-input-preflight verify-production-host-preflight verify-production-readiness-runner verify-release-completion verify-custody-response-proof verify-onboarding-evidence-tooling verify-agent-enrollment-wheel-clean-room
	python3 scripts/test_production_release_proof_target.py

verify-credential-policy-contracts:
	uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python scripts/test_credential_constraints.py
	$(MITMPROXY_TEST_RUN) python scripts/test_credential_constraints.py --proxy-transport-only
	cargo test --locked --manifest-path data-plane/decision-gate-rs/Cargo.toml

verify-control-plane-startup:
	uv run --no-project --isolated --python 3.11 --with-requirements requirements.lock python scripts/test_control_plane_startup.py

# Standalone browser names route through the same promoted OCI sequence.
verify-portal-browser-oauth-no-build: verify-consolidated-no-build

verify-portal-browser-oauth: verify-consolidated-no-build

# There is no live host callback. The promoted launcher and root watchdog own
# the complete same-journey sequence, including the one-use npm companion.
verify-agent-trust-same-journey: verify-consolidated-no-build

verify-onboarding-evidence-tooling:
	PYTHONDONTWRITEBYTECODE=1 $(TEST_PYTHON_RUN) -m unittest scripts.test_onboarding_evidence -v

verify-custody-response-proof:
	COMPOSE_PROJECT_NAME="$${COMPOSE_PROJECT_NAME:-serverware-custody-$$(date +%s)-$$$$-$$(openssl rand -hex 6)}" ./scripts/test_custody_response_proof.sh

verify-reproducible-builds:
	python3 scripts/test_reproducible_builds.py

verify-policy-activation-evidence:
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_policy_activation_evidence.py

verify-transparency-checkpoint:
	python3 scripts/test_transparency_checkpoint.py
	python3 scripts/test_checkpoint_sequence.py

verify-provider-policy-parity:
	python3 scripts/test_provider_policy_parity.py
	python3 scripts/test_traversal_response_evidence.py

# The prepared external runner owns this disposable Unix-socket test cluster.
# This target neither starts a server nor falls back to a production DSN.
verify-webauthn-trust-projection:
	test -n "$${SERVERWARE_TEST_POSTGRES_DSN:-}"
	python3 scripts/test_webauthn_trust_projection_postgres.py --postgres-dsn "$$SERVERWARE_TEST_POSTGRES_DSN"
	python3 scripts/test_postgres_trigger_manifest.py --postgres-dsn "$$SERVERWARE_TEST_POSTGRES_DSN"

# Component entrypoint only; not prepared native-controller coverage.
# Changed-excluded-test admission must continue to refuse an unprepared lane.
verify-authority-row-mutations:
	test -n "$${SERVERWARE_TEST_POSTGRES_DSN:-}"
	python3 scripts/test_authority_mutation_postgres.py --postgres-dsn "$$SERVERWARE_TEST_POSTGRES_DSN"

# Unexecuted component entrypoint, not approved native-controller coverage.
# All fixture role/schema/database-ACL changes remain in rolled-back transactions.
verify-authority-verifier-read:
	test -n "$${SERVERWARE_TEST_POSTGRES_DSN:-}"
	test "$${SERVERWARE_TEST_POSTGRES_DISPOSABLE:-}" = "1"
	python3 scripts/test_authority_verifier_read_postgres.py --postgres-dsn "$$SERVERWARE_TEST_POSTGRES_DSN" --disposable-cluster

# Catalog-only component fixture; no production DDL or TLS-admission claim.
# The prepared external runner owns the disposable, rolled-back test cluster.
verify-authority-planner-writer:
	test -n "$${SERVERWARE_TEST_POSTGRES_DSN:-}"
	test "$${SERVERWARE_TEST_POSTGRES_DISPOSABLE:-}" = "1"
	python3 scripts/test_authority_planner_writer_postgres.py --postgres-dsn "$$SERVERWARE_TEST_POSTGRES_DSN" --disposable-cluster

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
	$(CRYPTO_SCHEMA_PYTHON_RUN) scripts/test_release_completion.py

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
	curl -fsS -H "X-Serverware-Admin-Token: $${SERVERWARE_ADMIN_TOKEN:-dev-admin-token}" -X POST "http://localhost:$${SERVERWARE_CONTROL_PLANE_HOST_PORT:-3000}/api/demo/seed" >/dev/null
	SERVERWARE_CA_OUT=.tmp/serverware-ca.pem SERVERWARE_VERIFY_OUT=.tmp/attestation-verify.json ./scripts/install_verified_ca.sh
	docker compose up -d --force-recreate decision-gate-rs
	./scripts/wait_for_decision_gate.sh

verify-attestation: install-ca

reset:
	docker compose down -v
	rm -rf .tmp
