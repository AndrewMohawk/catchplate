#!/bin/sh
set -eu
umask 077

usage() {
    cat >&2 <<'EOF'
usage: install_coder_controller_v12.sh \
  SIGNED_BUNDLE_ROOT PINNED_RELEASE_SIGNER_PUBLIC_KEY \
  BUNDLE_MANIFEST_SHA256 RELEASE_ID CLIENT_GROUP DEPLOYMENT_PROFILE \
  EXTERNAL_WITNESS_SOCKET

The bundle envelope must be:
  manifest/signed-bundle.sha256
  manifest/signed-bundle.sha256.sig

Every binary, encrypted credential, public key, signed authorization document,
source publication input, OCI archive, policy, fixture, template, hook, script,
and systemd unit consumed by provisioning must be an exact member of that
manifest. The release manifest is signed outside this host. This installer does
not generate or trust a local activation key.

DEPLOYMENT_PROFILE is either local-trusted-host or external-production.
local-trusted-host is UserspaceDigestOnly with optional, unclaimed fs-verity
adapters. external-production is deliberately fail-closed until external
trust-generation, final-settlement, witness/checkpoint, verified-boot, and
hardware-backed key/approval adapters are implemented and provisioned. This
installer never generates HSM, TPM, TEE, or YubiKey evidence.

The installer first copies the candidate bundle into a root-owned immutable
snapshot, verifies it with the independently pinned signer, and re-executes the
manifest-bound installer from that snapshot. An independently installed
bootstrap verifier must authenticate this script before its first invocation.
EOF
    exit 2
}

fail() {
    echo "$*" >&2
    exit 2
}

require_sha256() {
    value=$1
    label=$2
    case "$value" in ""|*[!0-9a-f]*) fail "$label must be lowercase hexadecimal" ;; esac
    test "${#value}" -eq 64 || fail "$label must contain exactly 64 characters"
}

validate_release_id() {
    value=$1
    case "$value" in
        ""|.*|*[!A-Za-z0-9._-]*|*..*) fail "release ID is not path-safe" ;;
    esac
    test "${#value}" -le 96 || fail "release ID is too long"
}

validate_group_name() {
    value=$1
    case "$value" in ""|*[!A-Za-z0-9_-]*) fail "invalid group name: $value" ;; esac
}

validate_deployment_profile() {
    value=$1
    case "$value" in
        local-trusted-host) ;;
        external-production)
            fail "external-production is unavailable: external trust-generation, final-settlement, witness/checkpoint, verified-boot, HSM/TPM/TEE/YubiKey, and stronger publication-integrity adapters are prerequisite-only"
            ;;
        *) fail "unsupported controller-v12 deployment profile: $value" ;;
    esac
}

validate_absolute_socket() {
    value=$1
    case "$value" in /*) ;; *) fail "socket path must be absolute: $value" ;; esac
    case "$value" in *"/../"*|*"/./"*|*"//"*) fail "unsafe socket path: $value" ;; esac
    printf '%s' "$value" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null \
        && fail "socket path contains a control character"
    test -S "$value" && test ! -L "$value" \
        || fail "required socket is absent or is a symlink: $value"
}

require_absolute_root_file() {
    candidate=$1
    case "$candidate" in /*) ;; *) fail "path must be absolute: $candidate" ;; esac
    test -f "$candidate" && test ! -L "$candidate" \
        || fail "required regular non-symlink file is missing: $candidate"
    test "$(stat -c '%u:%h:%F' "$candidate")" = "0:1:regular file" \
        || fail "required input must be root-owned and single-link: $candidate"
    mode=$(stat -c '%a' "$candidate")
    test "$((0$mode & 022))" -eq 0 \
        || fail "required input must not be group/world writable: $candidate"
}

manifest_path_is_safe() {
    relative=$1
    case "$relative" in
        ""|/*|*"/../"*|../*|*/..|..|*"/./"*|./*|*"//"*|*" "*|*"	"*)
            return 1
            ;;
    esac
    printf '%s' "$relative" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null && return 1
    return 0
}

require_no_symlink_components() {
    root=$1
    relative=$2
    cursor=$root
    old_ifs=$IFS
    IFS=/
    set -- $relative
    IFS=$old_ifs
    for component
    do
        cursor=$cursor/$component
        test ! -L "$cursor" || fail "bundle path component is a symlink: $relative"
    done
}

verify_manifest_envelope() {
    root=$1
    signer=$2
    expected_digest=$3
    manifest=$root/manifest/signed-bundle.sha256
    signature=$root/manifest/signed-bundle.sha256.sig
    test -f "$manifest" && test ! -L "$manifest" \
        || fail "bundle manifest is absent or a symlink"
    test -f "$signature" && test ! -L "$signature" \
        || fail "bundle signature is absent or a symlink"
    test "$(sha256sum "$manifest" | awk '{print $1}')" = "$expected_digest" \
        || fail "bundle manifest digest mismatch"
    openssl pkeyutl -verify -pubin -inkey "$signer" \
        -rawin -in "$manifest" -sigfile "$signature" >/dev/null \
        || fail "bundle manifest signature verification failed"
    LC_ALL=C grep '[[:cntrl:]]' "$manifest" >/dev/null \
        && fail "bundle manifest contains control characters"
    duplicates=$(awk '{print $2}' "$manifest" | LC_ALL=C sort | uniq -d)
    test -z "$duplicates" || fail "bundle manifest contains duplicate paths"
    while IFS= read -r manifest_line || test -n "$manifest_line"
    do
        test -n "$manifest_line" || fail "bundle manifest contains an empty line"
        digest=${manifest_line%%  *}
        relative=${manifest_line#*  }
        test "$relative" != "$manifest_line" || fail "malformed bundle manifest line"
        require_sha256 "$digest" "bundle member digest"
        manifest_path_is_safe "$relative" \
            || fail "unsafe bundle manifest path: $relative"
        require_no_symlink_components "$root" "$relative"
        candidate=$root/$relative
        test -f "$candidate" && test ! -L "$candidate" \
            || fail "signed bundle member is absent or not regular: $relative"
        test "$(sha256sum "$candidate" | awk '{print $1}')" = "$digest" \
            || fail "bundle member digest mismatch: $relative"
    done < "$manifest"
}

test "$#" -eq 7 || usage
test "$(id -u)" -eq 0 || fail "controller-v12 installer must run as root"

input_bundle_root=$1
input_pinned_signer=$2
bundle_manifest_sha256=$3
release_id=$4
client_group=$5
deployment_profile=$6
external_witness_socket=$7

require_sha256 "$bundle_manifest_sha256" "bundle manifest digest"
validate_release_id "$release_id"
validate_group_name "$client_group"
validate_deployment_profile "$deployment_profile"
validate_absolute_socket "$external_witness_socket"
getent group "$client_group" >/dev/null \
    || fail "client group does not exist: $client_group"

install_root=/opt/serverware/coder-controller-v12
releases_root=$install_root/releases
current_link=$install_root/current
state_root=/var/lib/serverware/coder-controller-v12
staging_parent=$state_root/install-staging
trust_root=/etc/serverware/coder-controller-v12/trust
systemd_root=/etc/systemd/system
target_unit=serverware-coder-v12.target

for protected_path in \
    /opt/serverware "$install_root" "$releases_root" \
    /var/lib/serverware "$state_root" "$staging_parent" \
    /etc/serverware /etc/serverware/coder-controller-v12 "$trust_root" "$systemd_root"
do
    test ! -L "$protected_path" || fail "protected path is a symlink: $protected_path"
done

install -d -o root -g root -m 0755 /run/lock
exec 9>/run/lock/serverware-coder-controller-v12.install.lock
flock --exclusive --nonblock 9 \
    || fail "another controller-v12 install or rollback transaction is active"
chmod 0600 /run/lock/serverware-coder-controller-v12.install.lock

install -d -o root -g root -m 0755 /var/lib/serverware
install -d -o root -g root -m 0711 "$state_root"
install -d -o root -g root -m 0700 "$staging_parent"
install -d -o root -g root -m 0755 \
    /opt/serverware "$install_root" "$releases_root" \
    /etc/serverware /etc/serverware/coder-controller-v12 "$trust_root"

if test "${SERVERWARE_V12_VERIFIED_SNAPSHOT:-0}" != 1; then
    test -d "$input_bundle_root" && test ! -L "$input_bundle_root" \
        || fail "signed bundle root must be a non-symlink directory"
    input_bundle_root=$(CDPATH= cd -- "$input_bundle_root" && pwd -P)
    require_absolute_root_file "$input_pinned_signer"

    bootstrap_transaction=$(mktemp -d "$staging_parent/bootstrap.$release_id.XXXXXX")
    chmod 0700 "$bootstrap_transaction"
    bootstrap_cleanup() {
        chattr -R -i "$bootstrap_transaction" >/dev/null 2>&1 || true
        rm -rf -- "$bootstrap_transaction"
    }
    trap bootstrap_cleanup EXIT HUP INT TERM

    bundle_snapshot=$bootstrap_transaction/bundle
    pinned_signer_snapshot=$bootstrap_transaction/pinned-release-signer.pem
    install -d -o root -g root -m 0700 "$bundle_snapshot"
    cp -a --no-dereference "$input_bundle_root/." "$bundle_snapshot/"
    chown -hR root:root "$bundle_snapshot"
    chmod -R go-w "$bundle_snapshot"
    install -o root -g root -m 0444 "$input_pinned_signer" "$pinned_signer_snapshot"
    verify_manifest_envelope \
        "$bundle_snapshot" "$pinned_signer_snapshot" "$bundle_manifest_sha256"

    signed_installer_relative=provisioning/scripts/install_coder_controller_v12.sh
    signed_installer=$bundle_snapshot/$signed_installer_relative
    signed_installer_digest=$(sha256sum "$signed_installer" | awk '{print $1}')
    grep -Fx "$signed_installer_digest  $signed_installer_relative" \
        "$bundle_snapshot/manifest/signed-bundle.sha256" >/dev/null \
        || fail "bundle does not bind its provisioning installer"
    test -f "$signed_installer" && test ! -L "$signed_installer" \
        || fail "signed provisioning installer is absent"

    chmod -R a-w "$bundle_snapshot"
    chattr -R +i "$bundle_snapshot" \
        || fail "bundle snapshot filesystem does not support immutable release staging"
    export SERVERWARE_V12_VERIFIED_SNAPSHOT=1
    export SERVERWARE_V12_BUNDLE_SNAPSHOT=$bundle_snapshot
    export SERVERWARE_V12_PINNED_SIGNER_SNAPSHOT=$pinned_signer_snapshot
    export SERVERWARE_V12_BOOTSTRAP_TRANSACTION=$bootstrap_transaction
    trap - EXIT HUP INT TERM
    exec /bin/sh "$signed_installer" \
        "$input_bundle_root" "$input_pinned_signer" \
        "$bundle_manifest_sha256" "$release_id" \
        "$client_group" "$deployment_profile" "$external_witness_socket"
fi

asset_root=${SERVERWARE_V12_BUNDLE_SNAPSHOT:-}
pinned_signer=${SERVERWARE_V12_PINNED_SIGNER_SNAPSHOT:-}
transaction_root=${SERVERWARE_V12_BOOTSTRAP_TRANSACTION:-}
case "$asset_root" in "$staging_parent"/*/bundle) ;; *) fail "invalid verified bundle snapshot" ;; esac
case "$pinned_signer" in "$staging_parent"/*/pinned-release-signer.pem) ;; *) fail "invalid signer snapshot" ;; esac
case "$transaction_root" in "$staging_parent"/*) ;; *) fail "invalid bootstrap transaction" ;; esac
test -d "$asset_root" && test ! -L "$asset_root" \
    || fail "verified bundle snapshot is unavailable"
require_absolute_root_file "$pinned_signer"
verify_manifest_envelope "$asset_root" "$pinned_signer" "$bundle_manifest_sha256"

self_path=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")
test "$self_path" = "$asset_root/provisioning/scripts/install_coder_controller_v12.sh" \
    || fail "provisioning must continue from the signed installer snapshot"

cleanup_transaction() {
    chattr -R -i "$transaction_root" >/dev/null 2>&1 || true
    rm -rf -- "$transaction_root"
}
trap cleanup_transaction EXIT HUP INT TERM

bundle_manifest=$asset_root/manifest/signed-bundle.sha256
bundle_signature=$asset_root/manifest/signed-bundle.sha256.sig

require_asset() {
    relative=$1
    manifest_path_is_safe "$relative" || fail "unsafe required asset path: $relative"
    require_no_symlink_components "$asset_root" "$relative"
    candidate=$asset_root/$relative
    test -f "$candidate" && test ! -L "$candidate" \
        || fail "required bundle asset is missing: $relative"
    digest=$(sha256sum "$candidate" | awk '{print $1}')
    grep -Fx "$digest  $relative" "$bundle_manifest" >/dev/null \
        || fail "signed bundle manifest lacks exact asset binding: $relative"
}

units="
serverware-coder-runtime-v12.service
serverware-coder-controller-v12.socket
serverware-coder-plan-executor-v12.socket
serverware-coder-docker-proxy-v12.socket
serverware-coder-lifecycle-v12.socket
serverware-coder-trust-generation-v12.socket
serverware-coder-external-witness-v12.socket
serverware-coder-final-settlement-v12.socket
serverware-coder-receipt-authority-v12.socket
serverware-coder-final-verdict-authority-v12.socket
serverware-coder-lifecycle-privileged-v12.socket
serverware-coder-log-custody-authority-v12.socket
serverware-coder-private-dind-reconcile-v12.service
serverware-coder-lifecycle-privileged-v12.service
serverware-coder-lifecycle-v12.service
serverware-coder-trust-generation-v12.service
serverware-coder-external-witness-v12.service
serverware-coder-final-settlement-v12.service
serverware-coder-log-custody-authority-v12.service
serverware-coder-receipt-authority-v12.service
serverware-coder-final-verdict-authority-v12.service
serverware-coder-docker-proxy-v12.service
serverware-coder-plan-executor-v12.service
serverware-coder-controller-v12.service
serverware-coder-readiness-v12.service
serverware-coder-v12.target
"

provisioning_config_inputs="
controller-v12.conf.in
chromium-probe.fixture.in
config-generation-v12.manifest.in
docker-artifact-binding-v12.manifest.in
docker-lane-policy-v12.conf.in
docker-proxy-v12.conf.in
external-production-v12.profile
external-witness-checkpoint-v12.manifest.in
final-verdict-authority-v12.conf.in
five-lane-v12.manifest.in
key-authorization-v12.manifest.in
lane-deadlines-v12.manifest.in
lifecycle-v12.conf.in
lifecycle-privileged-v12.conf.in
local-external-witness-v12.json.in
local-final-settlement-v12.json.in
local-trust-generation-v12.json.in
log-authority-key-authorization-v12.json.in
log-custody-authority-v12.conf.in
log-custody-genesis-v12.manifest.in
native-snapshot-publication-v12.manifest.in
network-contract-v12.manifest.in
plan-executor-v12.conf.in
readiness-fixtures-v12.manifest.in
receipt-authority-v12.conf.in
receipt-authentication-key-authorization-v12.json.in
release-manifest-v12.in
revocation-checkpoint-v12.manifest.in
rollback-authorization-v12.manifest.in
source-ingress-v12.manifest.in
teardown.fixture.in
trusted-host-v12.profile
"

required_assets="
bin/serverware-coder-controller-v12
bin/serverware-coder-controller-client-v12
bin/serverware-coder-plan-executor-v12
bin/serverware-coder-docker-proxy-v12
bin/serverware-coder-receipt-authority-v12
bin/serverware-coder-local-trust-authority-v12
bin/serverware-coder-log-custody-authority-v12
bin/serverware-coder-final-verdict-authority-v12
bin/serverware-coder-lifecycle-v12
bin/serverware-coder-lifecycle-privileged-v12
bin/dockerd-v12
bin/containerd-v12
bin/containerd-shim-runc-v2-v12
bin/runc-v12
schemas/coder-test-controller-request.v1.schema.json
schemas/coder-test-controller-receipt.v12.schema.json
schemas/coder-docker-api-request.v12.schema.json
schemas/coder-docker-lane-capability.v12.schema.json
schemas/coder-docker-network-membership.v12.schema.json
schemas/coder-docker-service-instance.v12.schema.json
schemas/coder-docker-runner-execution.v12.schema.json
runner/runner.oci.tar
runner/runner.oci.digest
runner/browser.oci.tar
runner/browser.oci.digest
runner/buildkit.oci.tar
runner/buildkit.oci.digest
policy/pinned-pulls.v12.json
policy/exact-build-tuples.v12.json
policy/docker-api-rules.v12.json
policy/docker-artifact-binding-v12.manifest
policy/docker-artifact-binding-v12.manifest.sig
policy/lane-deadlines-v12.manifest
policy/lane-deadlines-v12.manifest.sig
network/host.nft
network/host-cleanup.nft
network/build-lane.nft
network/no-build-lane.nft
network/lane-cleanup.nft
network/network-contract-v12.manifest
network/network-contract-v12.manifest.sig
fixtures/readiness-fixtures-v12.manifest
fixtures/readiness-fixtures-v12.manifest.sig
fixtures/docker-101.fixture
fixtures/docker-half-close.fixture
fixtures/build-pinned-pull.fixture
fixtures/build-unpinned-egress-denied.fixture
fixtures/no-build-egress-denied.fixture
fixtures/service-health.fixture
fixtures/chromium-page.html
fixtures/chromium-script.js
fixtures/chromium-probe.fixture
fixtures/chromium-expected-cdp.json
fixtures/chromium-expected-dom.txt
fixtures/chromium-expected-js.txt
fixtures/chromium-expected-fetch.txt
fixtures/teardown.fixture
trust/requester-public-key.ed25519
trust/external-witness-public-key.ed25519
trust/external-witness-verification-key.pem
trust/readiness-fixture-public-key.pem
trust/release-bundle-signer-public-key.pem
trust/configuration-authority-public-key.pem
trust/source-ingress-authority-public-key.pem
trust/controller-identity-public-key.pem
trust/plan-executor-capability-public-key.pem
trust/docker-proxy-identity-public-key.pem
trust/receipt-authority-public-key.pem
trust/log-custody-authority-public-key.pem
trust/final-verdict-authority-public-key.pem
trust/final-settlement-public-key.pem
trust/lifecycle-authority-public-key.pem
trust/lifecycle-privileged-authority-public-key.pem
credentials/controller-identity-key.cred
credentials/plan-executor-capability-key.cred
credentials/docker-proxy-identity-key.cred
credentials/receipt-authority-key.cred
credentials/external-witness-key.cred
credentials/final-settlement-key.cred
credentials/log-custody-authority-key.cred
credentials/final-verdict-authority-key.cred
credentials/lifecycle-authority-key.cred
credentials/lifecycle-privileged-authority-key.cred
config/receipt-authority-v12.conf
config/final-verdict-authority-v12.conf
config/plan-executor-v12.conf
config/executor-invocation-inputs-v12.json
config/local-trust-generation-v12.json
config/local-external-witness-v12.json
config/local-final-settlement-v12.json
authorization/config-generation-v12.manifest
authorization/config-generation-v12.manifest.sig
authorization/key-authorization-v12.manifest
authorization/key-authorization-v12.manifest.sig
authorization/revocation-checkpoint-v12.manifest
authorization/revocation-checkpoint-v12.manifest.sig
authorization/rollback-authorization-v12.manifest
authorization/rollback-authorization-v12.manifest.sig
authorization/external-witness-checkpoint-v12.manifest
authorization/external-witness-checkpoint-v12.manifest.sig
authorization/log-custody-genesis-v12.manifest
authorization/log-custody-genesis-v12.manifest.sig
authorization/log-authority-key-authorization-v12.json
authorization/receipt-authentication-key-authorization-v12.json
authorization/trust-generation-bundle-v12.json
authorization/external-witness-key-authorization-v12.json
authorization/final-settlement-key-authorization-v12.json
authorization/final-settlement-genesis-v12.json
source/source-ingress-v12.manifest
source/source-ingress-v12.manifest.sig
source/canonical-source.bundle
source/canonical-source.bundle.sha256
source/native-point-snapshot.tar
source/native-point-snapshot.sha256
source/native-snapshot-publication-v12.manifest
source/native-snapshot-publication-v12.manifest.sig
release/installed-release-v12.manifest
release/installed-release-v12.manifest.sig
provisioning/scripts/install_coder_controller_v12.sh
provisioning/scripts/rollback_coder_controller_v12.sh
provisioning/ops/coder-controller-v12/prepare-readiness-release-assets-v12.sh
provisioning/ops/coder-controller-v12/offline-state-quarantine-v12.sh
provisioning/ops/coder-controller-v12/hooks/network-lifecycle-v12.sh
provisioning/ops/coder-controller-v12/hooks/dind-lifecycle-v12.sh
provisioning/ops/coder-controller-v12/hooks/runtime-directories-v12.sh
"

for input in $provisioning_config_inputs
do
    required_assets="$required_assets
provisioning/ops/coder-controller-v12/$input"
done
for unit in $units
do
    required_assets="$required_assets
provisioning/ops/systemd/$unit"
done
for relative in $required_assets
do
    require_asset "$relative"
done

test "$(sha256sum "$asset_root/trust/release-bundle-signer-public-key.pem" | awk '{print $1}')" = \
    "$(sha256sum "$pinned_signer" | awk '{print $1}')" \
    || fail "bundle signer does not match the independently pinned signer"
test "$(wc -c < "$asset_root/trust/requester-public-key.ed25519")" -eq 32 \
    || fail "requester public key must be a raw 32-byte Ed25519 key"
test "$(wc -c < "$asset_root/trust/external-witness-public-key.ed25519")" -eq 32 \
    || fail "external witness public key must be a raw 32-byte Ed25519 key"

verify_signed_document() {
    document=$1
    signature=$2
    public_key=$3
    openssl pkeyutl -verify -pubin -inkey "$public_key" \
        -rawin -in "$document" -sigfile "$signature" >/dev/null \
        || fail "signed document verification failed: $document"
}

config_authority=$asset_root/trust/configuration-authority-public-key.pem
source_authority=$asset_root/trust/source-ingress-authority-public-key.pem
witness_verification_key=$asset_root/trust/external-witness-verification-key.pem
readiness_authority=$asset_root/trust/readiness-fixture-public-key.pem

config_generation_doc=$asset_root/authorization/config-generation-v12.manifest
key_authorization_doc=$asset_root/authorization/key-authorization-v12.manifest
revocation_doc=$asset_root/authorization/revocation-checkpoint-v12.manifest
rollback_authorization_doc=$asset_root/authorization/rollback-authorization-v12.manifest
witness_checkpoint_doc=$asset_root/authorization/external-witness-checkpoint-v12.manifest
log_genesis_doc=$asset_root/authorization/log-custody-genesis-v12.manifest
log_authority_key_authorization_doc=$asset_root/authorization/log-authority-key-authorization-v12.json
receipt_authentication_key_authorization_doc=$asset_root/authorization/receipt-authentication-key-authorization-v12.json
deadline_doc=$asset_root/policy/lane-deadlines-v12.manifest
docker_artifact_binding_doc=$asset_root/policy/docker-artifact-binding-v12.manifest
source_ingress_doc=$asset_root/source/source-ingress-v12.manifest
native_publication_doc=$asset_root/source/native-snapshot-publication-v12.manifest
network_contract_doc=$asset_root/network/network-contract-v12.manifest
expected_release_manifest=$asset_root/release/installed-release-v12.manifest

verify_signed_document "$config_generation_doc" "$config_generation_doc.sig" "$config_authority"
verify_signed_document "$key_authorization_doc" "$key_authorization_doc.sig" "$config_authority"
verify_signed_document "$revocation_doc" "$revocation_doc.sig" "$config_authority"
verify_signed_document \
    "$rollback_authorization_doc" "$rollback_authorization_doc.sig" "$config_authority"
verify_signed_document "$deadline_doc" "$deadline_doc.sig" "$config_authority"
verify_signed_document \
    "$docker_artifact_binding_doc" "$docker_artifact_binding_doc.sig" "$config_authority"
verify_signed_document "$log_genesis_doc" "$log_genesis_doc.sig" "$config_authority"
verify_signed_document "$network_contract_doc" "$network_contract_doc.sig" "$config_authority"
verify_signed_document "$source_ingress_doc" "$source_ingress_doc.sig" "$source_authority"
verify_signed_document "$native_publication_doc" "$native_publication_doc.sig" "$source_authority"
verify_signed_document \
    "$witness_checkpoint_doc" "$witness_checkpoint_doc.sig" "$witness_verification_key"
verify_signed_document \
    "$asset_root/fixtures/readiness-fixtures-v12.manifest" \
    "$asset_root/fixtures/readiness-fixtures-v12.manifest.sig" \
    "$readiness_authority"
verify_signed_document \
    "$expected_release_manifest" \
    "$asset_root/release/installed-release-v12.manifest.sig" \
    "$pinned_signer"

document_value() {
    document=$1
    key=$2
    values=$(awk -F= -v wanted="$key" \
        '$1 == wanted { print substr($0, index($0, "=") + 1) }' "$document")
    test -n "$values" && test -z "$(printf '%s\n' "$values" | sed -n '2p')" \
        || fail "document must contain exactly one nonempty $key: $document"
    printf '%s' "$values" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null \
        && fail "document value contains a control character: $key"
    printf '%s\n' "$values"
}

require_document_version() {
    document=$1
    test "$(document_value "$document" document_version)" = 12 \
        || fail "unsupported signed document version: $document"
}

require_unsigned_integer() {
    value=$1
    label=$2
    case "$value" in ""|*[!0-9]*) fail "$label must be an unsigned integer" ;; esac
}

require_bounded_integer() {
    value=$1
    lower=$2
    upper=$3
    label=$4
    require_unsigned_integer "$value" "$label"
    test "$value" -ge "$lower" && test "$value" -le "$upper" \
        || fail "$label is outside its permitted bounds"
}

sha_file() {
    sha256sum "$1" | awk '{print $1}'
}

require_document_digest() {
    document=$1
    key=$2
    file=$3
    expected=$(document_value "$document" "$key")
    require_sha256 "$expected" "$key"
    test "$(sha_file "$file")" = "$expected" \
        || fail "$key does not bind the required file"
}

config_generation=$(document_value "$config_generation_doc" config_generation)
config_release_id=$(document_value "$config_generation_doc" release_id)
predecessor_release_id=$(document_value "$config_generation_doc" predecessor_release_id)
predecessor_config_generation=$(document_value "$config_generation_doc" predecessor_config_generation)
valid_from_epoch=$(document_value "$config_generation_doc" valid_from_epoch)
valid_until_epoch=$(document_value "$config_generation_doc" valid_until_epoch)
rollback_floor_generation=$(document_value "$config_generation_doc" rollback_floor_generation)
signed_client_group=$(document_value "$config_generation_doc" client_group)
signed_client_gid=$(document_value "$config_generation_doc" client_gid)
signed_deployment_profile=$(document_value "$config_generation_doc" deployment_profile)
signed_witness_socket=$(document_value "$config_generation_doc" external_witness_socket)
signed_executor_uid=$(document_value "$config_generation_doc" identity.executor.uid)

for signed_document in \
    "$config_generation_doc" "$key_authorization_doc" "$revocation_doc" \
    "$rollback_authorization_doc" "$witness_checkpoint_doc" "$deadline_doc" \
    "$docker_artifact_binding_doc" "$log_genesis_doc" \
    "$source_ingress_doc" "$native_publication_doc" "$network_contract_doc"
do
    require_document_version "$signed_document"
done

require_bounded_integer "$config_generation" 1 9223372036854775807 "config generation"
require_unsigned_integer "$predecessor_config_generation" "predecessor generation"
require_unsigned_integer "$valid_from_epoch" "valid-from time"
require_unsigned_integer "$valid_until_epoch" "valid-until time"
require_unsigned_integer "$rollback_floor_generation" "rollback floor"
test "$config_release_id" = "$release_id" || fail "configuration release ID mismatch"
test "$signed_client_group" = "$client_group" || fail "signed client group mismatch"
test "$signed_deployment_profile" = "$deployment_profile" \
    || fail "signed deployment profile mismatch"
client_gid=$(getent group "$client_group" | awk -F: '{print $3}')
test "$signed_client_gid" = "$client_gid" || fail "signed client GID mismatch"
test "$signed_witness_socket" = "$external_witness_socket" \
    || fail "signed external witness socket mismatch"
require_bounded_integer "$signed_executor_uid" 100 59999 "signed executor UID"
test "$(document_value "$config_generation_doc" private_dind.executor_uid)" = \
    "$signed_executor_uid" || fail "private DinD executor UID is not generation-bound"
test "$(document_value "$config_generation_doc" private_dind.admin_create_operation)" = \
    admin-create-private-dind-v12 || fail "signed private DinD create operation mismatch"
test "$(document_value "$config_generation_doc" private_dind.admin_destroy_operation)" = \
    admin-destroy-private-dind-v12 || fail "signed private DinD destroy operation mismatch"
test "$(document_value "$config_generation_doc" private_dind.admin_reconcile_operation)" = \
    admin-reconcile-private-dind-v12 || fail "signed private DinD reconcile operation mismatch"
for private_dind_flag in \
    private_dind.global_docker_daemon private_dind.host_docker_socket \
    private_dind.legacy_v11_lease
do
    test "$(document_value "$config_generation_doc" "$private_dind_flag")" = false \
        || fail "signed generation enables forbidden private DinD fallback: $private_dind_flag"
done
test "$(document_value "$config_generation_doc" private_dind.startup_destroy_nonterminal)" = true \
    || fail "signed generation does not require startup destruction"
test "$(document_value "$config_generation_doc" private_dind.signed_terminal_destruction_receipt)" = true \
    || fail "signed generation does not require terminal destruction receipts"
test "$(document_value "$config_generation_doc" private_dind.readiness_before_repository_work_every_invocation)" = true \
    || fail "signed generation does not require readiness before every repository invocation"
test "$(document_value "$config_generation_doc" private_dind.readiness_probe_order)" = \
    docker-upgrade,service-health,chromium,teardown \
    || fail "signed generation readiness probe order is incomplete"
test "$(document_value "$config_generation_doc" private_dind.docker_top_level_object_count_scope)" = \
    private-daemon-top-level-api:containers,images,nondefault-networks,volumes \
    || fail "signed generation overstates Docker object count scope"
test "$(document_value "$config_generation_doc" private_dind.docker_internal_storage_absence_proof)" = \
    'generation-state-root-absent;internal-layers-snapshots-build-cache-not-individually-counted' \
    || fail "signed generation overstates Docker internal storage accounting"
now_epoch=$(date +%s)
test "$now_epoch" -ge "$valid_from_epoch" && test "$now_epoch" -le "$valid_until_epoch" \
    || fail "configuration generation is outside its validity interval"
test "$rollback_floor_generation" -le "$config_generation" \
    || fail "rollback floor is newer than the configuration generation"

require_document_digest \
    "$config_generation_doc" key_authorization_sha256 "$key_authorization_doc"
require_document_digest \
    "$config_generation_doc" revocation_checkpoint_sha256 "$revocation_doc"
require_document_digest \
    "$config_generation_doc" deadline_profile_sha256 "$deadline_doc"
require_document_digest \
    "$config_generation_doc" source_ingress_descriptor_sha256 "$source_ingress_doc"
require_document_digest \
    "$config_generation_doc" native_snapshot_publication_sha256 "$native_publication_doc"
require_document_digest \
    "$config_generation_doc" network_contract_sha256 "$network_contract_doc"
require_document_digest \
    "$config_generation_doc" docker_artifact_binding_sha256 "$docker_artifact_binding_doc"
require_document_digest \
    "$config_generation_doc" log_custody_genesis_sha256 "$log_genesis_doc"
require_document_digest \
    "$config_generation_doc" log_authority_key_authorization_sha256 \
    "$log_authority_key_authorization_doc"
require_document_digest \
    "$config_generation_doc" receipt_authentication_key_authorization_sha256 \
    "$receipt_authentication_key_authorization_doc"
source_commit=$(document_value "$source_ingress_doc" source_commit)
case "$source_commit" in ""|*[!0-9a-f]*) fail "source commit must be lowercase hexadecimal" ;; esac
test "${#source_commit}" -eq 40 || test "${#source_commit}" -eq 64 \
    || fail "source commit must be a 40- or 64-character digest"
source_mode=$(document_value "$source_ingress_doc" publication_modes)
test "$source_mode" = "canonical-bundle,native-point-snapshot" \
    || fail "source ingress must authorize both canonical and native snapshot publication"
canonical_source_sha256=$(document_value "$source_ingress_doc" canonical_bundle_sha256)
native_snapshot_sha256=$(document_value "$source_ingress_doc" native_point_snapshot_sha256)
require_sha256 "$canonical_source_sha256" "canonical source bundle digest"
require_sha256 "$native_snapshot_sha256" "native snapshot digest"
test "$(sha_file "$asset_root/source/canonical-source.bundle")" = "$canonical_source_sha256" \
    || fail "canonical source bundle digest mismatch"
test "$(sha_file "$asset_root/source/native-point-snapshot.tar")" = "$native_snapshot_sha256" \
    || fail "native point snapshot digest mismatch"
test "$(document_value "$native_publication_doc" source_commit)" = "$source_commit" \
    || fail "native publication source commit mismatch"
test "$(document_value "$native_publication_doc" native_point_snapshot_sha256)" = \
    "$native_snapshot_sha256" || fail "native publication digest mismatch"
test "$(sed -n '1p' "$asset_root/source/canonical-source.bundle.sha256")" = \
    "$canonical_source_sha256" \
    && test -z "$(sed -n '2p' "$asset_root/source/canonical-source.bundle.sha256")" \
    || fail "canonical bundle digest file is not exact"
test "$(sed -n '1p' "$asset_root/source/native-point-snapshot.sha256")" = \
    "$native_snapshot_sha256" \
    && test -z "$(sed -n '2p' "$asset_root/source/native-point-snapshot.sha256")" \
    || fail "native snapshot digest file is not exact"

deadline_profile_id=$(document_value "$deadline_doc" profile_id)
test "$deadline_profile_id" = serverware-coder-five-lane-v12 \
    || fail "unexpected lane deadline profile"
build_deadline_ms=$(document_value "$deadline_doc" lane.build.deadline_ms)
unit_deadline_ms=$(document_value "$deadline_doc" lane.unit.deadline_ms)
integration_deadline_ms=$(document_value "$deadline_doc" lane.integration.deadline_ms)
e2e_deadline_ms=$(document_value "$deadline_doc" lane.e2e.deadline_ms)
attestation_deadline_ms=$(document_value "$deadline_doc" lane.attestation.deadline_ms)
cleanup_reserve_ms=$(document_value "$deadline_doc" cleanup_reserve_ms)
require_bounded_integer "$build_deadline_ms" 60000 86400000 "build deadline"
require_bounded_integer "$unit_deadline_ms" 60000 86400000 "unit deadline"
require_bounded_integer "$integration_deadline_ms" 60000 86400000 "integration deadline"
require_bounded_integer "$e2e_deadline_ms" 60000 86400000 "e2e deadline"
require_bounded_integer "$attestation_deadline_ms" 60000 86400000 "attestation deadline"
require_bounded_integer "$cleanup_reserve_ms" 10000 600000 "cleanup reserve"

test "$(document_value "$network_contract_doc" build_lane_slot)" = 0 \
    || fail "network contract must reserve slot 0 for the build lane"
test "$(document_value "$network_contract_doc" namespace_ipv4_prefix)" = 10.231 \
    || fail "network contract does not match the fixed namespace addressing"
test "$(document_value "$network_contract_doc" host_veth_prefix)" = swv12h \
    || fail "network contract does not match the fixed host veth prefix"
test "$(document_value "$network_contract_doc" address_family)" = ipv4-only \
    || fail "network contract must disable lane IPv6"
test "$(document_value "$network_contract_doc" build_egress)" = pinned-pulls-only \
    || fail "network contract must restrict build egress to pinned pulls"
test "$(document_value "$network_contract_doc" no_build_egress)" = none \
    || fail "network contract must deny no-build egress"
require_document_digest "$network_contract_doc" host_nft_sha256 \
    "$asset_root/network/host.nft"
require_document_digest "$network_contract_doc" host_cleanup_nft_sha256 \
    "$asset_root/network/host-cleanup.nft"
require_document_digest "$network_contract_doc" build_lane_nft_sha256 \
    "$asset_root/network/build-lane.nft"
require_document_digest "$network_contract_doc" no_build_lane_nft_sha256 \
    "$asset_root/network/no-build-lane.nft"
require_document_digest "$network_contract_doc" lane_cleanup_nft_sha256 \
    "$asset_root/network/lane-cleanup.nft"
require_document_digest "$network_contract_doc" pinned_pull_set_sha256 \
    "$asset_root/policy/pinned-pulls.v12.json"

current_target=
current_name=none
current_generation=0
if test -L "$current_link"; then
    current_target=$(readlink "$current_link")
    case "$current_target" in releases/*) ;; *) fail "current release symlink is unsafe" ;; esac
    current_name=${current_target#releases/}
    validate_release_id "$current_name"
    current_release=$install_root/$current_target
    test -d "$current_release" && test ! -L "$current_release" \
        || fail "current release symlink target is invalid"
    verify_signed_document \
        "$current_release/manifest/installed-release-v12.manifest" \
        "$current_release/manifest/installed-release-v12.manifest.sig" \
        "$pinned_signer"
    current_generation=$(document_value \
        "$current_release/manifest/installed-release-v12.manifest" config_generation)
    require_unsigned_integer "$current_generation" "current config generation"
elif test -e "$current_link"; then
    fail "current release path exists and is not a symlink"
fi
test "$predecessor_release_id" = "$current_name" \
    || fail "signed predecessor release does not match the active release"
test "$predecessor_config_generation" = "$current_generation" \
    || fail "signed predecessor generation does not match the active release"
test "$config_generation" -gt "$current_generation" \
    || fail "configuration generation is not monotonic"
test "$rollback_floor_generation" -le "$current_generation" \
    || test "$current_generation" -eq 0 \
    || fail "rollback floor excludes the declared predecessor"

test "$(document_value "$rollback_authorization_doc" source_release_id)" = "$release_id" \
    || fail "rollback authorization source release mismatch"
test "$(document_value "$rollback_authorization_doc" source_config_generation)" = \
    "$config_generation" || fail "rollback authorization source generation mismatch"
test "$(document_value "$rollback_authorization_doc" target_release_id)" = \
    "$predecessor_release_id" || fail "rollback authorization target release mismatch"
test "$(document_value "$rollback_authorization_doc" target_config_generation)" = \
    "$predecessor_config_generation" || fail "rollback authorization target generation mismatch"
test "$(document_value "$rollback_authorization_doc" rollback_floor_generation)" = \
    "$rollback_floor_generation" || fail "rollback authorization floor mismatch"
require_document_digest \
    "$rollback_authorization_doc" witness_checkpoint_sha256 "$witness_checkpoint_doc"
rollback_valid_until=$(document_value "$rollback_authorization_doc" valid_until_epoch)
require_unsigned_integer "$rollback_valid_until" "rollback authorization validity"
test "$now_epoch" -le "$rollback_valid_until" || fail "rollback authorization has expired"

witness_sequence=$(document_value "$witness_checkpoint_doc" witness_sequence)
require_unsigned_integer "$witness_sequence" "external witness sequence"
witness_valid_until=$(document_value "$witness_checkpoint_doc" valid_until_epoch)
require_unsigned_integer "$witness_valid_until" "external witness checkpoint validity"
test "$now_epoch" -le "$witness_valid_until" || fail "external witness checkpoint has expired"
test "$(document_value "$witness_checkpoint_doc" rollback_floor_generation)" = \
    "$rollback_floor_generation" || fail "witness checkpoint rollback floor mismatch"
minimum_witness_sequence=$(document_value \
    "$rollback_authorization_doc" minimum_witness_sequence)
require_unsigned_integer "$minimum_witness_sequence" "minimum witness sequence"
test "$minimum_witness_sequence" -le "$witness_sequence" \
    || fail "external witness sequence is below rollback authorization"

read_oci_digest() {
    digest_file=$1
    value=$(sed -n '1p' "$digest_file")
    test -z "$(sed -n '2p' "$digest_file")" || fail "OCI digest file has multiple lines"
    case "$value" in sha256:*) ;; *) fail "OCI digest must use sha256" ;; esac
    require_sha256 "${value#sha256:}" "OCI digest"
    printf '%s\n' "$value"
}

runner_oci_digest=$(read_oci_digest "$asset_root/runner/runner.oci.digest")
browser_oci_digest=$(read_oci_digest "$asset_root/runner/browser.oci.digest")
buildkit_oci_digest=$(read_oci_digest "$asset_root/runner/buildkit.oci.digest")

test "$(document_value "$log_genesis_doc" log_id)" = serverware-coder-controller-v12 \
    || fail "log-custody genesis has the wrong log ID"
test "$(document_value "$log_genesis_doc" genesis_kind)" = binary-fixed-empty-root-v12 \
    || fail "log-custody genesis does not match the local authority implementation"
test "$(document_value "$log_genesis_doc" checkpoint_sequence)" = 0 \
    && test "$(document_value "$log_genesis_doc" tree_size)" = 0 \
    || fail "log-custody genesis must begin at sequence and tree size zero"
zero_sha256=0000000000000000000000000000000000000000000000000000000000000000
log_empty_tree_root=$(document_value "$log_genesis_doc" tree_root_sha256)
require_sha256 "$log_empty_tree_root" "log-custody empty tree root"
test "$log_empty_tree_root" != "$zero_sha256" \
    && test "$(document_value "$log_genesis_doc" previous_signed_tree_head_envelope_sha256)" = \
        "$zero_sha256" || fail "log-custody genesis must use the domain-separated empty root"
test "$(document_value "$log_genesis_doc" integrity_mode)" = UserspaceDigestOnly \
    || fail "local log-custody genesis must not claim a stronger integrity mode"

test "$(document_value "$docker_artifact_binding_doc" binding_id)" = \
    serverware-coder-docker-artifacts-v12 \
    || fail "unexpected Docker artifact binding ID"
test "$(document_value "$docker_artifact_binding_doc" docker_api_request_schema_version)" = 12 \
    && test "$(document_value "$docker_artifact_binding_doc" docker_lane_capability_schema_version)" = 12 \
    || fail "Docker request/capability schema versions must be v12"
test "$(document_value "$docker_artifact_binding_doc" docker_network_membership_schema_version)" = 12 \
    && test "$(document_value "$docker_artifact_binding_doc" docker_service_instance_schema_version)" = 12 \
    && test "$(document_value "$docker_artifact_binding_doc" docker_runner_execution_schema_version)" = 12 \
    || fail "Docker ledger, service, and execution schemas must be v12"
test "$(document_value "$docker_artifact_binding_doc" integrity_mode)" = UserspaceDigestOnly \
    || fail "Docker artifact binding must not claim stronger publication integrity"
test "$(document_value "$docker_artifact_binding_doc" host_docker_socket_exposed)" = false \
    && test "$(document_value "$docker_artifact_binding_doc" global_docker_daemon_allowed)" = false \
    && test "$(document_value "$docker_artifact_binding_doc" legacy_v11_lease_allowed)" = false \
    || fail "Docker artifact binding enables a forbidden host/global/v11 fallback"
test "$(document_value "$docker_artifact_binding_doc" private_dind_lifecycle_contract)" = \
    serverware/private-dind-lifecycle/v12 \
    && test "$(document_value "$docker_artifact_binding_doc" lane_proxy_contract)" = \
        serverware/controller-lane-proxy/v12 \
    || fail "Docker artifact binding does not select the v12 private-DinD contracts"
require_document_digest "$docker_artifact_binding_doc" docker_api_request_schema_sha256 \
    "$asset_root/schemas/coder-docker-api-request.v12.schema.json"
require_document_digest "$docker_artifact_binding_doc" docker_lane_capability_schema_sha256 \
    "$asset_root/schemas/coder-docker-lane-capability.v12.schema.json"
require_document_digest "$docker_artifact_binding_doc" docker_network_membership_schema_sha256 \
    "$asset_root/schemas/coder-docker-network-membership.v12.schema.json"
require_document_digest "$docker_artifact_binding_doc" docker_service_instance_schema_sha256 \
    "$asset_root/schemas/coder-docker-service-instance.v12.schema.json"
require_document_digest "$docker_artifact_binding_doc" docker_runner_execution_schema_sha256 \
    "$asset_root/schemas/coder-docker-runner-execution.v12.schema.json"
require_document_digest "$docker_artifact_binding_doc" pinned_pull_set_sha256 \
    "$asset_root/policy/pinned-pulls.v12.json"
require_document_digest "$docker_artifact_binding_doc" exact_build_tuple_set_sha256 \
    "$asset_root/policy/exact-build-tuples.v12.json"
require_document_digest "$docker_artifact_binding_doc" docker_api_rule_set_sha256 \
    "$asset_root/policy/docker-api-rules.v12.json"
require_document_digest "$docker_artifact_binding_doc" runner_oci_archive_sha256 \
    "$asset_root/runner/runner.oci.tar"
require_document_digest "$docker_artifact_binding_doc" runner_oci_digest_file_sha256 \
    "$asset_root/runner/runner.oci.digest"
require_document_digest "$docker_artifact_binding_doc" browser_oci_archive_sha256 \
    "$asset_root/runner/browser.oci.tar"
require_document_digest "$docker_artifact_binding_doc" browser_oci_digest_file_sha256 \
    "$asset_root/runner/browser.oci.digest"
require_document_digest "$docker_artifact_binding_doc" buildkit_oci_archive_sha256 \
    "$asset_root/runner/buildkit.oci.tar"
require_document_digest "$docker_artifact_binding_doc" buildkit_oci_digest_file_sha256 \
    "$asset_root/runner/buildkit.oci.digest"

verify_fixture() {
    key=$1
    file=$2
    expected=$(document_value "$asset_root/fixtures/readiness-fixtures-v12.manifest" "$key")
    require_sha256 "$expected" "$key"
    test "$(sha_file "$asset_root/fixtures/$file")" = "$expected" \
        || fail "readiness fixture digest mismatch: $file"
}
verify_fixture docker_101_fixture_sha256 docker-101.fixture
verify_fixture docker_half_close_fixture_sha256 docker-half-close.fixture
verify_fixture build_pinned_pull_fixture_sha256 build-pinned-pull.fixture
verify_fixture build_unpinned_egress_denied_fixture_sha256 build-unpinned-egress-denied.fixture
verify_fixture no_build_egress_denied_fixture_sha256 no-build-egress-denied.fixture
verify_fixture service_health_fixture_sha256 service-health.fixture
verify_fixture chromium_page_fixture_sha256 chromium-page.html
verify_fixture chromium_script_fixture_sha256 chromium-script.js
verify_fixture chromium_probe_fixture_sha256 chromium-probe.fixture
verify_fixture chromium_expected_cdp_sha256 chromium-expected-cdp.json
verify_fixture chromium_expected_dom_sha256 chromium-expected-dom.txt
verify_fixture chromium_expected_js_sha256 chromium-expected-js.txt
verify_fixture chromium_expected_fetch_sha256 chromium-expected-fetch.txt
verify_fixture teardown_fixture_sha256 teardown.fixture

fixture_set_id=$(document_value \
    "$asset_root/fixtures/readiness-fixtures-v12.manifest" fixture_set_id)
require_sha256 "$fixture_set_id" "readiness fixture_set_id"
for readiness_binding in \
    fixture_set_digest_contract=serverware/readiness-assets-digest/v12 \
    role.docker_101=upgrade-client-stream \
    role.docker_half_close=upgrade-server-stream \
    role.build_pinned_pull=build-pinned-pull-contract \
    role.build_unpinned_egress_denied=build-egress-denial-contract \
    role.no_build_egress_denied=no-build-egress-denial-contract \
    role.service_health=service-container-probe-contract \
    role.chromium_page=chromium-document \
    role.chromium_script=chromium-javascript \
    role.chromium_probe=chromium-container-probe-contract \
    role.chromium_expected_cdp=chromium-cdp-expectation \
    role.chromium_expected_dom=chromium-dom-expectation \
    role.chromium_expected_js=chromium-javascript-expectation \
    role.chromium_expected_fetch=chromium-fetch-expectation \
    role.teardown=terminal-private-dind-absence-contract \
    probe_order=docker-upgrade,service-health,chromium,teardown \
    before_repository_work_every_invocation=true
do
    readiness_key=${readiness_binding%%=*}
    readiness_value=${readiness_binding#*=}
    test "$(document_value \
        "$asset_root/fixtures/readiness-fixtures-v12.manifest" \
        "$readiness_key")" = "$readiness_value" \
        || fail "readiness manifest binding mismatch: $readiness_key"
done
for readiness_requirement in \
    require_docker_101 require_half_close require_build_pinned_pull \
    require_build_unpinned_egress_denied require_no_build_egress_denied \
    require_service_start_health_stop require_chromium_cdp \
    require_dom_sentinel require_javascript_sentinel \
    require_fetch_sentinel require_teardown_proof
do
    test "$(document_value \
        "$asset_root/fixtures/readiness-fixtures-v12.manifest" \
        "$readiness_requirement")" = true \
        || fail "readiness manifest disables $readiness_requirement"
done
readiness_descriptor=$transaction_root/readiness-assets-v12.descriptor
install -o root -g root -m 0600 /dev/null "$readiness_descriptor"
for readiness_asset_key in \
    fixture_set_digest_contract \
    docker_101_fixture_sha256 docker_half_close_fixture_sha256 \
    build_pinned_pull_fixture_sha256 \
    build_unpinned_egress_denied_fixture_sha256 \
    no_build_egress_denied_fixture_sha256 \
    service_health_fixture_sha256 chromium_page_fixture_sha256 \
    chromium_script_fixture_sha256 chromium_probe_fixture_sha256 \
    chromium_expected_cdp_sha256 chromium_expected_dom_sha256 \
    chromium_expected_js_sha256 chromium_expected_fetch_sha256 \
    teardown_fixture_sha256 \
    role.docker_101 role.docker_half_close role.build_pinned_pull \
    role.build_unpinned_egress_denied role.no_build_egress_denied \
    role.service_health role.chromium_page role.chromium_script \
    role.chromium_probe role.chromium_expected_cdp \
    role.chromium_expected_dom role.chromium_expected_js \
    role.chromium_expected_fetch role.teardown \
    require_docker_101 require_half_close require_build_pinned_pull \
    require_build_unpinned_egress_denied \
    require_no_build_egress_denied require_service_start_health_stop \
    require_chromium_cdp require_dom_sentinel \
    require_javascript_sentinel require_fetch_sentinel \
    require_teardown_proof probe_order \
    before_repository_work_every_invocation
do
    printf '%s=%s\n' "$readiness_asset_key" \
        "$(document_value \
            "$asset_root/fixtures/readiness-fixtures-v12.manifest" \
            "$readiness_asset_key")" >> "$readiness_descriptor"
done
derived_fixture_set_id=$(sha_file "$readiness_descriptor")
test "$derived_fixture_set_id" = "$fixture_set_id" \
    || fail "readiness fixture_set_id is not the exact readiness asset digest"
teardown_contract='{"version":"serverware/readiness-teardown-contract/v12","dockerTopLevelObjectCountScope":"private-daemon-top-level-api:containers,images,nondefault-networks,volumes","dockerInternalStorageAbsenceProof":"generation-state-root-absent;internal-layers-snapshots-build-cache-not-individually-counted","requireExactSignedFixture":true,"requireDurableTerminalReceipt":true,"requireDockerAuthorityEstablished":true,"requireZeroContainers":true,"requireZeroImages":true,"requireZeroNetworks":true,"requireZeroVolumes":true,"requireZeroMounts":true,"requireZeroCgroupProcesses":true,"requireStateRootAbsent":true}'
test "$(wc -c < "$asset_root/fixtures/teardown.fixture" | tr -d ' ')" = \
    "${#teardown_contract}" \
    && test "$(cat "$asset_root/fixtures/teardown.fixture")" = \
        "$teardown_contract" \
    || fail "teardown fixture is not the canonical closed v12 contract"

credential_check_root=$transaction_root/credential-check
install -d -o root -g root -m 0700 "$credential_check_root"
service_key_names="
controller-identity
plan-executor-capability
docker-proxy-identity
receipt-authority
external-witness
final-settlement
log-custody-authority
final-verdict-authority
lifecycle-authority
lifecycle-privileged-authority
"
service_spki_digests=
for authority_key in \
    "$pinned_signer" "$config_authority" "$source_authority" \
    "$witness_verification_key" "$readiness_authority"
do
    authority_der=$credential_check_root/authority.$$.der
    openssl pkey -pubin -in "$authority_key" -outform DER -out "$authority_der" \
        || fail "authority public key is invalid: $authority_key"
    authority_spki=$(sha_file "$authority_der")
    case " $service_spki_digests " in
        *" $authority_spki "*) fail "authority SPKIs must be pairwise distinct" ;;
    esac
    service_spki_digests="$service_spki_digests $authority_spki"
    rm -f -- "$authority_der"
done
for key_name in $service_key_names
do
    credential_name=$key_name-key
    credential=$asset_root/credentials/$credential_name.cred
    public_key=$asset_root/trust/$key_name-public-key.pem
    decrypted=$credential_check_root/$credential_name.pem
    private_der=$credential_check_root/$credential_name.private.der
    public_der=$credential_check_root/$credential_name.public.der
    systemd-creds decrypt --name="$credential_name" "$credential" "$decrypted" >/dev/null \
        || fail "host cannot decrypt signed credential: $credential_name"
    openssl pkey -in "$decrypted" -pubout -outform DER -out "$private_der" \
        || fail "credential does not contain a supported private key: $credential_name"
    openssl pkey -pubin -in "$public_key" -outform DER -out "$public_der" \
        || fail "bundle public key is invalid: $public_key"
    cmp -s "$private_der" "$public_der" \
        || fail "encrypted credential does not match authorized public key: $credential_name"
    spki_digest=$(sha_file "$public_der")
    expected_spki=$(document_value "$key_authorization_doc" "key.$key_name.spki_sha256")
    require_sha256 "$expected_spki" "authorized SPKI digest"
    test "$spki_digest" = "$expected_spki" \
        || fail "service SPKI is not bound by key authorization: $key_name"
    test "$(document_value "$key_authorization_doc" "key.$key_name.status")" = authorized \
        || fail "service key is not authorized: $key_name"
    case " $service_spki_digests " in
        *" $spki_digest "*) fail "authority SPKIs must be pairwise distinct" ;;
    esac
    service_spki_digests="$service_spki_digests $spki_digest"
    case "$key_name" in
        controller-identity) controller_identity_spki=$spki_digest ;;
        plan-executor-capability) plan_executor_spki=$spki_digest ;;
        docker-proxy-identity) docker_proxy_spki=$spki_digest ;;
        receipt-authority) receipt_authority_spki=$spki_digest ;;
        external-witness) external_witness_spki=$spki_digest ;;
        final-settlement) final_settlement_spki=$spki_digest ;;
        log-custody-authority) log_custody_spki=$spki_digest ;;
        final-verdict-authority) final_verdict_spki=$spki_digest ;;
        lifecycle-authority) lifecycle_spki=$spki_digest ;;
        lifecycle-privileged-authority) lifecycle_privileged_spki=$spki_digest ;;
    esac
    rm -f -- "$decrypted" "$private_der" "$public_der"
done
rmdir "$credential_check_root"

test "$(document_value "$key_authorization_doc" config_generation)" = "$config_generation" \
    || fail "key authorization generation mismatch"
key_valid_from=$(document_value "$key_authorization_doc" valid_from_epoch)
key_valid_until=$(document_value "$key_authorization_doc" valid_until_epoch)
require_unsigned_integer "$key_valid_from" "key authorization valid-from time"
require_unsigned_integer "$key_valid_until" "key authorization valid-until time"
test "$now_epoch" -ge "$key_valid_from" && test "$now_epoch" -le "$key_valid_until" \
    || fail "key authorization is outside its validity interval"
test "$(document_value "$revocation_doc" config_generation)" = "$config_generation" \
    || fail "revocation checkpoint generation mismatch"
test "$(document_value "$revocation_doc" rollback_floor_generation)" = \
    "$rollback_floor_generation" || fail "revocation checkpoint rollback floor mismatch"
revocation_valid_until=$(document_value "$revocation_doc" valid_until_epoch)
require_unsigned_integer "$revocation_valid_until" "revocation checkpoint validity"
test "$now_epoch" -le "$revocation_valid_until" || fail "revocation checkpoint has expired"
revoked_count=$(document_value "$revocation_doc" revoked_spki_count)
require_bounded_integer "$revoked_count" 0 4096 "revoked SPKI count"
revoked_index=0
while test "$revoked_index" -lt "$revoked_count"
do
    revoked_spki=$(document_value "$revocation_doc" "revoked_spki.$revoked_index")
    require_sha256 "$revoked_spki" "revoked SPKI"
    case " $service_spki_digests " in
        *" $revoked_spki "*) fail "an authorized service key is revoked" ;;
    esac
    revoked_index=$((revoked_index + 1))
done

identity_names="controller executor docker_proxy receipt_authority log_custody final_verdict_authority trust_generation_authority external_witness_authority final_settlement_authority lifecycle"
service_uids=
service_gids=
for identity in $identity_names
do
    uid=$(document_value "$config_generation_doc" "identity.$identity.uid")
    gid=$(document_value "$config_generation_doc" "identity.$identity.gid")
    require_bounded_integer "$uid" 100 59999 "$identity UID"
    require_bounded_integer "$gid" 100 59999 "$identity GID"
    case " $service_uids " in *" $uid "*) fail "service UIDs must be distinct" ;; esac
    case " $service_gids " in *" $gid "*) fail "service GIDs must be distinct" ;; esac
    service_uids="$service_uids $uid"
    service_gids="$service_gids $gid"
    eval "${identity}_uid=\$uid"
    eval "${identity}_gid=\$gid"
done

api_group_names="executor_api docker_api receipt_api log_api verdict_api trust_api witness_api settlement_api lifecycle_api lifecycle_privileged_api cas"
case " $service_gids " in
    *" $client_gid "*) fail "client GID must differ from every service primary GID" ;;
esac
managed_gids=$service_gids
for api_group in $api_group_names
do
    gid=$(document_value "$config_generation_doc" "group.$api_group.gid")
    require_bounded_integer "$gid" 100 59999 "$api_group GID"
    case " $managed_gids $client_gid " in
        *" $gid "*) fail "managed and client GIDs must be pairwise distinct" ;;
    esac
    managed_gids="$managed_gids $gid"
    eval "${api_group}_gid=\$gid"
done

ensure_group() {
    name=$1
    expected_gid=$2
    if getent group "$name" >/dev/null; then
        actual_gid=$(getent group "$name" | awk -F: '{print $3}')
        test "$actual_gid" = "$expected_gid" \
            || fail "existing group has unexpected GID: $name"
    else
        ! getent group "$expected_gid" >/dev/null \
            || fail "required GID is already assigned: $expected_gid"
        groupadd --system --gid "$expected_gid" "$name"
    fi
}

ensure_user() {
    name=$1
    expected_uid=$2
    primary_group=$3
    if getent passwd "$name" >/dev/null; then
        test "$(id -u "$name")" = "$expected_uid" \
            || fail "existing service user has unexpected UID: $name"
        test "$(id -gn "$name")" = "$primary_group" \
            || fail "existing service user has unexpected primary group: $name"
    else
        ! getent passwd "$expected_uid" >/dev/null \
            || fail "required UID is already assigned: $expected_uid"
        useradd --system --uid "$expected_uid" --gid "$primary_group" \
            --home-dir /nonexistent --shell /usr/sbin/nologin "$name"
    fi
}

ensure_group serverware-coder-controller "$controller_gid"
ensure_group serverware-coder-executor "$executor_gid"
ensure_group serverware-coder-docker "$docker_proxy_gid"
ensure_group serverware-coder-receipt "$receipt_authority_gid"
ensure_group serverware-coder-log "$log_custody_gid"
ensure_group serverware-coder-verdict "$final_verdict_authority_gid"
ensure_group serverware-coder-trust "$trust_generation_authority_gid"
ensure_group serverware-coder-witness "$external_witness_authority_gid"
ensure_group serverware-coder-settlement "$final_settlement_authority_gid"
ensure_group serverware-coder-lifecycle "$lifecycle_gid"
ensure_group serverware-coder-executor-api "$executor_api_gid"
ensure_group serverware-coder-docker-api "$docker_api_gid"
ensure_group serverware-coder-receipt-api "$receipt_api_gid"
ensure_group serverware-coder-log-api "$log_api_gid"
ensure_group serverware-coder-verdict-api "$verdict_api_gid"
ensure_group serverware-coder-trust-api "$trust_api_gid"
ensure_group serverware-coder-witness-api "$witness_api_gid"
ensure_group serverware-coder-settlement-api "$settlement_api_gid"
ensure_group serverware-coder-lifecycle-api "$lifecycle_api_gid"
ensure_group serverware-coder-lifecycle-privileged-api "$lifecycle_privileged_api_gid"
ensure_group serverware-coder-cas "$cas_gid"

ensure_user serverware-coder-controller "$controller_uid" serverware-coder-controller
ensure_user serverware-coder-executor "$executor_uid" serverware-coder-executor
ensure_user serverware-coder-docker "$docker_proxy_uid" serverware-coder-docker
ensure_user serverware-coder-receipt "$receipt_authority_uid" serverware-coder-receipt
ensure_user serverware-coder-log "$log_custody_uid" serverware-coder-log
ensure_user serverware-coder-verdict "$final_verdict_authority_uid" serverware-coder-verdict
ensure_user serverware-coder-trust "$trust_generation_authority_uid" serverware-coder-trust
ensure_user serverware-coder-witness "$external_witness_authority_uid" serverware-coder-witness
ensure_user serverware-coder-settlement "$final_settlement_authority_uid" serverware-coder-settlement
ensure_user serverware-coder-lifecycle "$lifecycle_uid" serverware-coder-lifecycle

grep -F "\"executor_uid\": $executor_uid" \
    "$asset_root/config/plan-executor-v12.conf" >/dev/null \
    || fail "canonical plan executor config is not bound to the signed executor UID"
grep -F "\"lifecycle_root_signer_spki_sha256\": \"$lifecycle_privileged_spki\"" \
    "$asset_root/config/plan-executor-v12.conf" >/dev/null \
    || fail "canonical plan executor config is not bound to the privileged lifecycle signer"
grep -F "\"fixture_assets_sha256\": \"$fixture_set_id\"" \
    "$asset_root/config/plan-executor-v12.conf" >/dev/null \
    || fail "canonical plan executor config is not bound to the derived readiness asset digest"
grep -F "\"full_signed_readiness_before_repository_work_every_invocation\": true" \
    "$asset_root/config/plan-executor-v12.conf" >/dev/null \
    || fail "canonical plan executor config does not require full per-invocation readiness"

set_exact_group_members() {
    group=$1
    members=$2
    gpasswd -M "$members" "$group" >/dev/null
    actual=$(getent group "$group" | awk -F: '{print $4}')
    test "$actual" = "$members" \
        || fail "managed group membership is not exact: $group"
}

set_exact_group_members serverware-coder-executor-api \
    serverware-coder-controller,serverware-coder-executor
set_exact_group_members serverware-coder-docker-api \
    serverware-coder-controller,serverware-coder-executor,serverware-coder-docker
set_exact_group_members serverware-coder-receipt-api \
    serverware-coder-controller,serverware-coder-receipt,serverware-coder-verdict
set_exact_group_members serverware-coder-log-api \
    serverware-coder-receipt,serverware-coder-log
set_exact_group_members serverware-coder-verdict-api \
    serverware-coder-controller,serverware-coder-verdict
set_exact_group_members serverware-coder-trust-api \
    serverware-coder-controller,serverware-coder-receipt,serverware-coder-trust
set_exact_group_members serverware-coder-witness-api \
    serverware-coder-controller,serverware-coder-receipt,serverware-coder-witness
set_exact_group_members serverware-coder-settlement-api \
    serverware-coder-receipt,serverware-coder-settlement
set_exact_group_members serverware-coder-lifecycle-api \
    serverware-coder-controller,serverware-coder-executor,serverware-coder-docker,serverware-coder-lifecycle
set_exact_group_members serverware-coder-lifecycle-privileged-api \
    serverware-coder-lifecycle
set_exact_group_members serverware-coder-cas \
    serverware-coder-controller,serverware-coder-executor

install -d -o root -g root -m 0755 /var/lib/serverware
install -d -o root -g root -m 0711 "$state_root"
install -d -o serverware-coder-controller -g serverware-coder-controller -m 0700 \
    "$state_root/controller"
install -d -o serverware-coder-executor -g serverware-coder-executor -m 0700 \
    "$state_root/executor"
install -d -o root -g root -m 0555 \
    "$state_root/executor/operation-ledger"
install -d -o serverware-coder-docker -g serverware-coder-docker -m 0700 \
    "$state_root/docker-proxy"
install -d -o serverware-coder-receipt -g serverware-coder-receipt -m 0700 \
    "$state_root/receipt-authority"
install -d -o serverware-coder-log -g serverware-coder-log -m 0700 \
    "$state_root/log-custody"
install -d -o serverware-coder-verdict -g serverware-coder-verdict -m 0700 \
    "$state_root/final-verdict-authority"
install -d -o serverware-coder-trust -g serverware-coder-trust -m 0700 \
    "$state_root/trust-generation"
install -d -o serverware-coder-witness -g serverware-coder-witness -m 0700 \
    "$state_root/external-witness"
install -d -o serverware-coder-settlement -g serverware-coder-settlement -m 0700 \
    "$state_root/final-settlement"
install -d -o serverware-coder-lifecycle -g serverware-coder-lifecycle -m 0700 \
    "$state_root/lifecycle"
install -d -o root -g root -m 0700 \
    "$state_root/lifecycle-privileged" \
    "$state_root/lifecycle-privileged/terminal-destruction-receipts" \
    "$state_root/dind"
install -d -o serverware-coder-executor -g serverware-coder-executor -m 0700 \
    "$state_root/cas" "$state_root/cas/source" \
    "$state_root/cas/artifact" "$state_root/cas/oci"
install -d -o serverware-coder-executor -g serverware-coder-executor -m 0700 \
    "$state_root/cas/source/.serverware-cas-publication-journal-v12" \
    "$state_root/cas/artifact/.serverware-cas-publication-journal-v12"

stage=$transaction_root/release
unit_stage=$transaction_root/systemd
unit_backup=$transaction_root/systemd-backup
install -d -o root -g root -m 0700 "$stage" "$unit_stage" "$unit_backup"

install -d -o root -g root -m 0555 \
    "$stage/admin" "$stage/authorization" "$stage/bin" "$stage/config" \
    "$stage/credentials" "$stage/fixtures" "$stage/hooks" "$stage/manifest" \
    "$stage/network" "$stage/policy" "$stage/provisioning" "$stage/runner" \
    "$stage/schemas" "$stage/source" "$stage/systemd" "$stage/trust"
install -d -o root -g root -m 0555 \
    "$stage/provisioning/scripts" \
    "$stage/provisioning/ops/coder-controller-v12/hooks" \
    "$stage/provisioning/ops/systemd"

for binary in \
    serverware-coder-controller-v12 \
    serverware-coder-controller-client-v12 \
    serverware-coder-plan-executor-v12 \
    serverware-coder-docker-proxy-v12 \
    serverware-coder-receipt-authority-v12 \
    serverware-coder-local-trust-authority-v12 \
    serverware-coder-log-custody-authority-v12 \
    serverware-coder-final-verdict-authority-v12 \
    serverware-coder-lifecycle-v12 \
    serverware-coder-lifecycle-privileged-v12 \
    dockerd-v12 \
    containerd-v12 \
    containerd-shim-runc-v2-v12 \
    runc-v12
do
    install -o root -g root -m 0555 "$asset_root/bin/$binary" "$stage/bin/$binary"
done

for schema in \
    coder-test-controller-request.v1.schema.json \
    coder-test-controller-receipt.v12.schema.json \
    coder-docker-api-request.v12.schema.json \
    coder-docker-lane-capability.v12.schema.json \
    coder-docker-network-membership.v12.schema.json \
    coder-docker-service-instance.v12.schema.json \
    coder-docker-runner-execution.v12.schema.json
do
    install -o root -g root -m 0444 "$asset_root/schemas/$schema" "$stage/schemas/$schema"
done
for image in runner browser buildkit
do
    install -o root -g root -m 0444 "$asset_root/runner/$image.oci.tar" "$stage/runner/$image.oci.tar"
    install -o root -g root -m 0444 "$asset_root/runner/$image.oci.digest" "$stage/runner/$image.oci.digest"
done
for fixture in \
    readiness-fixtures-v12.manifest readiness-fixtures-v12.manifest.sig \
    docker-101.fixture docker-half-close.fixture build-pinned-pull.fixture \
    build-unpinned-egress-denied.fixture no-build-egress-denied.fixture \
    service-health.fixture \
    chromium-page.html chromium-script.js chromium-probe.fixture \
    chromium-expected-cdp.json \
    chromium-expected-dom.txt chromium-expected-js.txt \
    chromium-expected-fetch.txt teardown.fixture
do
    install -o root -g root -m 0444 "$asset_root/fixtures/$fixture" "$stage/fixtures/$fixture"
done
for network_file in \
    host.nft host-cleanup.nft build-lane.nft no-build-lane.nft lane-cleanup.nft \
    network-contract-v12.manifest network-contract-v12.manifest.sig
do
    install -o root -g root -m 0444 "$asset_root/network/$network_file" "$stage/network/$network_file"
done
for policy_file in \
    pinned-pulls.v12.json exact-build-tuples.v12.json docker-api-rules.v12.json \
    docker-artifact-binding-v12.manifest docker-artifact-binding-v12.manifest.sig \
    lane-deadlines-v12.manifest lane-deadlines-v12.manifest.sig
do
    install -o root -g root -m 0444 "$asset_root/policy/$policy_file" "$stage/policy/$policy_file"
done
for auth_file in \
    config-generation-v12.manifest config-generation-v12.manifest.sig \
    key-authorization-v12.manifest key-authorization-v12.manifest.sig \
    revocation-checkpoint-v12.manifest revocation-checkpoint-v12.manifest.sig \
    rollback-authorization-v12.manifest rollback-authorization-v12.manifest.sig \
    external-witness-checkpoint-v12.manifest external-witness-checkpoint-v12.manifest.sig \
    log-custody-genesis-v12.manifest log-custody-genesis-v12.manifest.sig \
    log-authority-key-authorization-v12.json \
    receipt-authentication-key-authorization-v12.json \
    trust-generation-bundle-v12.json \
    external-witness-key-authorization-v12.json \
    final-settlement-key-authorization-v12.json \
    final-settlement-genesis-v12.json
do
    install -o root -g root -m 0444 \
        "$asset_root/authorization/$auth_file" "$stage/authorization/$auth_file"
done
for source_file in \
    source-ingress-v12.manifest source-ingress-v12.manifest.sig \
    canonical-source.bundle canonical-source.bundle.sha256 \
    native-point-snapshot.tar native-point-snapshot.sha256 \
    native-snapshot-publication-v12.manifest native-snapshot-publication-v12.manifest.sig
do
    install -o root -g root -m 0444 "$asset_root/source/$source_file" "$stage/source/$source_file"
done
snapshot_members=$transaction_root/native-snapshot-members.v12
LC_ALL=C tar -tf "$stage/source/native-point-snapshot.tar" > "$snapshot_members"
test -s "$snapshot_members" || fail "native point snapshot is empty"
while IFS= read -r member || test -n "$member"
do
    normalized=${member%/}
    manifest_path_is_safe "$normalized" \
        || fail "unsafe native snapshot member: $member"
done < "$snapshot_members"
test -z "$(LC_ALL=C sort "$snapshot_members" | uniq -d)" \
    || fail "native point snapshot contains duplicate members"
LC_ALL=C tar -tvf "$stage/source/native-point-snapshot.tar" |
    awk 'substr($0, 1, 1) != "-" && substr($0, 1, 1) != "d" { exit 1 }' \
    || fail "native point snapshot contains a link, device, or special file"
install -d -o root -g root -m 0700 "$stage/source/input"
tar --extract --file "$stage/source/native-point-snapshot.tar" \
    --directory "$stage/source/input" \
    --no-same-owner --no-same-permissions
chown -hR root:root "$stage/source/input"
chmod -R a=rX "$stage/source/input"
for trust_file in \
    requester-public-key.ed25519 external-witness-public-key.ed25519 \
    external-witness-verification-key.pem readiness-fixture-public-key.pem \
    release-bundle-signer-public-key.pem configuration-authority-public-key.pem \
    source-ingress-authority-public-key.pem controller-identity-public-key.pem \
    plan-executor-capability-public-key.pem docker-proxy-identity-public-key.pem \
    receipt-authority-public-key.pem log-custody-authority-public-key.pem \
    final-verdict-authority-public-key.pem final-settlement-public-key.pem \
    lifecycle-authority-public-key.pem lifecycle-privileged-authority-public-key.pem
do
    install -o root -g root -m 0444 "$asset_root/trust/$trust_file" "$stage/trust/$trust_file"
done
for credential_name in \
    controller-identity-key plan-executor-capability-key docker-proxy-identity-key \
    receipt-authority-key log-custody-authority-key \
    external-witness-key final-settlement-key \
    final-verdict-authority-key lifecycle-authority-key \
    lifecycle-privileged-authority-key
do
    install -o root -g root -m 0400 \
        "$asset_root/credentials/$credential_name.cred" \
        "$stage/credentials/$credential_name.cred"
done
for canonical_config in receipt-authority-v12.conf final-verdict-authority-v12.conf \
    plan-executor-v12.conf executor-invocation-inputs-v12.json \
    local-trust-generation-v12.json local-external-witness-v12.json \
    local-final-settlement-v12.json
do
    install -o root -g root -m 0444 \
        "$asset_root/config/$canonical_config" "$stage/config/$canonical_config"
done

install -o root -g root -m 0444 "$bundle_manifest" "$stage/manifest/signed-bundle.sha256"
install -o root -g root -m 0444 "$bundle_signature" "$stage/manifest/signed-bundle.sha256.sig"

for script in install_coder_controller_v12.sh rollback_coder_controller_v12.sh
do
    install -o root -g root -m 0555 \
        "$asset_root/provisioning/scripts/$script" \
        "$stage/provisioning/scripts/$script"
done
for input in $provisioning_config_inputs
do
    install -o root -g root -m 0444 \
        "$asset_root/provisioning/ops/coder-controller-v12/$input" \
        "$stage/provisioning/ops/coder-controller-v12/$input"
done
for provisioning_admin in \
    prepare-readiness-release-assets-v12.sh \
    offline-state-quarantine-v12.sh
do
    install -o root -g root -m 0555 \
        "$asset_root/provisioning/ops/coder-controller-v12/$provisioning_admin" \
        "$stage/provisioning/ops/coder-controller-v12/$provisioning_admin"
done
for hook in network-lifecycle-v12.sh dind-lifecycle-v12.sh runtime-directories-v12.sh
do
    install -o root -g root -m 0555 \
        "$asset_root/provisioning/ops/coder-controller-v12/hooks/$hook" \
        "$stage/provisioning/ops/coder-controller-v12/hooks/$hook"
    install -o root -g root -m 0555 \
        "$asset_root/provisioning/ops/coder-controller-v12/hooks/$hook" \
        "$stage/hooks/$hook"
done
install -o root -g root -m 0555 \
    "$asset_root/provisioning/scripts/rollback_coder_controller_v12.sh" \
    "$stage/admin/rollback_coder_controller_v12.sh"
install -o root -g root -m 0555 \
    "$asset_root/provisioning/ops/coder-controller-v12/offline-state-quarantine-v12.sh" \
    "$stage/admin/offline-state-quarantine-v12.sh"

validate_substitution() {
    key=$1
    value=$2
    case "$key" in ""|*[!A-Z0-9_]*) fail "invalid template key: $key" ;; esac
    test -n "$value" || fail "empty template substitution: $key"
    printf '%s' "$value" | LC_ALL=C grep '[[:cntrl:]]' >/dev/null \
        && fail "template substitution contains a control character: $key"
    case "$value" in *"@"*) fail "template substitution contains placeholder syntax: $key" ;; esac
}

escape_sed() {
    printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

render_template() {
    source=$1
    destination=$2
    shift 2
    install -o root -g root -m 0444 "$source" "$destination"
    while test "$#" -gt 0
    do
        test "$#" -ge 2 || fail "template substitution is missing a value"
        key=$1
        value=$2
        shift 2
        validate_substitution "$key" "$value"
        escaped=$(escape_sed "$value")
        sed "s|@$key@|$escaped|g" "$destination" > "$destination.next"
        chmod 0444 "$destination.next"
        mv -fT "$destination.next" "$destination"
    done
    if grep -n '@[A-Z0-9_][A-Z0-9_]*@' "$destination" >/dev/null; then
        fail "unresolved required placeholder in $destination"
    fi
}

release_root=$releases_root/$release_id
test ! -e "$release_root" && test ! -L "$release_root" \
    || fail "release already exists: $release_root"

pinned_pull_set_sha256=$(sha_file "$stage/policy/pinned-pulls.v12.json")
exact_build_tuple_set_sha256=$(sha_file "$stage/policy/exact-build-tuples.v12.json")
docker_api_rule_set_sha256=$(sha_file "$stage/policy/docker-api-rules.v12.json")
template_root=$stage/provisioning/ops/coder-controller-v12
case "$deployment_profile" in
    local-trusted-host) selected_profile_template=trusted-host-v12.profile ;;
    external-production) selected_profile_template=external-production-v12.profile ;;
    *) fail "unreachable deployment profile" ;;
esac

render_template "$template_root/controller-v12.conf.in" "$stage/config/controller-v12.conf" \
    RELEASE_ROOT "$release_root" CLIENT_GROUP "$client_group" \
    DEPLOYMENT_PROFILE "$deployment_profile" CLEANUP_RESERVE_MS "$cleanup_reserve_ms"
render_template "$template_root/docker-proxy-v12.conf.in" "$stage/config/docker-proxy-v12.conf" \
    RELEASE_ROOT "$release_root" EXECUTOR_GROUP serverware-coder-docker-api \
    CONTROLLER_UID "$controller_uid" EXECUTOR_UID "$executor_uid" \
    DOCKER_API_GID "$docker_api_gid"
render_template "$template_root/log-custody-authority-v12.conf.in" "$stage/config/log-custody-authority-v12.json" \
    RELEASE_ROOT "$release_root" LOG_AUTHORITY_UID "$log_custody_uid" \
    RECEIPT_AUTHORITY_UID "$receipt_authority_uid"
render_template "$template_root/lifecycle-v12.conf.in" "$stage/config/lifecycle-v12.conf" \
    RELEASE_ROOT "$release_root" LIFECYCLE_GROUP serverware-coder-lifecycle-api \
    EXECUTOR_UID "$executor_uid" DOCKER_PROXY_UID "$docker_proxy_uid" \
    CLEANUP_RESERVE_MS "$cleanup_reserve_ms"
render_template "$template_root/lifecycle-privileged-v12.conf.in" "$stage/config/lifecycle-privileged-v12.conf" \
    RELEASE_ROOT "$release_root" LIFECYCLE_UID "$lifecycle_uid" \
    LIFECYCLE_GID "$lifecycle_gid" EXECUTOR_UID "$executor_uid" \
    DOCKER_PROXY_UID "$docker_proxy_uid" CLEANUP_RESERVE_MS "$cleanup_reserve_ms"
render_template "$template_root/docker-lane-policy-v12.conf.in" "$stage/config/docker-lane-policy-v12.conf" \
    RELEASE_ROOT "$release_root" \
    PINNED_PULL_SET_SHA256 "$pinned_pull_set_sha256" \
    EXACT_BUILD_TUPLE_SET_SHA256 "$exact_build_tuple_set_sha256" \
    DOCKER_API_RULE_SET_SHA256 "$docker_api_rule_set_sha256"
render_template "$template_root/five-lane-v12.manifest.in" "$stage/config/five-lane-v12.manifest" \
    RELEASE_ROOT "$release_root" BUILD_DEADLINE_MS "$build_deadline_ms" \
    UNIT_DEADLINE_MS "$unit_deadline_ms" \
    INTEGRATION_DEADLINE_MS "$integration_deadline_ms" \
    E2E_DEADLINE_MS "$e2e_deadline_ms" \
    ATTESTATION_DEADLINE_MS "$attestation_deadline_ms" \
    CLEANUP_RESERVE_MS "$cleanup_reserve_ms"
install -o root -g root -m 0444 "$template_root/trusted-host-v12.profile" \
    "$stage/config/trusted-host-v12.profile"
install -o root -g root -m 0444 "$template_root/external-production-v12.profile" \
    "$stage/config/external-production-v12.profile"
install -o root -g root -m 0444 "$template_root/$selected_profile_template" \
    "$stage/config/deployment-v12.profile"
test "$(document_value "$stage/config/trusted-host-v12.profile" profile_id)" = \
    local-trusted-host \
    && test "$(document_value "$stage/config/trusted-host-v12.profile" integrity_mode)" = \
        UserspaceDigestOnly \
    && test "$(document_value "$stage/config/trusted-host-v12.profile" fs_verity_required)" = \
        false || fail "local trusted-host profile overclaims publication integrity"
test "$(document_value "$stage/config/external-production-v12.profile" activation)" = \
    fail-closed \
    && test "$(document_value "$stage/config/external-production-v12.profile" local_authority_fallback)" = \
        false \
    && test "$(document_value "$stage/config/external-production-v12.profile" installer_generates_hardware_evidence)" = \
        false || fail "external-production profile must remain prerequisite-only and fail-closed"
test "$(document_value "$stage/config/deployment-v12.profile" deployment_profile)" = \
    "$deployment_profile" || fail "selected deployment profile content mismatch"

for unit in $units
do
    render_template \
        "$stage/provisioning/ops/systemd/$unit" "$stage/systemd/$unit" \
        RELEASE_ROOT "$release_root" CLIENT_GROUP "$client_group" \
        PLAN_EXECUTOR_CONFIG_SHA256 \
        "$(sha_file "$stage/config/plan-executor-v12.conf")"
done
for readiness_enforced_unit in \
    serverware-coder-plan-executor-v12.service \
    serverware-coder-readiness-v12.service
do
    grep -Fx \
        "Environment=SERVERWARE_CODER_REQUIRE_PER_INVOCATION_READINESS_V12=1" \
        "$stage/systemd/$readiness_enforced_unit" >/dev/null \
        || fail "rendered systemd unit does not enforce per-invocation readiness: $readiness_enforced_unit"
done

(
    CDPATH= cd -- "$stage/systemd"
    sha256sum $units | LC_ALL=C sort > "$stage/manifest/systemd-units.sha256"
)
(
    CDPATH= cd -- "$stage"
    sha256sum \
        provisioning/scripts/* \
        provisioning/ops/coder-controller-v12/*.in \
        provisioning/ops/coder-controller-v12/*.profile \
        provisioning/ops/coder-controller-v12/*.sh \
        provisioning/ops/coder-controller-v12/hooks/* \
        provisioning/ops/systemd/* |
        LC_ALL=C sort > manifest/provisioning-inputs.sha256
)
(
    CDPATH= cd -- "$stage"
    sha256sum \
        admin/* authorization/* bin/* config/* credentials/* fixtures/* hooks/* \
        network/* policy/* provisioning/scripts/* \
        provisioning/ops/coder-controller-v12/*.in \
        provisioning/ops/coder-controller-v12/*.profile \
        provisioning/ops/coder-controller-v12/*.sh \
        provisioning/ops/coder-controller-v12/hooks/* \
        provisioning/ops/systemd/* runner/* schemas/* \
        source/*.bundle source/*.manifest source/*.sha256 source/*.sig source/*.tar \
        systemd/* trust/* \
        manifest/systemd-units.sha256 manifest/provisioning-inputs.sha256 |
        LC_ALL=C sort > manifest/release-payload.sha256
)

computed_release_manifest=$transaction_root/computed-installed-release-v12.manifest
render_template "$template_root/release-manifest-v12.in" "$computed_release_manifest" \
    RELEASE_ID "$release_id" CONFIG_GENERATION "$config_generation" \
    PREDECESSOR_RELEASE_ID "$predecessor_release_id" \
    PREDECESSOR_CONFIG_GENERATION "$predecessor_config_generation" \
    VALID_FROM_EPOCH "$valid_from_epoch" VALID_UNTIL_EPOCH "$valid_until_epoch" \
    ROLLBACK_FLOOR_GENERATION "$rollback_floor_generation" \
    DEPLOYMENT_PROFILE "$deployment_profile" \
    CLIENT_GROUP "$client_group" CLIENT_GID "$client_gid" \
    EXTERNAL_WITNESS_SOCKET "$external_witness_socket" \
    CONTROLLER_UID "$controller_uid" CONTROLLER_GID "$controller_gid" \
    EXECUTOR_UID "$executor_uid" EXECUTOR_GID "$executor_gid" \
    DOCKER_PROXY_UID "$docker_proxy_uid" DOCKER_PROXY_GID "$docker_proxy_gid" \
    RECEIPT_AUTHORITY_UID "$receipt_authority_uid" \
    RECEIPT_AUTHORITY_GID "$receipt_authority_gid" \
    LOG_CUSTODY_UID "$log_custody_uid" LOG_CUSTODY_GID "$log_custody_gid" \
    FINAL_VERDICT_AUTHORITY_UID "$final_verdict_authority_uid" \
    FINAL_VERDICT_AUTHORITY_GID "$final_verdict_authority_gid" \
    TRUST_GENERATION_AUTHORITY_UID "$trust_generation_authority_uid" \
    TRUST_GENERATION_AUTHORITY_GID "$trust_generation_authority_gid" \
    EXTERNAL_WITNESS_AUTHORITY_UID "$external_witness_authority_uid" \
    EXTERNAL_WITNESS_AUTHORITY_GID "$external_witness_authority_gid" \
    FINAL_SETTLEMENT_AUTHORITY_UID "$final_settlement_authority_uid" \
    FINAL_SETTLEMENT_AUTHORITY_GID "$final_settlement_authority_gid" \
    LIFECYCLE_UID "$lifecycle_uid" LIFECYCLE_GID "$lifecycle_gid" \
    EXECUTOR_API_GID "$executor_api_gid" DOCKER_API_GID "$docker_api_gid" \
    RECEIPT_API_GID "$receipt_api_gid" LOG_API_GID "$log_api_gid" \
    VERDICT_API_GID "$verdict_api_gid" TRUST_API_GID "$trust_api_gid" \
    WITNESS_API_GID "$witness_api_gid" SETTLEMENT_API_GID "$settlement_api_gid" \
    LIFECYCLE_API_GID "$lifecycle_api_gid" \
    LIFECYCLE_PRIVILEGED_API_GID "$lifecycle_privileged_api_gid" \
    CAS_GID "$cas_gid" SOURCE_COMMIT "$source_commit" \
    SOURCE_CANONICAL_BUNDLE_SHA256 "$canonical_source_sha256" \
    SOURCE_NATIVE_SNAPSHOT_SHA256 "$native_snapshot_sha256" \
    SOURCE_INGRESS_DESCRIPTOR_SHA256 "$(sha_file "$stage/source/source-ingress-v12.manifest")" \
    SOURCE_INGRESS_SIGNATURE_SHA256 "$(sha_file "$stage/source/source-ingress-v12.manifest.sig")" \
    NATIVE_SNAPSHOT_PUBLICATION_SHA256 "$(sha_file "$stage/source/native-snapshot-publication-v12.manifest")" \
    NATIVE_SNAPSHOT_PUBLICATION_SIGNATURE_SHA256 "$(sha_file "$stage/source/native-snapshot-publication-v12.manifest.sig")" \
    RELEASE_PAYLOAD_INVENTORY_SHA256 "$(sha_file "$stage/manifest/release-payload.sha256")" \
    PROVISIONING_INPUTS_INVENTORY_SHA256 "$(sha_file "$stage/manifest/provisioning-inputs.sha256")" \
    CONFIG_GENERATION_DOCUMENT_SHA256 "$(sha_file "$stage/authorization/config-generation-v12.manifest")" \
    CONFIG_GENERATION_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/config-generation-v12.manifest.sig")" \
    KEY_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/key-authorization-v12.manifest")" \
    KEY_AUTHORIZATION_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/key-authorization-v12.manifest.sig")" \
    REVOCATION_CHECKPOINT_SHA256 "$(sha_file "$stage/authorization/revocation-checkpoint-v12.manifest")" \
    REVOCATION_CHECKPOINT_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/revocation-checkpoint-v12.manifest.sig")" \
    ROLLBACK_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/rollback-authorization-v12.manifest")" \
    ROLLBACK_AUTHORIZATION_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/rollback-authorization-v12.manifest.sig")" \
    EXTERNAL_WITNESS_CHECKPOINT_SHA256 "$(sha_file "$stage/authorization/external-witness-checkpoint-v12.manifest")" \
    EXTERNAL_WITNESS_CHECKPOINT_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/external-witness-checkpoint-v12.manifest.sig")" \
    DEADLINE_PROFILE_SHA256 "$(sha_file "$stage/policy/lane-deadlines-v12.manifest")" \
    DEADLINE_PROFILE_SIGNATURE_SHA256 "$(sha_file "$stage/policy/lane-deadlines-v12.manifest.sig")" \
    BUILD_DEADLINE_MS "$build_deadline_ms" UNIT_DEADLINE_MS "$unit_deadline_ms" \
    INTEGRATION_DEADLINE_MS "$integration_deadline_ms" E2E_DEADLINE_MS "$e2e_deadline_ms" \
    ATTESTATION_DEADLINE_MS "$attestation_deadline_ms" \
    CLEANUP_RESERVE_MS "$cleanup_reserve_ms" \
    REQUEST_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-test-controller-request.v1.schema.json")" \
    RECEIPT_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-test-controller-receipt.v12.schema.json")" \
    CONTROLLER_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-controller-v12")" \
    CLIENT_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-controller-client-v12")" \
    EXECUTOR_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-plan-executor-v12")" \
    DOCKER_PROXY_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-docker-proxy-v12")" \
    RECEIPT_AUTHORITY_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-receipt-authority-v12")" \
    LOCAL_TRUST_AUTHORITY_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-local-trust-authority-v12")" \
    LOG_CUSTODY_AUTHORITY_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-log-custody-authority-v12")" \
    FINAL_VERDICT_AUTHORITY_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-final-verdict-authority-v12")" \
    LIFECYCLE_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-lifecycle-v12")" \
    LIFECYCLE_PRIVILEGED_BINARY_SHA256 "$(sha_file "$stage/bin/serverware-coder-lifecycle-privileged-v12")" \
    RUNNER_OCI_SHA256 "$(sha_file "$stage/runner/runner.oci.tar")" RUNNER_OCI_DIGEST "$runner_oci_digest" \
    BROWSER_OCI_SHA256 "$(sha_file "$stage/runner/browser.oci.tar")" BROWSER_OCI_DIGEST "$browser_oci_digest" \
    BUILDKIT_OCI_SHA256 "$(sha_file "$stage/runner/buildkit.oci.tar")" BUILDKIT_OCI_DIGEST "$buildkit_oci_digest" \
    DOCKERD_BINARY_SHA256 "$(sha_file "$stage/bin/dockerd-v12")" \
    CONTAINERD_BINARY_SHA256 "$(sha_file "$stage/bin/containerd-v12")" \
    CONTAINERD_SHIM_BINARY_SHA256 "$(sha_file "$stage/bin/containerd-shim-runc-v2-v12")" \
    RUNC_BINARY_SHA256 "$(sha_file "$stage/bin/runc-v12")" \
    WORKFLOW_MANIFEST_SHA256 "$(sha_file "$stage/config/five-lane-v12.manifest")" \
    DOCKER_POLICY_SHA256 "$(sha_file "$stage/config/docker-lane-policy-v12.conf")" \
    DOCKER_ARTIFACT_BINDING_SHA256 "$(sha_file "$stage/policy/docker-artifact-binding-v12.manifest")" \
    DOCKER_ARTIFACT_BINDING_SIGNATURE_SHA256 "$(sha_file "$stage/policy/docker-artifact-binding-v12.manifest.sig")" \
    DOCKER_API_REQUEST_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-docker-api-request.v12.schema.json")" \
    DOCKER_LANE_CAPABILITY_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-docker-lane-capability.v12.schema.json")" \
    DOCKER_NETWORK_MEMBERSHIP_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-docker-network-membership.v12.schema.json")" \
    DOCKER_SERVICE_INSTANCE_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-docker-service-instance.v12.schema.json")" \
    DOCKER_RUNNER_EXECUTION_SCHEMA_SHA256 "$(sha_file "$stage/schemas/coder-docker-runner-execution.v12.schema.json")" \
    READINESS_MANIFEST_SHA256 "$(sha_file "$stage/fixtures/readiness-fixtures-v12.manifest")" \
    READINESS_SIGNATURE_SHA256 "$(sha_file "$stage/fixtures/readiness-fixtures-v12.manifest.sig")" \
    READINESS_FIXTURE_SET_ID "$fixture_set_id" \
    TRUSTED_HOST_PROFILE_SHA256 "$(sha_file "$stage/config/trusted-host-v12.profile")" \
    EXTERNAL_PRODUCTION_PROFILE_SHA256 "$(sha_file "$stage/config/external-production-v12.profile")" \
    SELECTED_DEPLOYMENT_PROFILE_SHA256 "$(sha_file "$stage/config/deployment-v12.profile")" \
    CONTROLLER_CONFIG_SHA256 "$(sha_file "$stage/config/controller-v12.conf")" \
    EXECUTOR_CONFIG_SHA256 "$(sha_file "$stage/config/plan-executor-v12.conf")" \
    EXECUTOR_INVOCATION_INPUTS_SHA256 "$(sha_file "$stage/config/executor-invocation-inputs-v12.json")" \
    DOCKER_PROXY_CONFIG_SHA256 "$(sha_file "$stage/config/docker-proxy-v12.conf")" \
    RECEIPT_AUTHORITY_CONFIG_SHA256 "$(sha_file "$stage/config/receipt-authority-v12.conf")" \
    LOCAL_TRUST_GENERATION_CONFIG_SHA256 "$(sha_file "$stage/config/local-trust-generation-v12.json")" \
    LOCAL_EXTERNAL_WITNESS_CONFIG_SHA256 "$(sha_file "$stage/config/local-external-witness-v12.json")" \
    LOCAL_FINAL_SETTLEMENT_CONFIG_SHA256 "$(sha_file "$stage/config/local-final-settlement-v12.json")" \
    LOG_CUSTODY_AUTHORITY_CONFIG_SHA256 "$(sha_file "$stage/config/log-custody-authority-v12.json")" \
    FINAL_VERDICT_CONFIG_SHA256 "$(sha_file "$stage/config/final-verdict-authority-v12.conf")" \
    LIFECYCLE_CONFIG_SHA256 "$(sha_file "$stage/config/lifecycle-v12.conf")" \
    LIFECYCLE_PRIVILEGED_CONFIG_SHA256 "$(sha_file "$stage/config/lifecycle-privileged-v12.conf")" \
    NETWORK_HOOK_SHA256 "$(sha_file "$stage/hooks/network-lifecycle-v12.sh")" \
    DIND_HOOK_SHA256 "$(sha_file "$stage/hooks/dind-lifecycle-v12.sh")" \
    RUNTIME_HOOK_SHA256 "$(sha_file "$stage/hooks/runtime-directories-v12.sh")" \
    NETWORK_CONTRACT_SHA256 "$(sha_file "$stage/network/network-contract-v12.manifest")" \
    NETWORK_CONTRACT_SIGNATURE_SHA256 "$(sha_file "$stage/network/network-contract-v12.manifest.sig")" \
    HOST_NFT_SHA256 "$(sha_file "$stage/network/host.nft")" \
    HOST_CLEANUP_NFT_SHA256 "$(sha_file "$stage/network/host-cleanup.nft")" \
    BUILD_LANE_NFT_SHA256 "$(sha_file "$stage/network/build-lane.nft")" \
    NO_BUILD_LANE_NFT_SHA256 "$(sha_file "$stage/network/no-build-lane.nft")" \
    LANE_CLEANUP_NFT_SHA256 "$(sha_file "$stage/network/lane-cleanup.nft")" \
    PINNED_PULL_SET_SHA256 "$pinned_pull_set_sha256" \
    EXACT_BUILD_TUPLE_SET_SHA256 "$exact_build_tuple_set_sha256" \
    DOCKER_API_RULE_SET_SHA256 "$docker_api_rule_set_sha256" \
    SYSTEMD_UNITS_MANIFEST_SHA256 "$(sha_file "$stage/manifest/systemd-units.sha256")" \
    REQUESTER_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/requester-public-key.ed25519")" \
    EXTERNAL_WITNESS_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/external-witness-public-key.ed25519")" \
    EXTERNAL_WITNESS_VERIFICATION_KEY_SHA256 "$(sha_file "$stage/trust/external-witness-verification-key.pem")" \
    RELEASE_SIGNER_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/release-bundle-signer-public-key.pem")" \
    CONFIGURATION_AUTHORITY_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/configuration-authority-public-key.pem")" \
    SOURCE_INGRESS_AUTHORITY_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/source-ingress-authority-public-key.pem")" \
    READINESS_FIXTURE_PUBLIC_KEY_SHA256 "$(sha_file "$stage/trust/readiness-fixture-public-key.pem")" \
    CONTROLLER_IDENTITY_SPKI_SHA256 "$controller_identity_spki" \
    PLAN_EXECUTOR_CAPABILITY_SPKI_SHA256 "$plan_executor_spki" \
    DOCKER_PROXY_IDENTITY_SPKI_SHA256 "$docker_proxy_spki" \
    RECEIPT_AUTHORITY_SPKI_SHA256 "$receipt_authority_spki" \
    EXTERNAL_WITNESS_SPKI_SHA256 "$external_witness_spki" \
    FINAL_SETTLEMENT_SPKI_SHA256 "$final_settlement_spki" \
    LOG_CUSTODY_AUTHORITY_SPKI_SHA256 "$log_custody_spki" \
    FINAL_VERDICT_AUTHORITY_SPKI_SHA256 "$final_verdict_spki" \
    LIFECYCLE_AUTHORITY_SPKI_SHA256 "$lifecycle_spki" \
    LIFECYCLE_PRIVILEGED_AUTHORITY_SPKI_SHA256 "$lifecycle_privileged_spki" \
    CONTROLLER_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/controller-identity-key.cred")" \
    PLAN_EXECUTOR_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/plan-executor-capability-key.cred")" \
    DOCKER_PROXY_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/docker-proxy-identity-key.cred")" \
    RECEIPT_AUTHORITY_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/receipt-authority-key.cred")" \
    EXTERNAL_WITNESS_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/external-witness-key.cred")" \
    FINAL_SETTLEMENT_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/final-settlement-key.cred")" \
    LOG_CUSTODY_AUTHORITY_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/log-custody-authority-key.cred")" \
    FINAL_VERDICT_AUTHORITY_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/final-verdict-authority-key.cred")" \
    LIFECYCLE_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/lifecycle-authority-key.cred")" \
    LIFECYCLE_PRIVILEGED_CREDENTIAL_SHA256 "$(sha_file "$stage/credentials/lifecycle-privileged-authority-key.cred")" \
    LOG_CUSTODY_GENESIS_SHA256 "$(sha_file "$stage/authorization/log-custody-genesis-v12.manifest")" \
    LOG_CUSTODY_GENESIS_SIGNATURE_SHA256 "$(sha_file "$stage/authorization/log-custody-genesis-v12.manifest.sig")" \
    LOG_AUTHORITY_KEY_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/log-authority-key-authorization-v12.json")" \
    RECEIPT_AUTHENTICATION_KEY_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/receipt-authentication-key-authorization-v12.json")" \
    TRUST_GENERATION_BUNDLE_SHA256 "$(sha_file "$stage/authorization/trust-generation-bundle-v12.json")" \
    EXTERNAL_WITNESS_KEY_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/external-witness-key-authorization-v12.json")" \
    FINAL_SETTLEMENT_KEY_AUTHORIZATION_SHA256 "$(sha_file "$stage/authorization/final-settlement-key-authorization-v12.json")" \
    FINAL_SETTLEMENT_GENESIS_SHA256 "$(sha_file "$stage/authorization/final-settlement-genesis-v12.json")" \
    ROLLBACK_SCRIPT_SHA256 "$(sha_file "$stage/admin/rollback_coder_controller_v12.sh")" \
    OFFLINE_STATE_QUARANTINE_SCRIPT_SHA256 "$(sha_file "$stage/admin/offline-state-quarantine-v12.sh")" \
    READINESS_ASSET_PREPARER_SHA256 "$(sha_file "$stage/provisioning/ops/coder-controller-v12/prepare-readiness-release-assets-v12.sh")"

cmp -s "$computed_release_manifest" "$expected_release_manifest" \
    || fail "externally signed release manifest does not match the computed release"
test "$(document_value "$expected_release_manifest" identity.executor.uid)" = "$executor_uid" \
    || fail "externally signed release manifest executor UID mismatch"
test "$(document_value "$expected_release_manifest" private_dind.executor_uid)" = "$executor_uid" \
    || fail "externally signed release manifest private DinD executor UID mismatch"
test "$(document_value "$expected_release_manifest" private_dind.admin_create_operation)" = \
    admin-create-private-dind-v12 \
    && test "$(document_value "$expected_release_manifest" private_dind.admin_destroy_operation)" = \
        admin-destroy-private-dind-v12 \
    && test "$(document_value "$expected_release_manifest" private_dind.admin_reconcile_operation)" = \
        admin-reconcile-private-dind-v12 \
    || fail "externally signed release manifest private DinD modes mismatch"
test "$(document_value "$expected_release_manifest" readiness_fixture_set_id)" = \
    "$fixture_set_id" \
    && test "$(document_value "$expected_release_manifest" executor_lifecycle_root_signer_spki_sha256)" = \
        "$lifecycle_privileged_spki" \
    && test "$(document_value "$expected_release_manifest" readiness_before_repository_work_every_invocation)" = \
        true \
    || fail "externally signed release manifest omits readiness or privileged signer binding"
install -o root -g root -m 0444 \
    "$expected_release_manifest" "$stage/manifest/installed-release-v12.manifest"
install -o root -g root -m 0444 \
    "$asset_root/release/installed-release-v12.manifest.sig" \
    "$stage/manifest/installed-release-v12.manifest.sig"

(
    CDPATH= cd -- "$stage"
    sha256sum \
        admin/* authorization/* bin/* config/* credentials/* fixtures/* hooks/* \
        manifest/installed-release-v12.manifest \
        manifest/installed-release-v12.manifest.sig \
        manifest/provisioning-inputs.sha256 manifest/release-payload.sha256 \
        manifest/signed-bundle.sha256 manifest/signed-bundle.sha256.sig \
        manifest/systemd-units.sha256 network/* policy/* \
        provisioning/scripts/* provisioning/ops/coder-controller-v12/*.in \
        provisioning/ops/coder-controller-v12/*.profile \
        provisioning/ops/coder-controller-v12/*.sh \
        provisioning/ops/coder-controller-v12/hooks/* \
        provisioning/ops/systemd/* runner/* schemas/* \
        source/*.bundle source/*.manifest source/*.sha256 source/*.sig source/*.tar \
        systemd/* trust/* |
        LC_ALL=C sort > manifest/release-files.sha256
)

persistent_trust_files="
release-bundle-signer-public-key.pem
configuration-authority-public-key.pem
source-ingress-authority-public-key.pem
external-witness-verification-key.pem
"
new_persistent_trust=$transaction_root/new-persistent-trust
install -o root -g root -m 0600 /dev/null "$new_persistent_trust"
for trust_file in $persistent_trust_files
do
    persistent=$trust_root/$trust_file
    candidate=$stage/trust/$trust_file
    if test -e "$persistent" || test -L "$persistent"; then
        test -f "$persistent" && test ! -L "$persistent" \
            || fail "persistent trust anchor is not a regular file: $persistent"
        test "$(stat -c '%u:%a:%h:%F' "$persistent")" = "0:444:1:regular file" \
            || fail "persistent trust anchor has unsafe metadata: $persistent"
        cmp -s "$persistent" "$candidate" \
            || fail "authority rotation requires a separately authorized procedure: $trust_file"
    else
        printf '%s\n' "$trust_file" >> "$new_persistent_trust"
    fi
done

current_was_active=0
systemctl is-active --quiet "$target_unit" && current_was_active=1 || true
current_was_enabled=0
systemctl is-enabled --quiet "$target_unit" && current_was_enabled=1 || true

stop_units_bounded() {
    timeout --signal=KILL 45s systemctl stop \
        serverware-coder-controller-v12.service \
        serverware-coder-plan-executor-v12.service \
        serverware-coder-docker-proxy-v12.service \
        serverware-coder-lifecycle-v12.service >/dev/null 2>&1 || true
    if systemctl is-active --quiet serverware-coder-private-dind-reconcile-v12.service; then
        timeout --signal=KILL 210s systemctl stop \
            serverware-coder-private-dind-reconcile-v12.service >/dev/null 2>&1 \
            || fail "private DinD reconciliation did not produce bounded terminal cleanup"
    fi
    timeout --signal=KILL 45s systemctl stop "$target_unit" $units >/dev/null 2>&1 || true
    for unit in $units
    do
        case "$unit" in
        serverware-coder-private-dind-reconcile-v12.service) ;;
        *.service)
            systemctl kill --kill-who=all --signal=KILL "$unit" >/dev/null 2>&1 || true
            ;;
        esac
    done
    for unit in $units
    do
        test "$(systemctl is-active "$unit" 2>/dev/null || true)" != active \
            || fail "unit remained active after bounded control-group cleanup: $unit"
    done
}

backup_units() {
    for unit in $units
    do
        target=$systemd_root/$unit
        if test -e "$target" || test -L "$target"; then
            test -f "$target" && test ! -L "$target" \
                || fail "existing systemd unit is not a regular file: $target"
            cp -a -- "$target" "$unit_backup/$unit"
        fi
    done
}

restore_units() {
    for unit in $units
    do
        rm -f -- "$systemd_root/$unit"
        test ! -e "$unit_backup/$unit" \
            || cp -a -- "$unit_backup/$unit" "$systemd_root/$unit"
    done
}

backup_units
rollback_required=1
rollback_install() {
    status=$?
    test "$rollback_required" -eq 1 || exit "$status"
    reconcile_load_state=$(systemctl show --property=LoadState --value \
        serverware-coder-private-dind-reconcile-v12.service 2>/dev/null || true)
    if test "$reconcile_load_state" = loaded \
        && ! timeout --signal=KILL 210s systemctl stop \
            serverware-coder-private-dind-reconcile-v12.service >/dev/null 2>&1
    then
        trap - EXIT HUP INT TERM
        echo "failed release could not complete signed private DinD cleanup; refusing automatic service restoration" >&2
        exit 2
    fi
    timeout --signal=KILL 30s systemctl stop "$target_unit" $units >/dev/null 2>&1 || true
    for unit in $units
    do
        case "$unit" in
        serverware-coder-private-dind-reconcile-v12.service) ;;
        *.service)
            systemctl kill --kill-who=all --signal=KILL "$unit" >/dev/null 2>&1 || true
            ;;
        esac
    done
    if test -n "$current_target"; then
        rm -f -- "$current_link.rollback"
        ln -s "$current_target" "$current_link.rollback"
        mv -Tf "$current_link.rollback" "$current_link"
    else
        rm -f -- "$current_link"
    fi
    if test -d "$release_root" && test ! -L "$release_root"; then
        chattr -R -i "$release_root" >/dev/null 2>&1 || true
        rm -rf -- "$release_root"
    fi
    while IFS= read -r trust_file
    do
        test -n "$trust_file" || continue
        rm -f -- "$trust_root/$trust_file"
    done < "$new_persistent_trust"
    restore_units
    systemctl daemon-reload >/dev/null 2>&1 || true
    if test "$current_was_enabled" -eq 1; then
        systemctl enable "$target_unit" >/dev/null 2>&1 || true
    else
        systemctl disable "$target_unit" >/dev/null 2>&1 || true
    fi
    if test "$current_was_active" -eq 1 && test -n "$current_target"; then
        systemctl start "$target_unit" >/dev/null 2>&1 || true
    fi
    cleanup_transaction
    exit "$status"
}
trap rollback_install EXIT HUP INT TERM

stop_units_bounded
chmod 0555 "$stage"
mv -T "$stage" "$release_root"
chown -hR root:root "$release_root"
chmod -R a-w "$release_root"
chmod 0555 "$release_root"
sync -f "$release_root"
sync -f "$releases_root"
chattr -R +i "$release_root" \
    || fail "release filesystem does not support immutable release directories"

while IFS= read -r trust_file
do
    test -n "$trust_file" || continue
    install -o root -g root -m 0444 \
        "$release_root/trust/$trust_file" "$trust_root/$trust_file"
    sync -f "$trust_root/$trust_file"
done < "$new_persistent_trust"
sync -f "$trust_root"

for unit in $units
do
    install -o root -g root -m 0644 "$release_root/systemd/$unit" "$unit_stage/$unit"
    mv -fT "$unit_stage/$unit" "$systemd_root/$unit"
done
sync -f "$systemd_root"

rm -f -- "$current_link.next"
ln -s "releases/$release_id" "$current_link.next"
mv -Tf "$current_link.next" "$current_link"
sync -f "$install_root"

systemctl daemon-reload
systemctl start "$target_unit"

for unit in \
    serverware-coder-runtime-v12.service \
    serverware-coder-controller-v12.socket \
    serverware-coder-plan-executor-v12.socket \
    serverware-coder-docker-proxy-v12.socket \
    serverware-coder-lifecycle-v12.socket \
    serverware-coder-trust-generation-v12.socket \
    serverware-coder-external-witness-v12.socket \
    serverware-coder-final-settlement-v12.socket \
    serverware-coder-receipt-authority-v12.socket \
    serverware-coder-final-verdict-authority-v12.socket \
    serverware-coder-lifecycle-privileged-v12.socket \
    serverware-coder-log-custody-authority-v12.socket \
    serverware-coder-private-dind-reconcile-v12.service \
    serverware-coder-lifecycle-privileged-v12.service \
    serverware-coder-lifecycle-v12.service \
    serverware-coder-trust-generation-v12.service \
    serverware-coder-external-witness-v12.service \
    serverware-coder-final-settlement-v12.service \
    serverware-coder-log-custody-authority-v12.service \
    serverware-coder-receipt-authority-v12.service \
    serverware-coder-final-verdict-authority-v12.service \
    serverware-coder-docker-proxy-v12.service \
    serverware-coder-plan-executor-v12.service \
    serverware-coder-controller-v12.service \
    serverware-coder-readiness-v12.service
do
    systemctl is-active --quiet "$unit" \
        || fail "required v12 unit is not active after readiness: $unit"
done

systemctl enable "$target_unit"
printf '%s\n' "$current_target" > "$state_root/previous-release"
chown root:root "$state_root/previous-release"
chmod 0600 "$state_root/previous-release"
printf '%s\n' "$config_generation" > "$state_root/active-config-generation"
chown root:root "$state_root/active-config-generation"
chmod 0600 "$state_root/active-config-generation"
sync -f "$state_root/previous-release"
sync -f "$state_root/active-config-generation"
sync -f "$state_root"

rollback_required=0
trap cleanup_transaction EXIT HUP INT TERM
cleanup_transaction
trap - EXIT HUP INT TERM

printf 'installed controller-v12 release %s generation %s profile %s with UserspaceDigestOnly and no hardware-evidence claim\n' \
    "$release_id" "$config_generation" "$deployment_profile"
