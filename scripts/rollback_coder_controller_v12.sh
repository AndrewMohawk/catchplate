#!/bin/sh
set -eu
umask 077

usage() {
    echo "usage: rollback_coder_controller_v12.sh TARGET_RELEASE_ID" >&2
    exit 2
}

fail() {
    echo "$*" >&2
    exit 2
}

validate_release_id() {
    value=$1
    case "$value" in
        ""|.*|*[!A-Za-z0-9._-]*|*..*) fail "release ID is not path-safe" ;;
    esac
    test "${#value}" -le 96 || fail "release ID is too long"
}

require_sha256() {
    value=$1
    label=$2
    case "$value" in ""|*[!0-9a-f]*) fail "$label must be lowercase hexadecimal" ;; esac
    test "${#value}" -eq 64 || fail "$label must contain exactly 64 characters"
}

require_unsigned_integer() {
    value=$1
    label=$2
    case "$value" in ""|*[!0-9]*) fail "$label must be an unsigned integer" ;; esac
}

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

verify_signed_document() {
    document=$1
    signature=$2
    public_key=$3
    test -f "$document" && test ! -L "$document" \
        || fail "signed document is absent or a symlink: $document"
    test -f "$signature" && test ! -L "$signature" \
        || fail "signature is absent or a symlink: $signature"
    openssl pkeyutl -verify -pubin -inkey "$public_key" \
        -rawin -in "$document" -sigfile "$signature" >/dev/null \
        || fail "signed document verification failed: $document"
}

verify_release() {
    release=$1
    manifest=$release/manifest/installed-release-v12.manifest
    verify_signed_document "$manifest" "$manifest.sig" "$release_signer"
    verify_signed_document \
        "$release/manifest/signed-bundle.sha256" \
        "$release/manifest/signed-bundle.sha256.sig" \
        "$release_signer"
    test "$(sha256sum "$release/manifest/release-payload.sha256" | awk '{print $1}')" = \
        "$(document_value "$manifest" release_payload_inventory_sha256)" \
        || fail "release payload inventory is not bound by the signed release manifest"
    (
        CDPATH= cd -- "$release"
        sha256sum --check --strict manifest/release-payload.sha256
        sha256sum --check --strict manifest/release-files.sha256
        sha256sum --check --strict manifest/systemd-units.sha256
        sha256sum --check --strict manifest/provisioning-inputs.sha256
    ) >/dev/null || fail "release file verification failed: $release"
}

test "$#" -eq 1 || usage
test "$(id -u)" -eq 0 || fail "controller-v12 rollback must run as root"
target_release_id=$1
validate_release_id "$target_release_id"

install_root=/opt/serverware/coder-controller-v12
releases_root=$install_root/releases
current_link=$install_root/current
state_root=/var/lib/serverware/coder-controller-v12
staging_parent=$state_root/install-staging
trust_root=/etc/serverware/coder-controller-v12/trust
systemd_root=/etc/systemd/system
target_unit=serverware-coder-v12.target
release_signer=$trust_root/release-bundle-signer-public-key.pem
config_authority=$trust_root/configuration-authority-public-key.pem
witness_verification_key=$trust_root/external-witness-verification-key.pem

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

for path in \
    /opt/serverware "$install_root" "$releases_root" \
    /var/lib/serverware "$state_root" "$staging_parent" \
    /etc/serverware /etc/serverware/coder-controller-v12 "$trust_root" "$systemd_root"
do
    test ! -L "$path" || fail "protected rollback path is a symlink: $path"
done
for authority in "$release_signer" "$config_authority" "$witness_verification_key"
do
    test -f "$authority" && test ! -L "$authority" \
        || fail "persistent rollback authority is unavailable: $authority"
    test "$(stat -c '%u:%a:%h:%F' "$authority")" = "0:444:1:regular file" \
        || fail "persistent rollback authority has unsafe metadata: $authority"
done

install -d -o root -g root -m 0755 /run/lock
exec 9>/run/lock/serverware-coder-controller-v12.install.lock
flock --exclusive --nonblock 9 \
    || fail "another controller-v12 install or rollback transaction is active"
chmod 0600 /run/lock/serverware-coder-controller-v12.install.lock

test -L "$current_link" || fail "current release link is absent or not a symlink"
current_target=$(readlink "$current_link")
case "$current_target" in releases/*) ;; *) fail "current release link target is unsafe" ;; esac
current_release_id=${current_target#releases/}
validate_release_id "$current_release_id"
test "$current_release_id" != "$target_release_id" || {
    echo "controller-v12 release $target_release_id is already current"
    exit 0
}

current_release=$install_root/$current_target
target_release=$releases_root/$target_release_id
test -d "$current_release" && test ! -L "$current_release" \
    || fail "current release directory is invalid"
test -d "$target_release" && test ! -L "$target_release" \
    || fail "requested rollback release directory is invalid"

self_path=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)/$(basename -- "$0")
test "$self_path" = "$current_release/admin/rollback_coder_controller_v12.sh" \
    || fail "rollback must execute from the active signed release"

verify_release "$current_release"
verify_release "$target_release"

current_manifest=$current_release/manifest/installed-release-v12.manifest
target_manifest=$target_release/manifest/installed-release-v12.manifest
test "$(document_value "$current_manifest" release_id)" = "$current_release_id" \
    || fail "active release manifest ID mismatch"
test "$(document_value "$target_manifest" release_id)" = "$target_release_id" \
    || fail "target release manifest ID mismatch"
current_generation=$(document_value "$current_manifest" config_generation)
target_generation=$(document_value "$target_manifest" config_generation)
rollback_floor=$(document_value "$current_manifest" rollback_floor_generation)
require_unsigned_integer "$current_generation" "current generation"
require_unsigned_integer "$target_generation" "target generation"
require_unsigned_integer "$rollback_floor" "rollback floor"
test "$target_generation" -ge "$rollback_floor" \
    || fail "requested target is below the signed rollback floor"
test "$(document_value "$current_manifest" predecessor_release_id)" = "$target_release_id" \
    || fail "requested target is not the active release's signed predecessor"
test "$(document_value "$current_manifest" predecessor_config_generation)" = \
    "$target_generation" || fail "signed predecessor generation mismatch"

current_config_doc=$current_release/authorization/config-generation-v12.manifest
target_config_doc=$target_release/authorization/config-generation-v12.manifest
rollback_auth=$current_release/authorization/rollback-authorization-v12.manifest
witness_checkpoint=$current_release/authorization/external-witness-checkpoint-v12.manifest
current_revocation=$current_release/authorization/revocation-checkpoint-v12.manifest
target_revocation=$target_release/authorization/revocation-checkpoint-v12.manifest
current_key_authorization=$current_release/authorization/key-authorization-v12.manifest
target_key_authorization=$target_release/authorization/key-authorization-v12.manifest

verify_signed_document "$current_config_doc" "$current_config_doc.sig" "$config_authority"
verify_signed_document "$target_config_doc" "$target_config_doc.sig" "$config_authority"
verify_signed_document "$rollback_auth" "$rollback_auth.sig" "$config_authority"
verify_signed_document "$current_revocation" "$current_revocation.sig" "$config_authority"
verify_signed_document "$target_revocation" "$target_revocation.sig" "$config_authority"
verify_signed_document \
    "$current_key_authorization" "$current_key_authorization.sig" "$config_authority"
verify_signed_document \
    "$target_key_authorization" "$target_key_authorization.sig" "$config_authority"
verify_signed_document \
    "$witness_checkpoint" "$witness_checkpoint.sig" "$witness_verification_key"
for signed_document in \
    "$current_config_doc" "$target_config_doc" "$rollback_auth" \
    "$current_revocation" "$target_revocation" "$current_key_authorization" \
    "$target_key_authorization" "$witness_checkpoint"
do
    require_document_version "$signed_document"
done

test "$(document_value "$current_config_doc" config_generation)" = "$current_generation" \
    || fail "active configuration generation mismatch"
test "$(document_value "$target_config_doc" config_generation)" = "$target_generation" \
    || fail "target configuration generation mismatch"
for release_pair in \
    "$current_manifest:$current_config_doc" \
    "$target_manifest:$target_config_doc"
do
    release_manifest=${release_pair%%:*}
    generation_manifest=${release_pair#*:}
    release_executor_uid=$(document_value "$release_manifest" identity.executor.uid)
    generation_executor_uid=$(document_value "$generation_manifest" identity.executor.uid)
    require_unsigned_integer "$release_executor_uid" "release executor UID"
    test "$release_executor_uid" = "$generation_executor_uid" \
        && test "$(document_value "$release_manifest" private_dind.executor_uid)" = \
            "$generation_executor_uid" \
        && test "$(document_value "$generation_manifest" private_dind.executor_uid)" = \
            "$generation_executor_uid" \
        || fail "rollback release/config private DinD executor UID mismatch"
    test "$(document_value "$release_manifest" private_dind.admin_create_operation)" = \
        admin-create-private-dind-v12 \
        && test "$(document_value "$release_manifest" private_dind.admin_destroy_operation)" = \
            admin-destroy-private-dind-v12 \
        && test "$(document_value "$release_manifest" private_dind.admin_reconcile_operation)" = \
            admin-reconcile-private-dind-v12 \
        || fail "rollback release does not bind the fixed private DinD helper modes"
done
test "$(document_value "$current_config_doc" predecessor_release_id)" = "$target_release_id" \
    || fail "active configuration predecessor mismatch"
test "$(document_value "$current_config_doc" predecessor_config_generation)" = \
    "$target_generation" || fail "active configuration predecessor generation mismatch"
test "$(document_value "$rollback_auth" source_release_id)" = "$current_release_id" \
    || fail "rollback authorization source release mismatch"
test "$(document_value "$rollback_auth" source_config_generation)" = "$current_generation" \
    || fail "rollback authorization source generation mismatch"
test "$(document_value "$rollback_auth" target_release_id)" = "$target_release_id" \
    || fail "rollback authorization target release mismatch"
test "$(document_value "$rollback_auth" target_config_generation)" = "$target_generation" \
    || fail "rollback authorization target generation mismatch"
test "$(document_value "$rollback_auth" rollback_floor_generation)" = "$rollback_floor" \
    || fail "rollback authorization floor mismatch"

verify_authorized_release_keys() {
    release_manifest=$1
    authorization=$2
    revocation=$3
    test "$(document_value "$authorization" config_generation)" = \
        "$(document_value "$release_manifest" config_generation)" \
        || fail "key authorization generation does not match release"
    for key_binding in \
        controller-identity:controller_identity_spki_sha256 \
        plan-executor-capability:plan_executor_capability_spki_sha256 \
        docker-proxy-identity:docker_proxy_identity_spki_sha256 \
        receipt-authority:receipt_authority_spki_sha256 \
        final-verdict-authority:final_verdict_authority_spki_sha256 \
        lifecycle-authority:lifecycle_authority_spki_sha256 \
        lifecycle-privileged-authority:lifecycle_privileged_authority_spki_sha256
    do
        key_name=${key_binding%%:*}
        manifest_field=${key_binding#*:}
        spki=$(document_value "$release_manifest" "$manifest_field")
        require_sha256 "$spki" "release authority SPKI"
        test "$(document_value "$authorization" "key.$key_name.spki_sha256")" = "$spki" \
            || fail "release authority SPKI is not authorized: $key_name"
        test "$(document_value "$authorization" "key.$key_name.status")" = authorized \
            || fail "release authority key is not authorized: $key_name"
        revoked_count=$(document_value "$revocation" revoked_spki_count)
        require_unsigned_integer "$revoked_count" "revoked SPKI count"
        test "$revoked_count" -le 4096 || fail "revocation checkpoint is unreasonably large"
        revoked_index=0
        while test "$revoked_index" -lt "$revoked_count"
        do
            revoked_spki=$(document_value "$revocation" "revoked_spki.$revoked_index")
            require_sha256 "$revoked_spki" "revoked SPKI"
            test "$revoked_spki" != "$spki" \
                || fail "release authority key is revoked: $key_name"
            revoked_index=$((revoked_index + 1))
        done
    done
}

verify_authorized_release_keys \
    "$current_manifest" "$current_key_authorization" "$current_revocation"
verify_authorized_release_keys \
    "$target_manifest" "$target_key_authorization" "$target_revocation"

witness_checkpoint_digest=$(sha256sum "$witness_checkpoint" | awk '{print $1}')
expected_witness_digest=$(document_value "$rollback_auth" witness_checkpoint_sha256)
require_sha256 "$expected_witness_digest" "rollback witness checkpoint digest"
test "$witness_checkpoint_digest" = "$expected_witness_digest" \
    || fail "rollback authorization does not bind the witness checkpoint"
witness_sequence=$(document_value "$witness_checkpoint" witness_sequence)
minimum_witness_sequence=$(document_value "$rollback_auth" minimum_witness_sequence)
require_unsigned_integer "$witness_sequence" "witness sequence"
require_unsigned_integer "$minimum_witness_sequence" "minimum witness sequence"
test "$witness_sequence" -ge "$minimum_witness_sequence" \
    || fail "witness checkpoint is below the rollback authorization floor"
test "$(document_value "$witness_checkpoint" rollback_floor_generation)" = "$rollback_floor" \
    || fail "witness checkpoint rollback floor mismatch"

now_epoch=$(date +%s)
for validity in \
    "$(document_value "$rollback_auth" valid_until_epoch)" \
    "$(document_value "$witness_checkpoint" valid_until_epoch)" \
    "$(document_value "$current_revocation" valid_until_epoch)" \
    "$(document_value "$target_revocation" valid_until_epoch)" \
    "$(document_value "$current_key_authorization" valid_until_epoch)" \
    "$(document_value "$target_key_authorization" valid_until_epoch)" \
    "$(document_value "$target_config_doc" valid_until_epoch)"
do
    require_unsigned_integer "$validity" "rollback validity"
    test "$now_epoch" -le "$validity" || fail "a rollback trust document has expired"
done
for valid_from in \
    "$(document_value "$current_key_authorization" valid_from_epoch)" \
    "$(document_value "$target_key_authorization" valid_from_epoch)" \
    "$(document_value "$target_config_doc" valid_from_epoch)"
do
    require_unsigned_integer "$valid_from" "rollback valid-from time"
    test "$now_epoch" -ge "$valid_from" \
        || fail "a rollback trust document is not yet valid"
done

current_script_digest=$(sha256sum "$self_path" | awk '{print $1}')
test "$current_script_digest" = "$(document_value "$current_manifest" rollback_script_sha256)" \
    || fail "active rollback script is not bound by the release manifest"

external_witness_socket=$(document_value "$current_manifest" external_witness_socket)
case "$external_witness_socket" in /*) ;; *) fail "signed witness socket is not absolute" ;; esac
test -S "$external_witness_socket" && test ! -L "$external_witness_socket" \
    || fail "external witness socket is unavailable"

install -d -o root -g root -m 0700 "$staging_parent"
transaction_root=$(mktemp -d "$staging_parent/rollback.$current_release_id.XXXXXX")
unit_backup=$transaction_root/systemd-backup
install -d -o root -g root -m 0700 "$unit_backup"

cleanup_transaction() {
    rm -rf -- "$transaction_root"
}
trap cleanup_transaction EXIT HUP INT TERM

for unit in $units
do
    target=$systemd_root/$unit
    test -f "$target" && test ! -L "$target" \
        || fail "active systemd unit is absent or unsafe: $target"
    cp -a -- "$target" "$unit_backup/$unit"
done

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
            || fail "unit remained active after bounded cleanup: $unit"
    done
}

rollback_required=1
restore_current() {
    status=$?
    test "$rollback_required" -eq 1 || exit "$status"
    reconcile_load_state=$(systemctl show --property=LoadState --value \
        serverware-coder-private-dind-reconcile-v12.service 2>/dev/null || true)
    if test "$reconcile_load_state" = loaded \
        && ! timeout --signal=KILL 210s systemctl stop \
            serverware-coder-private-dind-reconcile-v12.service >/dev/null 2>&1
    then
        trap - EXIT HUP INT TERM
        echo "rollback target could not complete signed private DinD cleanup; refusing automatic service restoration" >&2
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
        rm -f -- "$systemd_root/$unit"
        cp -a -- "$unit_backup/$unit" "$systemd_root/$unit"
    done
    rm -f -- "$current_link.failed"
    ln -s "$current_target" "$current_link.failed"
    mv -Tf "$current_link.failed" "$current_link"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if test "$current_was_enabled" -eq 1; then
        systemctl enable "$target_unit" >/dev/null 2>&1 || true
    fi
    systemctl start "$target_unit" >/dev/null 2>&1 || true
    cleanup_transaction
    exit "$status"
}
trap restore_current EXIT HUP INT TERM

# No service is stopped and no symlink is changed before all checks above pass.
stop_units_bounded

for unit in $units
do
    install -o root -g root -m 0644 "$target_release/systemd/$unit" "$systemd_root/$unit.next"
    mv -fT "$systemd_root/$unit.next" "$systemd_root/$unit"
done
sync -f "$systemd_root"

rm -f -- "$current_link.next"
ln -s "releases/$target_release_id" "$current_link.next"
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
        || fail "rollback readiness gate failed: $unit"
done

if test "$current_was_enabled" -eq 1; then
    systemctl enable "$target_unit"
else
    systemctl disable "$target_unit"
fi
printf '%s\n' "$current_target" > "$state_root/previous-release"
chown root:root "$state_root/previous-release"
chmod 0600 "$state_root/previous-release"
printf '%s\n' "$target_generation" > "$state_root/active-config-generation"
chown root:root "$state_root/active-config-generation"
chmod 0600 "$state_root/active-config-generation"
sync -f "$state_root/previous-release"
sync -f "$state_root/active-config-generation"
sync -f "$state_root"

rollback_required=0
trap cleanup_transaction EXIT HUP INT TERM
cleanup_transaction
trap - EXIT HUP INT TERM
printf 'rolled controller-v12 back from %s to signed predecessor %s\n' \
    "$current_release_id" "$target_release_id"
