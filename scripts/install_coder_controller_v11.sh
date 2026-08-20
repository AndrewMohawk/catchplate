#!/bin/sh
set -eu
umask 077

usage() {
    echo "usage: $0 SOURCE_ROOT ARTIFACT_ROOT CLIENT_UID CLIENT_GID PLAN_FRAGMENT STATIC_ASSET_ROOT REQUEST_TEMPLATE_DIR PINNED_INPUT_MANIFEST PINNED_INPUT_MANIFEST_SHA256" >&2
    exit 2
}

test "$#" -eq 9 || usage
test "$(id -u)" -eq 0 || {
    echo "installer must run as root" >&2
    exit 1
}

source_root=$1
artifact_root=$2
client_uid=$3
client_gid=$4
plan_fragment=$5
static_asset_root=$6
request_template_dir=$7
pinned_input_manifest=$8
pinned_input_manifest_sha256=$9
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
plan_bundle_dir=$static_asset_root/plans
release_bin_dir=$static_asset_root/bin
runner_bundle_dir=$static_asset_root/runner
network_bundle_dir=$static_asset_root/network
runner_archive=$runner_bundle_dir/serverware-coder-runner-v11.tar
runner_image_file=$runner_bundle_dir/serverware-coder-runner-v11.image
pre_seal_rules=$network_bundle_dir/pre-seal.nft
post_seal_rules=$network_bundle_dir/post-seal.nft
dockerd_path=${SERVERWARE_CONTROLLER_DOCKERD_PATH:-/usr/bin/dockerd}
docker_path=${SERVERWARE_CONTROLLER_DOCKER_PATH:-/usr/bin/docker}
nft_path=${SERVERWARE_CONTROLLER_NFT_PATH:-/usr/sbin/nft}

config_dir=/etc/serverware/coder-controller-v11
controller_config=$config_dir/controller.conf
proxy_config=$config_dir/docker-proxy.conf
manifest_file=$config_dir/trusted-plan-manifest-v11.bin
receipt_seed=$config_dir/receipt-signing-key.ed25519
receipt_public=$config_dir/receipt-public-key.ed25519
requester_seed=$config_dir/requester-signing-key.ed25519
requester_public=$config_dir/requester-public-key.ed25519
final_verdict_public=$config_dir/final-verdict-public-key.ed25519
request_template_target=$config_dir/request-templates
pinned_input_manifest_target=$config_dir/pinned-inputs.sha256
pinned_input_manifest_digest_target=$config_dir/pinned-inputs.sha256.digest
network_target=$config_dir/network
plan_target=/opt/serverware/controller-plans
runner_target=/opt/serverware/controller-runner-v11
state_dir=/var/lib/serverware/coder-controller-v11
proxy_state_dir=/var/lib/serverware/coder-docker-proxy-v11
controller_service=/etc/systemd/system/serverware-coder-controller-v11.service
proxy_service=/etc/systemd/system/serverware-coder-docker-proxy-v11.service

safe_config_value() {
    case "$1" in
        ""|*[!A-Za-z0-9_./:@+-]*|*"="*|*"#"*)
            echo "unsafe structured config value: $1" >&2
            exit 2
            ;;
    esac
}

case "$source_root:$artifact_root" in
    /*:/*) ;;
    *) echo "source and artifact roots must be absolute" >&2; exit 2 ;;
esac
safe_config_value "$source_root"
safe_config_value "$artifact_root"
case "$client_uid:$client_gid" in
    *[!0-9:]*|:*|*:) echo "client UID/GID must be decimal" >&2; exit 2 ;;
esac
test "$source_root" != "$artifact_root"
case "$source_root/" in "$artifact_root/"*) exit 2 ;; esac
case "$artifact_root/" in "$source_root/"*) exit 2 ;; esac
test -d "$source_root" && test ! -L "$source_root"
test -f "$plan_fragment" && test ! -L "$plan_fragment"
test "$(stat -c '%u:%a:%h:%F' "$plan_fragment")" = "0:400:1:regular file"
test -d "$plan_bundle_dir" && test ! -L "$plan_bundle_dir"
test -d "$release_bin_dir" && test ! -L "$release_bin_dir"
test -d "$request_template_dir" && test ! -L "$request_template_dir"
test -f "$pinned_input_manifest" && test ! -L "$pinned_input_manifest"
test "$(stat -c '%u:%a:%h:%F' "$pinned_input_manifest")" = "0:400:1:regular file"
case "$pinned_input_manifest_sha256" in
    *[!0-9a-f]*|"") echo "pinned input manifest digest must be lowercase SHA-256" >&2; exit 2 ;;
esac
test "${#pinned_input_manifest_sha256}" -eq 64
test "$(sha256sum "$pinned_input_manifest" | awk '{print $1}')" = "$pinned_input_manifest_sha256"
manifest_directory=$(CDPATH= cd -- "$(dirname -- "$pinned_input_manifest")" && pwd -P)
(CDPATH= cd -- "$manifest_directory" && sha256sum --check --strict "$(basename -- "$pinned_input_manifest")")

require_pinned_input() {
    input=$1
    input_digest=$(sha256sum "$input" | awk '{print $1}')
    grep -Fx "$input_digest  $input" "$pinned_input_manifest" >/dev/null || {
        echo "pinned input manifest lacks exact absolute binding: $input" >&2
        exit 2
    }
}

for input in \
    "$runner_archive" "$runner_image_file" \
    "$pre_seal_rules" "$post_seal_rules" \
    "$dockerd_path" "$docker_path" "$nft_path"
do
    test -f "$input" && test ! -L "$input" || {
        echo "missing regular pinned controller input: $input" >&2
        exit 2
    }
    test "$(stat -c '%u:%h:%F' "$input")" = "0:1:regular file" || {
        echo "pinned controller input must be root-owned and single-link: $input" >&2
        exit 2
    }
    input_mode=$(stat -c '%a' "$input")
    test "$((0$input_mode & 022))" -eq 0 || {
        echo "pinned controller input must not be group/world writable: $input" >&2
        exit 2
    }
done
runner_image=$(sed -n '1p' "$runner_image_file")
test -z "$(sed -n '2p' "$runner_image_file")"
case "$runner_image" in
    *@sha256:????????????????????????????????????????????????????????????????) ;;
    *) echo "runner image must be one digest-addressed reference" >&2; exit 2 ;;
esac
runner_digest=${runner_image##*@sha256:}
case "$runner_digest" in *[!0-9a-f]*) exit 2 ;; esac

for binary in \
    serverware-coder-controller \
    serverware-coder-controller-client \
    serverware-coder-docker-proxy \
    serverware-coder-controller-launcher \
    serverware-coder-plan
do
    test -f "$release_bin_dir/$binary" && test ! -L "$release_bin_dir/$binary" || {
        echo "missing prebuilt static release binary: $release_bin_dir/$binary" >&2
        exit 2
    }
    require_pinned_input "$release_bin_dir/$binary"
done

plan_immutable_paths=$(mktemp /var/tmp/serverware-plan-paths.XXXXXX)
trap 'rm -f "$plan_immutable_paths"' EXIT HUP INT TERM
while IFS='=' read -r key target
do
    case "$key" in
        plan.*.executable|plan.*.closure.exec.*) ;;
        plan.*.closure.read.*)
            echo "v11 concrete plans must not use an interpreter/DSO/read closure" >&2
            exit 2
            ;;
        *) continue ;;
    esac
    case "$target" in
        /opt/serverware/controller-plans/*)
            relative=${target#/opt/serverware/controller-plans/}
            case "/$relative/" in
                *"/../"*|*"/./"*|*"//"*) exit 2 ;;
            esac
            test -f "$plan_bundle_dir/$relative" && test ! -L "$plan_bundle_dir/$relative"
            require_pinned_input "$plan_bundle_dir/$relative"
            printf '%s\n' "$target" >> "$plan_immutable_paths"
            ;;
        *)
            echo "v11 concrete plan executable must be in the installed static plan bundle: $target" >&2
            exit 2
            ;;
    esac
done < "$plan_fragment"
test "$(sort -u "$plan_immutable_paths" | wc -l)" -eq 5 || {
    echo "plan fragment must resolve to exactly five static plan executables" >&2
    exit 2
}

for plan_label in \
    serverware-build-v1 \
    serverware-unit-no-build-v1 \
    serverware-integration-no-build-v1 \
    serverware-e2e-no-build-v1 \
    serverware-attestation-no-build-v1
do
    template_source=$request_template_dir/$plan_label.request.json
    digest_source=$request_template_dir/$plan_label.plan-configuration.sha256
    test -f "$template_source" && test ! -L "$template_source"
    test -f "$digest_source" && test ! -L "$digest_source"
    require_pinned_input "$template_source"
    require_pinned_input "$digest_source"
    value=$(sed -n '1p' "$digest_source")
    test -z "$(sed -n '2p' "$digest_source")"
    case "$value" in *[!0-9a-f]*|"") exit 2 ;; esac
    test "${#value}" -eq 64
done
test -f "$request_template_dir/final-verdict-public-key.ed25519"
test ! -L "$request_template_dir/final-verdict-public-key.ed25519"
test "$(wc -c < "$request_template_dir/final-verdict-public-key.ed25519")" -eq 32
require_pinned_input "$request_template_dir/final-verdict-public-key.ed25519"
for input in \
    "$plan_fragment" "$runner_archive" "$runner_image_file" \
    "$pre_seal_rules" "$post_seal_rules" \
    "$dockerd_path" "$docker_path" "$nft_path" \
    "$repo_root/ops/systemd/serverware-coder-controller-v11.service" \
    "$repo_root/ops/systemd/serverware-coder-docker-proxy-v11.service" \
    "$repo_root/ops/coder-controller-v11/controller-v11.conf.in" \
    "$repo_root/ops/coder-controller-v11/docker-proxy-v11.conf.in" \
    "$repo_root/ops/coder-controller-v11/five-plan-v11.conf" \
    "$repo_root/ops/coder-controller-v11/five-plan-v11.manifest"
do
    require_pinned_input "$input"
done

test -e /run/netns/serverware-coder-controller-v11 || {
    echo "missing controller network namespace: /run/netns/serverware-coder-controller-v11" >&2
    exit 2
}
test -S /run/serverware/controller-receipt-authority-v11.sock || {
    echo "missing root receipt authority socket" >&2
    exit 2
}
test -f /etc/systemd/system/serverware-coder-receipt-authority-v11.service \
    || test -f /usr/lib/systemd/system/serverware-coder-receipt-authority-v11.service \
    || {
        echo "missing receipt authority systemd service" >&2
        exit 2
    }

transaction_root=$(mktemp -d /var/lib/serverware/.coder-controller-v11-install.XXXXXX)
stage=$transaction_root/stage
backup=$transaction_root/backup
mkdir -p \
    "$stage/config/request-templates" "$stage/config/network" \
    "$stage/bin" "$stage/plans" "$stage/runner" "$stage/systemd" \
    "$backup"
chmod 0700 "$transaction_root" "$stage" "$backup"

cleanup_staging() {
    rm -rf -- "$transaction_root"
    rm -f -- "$plan_immutable_paths"
}
trap cleanup_staging EXIT HUP INT TERM

generate_seed() {
    output=$1
    existing=$2
    if test -f "$existing" && test ! -L "$existing" \
        && test "$(wc -c < "$existing")" -eq 32; then
        install -o root -g root -m 0400 "$existing" "$output"
        return
    fi
    temporary=$transaction_root/seed.der
    openssl genpkey -algorithm ED25519 -outform DER -out "$temporary"
    test "$(wc -c < "$temporary")" -eq 48
    tail -c 32 "$temporary" > "$output"
    rm -f "$temporary"
    chown root:root "$output"
    chmod 0400 "$output"
    test "$(wc -c < "$output")" -eq 32
}

generate_seed "$stage/config/receipt-signing-key.ed25519" "$receipt_seed"
generate_seed "$stage/config/requester-signing-key.ed25519" "$requester_seed"
install -o root -g root -m 0444 \
    "$request_template_dir/final-verdict-public-key.ed25519" \
    "$stage/config/final-verdict-public-key.ed25519"
install -o root -g root -m 0400 \
    "$pinned_input_manifest" "$stage/config/pinned-inputs.sha256"
printf '%s\n' "$pinned_input_manifest_sha256" \
    > "$stage/config/pinned-inputs.sha256.digest"
chmod 0400 "$stage/config/pinned-inputs.sha256.digest"

for plan_label in \
    serverware-build-v1 \
    serverware-unit-no-build-v1 \
    serverware-integration-no-build-v1 \
    serverware-e2e-no-build-v1 \
    serverware-attestation-no-build-v1
do
    install -o root -g root -m 0444 \
        "$request_template_dir/$plan_label.request.json" \
        "$stage/config/request-templates/$plan_label.request.json"
done

for binary in \
    serverware-coder-controller \
    serverware-coder-controller-client \
    serverware-coder-docker-proxy \
    serverware-coder-controller-launcher \
    serverware-coder-plan
do
    install -o root -g root -m 0555 \
        "$release_bin_dir/$binary" "$stage/bin/$binary"
done

sort -u "$plan_immutable_paths" |
while IFS= read -r target
do
    relative=${target#/opt/serverware/controller-plans/}
    install -d -o root -g root -m 0555 "$stage/plans/$(dirname -- "$relative")"
    install -o root -g root -m 0555 \
        "$plan_bundle_dir/$relative" "$stage/plans/$relative"
done
install -o root -g root -m 0444 "$runner_archive" \
    "$stage/runner/serverware-coder-runner-v11.tar"
install -o root -g root -m 0444 "$runner_image_file" \
    "$stage/runner/serverware-coder-runner-v11.image"
install -o root -g root -m 0444 "$pre_seal_rules" \
    "$stage/config/network/pre-seal.nft"
install -o root -g root -m 0444 "$post_seal_rules" \
    "$stage/config/network/post-seal.nft"

{
    printf '%s\n' \
        'mode=trusted-host-v11' \
        'socket_path=/run/serverware/coder-controller-v11.sock' \
        'socket_uid=0' \
        "socket_gid=$client_gid" \
        'socket_mode=0o660' \
        'max_connections=32' \
        'first_frame_timeout_ms=5000' \
        "allow_uid=$client_uid" \
        "allow_gid=$client_gid" \
        'state_dir=/var/lib/serverware/coder-controller-v11' \
        "source_root=$source_root" \
        'signing_key_path=/etc/serverware/coder-controller-v11/receipt-signing-key.ed25519' \
        'public_key_path=/etc/serverware/coder-controller-v11/receipt-public-key.ed25519' \
        'requester_public_key_path=/etc/serverware/coder-controller-v11/requester-public-key.ed25519' \
        'final_verdict_public_key_path=/etc/serverware/coder-controller-v11/final-verdict-public-key.ed25519' \
        'cgroup_root=/sys/fs/cgroup/serverware-coder-controller-v11' \
        'trust_epoch=1' \
        'revocation_epoch=1' \
        'deadline.serverware-build-v1.ms=7200000' \
        'deadline.serverware-unit-no-build-v1.ms=900000' \
        'deadline.serverware-integration-no-build-v1.ms=1800000' \
        'deadline.serverware-e2e-no-build-v1.ms=2700000' \
        'deadline.serverware-attestation-no-build-v1.ms=900000' \
        "artifact_path=$artifact_root" \
        'denied_socket_path=/run/docker.sock' \
        'denied_socket_path=/var/run/docker.sock' \
        'denied_socket_path=/run/containerd/containerd.sock' \
        'denied_socket_path=/run/podman/podman.sock'
    while IFS='=' read -r key value
    do
        test -n "$key" || continue
        case "$key" in \#*) continue ;; esac
        test "$value" = '@SOURCE_ROOT@' && value=$source_root
        case "$key:$value" in
            plan.*.configuration_sha256:@REQUEST_TEMPLATE@)
                plan_label=${key#plan.}
                plan_label=${plan_label%.configuration_sha256}
                value=$(sed -n '1p' "$request_template_dir/$plan_label.plan-configuration.sha256")
                ;;
        esac
        safe_config_value "$key"
        safe_config_value "$value"
        printf '%s=%s\n' "$key" "$value"
    done < "$plan_fragment"
} > "$stage/config/controller.conf"
chmod 0400 "$stage/config/controller.conf"

dockerd_sha256=$(sha256sum "$dockerd_path" | awk '{print $1}')
docker_sha256=$(sha256sum "$docker_path" | awk '{print $1}')
nft_sha256=$(sha256sum "$nft_path" | awk '{print $1}')
pre_seal_rules_sha256=$(sha256sum "$pre_seal_rules" | awk '{print $1}')
post_seal_rules_sha256=$(sha256sum "$post_seal_rules" | awk '{print $1}')
runner_archive_sha256=$(sha256sum "$runner_archive" | awk '{print $1}')
{
    printf '%s\n' \
        'version=11' \
        'executor_socket=/run/serverware/controller-plan-executor-v11.sock' \
        'proxy_socket=/run/serverware/controller-docker-proxy.sock' \
        'private_socket=/run/serverware/private-docker-v11.sock' \
        'state_root=/var/lib/serverware/coder-docker-proxy-v11' \
        "source_root=$source_root" \
        "artifact_root=$artifact_root" \
        "client_uid=$client_uid" \
        "client_gid=$client_gid" \
        "dockerd_path=$dockerd_path" \
        "dockerd_sha256=$dockerd_sha256" \
        "docker_path=$docker_path" \
        "docker_sha256=$docker_sha256" \
        "nft_path=$nft_path" \
        "nft_sha256=$nft_sha256" \
        'pre_seal_rules=/etc/serverware/coder-controller-v11/network/pre-seal.nft' \
        "pre_seal_rules_sha256=$pre_seal_rules_sha256" \
        'post_seal_rules=/etc/serverware/coder-controller-v11/network/post-seal.nft' \
        "post_seal_rules_sha256=$post_seal_rules_sha256" \
        'runner_archive=/opt/serverware/controller-runner-v11/serverware-coder-runner-v11.tar' \
        "runner_archive_sha256=$runner_archive_sha256" \
        "runner_image=$runner_image"
} > "$stage/config/docker-proxy.conf"
chmod 0400 "$stage/config/docker-proxy.conf"

install -o root -g root -m 0644 \
    "$repo_root/ops/systemd/serverware-coder-controller-v11.service" \
    "$stage/systemd/serverware-coder-controller-v11.service"
install -o root -g root -m 0644 \
    "$repo_root/ops/systemd/serverware-coder-docker-proxy-v11.service" \
    "$stage/systemd/serverware-coder-docker-proxy-v11.service"

install -d -o "$client_uid" -g "$client_gid" -m 0700 "$artifact_root"
install -d -o root -g root -m 0700 "$state_dir" "$proxy_state_dir"
install -d -o root -g root -m 0700 \
    "$state_dir/acceptance" "$state_dir/builds" \
    "$state_dir/evidence" "$state_dir/orphan-journal" \
    "$state_dir/cas" "$state_dir/cas/sha256"

controller_was_active=0
proxy_was_active=0
systemctl is-active --quiet serverware-coder-controller-v11.service \
    && controller_was_active=1 || true
systemctl is-active --quiet serverware-coder-docker-proxy-v11.service \
    && proxy_was_active=1 || true
systemctl stop serverware-coder-controller-v11.service \
    serverware-coder-docker-proxy-v11.service || true

backup_target() {
    target=$1
    name=$2
    if test -e "$target" || test -L "$target"; then
        cp -a -- "$target" "$backup/$name"
    fi
}
backup_target "$config_dir" config
backup_target "$plan_target" plans
backup_target "$runner_target" runner
backup_target "$controller_service" controller.service
backup_target "$proxy_service" proxy.service
for binary in \
    serverware-coder-controller \
    serverware-coder-controller-client \
    serverware-coder-docker-proxy \
    serverware-coder-controller-launcher \
    serverware-coder-plan
do
    backup_target "/usr/local/libexec/$binary" "bin.$binary"
done

rollback_required=1
rollback() {
    status=$?
    test "$rollback_required" -eq 1 || exit "$status"
    systemctl stop serverware-coder-controller-v11.service \
        serverware-coder-docker-proxy-v11.service >/dev/null 2>&1 || true
    for target in "$config_dir" "$plan_target" "$runner_target"; do
        test ! -e "$target" && test ! -L "$target" || chattr -Ri "$target" >/dev/null 2>&1 || true
        rm -rf -- "$target"
    done
    for binary in \
        serverware-coder-controller \
        serverware-coder-controller-client \
        serverware-coder-docker-proxy \
        serverware-coder-controller-launcher \
        serverware-coder-plan
    do
        chattr -i "/usr/local/libexec/$binary" >/dev/null 2>&1 || true
        rm -f -- "/usr/local/libexec/$binary"
        test ! -e "$backup/bin.$binary" || cp -a -- "$backup/bin.$binary" "/usr/local/libexec/$binary"
    done
    rm -f -- "$controller_service" "$proxy_service"
    test ! -e "$backup/controller.service" || cp -a -- "$backup/controller.service" "$controller_service"
    test ! -e "$backup/proxy.service" || cp -a -- "$backup/proxy.service" "$proxy_service"
    test ! -e "$backup/config" || cp -a -- "$backup/config" "$config_dir"
    test ! -e "$backup/plans" || cp -a -- "$backup/plans" "$plan_target"
    test ! -e "$backup/runner" || cp -a -- "$backup/runner" "$runner_target"
    systemctl daemon-reload >/dev/null 2>&1 || true
    test "$proxy_was_active" -eq 0 || systemctl start serverware-coder-docker-proxy-v11.service >/dev/null 2>&1 || true
    test "$controller_was_active" -eq 0 || systemctl start serverware-coder-controller-v11.service >/dev/null 2>&1 || true
    cleanup_staging
    exit "$status"
}
trap rollback EXIT HUP INT TERM

for target in "$config_dir" "$plan_target" "$runner_target"; do
    test ! -e "$target" && test ! -L "$target" || chattr -Ri "$target" >/dev/null 2>&1 || true
    rm -rf -- "$target"
done
install -d -o root -g "$client_gid" -m 0750 "$config_dir"
cp -a -- "$stage/config/." "$config_dir/"
chown -R root:root "$config_dir"
chmod 0750 "$config_dir"
chmod 0555 "$request_template_target" "$network_target"
chmod 0440 "$requester_seed"
chgrp "$client_gid" "$requester_seed"

install -d -o root -g root -m 0555 "$plan_target" "$runner_target"
cp -a -- "$stage/plans/." "$plan_target/"
cp -a -- "$stage/runner/." "$runner_target/"
chown -R root:root "$plan_target" "$runner_target"
sort -u "$plan_immutable_paths" |
while IFS= read -r immutable
do
    chattr +i "$immutable"
done

for binary in \
    serverware-coder-controller \
    serverware-coder-controller-client \
    serverware-coder-docker-proxy \
    serverware-coder-controller-launcher \
    serverware-coder-plan
do
    chattr -i "/usr/local/libexec/$binary" >/dev/null 2>&1 || true
    install -o root -g root -m 0555 \
        "$stage/bin/$binary" "/usr/local/libexec/$binary"
done

rm -f -- "$receipt_public" "$requester_public" "$manifest_file"
/usr/local/libexec/serverware-coder-controller \
    --provision-trusted-host "$controller_config"
test "$(wc -c < "$receipt_public")" -eq 32
test "$(wc -c < "$requester_public")" -eq 32
test -s "$manifest_file"
chown root:root "$receipt_public" "$requester_public" "$manifest_file"
chmod 0444 "$receipt_public" "$requester_public" "$manifest_file"

for immutable in \
    "$controller_config" "$proxy_config" \
    "$receipt_seed" "$receipt_public" \
    "$requester_seed" "$requester_public" \
    "$final_verdict_public" "$manifest_file" \
    "$pinned_input_manifest_target" \
    "$pinned_input_manifest_digest_target" \
    "$request_template_target"/*.request.json \
    "$network_target"/*.nft \
    "$plan_target"/* \
    "$runner_target"/* \
    /usr/local/libexec/serverware-coder-controller \
    /usr/local/libexec/serverware-coder-controller-client \
    /usr/local/libexec/serverware-coder-docker-proxy \
    /usr/local/libexec/serverware-coder-controller-launcher \
    /usr/local/libexec/serverware-coder-plan
do
    chattr +i "$immutable"
done
sync -f "$config_dir"
sync -f "$plan_target"
sync -f "$runner_target"
sync -f /usr/local/libexec

install -o root -g root -m 0644 \
    "$stage/systemd/serverware-coder-controller-v11.service" \
    "$controller_service"
install -o root -g root -m 0644 \
    "$stage/systemd/serverware-coder-docker-proxy-v11.service" \
    "$proxy_service"
systemctl daemon-reload
systemctl enable serverware-coder-docker-proxy-v11.service \
    serverware-coder-controller-v11.service
systemctl start serverware-coder-docker-proxy-v11.service
systemctl start serverware-coder-controller-v11.service

rollback_required=0
trap cleanup_staging EXIT HUP INT TERM
cleanup_staging
trap - EXIT HUP INT TERM
