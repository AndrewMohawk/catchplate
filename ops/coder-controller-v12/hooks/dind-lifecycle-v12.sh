#!/bin/sh
set -eu
umask 077

usage() {
    echo "usage: $0 create|destroy|reconcile RELEASE_ROOT LANE_ID CAPABILITY_FILE" >&2
    exit 2
}

test "$(id -u)" -eq 0 || {
    echo "private DinD lifecycle hook requires root" >&2
    exit 1
}

action=${1:-}
release_root=${2:-}
lane_id=${3:-}
capability_file=${4:-}

case "$action" in create|destroy|reconcile) ;; *) usage ;; esac
case "$release_root" in
    /opt/serverware/coder-controller-v12/releases/*) ;;
    *) usage ;;
esac
release_id=${release_root#/opt/serverware/coder-controller-v12/releases/}
case "$release_id" in ""|*/*|.*|*[!A-Za-z0-9._-]*|*..*) usage ;; esac
test -d "$release_root" && test ! -L "$release_root" || usage
case "$lane_id" in ""|*[!A-Za-z0-9_-]*) usage ;; esac
test "${#lane_id}" -le 64 || usage
case "$capability_file" in
    /var/lib/serverware/coder-controller-v12/lifecycle-privileged/*) ;;
    *) usage ;;
esac
test -f "$capability_file" && test ! -L "$capability_file" || usage
test "$(stat -c '%u:%a:%h:%F' "$capability_file")" = "0:400:1:regular file" || {
    echo "DinD lifecycle capability must be root-owned, single-link, and 0400" >&2
    exit 2
}

unset DOCKER_API_VERSION DOCKER_CERT_PATH DOCKER_CONFIG DOCKER_CONTEXT
unset DOCKER_CUSTOM_HEADERS DOCKER_HOST DOCKER_TLS_VERIFY BUILDX_BUILDER BUILDX_CONFIG

binary=$release_root/bin/serverware-coder-lifecycle-privileged-v12
config=$release_root/config/lifecycle-privileged-v12.conf
test -x "$binary" && test -f "$config" && test ! -L "$config" || usage

case "$action" in
    create)
        exec "$binary" admin-create-private-dind-v12 \
            --config "$config" \
            --lane-id "$lane_id" \
            --capability-file "$capability_file"
        ;;
    destroy)
        exec "$binary" admin-destroy-private-dind-v12 \
            --config "$config" \
            --lane-id "$lane_id" \
            --capability-file "$capability_file"
        ;;
    reconcile)
        exec "$binary" admin-reconcile-private-dind-v12 \
            --config "$config" \
            --lane-id "$lane_id" \
            --capability-file "$capability_file"
        ;;
esac
