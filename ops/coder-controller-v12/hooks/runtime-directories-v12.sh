#!/bin/sh
set -eu
umask 077

usage() {
    echo "usage: $0 setup|cleanup CLIENT_GROUP" >&2
    exit 2
}

test "$(id -u)" -eq 0 || {
    echo "runtime directory hook requires root" >&2
    exit 1
}

action=${1:-}
client_group=${2:-}
case "$action" in setup|cleanup) ;; *) usage ;; esac
case "$client_group" in ""|*[!A-Za-z0-9_-]*) usage ;; esac
getent group "$client_group" >/dev/null || {
    echo "client group does not exist: $client_group" >&2
    exit 2
}

runtime_root=/run/serverware/coder/v12
for path in /run/serverware /run/serverware/coder "$runtime_root"
do
    test ! -L "$path" || {
        echo "runtime parent is a symlink: $path" >&2
        exit 2
    }
done

case "$action" in
    setup)
        install -d -o root -g root -m 0711 \
            /run/serverware /run/serverware/coder "$runtime_root"
        install -d -o root -g root -m 0755 /run/netns
        install -d -o serverware-coder-controller -g "$client_group" -m 0750 \
            "$runtime_root/controller"
        install -d -o serverware-coder-executor -g serverware-coder-executor-api -m 0750 \
            "$runtime_root/plan-executor"
        install -d -o serverware-coder-docker -g serverware-coder-docker-api -m 0750 \
            "$runtime_root/docker-proxy"
        install -d -o serverware-coder-receipt -g serverware-coder-receipt-api -m 0750 \
            "$runtime_root/receipt-authority"
        install -d -o serverware-coder-verdict -g serverware-coder-verdict-api -m 0750 \
            "$runtime_root/final-verdict-authority"
        install -d -o serverware-coder-lifecycle -g serverware-coder-lifecycle-api -m 0750 \
            "$runtime_root/lifecycle"
        install -d -o root -g serverware-coder-lifecycle-privileged-api -m 0750 \
            "$runtime_root/lifecycle-privileged"
        install -d -o root -g root -m 0700 "$runtime_root/dind"
        install -d -o serverware-coder-trust -g serverware-coder-trust-api -m 0750 \
            "$runtime_root/trust-generation"
        install -d -o serverware-coder-witness -g serverware-coder-witness-api -m 0750 \
            "$runtime_root/external-witness"
        install -d -o serverware-coder-settlement -g serverware-coder-settlement-api -m 0750 \
            "$runtime_root/final-settlement"
        install -d -o serverware-coder-log -g serverware-coder-log-api -m 0750 \
            "$runtime_root/log-custody"
        ;;
    cleanup)
        rm -f -- \
            "$runtime_root/controller/control.sock" \
            "$runtime_root/plan-executor/control.sock" \
            "$runtime_root/docker-proxy/control.sock" \
            "$runtime_root/receipt-authority/control.sock" \
            "$runtime_root/final-verdict-authority/control.sock" \
            "$runtime_root/lifecycle/control.sock" \
            "$runtime_root/lifecycle-privileged/control.sock" \
            "$runtime_root/trust-generation/control.sock" \
            "$runtime_root/external-witness/control.sock" \
            "$runtime_root/final-settlement/control.sock" \
            "$runtime_root/log-custody/control.sock"
        rmdir -- \
            "$runtime_root/controller" \
            "$runtime_root/plan-executor" \
            "$runtime_root/docker-proxy" \
            "$runtime_root/receipt-authority" \
            "$runtime_root/final-verdict-authority" \
            "$runtime_root/lifecycle" \
            "$runtime_root/lifecycle-privileged" \
            "$runtime_root/trust-generation" \
            "$runtime_root/external-witness" \
            "$runtime_root/final-settlement" \
            "$runtime_root/log-custody" \
            "$runtime_root/dind" >/dev/null 2>&1 || true
        rmdir -- "$runtime_root" /run/serverware/coder /run/serverware >/dev/null 2>&1 || true
        ;;
esac
