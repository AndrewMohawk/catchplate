#!/bin/sh
set -eu
umask 077

fail() {
    echo "$*" >&2
    exit 2
}

acknowledgement=I_ACKNOWLEDGE_QUARANTINE_IS_NOT_MIGRATION_AND_REPLAY_HISTORY_MAY_BE_LOST
test "$#" -eq 2 || fail \
    "usage: $0 <lifecycle-cache|private-dind-ledger|executor-operation-ledger|controller-journals|all> $acknowledgement"
scope=$1
test "$2" = "$acknowledgement" \
    || fail "explicit quarantine and replay-history acknowledgement is required"
case "$scope" in
    lifecycle-cache|private-dind-ledger|executor-operation-ledger|controller-journals|all) ;;
    *) fail "unsupported offline quarantine scope: $scope" ;;
esac
test "$(id -u)" -eq 0 || fail "offline v12 state quarantine requires UID 0"

state_root=/var/lib/catchplate/coder-controller-v12
quarantine_root=$state_root/offline-quarantine-v12
dind_root=$state_root/dind
socket_root=/run/catchplate/coder/v12/dind
netns_root=/run/netns
cgroup_root=/sys/fs/cgroup/system.slice/catchplate-coder-lifecycle-privileged-v12.service
max_entries=8192
max_depth=12
audit_count=0

for protected in /var/lib/catchplate "$state_root" "$quarantine_root"
do
    test ! -L "$protected" || fail "protected path is a symlink: $protected"
done
test -d "$state_root" || fail "controller v12 state root is absent"
test "$(stat -c '%u:%F' "$state_root")" = "0:directory" \
    || fail "controller v12 state root is not a root-owned directory"

for unit in \
    catchplate-coder-v12.target \
    catchplate-coder-controller-v12.socket \
    catchplate-coder-controller-v12.service \
    catchplate-coder-plan-executor-v12.socket \
    catchplate-coder-plan-executor-v12.service \
    catchplate-coder-docker-proxy-v12.socket \
    catchplate-coder-docker-proxy-v12.service \
    catchplate-coder-lifecycle-v12.socket \
    catchplate-coder-lifecycle-v12.service \
    catchplate-coder-lifecycle-privileged-v12.socket \
    catchplate-coder-lifecycle-privileged-v12.service \
    catchplate-coder-private-dind-reconcile-v12.service \
    catchplate-coder-readiness-v12.service
do
    systemctl is-active --quiet "$unit" \
        && fail "v12 service must be inactive before offline quarantine: $unit"
done

for socket in \
    /run/catchplate/coder/v12/controller/control.sock \
    /run/catchplate/coder/v12/plan-executor/control.sock \
    /run/catchplate/coder/v12/docker-proxy/control.sock \
    /run/catchplate/coder/v12/lifecycle/control.sock \
    /run/catchplate/coder/v12/lifecycle-privileged/control.sock
do
    test ! -e "$socket" && test ! -L "$socket" \
        || fail "v12 control socket or stale path remains: $socket"
done

require_empty_directory() {
    directory=$1
    test ! -L "$directory" || fail "resource root is a symlink: $directory"
    test ! -e "$directory" && return 0
    test -d "$directory" || fail "resource root is not a directory: $directory"
    for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*
    do
        test -e "$entry" || test -L "$entry" || continue
        fail "offline quarantine requires an empty resource root: $directory"
    done
}

require_empty_directory "$dind_root"
require_empty_directory "$socket_root"
for netns in "$netns_root"/catchplate-coder-v12-*
do
    test -e "$netns" || test -L "$netns" || continue
    fail "owned network namespace remains: $netns"
done
if test -e "$cgroup_root" || test -L "$cgroup_root"; then
    test -d "$cgroup_root" && test ! -L "$cgroup_root" \
        || fail "private DinD cgroup root is unsafe"
    test -r "$cgroup_root/cgroup.procs" \
        || fail "private DinD cgroup process list is unreadable"
    if IFS= read -r cgroup_pid < "$cgroup_root/cgroup.procs"; then
        fail "private DinD cgroup still has process: $cgroup_pid"
    fi
    # The delegated service root intentionally has no direct processes.
    # Include its supervisor/.control descendants in the offline check.
    test -r "$cgroup_root/cgroup.events" && test ! -L "$cgroup_root/cgroup.events" \
        || fail "private DinD aggregate cgroup state is unreadable or unsafe"
    cgroup_empty_seen=no
    while IFS= read -r cgroup_event
    do
        case "$cgroup_event" in
            'populated 0')
                test "$cgroup_empty_seen" = no || fail "duplicate cgroup populated state"
                cgroup_empty_seen=yes
                ;;
            'populated '*) fail "private DinD cgroup subtree still has processes" ;;
        esac
    done < "$cgroup_root/cgroup.events"
    test "$cgroup_empty_seen" = yes || fail "private DinD aggregate populated state is absent"
    for child in "$cgroup_root"/catchplate-coder-v12-*
    do
        test -e "$child" || test -L "$child" || continue
        fail "owned private DinD child cgroup remains: $child"
    done
fi

audit_tree() {
    path=$1
    depth=$2
    test "$depth" -le "$max_depth" \
        || fail "quarantine candidate exceeds maximum tree depth: $path"
    test ! -L "$path" || fail "quarantine candidate contains a symlink: $path"
    if test -f "$path"; then
        audit_count=$((audit_count + 1))
        test "$audit_count" -le "$max_entries" \
            || fail "quarantine candidate exceeds maximum entry count"
        return
    fi
    test -d "$path" || fail "quarantine candidate contains a special file: $path"
    audit_count=$((audit_count + 1))
    test "$audit_count" -le "$max_entries" \
        || fail "quarantine candidate exceeds maximum entry count"
    for child in "$path"/* "$path"/.[!.]* "$path"/..?*
    do
        test -e "$child" || test -L "$child" || continue
        audit_tree "$child" "$((depth + 1))"
    done
}

case "$scope" in
    lifecycle-cache)
        candidates="$state_root/lifecycle"
        ;;
    private-dind-ledger)
        candidates="$state_root/lifecycle-privileged
$state_root/docker-proxy"
        ;;
    executor-operation-ledger)
        candidates="$state_root/executor/operation-ledger"
        ;;
    controller-journals)
        candidates="$state_root/controller"
        ;;
    all)
        candidates="$state_root/controller
$state_root/lifecycle
$state_root/lifecycle-privileged
$state_root/docker-proxy
$state_root/executor/operation-ledger"
        ;;
esac

present_candidates=
for candidate in $candidates
do
    case "$candidate" in "$state_root"/*) ;; *) fail "candidate escaped state root" ;; esac
    test ! -L "$candidate" || fail "quarantine candidate is a symlink: $candidate"
    test -e "$candidate" || continue
    audit_tree "$candidate" 0
    present_candidates="$present_candidates
$candidate"
done
test -n "$present_candidates" || fail "selected quarantine scope has no state"

quarantine_id=$(cat /proc/sys/kernel/random/uuid)
case "$quarantine_id" in
    ????????-????-????-????-????????????) ;;
    *) fail "kernel did not provide a bounded quarantine identifier" ;;
esac
case "$quarantine_id" in *[!0-9a-f-]*) fail "quarantine identifier is not lowercase UUID text" ;; esac
destination=$quarantine_root/$quarantine_id
install -d -o root -g root -m 0700 "$quarantine_root"
test ! -e "$destination" && test ! -L "$destination" \
    || fail "quarantine destination already exists"
install -d -o root -g root -m 0700 "$destination"
manifest=$destination/quarantine-v12.manifest
{
    printf '%s\n' \
        "version=catchplate/offline-state-quarantine/v12" \
        "disposition=QUARANTINED_NOT_MIGRATED" \
        "scope=$scope" \
        "maximum_entries=$max_entries" \
        "maximum_depth=$max_depth" \
        "audited_entries=$audit_count" \
        "signature_claim=none" \
        "runtime_reuse=forbidden"
} > "$manifest"
chmod 0600 "$manifest"

for candidate in $present_candidates
do
    relative=${candidate#"$state_root"/}
    destination_name=$(printf '%s' "$relative" | tr / _)
    target=$destination/$destination_name
    test ! -e "$target" && test ! -L "$target" \
        || fail "quarantine target collision: $target"
    mv -T "$candidate" "$target"
    printf 'moved.%s=%s\n' "$destination_name" "$relative" >> "$manifest"
    sync -f "$target"
done
sync -f "$manifest"
sync -f "$destination"
sync -f "$quarantine_root"
printf '%s\n' \
    "Quarantined structurally incompatible v12 state at $destination." \
    "The quarantine is not a migration and is never parsed by in-service v12 code."
