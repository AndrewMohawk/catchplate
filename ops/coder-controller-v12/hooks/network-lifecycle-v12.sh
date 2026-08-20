#!/bin/sh
set -eu
umask 077

fail() {
    echo "$*" >&2
    exit 2
}

usage() {
    cat >&2 <<'EOF'
usage:
  network-lifecycle-v12.sh setup-host HOST_RULESET OWNERSHIP_LEDGER
  network-lifecycle-v12.sh cleanup-host HOST_CLEANUP_RULESET LANE_CLEANUP_RULESET OWNERSHIP_LEDGER
  network-lifecycle-v12.sh create-lane GENERATION SLOT build|no-build LANE_RULESET OWNERSHIP_LEDGER
  network-lifecycle-v12.sh destroy-lane GENERATION SLOT LANE_CLEANUP_RULESET OWNERSHIP_LEDGER
  network-lifecycle-v12.sh reconcile-lane GENERATION SLOT build|no-build LANE_RULESET OWNERSHIP_LEDGER
EOF
    exit 2
}

test "$(id -u)" -eq 0 || fail "network lifecycle hook requires root"

validate_generation() {
    generation=$1
    case "$generation" in
        ""|.*|*[!A-Za-z0-9._-]*|*..*) fail "invalid lane generation" ;;
    esac
    test "${#generation}" -le 64 || fail "lane generation is too long"
}

validate_slot() {
    slot=$1
    case "$slot" in 0|1|2|3|4) ;; *) fail "lane slot must be 0 through 4" ;; esac
}

validate_slot_profile() {
    case "$profile:$slot" in
        build:0|no-build:1) ;;
        *) fail "lane slot and network profile do not match the fixed workflow" ;;
    esac
}

validate_ruleset() {
    ruleset=$1
    case "$ruleset" in /*) ;; *) fail "ruleset path must be absolute" ;; esac
    test -f "$ruleset" && test ! -L "$ruleset" \
        || fail "ruleset must be a regular non-symlink file: $ruleset"
    test "$(stat -c '%u:%a:%h:%F' "$ruleset")" = "0:444:1:regular file" \
        || fail "ruleset must be root-owned, single-link, and 0444: $ruleset"
}

validate_ledger() {
    ledger=$1
    case "$ledger" in
        /var/lib/serverware/coder-controller-v12/lifecycle-privileged/*) ;;
        *) fail "ownership ledger is outside the privileged lifecycle state root" ;;
    esac
    test ! -L "$ledger" || fail "ownership ledger must not be a symlink"
    if test -e "$ledger"; then
        test -f "$ledger" && test "$(stat -c '%u:%a:%h' "$ledger")" = \
            "0:600:1" \
            || fail "ownership ledger has unsafe metadata"
    else
        install -d -o root -g root -m 0700 "$(dirname -- "$ledger")"
        install -o root -g root -m 0600 /dev/null "$ledger"
    fi
}

lock_ledger() {
    lock=$ledger.lock
    if test ! -e "$lock"; then
        install -o root -g root -m 0600 /dev/null "$lock"
    fi
    test ! -L "$lock" \
        && test -f "$lock" \
        && test "$(stat -c '%u:%a:%h' "$lock")" = "0:600:1" \
        || fail "ownership ledger lock has unsafe metadata"
    exec 9>>"$lock"
    flock -x 9
}

set_lane_addresses() {
    subnet_index=$1
    address_index=$((subnet_index * 4))
    second_octet=$((64 + (address_index / 65536)))
    third_octet=$(((address_index / 256) % 256))
    fourth_octet=$((address_index % 256))
    host_address=10.$second_octet.$third_octet.$((fourth_octet + 1))/30
    lane_address=10.$second_octet.$third_octet.$((fourth_octet + 2))/30
    lane_gateway=10.$second_octet.$third_octet.$((fourth_octet + 1))
}

allocate_lane_names() {
    seed=$(printf '%s|%s\n' "$generation" "$slot" | sha256sum)
    seed=${seed%% *}
    seed_prefix=$(printf '%s' "$seed" | cut -c 1-5)
    start=$(printf '%d' "0x$seed_prefix")
    probe=0
    while test "$probe" -lt 4096
    do
        subnet_index=$(((start + probe) % 1048576))
        if awk -F'|' -v candidate="$subnet_index" \
            '$1 == "network" && $8 == candidate { found=1 }
             END { exit !found }' "$ledger"
        then
            probe=$((probe + 1))
            continue
        fi
        token=$(printf '%05x' "$subnet_index")
        namespace=serverware-coder-v12-$token
        host_veth=swv12h$token
        peer_veth=swv12p$token
        ! namespace_exists "$namespace" \
            || fail "unowned allocated namespace already exists: $namespace"
        ! ip link show dev "$host_veth" >/dev/null 2>&1 \
            || fail "unowned allocated host veth already exists: $host_veth"
        ! ip link show dev "$peer_veth" >/dev/null 2>&1 \
            || fail "unowned allocated peer veth already exists: $peer_veth"
        set_lane_addresses "$subnet_index"
        return
    done
    fail "no collision-free private-DinD subnet is available within the bounded allocator"
}

load_lane_record() {
    record_line=$(awk -F'|' -v generation="$generation" -v slot="$slot" \
        '$1 == "network" && $2 == generation && $3 == slot { print; count++ }
         END { if (count != 1) exit 1 }' "$ledger") \
        || fail "lane is not uniquely owned by the requested generation"
    IFS='|' read -r record record_generation record_slot \
        namespace host_veth peer_veth profile subnet_index \
        host_address lane_address lane_gateway <<EOF
$record_line
EOF
    test "$record" = network \
        && test "$record_generation" = "$generation" \
        && test "$record_slot" = "$slot" \
        || fail "lane ownership record changed during load"
    case "$subnet_index" in
        ""|*[!0-9]*) fail "lane ownership subnet index is invalid" ;;
    esac
    test "$subnet_index" -lt 1048576 \
        || fail "lane ownership subnet index exceeds allocator range"
    lane_veth=eth0
}

namespace_exists() {
    ip netns list | awk '{print $1}' | grep -Fx "$1" >/dev/null
}

ledger_has_lane() {
    awk -F'|' -v generation="$generation" -v slot="$slot" \
        '$1 == "network" && $2 == generation && $3 == slot { count++ }
         END { exit count != 1 }' "$ledger"
}

remove_lane_record() {
    replacement=$ledger.next.$$
    awk -F'|' -v generation="$generation" -v slot="$slot" \
        '!(($1 == "network") && ($2 == generation) && ($3 == slot)) { print }' \
        "$ledger" > "$replacement"
    chown root:root "$replacement"
    chmod 0600 "$replacement"
    mv -fT "$replacement" "$ledger"
    sync -f "$ledger"
}

destroy_owned_lane() {
    cleanup_ruleset=$1
    if namespace_exists "$namespace"; then
        ip netns exec "$namespace" nft -f "$cleanup_ruleset" >/dev/null 2>&1 || true
        ip netns delete "$namespace"
    fi
    if ip link show dev "$host_veth" >/dev/null 2>&1; then
        ip link delete "$host_veth"
    fi
    remove_lane_record
}

action=${1:-}
case "$action" in
    setup-host)
        test "$#" -eq 3 || usage
        host_ruleset=$2
        ledger=$3
        validate_ruleset "$host_ruleset"
        validate_ledger "$ledger"
        lock_ledger
        install -d -o root -g root -m 0755 /run/netns
        if ! grep -F 'host|ip_forward|' "$ledger" >/dev/null; then
            previous_forward=$(sysctl -n net.ipv4.ip_forward)
            case "$previous_forward" in 0|1) ;; *) fail "unexpected ip_forward value" ;; esac
            printf 'host|ip_forward|%s\n' "$previous_forward" >> "$ledger"
            sync -f "$ledger"
        fi
        sysctl -q -w net.ipv4.ip_forward=1
        nft -f "$host_ruleset"
        ;;
    cleanup-host)
        test "$#" -eq 4 || usage
        host_cleanup_ruleset=$2
        lane_cleanup_ruleset=$3
        ledger=$4
        validate_ruleset "$host_cleanup_ruleset"
        validate_ruleset "$lane_cleanup_ruleset"
        validate_ledger "$ledger"
        lock_ledger
        while IFS='|' read -r record generation slot namespace host_veth \
            peer_veth profile subnet_index host_address lane_address lane_gateway
        do
            test "$record" = network || continue
            validate_generation "$generation"
            validate_slot "$slot"
            lane_veth=eth0
            destroy_owned_lane "$lane_cleanup_ruleset"
        done < "$ledger"
        nft -f "$host_cleanup_ruleset"
        previous_forward=$(awk -F'|' '$1 == "host" && $2 == "ip_forward" { print $3 }' "$ledger")
        case "$previous_forward" in
            0|1) sysctl -q -w "net.ipv4.ip_forward=$previous_forward" ;;
            "") ;;
            *) fail "ownership ledger contains an invalid ip_forward value" ;;
        esac
        install -o root -g root -m 0600 /dev/null "$ledger"
        sync -f "$ledger"
        ;;
    create-lane)
        test "$#" -eq 6 || usage
        generation=$2
        slot=$3
        profile=$4
        lane_ruleset=$5
        ledger=$6
        validate_generation "$generation"
        validate_slot "$slot"
        validate_slot_profile
        validate_ruleset "$lane_ruleset"
        validate_ledger "$ledger"
        lock_ledger
        ! ledger_has_lane \
            || fail "lane generation is already owned in the lifecycle ledger"
        allocate_lane_names
        cleanup_partial() {
            ip netns delete "$namespace" >/dev/null 2>&1 || true
            ip link delete "$host_veth" >/dev/null 2>&1 || true
        }
        trap cleanup_partial EXIT HUP INT TERM
        ip netns add "$namespace"
        ip link add "$host_veth" type veth peer name "$peer_veth"
        ip link set "$peer_veth" netns "$namespace"
        ip address add "$host_address" dev "$host_veth"
        ip link set "$host_veth" up
        ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
        ip netns exec "$namespace" ip link set lo up
        ip netns exec "$namespace" ip link set "$peer_veth" name "$lane_veth"
        ip netns exec "$namespace" ip address add "$lane_address" dev "$lane_veth"
        ip netns exec "$namespace" ip link set "$lane_veth" up
        ip netns exec "$namespace" ip route add default via "$lane_gateway" dev "$lane_veth"
        ip netns exec "$namespace" nft -f "$lane_ruleset"
        printf 'network|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
            "$generation" "$slot" "$namespace" "$host_veth" \
            "$peer_veth" "$profile" "$subnet_index" "$host_address" \
            "$lane_address" "$lane_gateway" >> "$ledger"
        sync -f "$ledger"
        trap - EXIT HUP INT TERM
        ;;
    destroy-lane)
        test "$#" -eq 5 || usage
        generation=$2
        slot=$3
        cleanup_ruleset=$4
        ledger=$5
        validate_generation "$generation"
        validate_slot "$slot"
        validate_ruleset "$cleanup_ruleset"
        validate_ledger "$ledger"
        lock_ledger
        load_lane_record
        destroy_owned_lane "$cleanup_ruleset"
        ;;
    reconcile-lane)
        test "$#" -eq 6 || usage
        generation=$2
        slot=$3
        requested_profile=$4
        profile=$requested_profile
        lane_ruleset=$5
        ledger=$6
        validate_generation "$generation"
        validate_slot "$slot"
        validate_slot_profile
        validate_ruleset "$lane_ruleset"
        validate_ledger "$ledger"
        lock_ledger
        if ledger_has_lane; then
            load_lane_record
            test "$profile" = "$requested_profile" \
                || fail "owned lane profile differs from reconcile authority"
            namespace_exists "$namespace" \
                && ip link show dev "$host_veth" >/dev/null 2>&1 \
                || fail "owned lane has an uncertain partial outcome and must be destroyed"
            ip netns exec "$namespace" nft -f "$lane_ruleset"
        fi
        ;;
    *)
        usage
        ;;
esac
