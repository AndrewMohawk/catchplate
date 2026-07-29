#!/bin/sh
set -eu

readonly_root=/opt/serverware-rust-tests
manifest=$readonly_root/SHA256SUMS
harness_root=$readonly_root/harnesses

test "$#" -eq 0 || {
    echo "the fixed Rust test runner does not accept arguments" >&2
    exit 2
}
command -v cargo >/dev/null 2>&1 && {
    echo "cargo must not exist in the Rust test runtime" >&2
    exit 2
}
command -v rustc >/dev/null 2>&1 && {
    echo "rustc must not exist in the Rust test runtime" >&2
    exit 2
}
test -f "$manifest" && test ! -L "$manifest"
test -d "$harness_root" && test ! -L "$harness_root"

cd "$harness_root"

manifest_count=0
seen_names='|'
while read -r expected_digest harness_name extra; do
    test -z "${extra:-}" || {
        echo "malformed Rust test harness manifest entry" >&2
        exit 2
    }
    test "${#expected_digest}" -eq 64
    case "$expected_digest" in
        *[!0-9a-f]*)
            echo "invalid Rust test harness digest" >&2
            exit 2
            ;;
    esac
    case "$harness_name" in
        ""|-*|*[!a-z0-9_-]*)
            echo "invalid Rust test harness name: $harness_name" >&2
            exit 2
            ;;
    esac
    harness_stem=${harness_name%-*}
    harness_hash=${harness_name##*-}
    test "$harness_stem" != "$harness_name" \
        && test "${#harness_hash}" -eq 16 || {
        echo "invalid Rust test harness target/hash layout: $harness_name" >&2
        exit 2
    }
    case "$harness_stem" in
        ""|[0-9]*|*[!a-z0-9_]*)
            echo "invalid Rust test harness target name: $harness_name" >&2
            exit 2
            ;;
    esac
    case "$harness_hash" in
        *[!0-9a-f]*)
            echo "invalid Rust test harness hash suffix: $harness_name" >&2
            exit 2
            ;;
    esac
    case "$seen_names" in
        *"|$harness_name|"*)
            echo "duplicate Rust test harness name: $harness_name" >&2
            exit 2
            ;;
    esac
    seen_names="$seen_names$harness_name|"
    test -f "$harness_name" && test ! -L "$harness_name" && test -x "$harness_name"
    manifest_count=$((manifest_count + 1))
    test "$manifest_count" -le 64 || {
        echo "Rust test harness manifest exceeds the bounded count" >&2
        exit 2
    }
done < "$manifest"
test "$manifest_count" -gt 0

actual_count=0
for harness_path in ./*; do
    test -f "$harness_path" && test ! -L "$harness_path" && test -x "$harness_path" || {
        echo "unexpected entry in Rust test harness directory: $harness_path" >&2
        exit 2
    }
    actual_count=$((actual_count + 1))
done
for hidden_path in ./.[!.]* ./..?*; do
    test ! -e "$hidden_path" && test ! -L "$hidden_path" || {
        echo "hidden files are forbidden in the Rust test harness directory" >&2
        exit 2
    }
done
test "$actual_count" -eq "$manifest_count" || {
    echo "Rust test harness directory does not match its manifest" >&2
    exit 2
}

sha256sum --check --strict "$manifest"

cd /tmp
while read -r _ harness_name _; do
    printf 'running prebuilt Rust test harness: %s\n' "$harness_name"
    if "$harness_root/$harness_name" --test-threads=1; then
        :
    else
        harness_status=$?
        printf 'Rust test harness failed: %s (exit %s)\n' \
            "$harness_name" "$harness_status" >&2
        exit "$harness_status"
    fi
done < "$manifest"
