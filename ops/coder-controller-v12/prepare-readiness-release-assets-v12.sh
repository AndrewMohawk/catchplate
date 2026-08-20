#!/bin/sh
set -eu
umask 077

fail() {
    echo "$*" >&2
    exit 2
}

test "$#" -eq 6 || fail \
    "usage: $0 OUTPUT_ROOT RELEASE_ROOT FIXTURE_INPUT_ROOT EXECUTOR_CONFIG_DRAFT LIFECYCLE_PRIVILEGED_PUBLIC_KEY BROWSER_IMAGE_REFERENCE"

output_root=$1
release_root=$2
fixture_input_root=$3
executor_config_draft=$4
lifecycle_privileged_public_key=$5
browser_image_reference=$6

for path in "$output_root" "$release_root" "$fixture_input_root" \
    "$executor_config_draft" "$lifecycle_privileged_public_key"
do
    case "$path" in /*) ;; *) fail "every path argument must be absolute: $path" ;; esac
done
test ! -e "$output_root" && test ! -L "$output_root" \
    || fail "OUTPUT_ROOT must not already exist"
test -d "$fixture_input_root" && test ! -L "$fixture_input_root" \
    || fail "fixture input root must be a non-symlink directory"
for input in "$executor_config_draft" "$lifecycle_privileged_public_key"
do
    test -f "$input" && test ! -L "$input" \
        || fail "required release input is absent, not regular, or a symlink: $input"
done
test "$(grep -o '@DERIVED_READINESS_ASSETS_SHA256@' \
    "$executor_config_draft" | wc -l | tr -d ' ')" -eq 1 \
    || fail "executor config draft must contain exactly one derived readiness digest slot"
test "$(grep -o '@LIFECYCLE_PRIVILEGED_AUTHORITY_SPKI_SHA256@' \
    "$executor_config_draft" | wc -l | tr -d ' ')" -eq 1 \
    || fail "executor config draft must contain exactly one privileged signer slot"
case "$browser_image_reference" in
    ""|*[!A-Za-z0-9._:/@+-]*|*\"*|*\\*|*"	"*|*" "*)
        fail "browser image reference is not an exact OCI reference"
        ;;
esac
test "${#browser_image_reference}" -le 512 \
    || fail "browser image reference is too long"

script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
install -d -m 0755 "$output_root/config" "$output_root/fixtures"

sha_file() {
    sha256sum "$1" | awk '{print $1}'
}

require_sha256() {
    value=$1
    label=$2
    case "$value" in ""|*[!0-9a-f]*) fail "$label is not lowercase hexadecimal" ;; esac
    test "${#value}" -eq 64 || fail "$label is not exactly 64 characters"
}

copy_fixture() {
    name=$1
    source=$fixture_input_root/$name
    test -f "$source" && test ! -L "$source" \
        || fail "required readiness fixture is absent, not regular, or a symlink: $name"
    install -m 0444 "$source" "$output_root/fixtures/$name"
}

for fixture in \
    docker-101.fixture docker-half-close.fixture \
    build-pinned-pull.fixture build-unpinned-egress-denied.fixture \
    no-build-egress-denied.fixture service-health.fixture \
    chromium-page.html chromium-script.js chromium-expected-cdp.json \
    chromium-expected-dom.txt chromium-expected-js.txt \
    chromium-expected-fetch.txt
do
    copy_fixture "$fixture"
done

escaped_browser_reference=$(printf '%s' "$browser_image_reference" |
    sed 's/[\\&|]/\\&/g')
chromium_contract=$(sed \
    "s|@BROWSER_IMAGE_REFERENCE@|$escaped_browser_reference|g" \
    "$script_root/chromium-probe.fixture.in")
case "$chromium_contract" in *"@BROWSER_IMAGE_REFERENCE@"*)
    fail "Chromium readiness contract was not rendered"
esac
printf '%s' "$chromium_contract" \
    > "$output_root/fixtures/chromium-probe.fixture"
chmod 0444 "$output_root/fixtures/chromium-probe.fixture"

teardown_contract=$(cat "$script_root/teardown.fixture.in")
printf '%s' "$teardown_contract" > "$output_root/fixtures/teardown.fixture"
chmod 0444 "$output_root/fixtures/teardown.fixture"

docker_101_fixture_sha256=$(sha_file "$output_root/fixtures/docker-101.fixture")
docker_half_close_fixture_sha256=$(sha_file "$output_root/fixtures/docker-half-close.fixture")
build_pinned_pull_fixture_sha256=$(sha_file "$output_root/fixtures/build-pinned-pull.fixture")
build_unpinned_egress_denied_fixture_sha256=$(sha_file "$output_root/fixtures/build-unpinned-egress-denied.fixture")
no_build_egress_denied_fixture_sha256=$(sha_file "$output_root/fixtures/no-build-egress-denied.fixture")
service_health_fixture_sha256=$(sha_file "$output_root/fixtures/service-health.fixture")
chromium_page_fixture_sha256=$(sha_file "$output_root/fixtures/chromium-page.html")
chromium_script_fixture_sha256=$(sha_file "$output_root/fixtures/chromium-script.js")
chromium_probe_fixture_sha256=$(sha_file "$output_root/fixtures/chromium-probe.fixture")
chromium_expected_cdp_sha256=$(sha_file "$output_root/fixtures/chromium-expected-cdp.json")
chromium_expected_dom_sha256=$(sha_file "$output_root/fixtures/chromium-expected-dom.txt")
chromium_expected_js_sha256=$(sha_file "$output_root/fixtures/chromium-expected-js.txt")
chromium_expected_fetch_sha256=$(sha_file "$output_root/fixtures/chromium-expected-fetch.txt")
teardown_fixture_sha256=$(sha_file "$output_root/fixtures/teardown.fixture")

descriptor=$output_root/readiness-assets-v12.descriptor.tmp
{
    printf '%s\n' \
        "fixture_set_digest_contract=serverware/readiness-assets-digest/v12" \
        "docker_101_fixture_sha256=$docker_101_fixture_sha256" \
        "docker_half_close_fixture_sha256=$docker_half_close_fixture_sha256" \
        "build_pinned_pull_fixture_sha256=$build_pinned_pull_fixture_sha256" \
        "build_unpinned_egress_denied_fixture_sha256=$build_unpinned_egress_denied_fixture_sha256" \
        "no_build_egress_denied_fixture_sha256=$no_build_egress_denied_fixture_sha256" \
        "service_health_fixture_sha256=$service_health_fixture_sha256" \
        "chromium_page_fixture_sha256=$chromium_page_fixture_sha256" \
        "chromium_script_fixture_sha256=$chromium_script_fixture_sha256" \
        "chromium_probe_fixture_sha256=$chromium_probe_fixture_sha256" \
        "chromium_expected_cdp_sha256=$chromium_expected_cdp_sha256" \
        "chromium_expected_dom_sha256=$chromium_expected_dom_sha256" \
        "chromium_expected_js_sha256=$chromium_expected_js_sha256" \
        "chromium_expected_fetch_sha256=$chromium_expected_fetch_sha256" \
        "teardown_fixture_sha256=$teardown_fixture_sha256" \
        "role.docker_101=upgrade-client-stream" \
        "role.docker_half_close=upgrade-server-stream" \
        "role.build_pinned_pull=build-pinned-pull-contract" \
        "role.build_unpinned_egress_denied=build-egress-denial-contract" \
        "role.no_build_egress_denied=no-build-egress-denial-contract" \
        "role.service_health=service-container-probe-contract" \
        "role.chromium_page=chromium-document" \
        "role.chromium_script=chromium-javascript" \
        "role.chromium_probe=chromium-container-probe-contract" \
        "role.chromium_expected_cdp=chromium-cdp-expectation" \
        "role.chromium_expected_dom=chromium-dom-expectation" \
        "role.chromium_expected_js=chromium-javascript-expectation" \
        "role.chromium_expected_fetch=chromium-fetch-expectation" \
        "role.teardown=terminal-private-dind-absence-contract" \
        "require_docker_101=true" \
        "require_half_close=true" \
        "require_build_pinned_pull=true" \
        "require_build_unpinned_egress_denied=true" \
        "require_no_build_egress_denied=true" \
        "require_service_start_health_stop=true" \
        "require_chromium_cdp=true" \
        "require_dom_sentinel=true" \
        "require_javascript_sentinel=true" \
        "require_fetch_sentinel=true" \
        "require_teardown_proof=true" \
        "probe_order=docker-upgrade,service-health,chromium,teardown" \
        "before_repository_work_every_invocation=true"
} > "$descriptor"
fixture_set_id=$(sha_file "$descriptor")
require_sha256 "$fixture_set_id" "derived readiness fixture set ID"

render_template() {
    source=$1
    destination=$2
    shift 2
    install -m 0444 "$source" "$destination"
    while test "$#" -gt 0
    do
        test "$#" -ge 2 || fail "template substitution lacks a value"
        key=$1
        value=$2
        shift 2
        escaped=$(printf '%s' "$value" | sed 's/[\\&|]/\\&/g')
        sed "s|@$key@|$escaped|g" "$destination" > "$destination.next"
        chmod 0444 "$destination.next"
        mv -fT "$destination.next" "$destination"
    done
    grep -n '@[A-Z0-9_][A-Z0-9_]*@' "$destination" >/dev/null \
        && fail "unresolved placeholder in $destination"
}

render_template \
    "$script_root/readiness-fixtures-v12.manifest.in" \
    "$output_root/fixtures/readiness-fixtures-v12.manifest" \
    DERIVED_READINESS_ASSETS_SHA256 "$fixture_set_id" \
    RELEASE_ROOT "$release_root" \
    DOCKER_101_FIXTURE_SHA256 "$docker_101_fixture_sha256" \
    DOCKER_HALF_CLOSE_FIXTURE_SHA256 "$docker_half_close_fixture_sha256" \
    BUILD_PINNED_PULL_FIXTURE_SHA256 "$build_pinned_pull_fixture_sha256" \
    BUILD_UNPINNED_EGRESS_DENIED_FIXTURE_SHA256 "$build_unpinned_egress_denied_fixture_sha256" \
    NO_BUILD_EGRESS_DENIED_FIXTURE_SHA256 "$no_build_egress_denied_fixture_sha256" \
    SERVICE_HEALTH_FIXTURE_SHA256 "$service_health_fixture_sha256" \
    CHROMIUM_PAGE_FIXTURE_SHA256 "$chromium_page_fixture_sha256" \
    CHROMIUM_SCRIPT_FIXTURE_SHA256 "$chromium_script_fixture_sha256" \
    CHROMIUM_PROBE_FIXTURE_SHA256 "$chromium_probe_fixture_sha256" \
    CHROMIUM_EXPECTED_CDP_SHA256 "$chromium_expected_cdp_sha256" \
    CHROMIUM_EXPECTED_DOM_SHA256 "$chromium_expected_dom_sha256" \
    CHROMIUM_EXPECTED_JS_SHA256 "$chromium_expected_js_sha256" \
    CHROMIUM_EXPECTED_FETCH_SHA256 "$chromium_expected_fetch_sha256" \
    TEARDOWN_FIXTURE_SHA256 "$teardown_fixture_sha256"

spki_der=$output_root/lifecycle-privileged-authority.spki.der.tmp
openssl pkey -pubin -in "$lifecycle_privileged_public_key" \
    -outform DER -out "$spki_der" \
    || fail "privileged lifecycle public key is not valid SPKI"
lifecycle_privileged_spki=$(sha_file "$spki_der")
require_sha256 "$lifecycle_privileged_spki" \
    "privileged lifecycle signer SPKI digest"

render_template \
    "$executor_config_draft" \
    "$output_root/config/plan-executor-v12.conf" \
    DERIVED_READINESS_ASSETS_SHA256 "$fixture_set_id" \
    LIFECYCLE_PRIVILEGED_AUTHORITY_SPKI_SHA256 \
    "$lifecycle_privileged_spki"

rm -f -- "$descriptor" "$spki_der"
test ! -e "$output_root/fixtures/readiness-fixtures-v12.manifest.sig" \
    || fail "asset preparation must not reuse a readiness signature"
printf '%s\n' \
    "fixture_set_id=$fixture_set_id" \
    "lifecycle_privileged_authority_spki_sha256=$lifecycle_privileged_spki" \
    "Prepared canonical unsigned readiness assets and executor config. Sign readiness-fixtures-v12.manifest with the authorized readiness key, then sign the complete release bundle."
