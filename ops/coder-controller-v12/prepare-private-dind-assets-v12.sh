#!/bin/sh
set -eu
umask 077

test "$#" -eq 7 || {
    echo "usage: $0 OUTPUT_ROOT DOCKERD CONTAINERD CONTAINERD_SHIM_RUNC_V2 RUNC PINNED_PULL_SET EXACT_BUILD_TUPLE_SET" >&2
    exit 2
}

output_root=$1
dockerd=$2
containerd=$3
containerd_shim=$4
runc=$5
pinned_pulls=$6
exact_builds=$7

case "$output_root" in /*) ;; *) echo "OUTPUT_ROOT must be absolute" >&2; exit 2 ;; esac
for input in \
    "$dockerd" "$containerd" "$containerd_shim" "$runc" \
    "$pinned_pulls" "$exact_builds"
do
    case "$input" in /*) ;; *) echo "every private-DinD input must be absolute" >&2; exit 2 ;; esac
    test -f "$input" && test ! -L "$input" || {
        echo "private-DinD input is absent, not regular, or a symlink: $input" >&2
        exit 2
    }
done

script_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_root/../.." && pwd -P)
test -f "$repository_root/data-plane/decision-gate-rs/src/docker_policy.rs"
test -f "$repository_root/data-plane/decision-gate-rs/src/docker_contract.rs"
test -f "$repository_root/data-plane/decision-gate-rs/src/dind_lifecycle.rs"

install -d -m 0755 \
    "$output_root/bin" "$output_root/policy" "$output_root/schemas"
install -m 0555 "$dockerd" "$output_root/bin/dockerd-v12"
install -m 0555 "$containerd" "$output_root/bin/containerd-v12"
install -m 0555 \
    "$containerd_shim" \
    "$output_root/bin/containerd-shim-runc-v2-v12"
install -m 0555 "$runc" "$output_root/bin/runc-v12"
install -m 0444 \
    "$pinned_pulls" "$output_root/policy/pinned-pulls.v12.json"
install -m 0444 \
    "$exact_builds" "$output_root/policy/exact-build-tuples.v12.json"

install -m 0444 \
    "$script_root/schemas/coder-docker-api-request.v12.schema.json" \
    "$output_root/schemas/coder-docker-api-request.v12.schema.json"
install -m 0444 \
    "$script_root/schemas/coder-docker-lane-capability.v12.schema.json" \
    "$output_root/schemas/coder-docker-lane-capability.v12.schema.json"
for schema in \
    coder-docker-network-membership.v12.schema.json \
    coder-docker-service-instance.v12.schema.json \
    coder-docker-runner-execution.v12.schema.json
do
    install -m 0444 \
        "$repository_root/schemas/$schema" \
        "$output_root/schemas/$schema"
done

docker_policy_sha256=$(sha256sum \
    "$repository_root/data-plane/decision-gate-rs/src/docker_policy.rs")
docker_policy_sha256=${docker_policy_sha256%% *}
docker_contract_sha256=$(sha256sum \
    "$repository_root/data-plane/decision-gate-rs/src/docker_contract.rs")
docker_contract_sha256=${docker_contract_sha256%% *}
dind_lifecycle_sha256=$(sha256sum \
    "$repository_root/data-plane/decision-gate-rs/src/dind_lifecycle.rs")
dind_lifecycle_sha256=${dind_lifecycle_sha256%% *}

printf '%s\n' \
    "{\"archiveContract\":{\"format\":\"catchplate/docker-image-archive-set/v12\",\"importVerification\":\"recanonicalize-and-require-byte-identity\",\"outerContainer\":\"canonical-ustar-v12\",\"producer\":\"canonicalize_docker_image_archive_v12\"},\"compiledSources\":{\"dindLifecycleSha256\":\"$dind_lifecycle_sha256\",\"dockerContractSha256\":\"$docker_contract_sha256\",\"dockerPolicySha256\":\"$docker_policy_sha256\"},\"contract\":\"catchplate/docker-api-rules/v12\",\"default\":\"deny\",\"enforcement\":\"compiled-rust-source-digest-bound-v12\",\"operationProfiles\":{\"build\":[\"createBuildDind\",\"pullPinned\",\"buildExact\",\"createRunner\",\"runRepositoryBody\",\"stopRunner\",\"exportOwnedOci\",\"destroyBuildDind\",\"queryAuthoritativeState\",\"readinessProbe\"],\"noBuild\":[\"createNoBuildDind\",\"importSealedOci\",\"createRunner\",\"createServices\",\"runRepositoryBody\",\"stopRunner\",\"destroyServices\",\"destroyNoBuildDind\",\"queryAuthoritativeState\",\"readinessProbe\"]},\"ownershipLabels\":{\"generation\":\"com.catchplate.coder.v12.generation\",\"lane\":\"com.catchplate.coder.v12.lane\",\"namespace\":\"com.catchplate.coder.v12.owner\",\"resource\":\"com.catchplate.coder.v12.resource\"},\"version\":12}" \
    > "$output_root/policy/docker-api-rules.v12.json"
chmod 0444 "$output_root/policy/docker-api-rules.v12.json"

printf '%s\n' \
    'Prepared exact v12 private-DinD assets. Sign the complete bundle and bind every emitted digest before installation.'
