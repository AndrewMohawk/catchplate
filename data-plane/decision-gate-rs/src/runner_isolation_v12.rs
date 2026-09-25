//! Closed Linux Engine API 1.45 runner configuration and pre-start readback.
//!
//! This checks the daemon's retained configuration, not kernel enforcement or
//! the sealed image's identity. Those remain independent readiness obligations.
//! In Moby 26, map-style HostConfig.Tmpfs is not in inspect.Mounts: see
//! container/container_unix.go::{TmpfsMounts,GetMountPoints}. Default protected
//! paths below are the Moby 26 oci/defaults.go profile; drift fails closed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

use crate::coder_controller_v11::{ControllerError, Result};
use crate::plan_protocol::{
    RunnerExecutionBoundsV12, RUNNER_PRIVATE_DATA_PATH_V12,
};
use crate::plan_protocol::body_launch_contract_v12::{
    CONTEXT_DIRECTORY, CONTEXT_PATH, SUPERVISOR_EXECUTABLE,
};

const MASKED_PATHS: &[&str] = &[
    "/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys",
    "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
    "/proc/sched_debug", "/proc/scsi", "/sys/firmware",
    "/sys/devices/virtual/powercap",
];
const READONLY_PATHS: &[&str] = &[
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys",
    "/proc/sysrq-trigger",
];
const HOST_ZERO_FIELDS: &[&str] = &[
    "CpuShares", "NanoCpus", "BlkioWeight", "CpuRealtimePeriod",
    "CpuRealtimeRuntime", "MemoryReservation", "OomScoreAdj", "CpuCount",
    "CpuPercent", "IOMaximumIOps", "IOMaximumBandwidth",
];
const HOST_EMPTY_STRINGS: &[&str] = &[
    "ContainerIDFile", "VolumeDriver", "Cgroup", "CgroupParent",
    "CpusetCpus", "CpusetMems", "Isolation",
];
const HOST_EMPTY_ARRAYS: &[&str] = &[
    "VolumesFrom", "Dns", "DnsOptions", "DnsSearch", "ExtraHosts",
    "GroupAdd", "Links", "BlkioWeightDevice", "BlkioDeviceReadBps",
    "BlkioDeviceWriteBps", "BlkioDeviceReadIOps", "BlkioDeviceWriteIOps",
    "Devices", "DeviceCgroupRules", "DeviceRequests",
];
const HOST_OPTIONAL_EMPTY_MAPS: &[&str] = &[
    "Annotations", "StorageOpt", "Sysctls",
];

fn rejected(field: &str) -> ControllerError {
    ControllerError::InvalidOwned(format!(
        "runner pre-start isolation differs: {field}",
    ))
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>> {
    value.as_object().ok_or_else(|| rejected(field))
}

fn exact(map: &Map<String, Value>, name: &str, expected: &Value) -> Result<()> {
    if map.get(name) != Some(expected) {
        return Err(rejected(name));
    }
    Ok(())
}

fn empty_array(value: Option<&Value>, optional: bool) -> bool {
    match value {
        None => optional,
        Some(Value::Null) => true,
        Some(Value::Array(values)) => values.is_empty(),
        _ => false,
    }
}

fn empty_map(value: Option<&Value>, optional: bool) -> bool {
    match value {
        None => optional,
        Some(Value::Null) => true,
        Some(Value::Object(values)) => values.is_empty(),
        _ => false,
    }
}

fn canonical_path(path: &str) -> bool {
    path.len() <= 4096
        && path.starts_with('/')
        && path != "/"
        && !path.bytes().any(|byte| byte < 0x20 || byte == 0x7f || byte == b':')
        && path[1..].split('/').all(|part| !part.is_empty() && part != "." && part != "..")
}

fn overlap(left: &str, right: &str) -> bool {
    left == right
        || left.strip_prefix(right).is_some_and(|tail| tail.starts_with('/'))
        || right.strip_prefix(left).is_some_and(|tail| tail.starts_with('/'))
}

/// Parse only the already-authorized controller bind form, never Docker's
/// general volume/mount option language. Authority over the sources is retained
/// by the caller; this helper does not authorize arbitrary host paths.
fn bind_inventory(binds: &[String]) -> Result<BTreeMap<String, (String, bool)>> {
    if !(3..=4).contains(&binds.len()) {
        return Err(rejected("bind count"));
    }
    let mut result = BTreeMap::new();
    let mut previous: Option<&str> = None;
    for bind in binds {
        let parts: Vec<_> = bind.split(':').collect();
        if parts.len() != 3
            || !canonical_path(parts[0])
            || !canonical_path(parts[1])
            || !matches!(parts[2], "ro" | "rw")
            || previous.is_some_and(|prior| prior >= bind.as_str())
            || ["/run", "/tmp", RUNNER_PRIVATE_DATA_PATH_V12]
                .iter().any(|path| overlap(path, parts[1]))
            || result.keys().any(|path: &String| overlap(path, parts[1]))
        {
            return Err(rejected("bind shape or destination"));
        }
        previous = Some(bind);
        result.insert(parts[1].to_owned(), (parts[0].to_owned(), parts[2] == "rw"));
    }
    if result.values().filter(|(_, writable)| *writable).count() != 1 {
        return Err(rejected("bind writable inventory"));
    }
    if !result.get(CONTEXT_DIRECTORY).is_some_and(|(_, writable)| !writable)
        || result.keys().any(|path| overlap(path, SUPERVISOR_EXECUTABLE))
    {
        return Err(rejected("fixed read-only launch context or sealed supervisor mount"));
    }
    Ok(result)
}

pub(super) fn execution_host_config_v12(
    bounds: &RunnerExecutionBoundsV12,
    binds: Vec<String>,
    network_mode: &str,
) -> Result<Value> {
    bounds.validate().map_err(|error| ControllerError::InvalidOwned(error.to_string()))?;
    bind_inventory(&binds)?;
    let private_network = network_mode.strip_prefix("swv12-net-").is_some_and(|suffix| {
        suffix.len() == 20 && suffix.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if network_mode != "none" && !private_network {
        return Err(rejected("network mode"));
    }
    let tmpfs_options = |bytes| format!(
        "rw,nosuid,nodev,noexec,size={bytes},mode=0700,uid={},gid={}",
        bounds.user_uid, bounds.user_gid,
    );
    Ok(json!({
        "AutoRemove": false,
        "Binds": binds,
        "CapAdd": [],
        "CapDrop": ["ALL"],
        "CgroupnsMode": "private",
        "CpuPeriod": bounds.cpu_period_micros,
        "CpuQuota": bounds.cpu_quota_micros,
        "Init": false,
        "IpcMode": "private",
        "LogConfig": {"Type": "json-file", "Config": {
            "max-size": "8m", "max-file": "1", "compress": "false"
        }},
        "Memory": bounds.memory_bytes,
        "MemorySwap": bounds.memory_bytes,
        "MemorySwappiness": 0,
        "NetworkMode": network_mode,
        "OomKillDisable": false,
        "PidMode": "",
        "PidsLimit": bounds.pids,
        "PortBindings": {},
        "Privileged": false,
        "PublishAllPorts": false,
        "ReadonlyRootfs": true,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "Runtime": "runc",
        "SecurityOpt": ["no-new-privileges=true"],
        "ShmSize": bounds.shm_bytes,
        "Tmpfs": {
            "/run": tmpfs_options(bounds.run_tmpfs_bytes),
            "/tmp": tmpfs_options(bounds.tmp_tmpfs_bytes),
            (RUNNER_PRIVATE_DATA_PATH_V12): tmpfs_options(bounds.private_data_bytes)
        },
        "UTSMode": "",
        "Ulimits": [{"Name": "nofile", "Soft": bounds.open_files, "Hard": bounds.open_files}],
        "UsernsMode": ""
    }))
}

fn validate_host(observed: &Value, expected: &Value) -> Result<()> {
    let actual = object(observed, "HostConfig")?;
    let expected = object(expected, "expected HostConfig")?;
    let mut allowed: BTreeSet<&str> = expected.keys().map(String::as_str).collect();
    for (key, value) in expected {
        // Go's nil and empty slice encodings both describe the closed empty
        // addition set. No nonempty capability list is equivalent.
        if key == "CapAdd" && value == &json!([]) {
            if !empty_array(actual.get(key), false) {
                return Err(rejected(key));
            }
        } else {
            exact(actual, key, value)?;
        }
    }
    for name in HOST_ZERO_FIELDS {
        allowed.insert(name);
        exact(actual, name, &json!(0))?;
    }
    for name in HOST_EMPTY_STRINGS {
        allowed.insert(name);
        exact(actual, name, &json!(""))?;
    }
    for name in HOST_EMPTY_ARRAYS {
        allowed.insert(name);
        if !empty_array(actual.get(*name), false) {
            return Err(rejected(name));
        }
    }
    for name in HOST_OPTIONAL_EMPTY_MAPS {
        allowed.insert(name);
        if !empty_map(actual.get(*name), true) {
            return Err(rejected(name));
        }
    }
    allowed.extend(["KernelMemory", "KernelMemoryTCP", "Mounts", "ConsoleSize", "MaskedPaths", "ReadonlyPaths"]);
    for name in ["KernelMemory", "KernelMemoryTCP"] {
        if actual.get(name).is_some_and(|value| value != &json!(0)) {
            return Err(rejected(name));
        }
    }
    if !empty_array(actual.get("Mounts"), true) {
        return Err(rejected("HostConfig.Mounts"));
    }
    exact(actual, "ConsoleSize", &json!([0, 0]))?;
    exact(actual, "MaskedPaths", &json!(MASKED_PATHS))?;
    exact(actual, "ReadonlyPaths", &json!(READONLY_PATHS))?;
    if actual.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(rejected("unknown HostConfig field"));
    }
    Ok(())
}

fn validate_config(actual: &Value, expected: &Value, container_id: &str) -> Result<()> {
    let actual = object(actual, "Config")?;
    let expected = object(expected, "expected create body")?;
    let exact_fields = [
        "User", "Image", "Entrypoint", "Cmd", "Env", "WorkingDir", "Labels",
        "AttachStdin", "AttachStdout", "AttachStderr", "OpenStdin", "StdinOnce",
        "Tty", "StopTimeout", "StopSignal",
    ];
    let mut allowed: BTreeSet<&str> = exact_fields.into_iter().collect();
    for name in exact_fields {
        let value = expected.get(name).ok_or_else(|| rejected(name))?;
        if value.is_null() {
            return Err(rejected(name));
        }
        // Empty image Env can become nil during Moby's config merge. The
        // zero-argument command may likewise have a nil slice representation.
        // Missing fields and any nonempty additions are never equivalent.
        if matches!(name, "Env" | "Cmd") && value == &json!([]) {
            if !empty_array(actual.get(name), false) {
                return Err(rejected(name));
            }
        } else {
            exact(actual, name, value)?;
        }
    }
    allowed.extend([
        "Hostname", "Domainname", "Healthcheck", "Volumes", "ExposedPorts",
        "OnBuild", "Shell", "ArgsEscaped", "NetworkDisabled", "MacAddress",
    ]);
    exact(actual, "Hostname", &json!(&container_id[..12]))?;
    exact(actual, "Domainname", &json!(""))?;
    for name in ["Volumes", "ExposedPorts"] {
        if !empty_map(actual.get(name), name == "ExposedPorts") {
            return Err(rejected(name));
        }
    }
    for name in ["OnBuild", "Shell"] {
        if !empty_array(actual.get(name), name == "Shell") {
            return Err(rejected(name));
        }
    }
    if actual.get("ArgsEscaped").is_some_and(|value| value != &json!(false))
        || actual.get("MacAddress").is_some_and(|value| value != &json!(""))
    {
        return Err(rejected("image platform defaults"));
    }
    let network_disabled = expected.get("NetworkDisabled").and_then(Value::as_bool)
        .ok_or_else(|| rejected("expected NetworkDisabled"))?;
    if network_disabled {
        exact(actual, "NetworkDisabled", &json!(true))?;
    } else if actual.get("NetworkDisabled").is_some_and(|value| value != &json!(false)) {
        return Err(rejected("NetworkDisabled"));
    }
    // A disabled image healthcheck is not another executable lane. Zero timing
    // fields may be omitted by the Engine's image-spec JSON serialization.
    exact(expected, "Healthcheck", &json!({"Test": ["NONE"]}))?;
    let health = object(actual.get("Healthcheck").ok_or_else(|| rejected("Healthcheck"))?, "Healthcheck")?;
    exact(health, "Test", &json!(["NONE"]))?;
    for (name, value) in health {
        if name != "Test" && (!matches!(name.as_str(), "Interval" | "Timeout" | "StartPeriod" | "StartInterval" | "Retries") || value != &json!(0)) {
            return Err(rejected("Healthcheck timing or extra field"));
        }
    }
    if actual.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(rejected("unknown Config field"));
    }
    Ok(())
}

fn validate_mounts(observed: &Value, expected_host: &Value) -> Result<()> {
    let binds = expected_host.get("Binds").and_then(Value::as_array)
        .ok_or_else(|| rejected("expected Binds"))?
        .iter().map(|value| value.as_str().map(str::to_owned)
            .ok_or_else(|| rejected("expected bind type")))
        .collect::<Result<Vec<_>>>()?;
    let mut expected = bind_inventory(&binds)?;
    let mounts = observed.as_array().ok_or_else(|| rejected("Mounts"))?;
    if mounts.len() != expected.len() {
        return Err(rejected("mount inventory count"));
    }
    for value in mounts {
        let mount = object(value, "Mounts entry")?;
        let destination = mount.get("Destination").and_then(Value::as_str)
            .ok_or_else(|| rejected("mount destination"))?;
        let (source, writable) = expected.remove(destination)
            .ok_or_else(|| rejected("unknown or duplicate mount destination"))?;
        exact(mount, "Type", &json!("bind"))?;
        exact(mount, "Source", &json!(source))?;
        exact(mount, "RW", &json!(writable))?;
        exact(mount, "Mode", &json!(if writable { "rw" } else { "ro" }))?;
        exact(mount, "Propagation", &json!("rprivate"))?;
        for name in ["Name", "Driver"] {
            if mount.get(name).is_some_and(|value| value != &json!("")) {
                return Err(rejected(name));
            }
        }
        if mount.keys().any(|name| !matches!(name.as_str(), "Type" | "Source" | "Destination" | "RW" | "Mode" | "Propagation" | "Name" | "Driver")) {
            return Err(rejected("unknown mount field"));
        }
    }
    Ok(())
}

fn validate_networks(observed: &Value, expected_host: &Value) -> Result<()> {
    // Moby 26 daemon/container_operations.go::updateContainerNetworkSettings
    // seeds only an empty configured endpoint for the private-network case.
    // NetworkDisabled returns before seeding; allocation happens at start.
    let network = object(observed, "NetworkSettings")?;
    let mode = expected_host.get("NetworkMode").and_then(Value::as_str)
        .ok_or_else(|| rejected("expected NetworkMode"))?;
    for name in [
        "Bridge", "SandboxID", "SandboxKey", "LinkLocalIPv6Address",
        "EndpointID", "Gateway", "GlobalIPv6Address", "IPAddress",
        "IPv6Gateway", "MacAddress",
    ] {
        exact(network, name, &json!(""))?;
    }
    for name in ["LinkLocalIPv6PrefixLen", "GlobalIPv6PrefixLen", "IPPrefixLen"] {
        exact(network, name, &json!(0))?;
    }
    exact(network, "HairpinMode", &json!(false))?;
    if !empty_map(network.get("Ports"), false)
        || !empty_array(network.get("SecondaryIPAddresses"), false)
        || !empty_array(network.get("SecondaryIPv6Addresses"), false)
    {
        return Err(rejected("allocated network data"));
    }
    let endpoints = object(network.get("Networks").ok_or_else(|| rejected("Networks"))?, "Networks")?;
    if mode == "none" {
        if !endpoints.is_empty() {
            return Err(rejected("disabled network inventory"));
        }
    } else {
        if endpoints.len() != 1 {
            return Err(rejected("private network inventory"));
        }
        let endpoint = object(endpoints.get(mode).ok_or_else(|| rejected("private network name"))?, "private endpoint")?;
        exact(endpoint, "IPAMConfig", &Value::Null)?;
        for name in ["Links", "Aliases", "DNSNames"] {
            if !empty_array(endpoint.get(name), false) {
                return Err(rejected(name));
            }
        }
        for name in ["MacAddress", "NetworkID", "EndpointID", "Gateway", "IPAddress", "IPv6Gateway", "GlobalIPv6Address"] {
            exact(endpoint, name, &json!(""))?;
        }
        for name in ["IPPrefixLen", "GlobalIPv6PrefixLen"] {
            exact(endpoint, name, &json!(0))?;
        }
        if !empty_map(endpoint.get("DriverOpts"), false)
            || endpoint.len() != 14
        {
            return Err(rejected("private endpoint options"));
        }
    }
    if network.len() != 18 {
        return Err(rejected("unknown NetworkSettings field"));
    }
    Ok(())
}

pub(super) fn validate_runner_inspect_v12(
    observed: &Value,
    expected_create: &Value,
    container_id: &str,
) -> Result<()> {
    if container_id.len() != 64 || !container_id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(rejected("container ID"));
    }
    let observed = object(observed, "inspect document")?;
    exact(observed, "Id", &json!(container_id))?;
    exact(observed, "Platform", &json!("linux"))?;
    // These are the actual executable/argument fields retained by Moby's
    // newContainer, not just its duplicate portable Config representation.
    let entrypoint = expected_create.get("Entrypoint").and_then(Value::as_array)
        .filter(|values| values.len() == 1 && values[0].is_string())
        .ok_or_else(|| rejected("expected single executable"))?;
    let arguments = expected_create.get("Cmd").and_then(Value::as_array)
        .filter(|values| values.iter().all(Value::is_string))
        .ok_or_else(|| rejected("expected executable arguments"))?;
    if entrypoint[0] != json!(SUPERVISOR_EXECUTABLE)
        || arguments != &vec![json!(CONTEXT_PATH)]
        || expected_create.get("Env") != Some(&json!([]))
        || expected_create.get("WorkingDir") != Some(&json!("/"))
    {
        return Err(rejected("fixed supervisor launch"));
    }
    exact(observed, "Path", &entrypoint[0])?;
    if arguments.is_empty() {
        if !empty_array(observed.get("Args"), false) {
            return Err(rejected("Args"));
        }
    } else {
        exact(observed, "Args", &json!(arguments))?;
    }
    exact(observed, "RestartCount", &json!(0))?;
    if !empty_array(observed.get("ExecIDs"), false) {
        return Err(rejected("ExecIDs"));
    }
    let state = object(observed.get("State").ok_or_else(|| rejected("State"))?, "State")?;
    for name in ["Running", "Paused", "Restarting", "Dead", "OOMKilled"] {
        exact(state, name, &json!(false))?;
    }
    exact(state, "Status", &json!("created"))?;
    exact(state, "Pid", &json!(0))?;
    exact(state, "ExitCode", &json!(0))?;
    exact(state, "Error", &json!(""))?;
    exact(state, "StartedAt", &json!("0001-01-01T00:00:00Z"))?;
    exact(state, "FinishedAt", &json!("0001-01-01T00:00:00Z"))?;
    if state.get("Health").is_some_and(|value| !value.is_null()) {
        return Err(rejected("started health state"));
    }
    let state_fields = if state.contains_key("Health") { 12 } else { 11 };
    if state.len() != state_fields {
        return Err(rejected("unknown State field"));
    }
    let expected_host = expected_create.get("HostConfig").ok_or_else(|| rejected("expected HostConfig"))?;
    validate_host(observed.get("HostConfig").ok_or_else(|| rejected("HostConfig"))?, expected_host)?;
    validate_config(observed.get("Config").ok_or_else(|| rejected("Config"))?, expected_create, container_id)?;
    validate_mounts(observed.get("Mounts").ok_or_else(|| rejected("Mounts"))?, expected_host)?;
    validate_networks(observed.get("NetworkSettings").ok_or_else(|| rejected("NetworkSettings"))?, expected_host)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn bounds() -> RunnerExecutionBoundsV12 {
        RunnerExecutionBoundsV12 {
            user_uid: 10001, user_gid: 10001,
            cpu_quota_micros: 200_000, cpu_period_micros: 100_000,
            memory_bytes: 4 * 1024 * 1024 * 1024, pids: 128, open_files: 1024,
            shm_bytes: 64 * 1024 * 1024, run_tmpfs_bytes: 64 * 1024 * 1024,
            tmp_tmpfs_bytes: 256 * 1024 * 1024, private_data_bytes: 2 * 1024 * 1024 * 1024,
            output_bytes: 64 * 1024 * 1024, output_inodes: 1024,
        }
    }

    fn fixture() -> (Value, Value) {
        let host = execution_host_config_v12(&bounds(), vec![
            format!("/owned/launch:{CONTEXT_DIRECTORY}:ro"),
            "/owned/output:/opt/results:rw".into(),
            "/owned/source:/opt/serverware/src:ro".into(),
        ], "none").unwrap();
        let expected = json!({
            "User": "10001:10001", "Image": "sealed@sha256:abcd",
            "Entrypoint": [SUPERVISOR_EXECUTABLE], "Cmd": [CONTEXT_PATH],
            "Env": [], "WorkingDir": "/",
            "Labels": {"owner": "source-bound"},
            "AttachStdin": false, "AttachStdout": false, "AttachStderr": false,
            "OpenStdin": false, "StdinOnce": false, "Tty": false,
            "StopTimeout": 10, "StopSignal": "SIGTERM",
            "NetworkDisabled": true, "Healthcheck": {"Test": ["NONE"]},
            "HostConfig": host,
        });
        let mut config = expected.clone();
        let config_map = config.as_object_mut().unwrap();
        config_map.remove("HostConfig");
        config_map.insert("Hostname".into(), json!(&ID[..12]));
        config_map.insert("Domainname".into(), json!(""));
        config_map.insert("Volumes".into(), Value::Null);
        config_map.insert("OnBuild".into(), Value::Null);
        let mut actual_host = host;
        let host_map = actual_host.as_object_mut().unwrap();
        for name in HOST_ZERO_FIELDS { host_map.insert((*name).into(), json!(0)); }
        for name in HOST_EMPTY_STRINGS { host_map.insert((*name).into(), json!("")); }
        for name in HOST_EMPTY_ARRAYS { host_map.insert((*name).into(), Value::Null); }
        host_map.insert("ConsoleSize".into(), json!([0, 0]));
        host_map.insert("MaskedPaths".into(), json!(MASKED_PATHS));
        host_map.insert("ReadonlyPaths".into(), json!(READONLY_PATHS));
        let observed = json!({
            "Id": ID, "Platform": "linux", "RestartCount": 0, "ExecIDs": null,
            "Path": SUPERVISOR_EXECUTABLE, "Args": [CONTEXT_PATH],
            "State": {"Status": "created", "Running": false, "Paused": false,
                "Restarting": false, "Dead": false, "OOMKilled": false, "Pid": 0,
                "ExitCode": 0, "Error": "", "StartedAt": "0001-01-01T00:00:00Z",
                "FinishedAt": "0001-01-01T00:00:00Z"},
            "Config": config, "HostConfig": actual_host,
            "NetworkSettings": {
                "Bridge":"", "SandboxID":"", "SandboxKey":"", "Ports":{},
                "HairpinMode":false, "LinkLocalIPv6Address":"", "LinkLocalIPv6PrefixLen":0,
                "SecondaryIPAddresses":null, "SecondaryIPv6Addresses":null,
                "EndpointID":"", "Gateway":"", "GlobalIPv6Address":"", "GlobalIPv6PrefixLen":0,
                "IPAddress":"", "IPPrefixLen":0, "IPv6Gateway":"", "MacAddress":"", "Networks":{}
            },
            "Mounts": [
                {"Type": "bind", "Source": "/owned/launch", "Destination": CONTEXT_DIRECTORY, "Mode": "ro", "RW": false, "Propagation": "rprivate"},
                {"Type": "bind", "Source": "/owned/source", "Destination": "/opt/serverware/src", "Mode": "ro", "RW": false, "Propagation": "rprivate"},
                {"Type": "bind", "Source": "/owned/output", "Destination": "/opt/results", "Mode": "rw", "RW": true, "Propagation": "rprivate"}
            ]
        });
        (expected, observed)
    }

    #[test]
    fn exact_created_runner_and_closed_empty_defaults_are_accepted() {
        let (expected, mut observed) = fixture();
        validate_runner_inspect_v12(&observed, &expected, ID).unwrap();
        observed["HostConfig"]["CapAdd"] = Value::Null;
        observed["HostConfig"]["Devices"] = json!([]);
        observed["Config"]["Volumes"] = json!({});
        observed["Config"]["Healthcheck"]["Interval"] = json!(0);
        validate_runner_inspect_v12(&observed, &expected, ID).unwrap();
    }

    #[test]
    fn fixed_supervisor_command_and_empty_environment_reject_inherited_authority() {
        let (mut expected, mut observed) = fixture();
        observed["Config"]["Env"] = Value::Null;
        validate_runner_inspect_v12(&observed, &expected, ID).unwrap();
        for name in ["Cmd", "Env"] {
            let mut missing = observed.clone();
            missing["Config"].as_object_mut().unwrap().remove(name);
            assert!(validate_runner_inspect_v12(&missing, &expected, ID).is_err(), "{name}");
            let mut extra = observed.clone();
            extra["Config"][name] = json!(["unexpected"]);
            assert!(validate_runner_inspect_v12(&extra, &expected, ID).is_err(), "{name}");
        }
        let mut missing = observed.clone();
        missing.as_object_mut().unwrap().remove("Args");
        assert!(validate_runner_inspect_v12(&missing, &expected, ID).is_err());
        let mut extra = observed.clone();
        extra["Args"] = json!(["unexpected"]);
        assert!(validate_runner_inspect_v12(&extra, &expected, ID).is_err());
        expected["Cmd"] = json!([]);
        observed["Config"]["Cmd"] = json!([]);
        observed["Args"] = json!([]);
        assert!(validate_runner_inspect_v12(&observed, &expected, ID).is_err());
    }

    #[test]
    fn host_config_binds_all_execution_bounds_and_fixed_log_limit() {
        let (expected, _) = fixture();
        let host = &expected["HostConfig"];
        assert_eq!(host["Memory"], json!(4u64 * 1024 * 1024 * 1024));
        assert_eq!(host["MemorySwap"], host["Memory"]);
        assert_eq!(host["CpuQuota"], json!(200_000));
        assert_eq!(host["PidsLimit"], json!(128));
        assert_eq!(host["Ulimits"], json!([{"Name":"nofile","Soft":1024,"Hard":1024}]));
        assert_eq!(host["Tmpfs"][RUNNER_PRIVATE_DATA_PATH_V12], json!("rw,nosuid,nodev,noexec,size=2147483648,mode=0700,uid=10001,gid=10001"));
        assert_eq!(host["LogConfig"]["Config"]["max-size"], json!("8m"));
        let mut bad = bounds();
        bad.pids = 0;
        assert!(execution_host_config_v12(&bad, vec![], "none").is_err());
    }

    #[test]
    fn every_explicit_host_field_and_required_config_field_rejects_drift() {
        let (expected, observed) = fixture();
        for name in expected["HostConfig"].as_object().unwrap().keys() {
            let mut changed = observed.clone();
            changed["HostConfig"][name] = json!("wrong-type-and-value");
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
        for name in ["User", "Image", "Entrypoint", "Cmd", "Env", "WorkingDir", "Labels", "AttachStdin", "AttachStdout", "AttachStderr", "OpenStdin", "StdinOnce", "Tty", "StopSignal", "StopTimeout"] {
            let mut changed = observed.clone();
            changed["Config"].as_object_mut().unwrap().remove(name);
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
    }

    #[test]
    fn default_extensions_cannot_add_devices_capabilities_namespaces_or_resources() {
        let (expected, observed) = fixture();
        for (name, value) in [
            ("CapAdd", json!(["SYS_ADMIN"])), ("Devices", json!([{}])),
            ("DeviceRequests", json!([{}])), ("VolumesFrom", json!(["other"])),
            ("PidMode", json!("host")), ("CgroupParent", json!("outside")),
            ("StorageOpt", json!({"size":"unbounded"})), ("Sysctls", json!({"kernel.shmmax":"99"})),
            ("Ulimits", json!([{"Name":"nofile","Soft":1024,"Hard":1024},{"Name":"core","Soft":-1,"Hard":-1}])),
            ("RestartPolicy", json!({"Name":"always","MaximumRetryCount":0})),
            ("LogConfig", json!({"Type":"syslog","Config":{}})),
            ("MaskedPaths", json!([])), ("ReadonlyPaths", json!([])),
            ("UnknownFutureOption", json!(false)),
        ] {
            let mut changed = observed.clone();
            changed["HostConfig"][name] = value;
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
    }

    #[test]
    fn image_inherited_environment_labels_health_or_volume_is_not_silent() {
        let (expected, observed) = fixture();
        for (name, value) in [
            ("Env", json!(["LANG=C.UTF-8","UNAPPROVED=1"])),
            ("Labels", json!({"owner":"source-bound","extra":"image"})),
            ("Healthcheck", json!({"Test":["CMD","unexpected"]})),
            ("Volumes", json!({"/extra":{}})), ("ExposedPorts", json!({"5432/tcp":{}})),
            ("OnBuild", json!(["RUN unexpected"])), ("Shell", json!(["/bin/sh","-c"])),
        ] {
            let mut changed = observed.clone();
            changed["Config"][name] = value;
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
    }

    #[test]
    fn mounts_reject_extra_unnamed_volumes_duplicate_destinations_and_drift() {
        let (expected, observed) = fixture();
        for value in [json!({"Type":"volume","Destination":"/extra","RW":true}), observed["Mounts"][0].clone()] {
            let mut changed = observed.clone();
            changed["Mounts"].as_array_mut().unwrap().push(value);
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err());
        }
        for (name, value) in [("Source",json!("/other")),("Type",json!("tmpfs")),("RW",json!(true)),("Propagation",json!("rshared")),("Mode",json!("ro,z"))] {
            let mut changed = observed.clone();
            changed["Mounts"][0][name] = value;
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
    }

    #[test]
    fn started_missing_coerced_or_different_container_is_rejected() {
        let (expected, observed) = fixture();
        for (name, value) in [("Running",json!(true)),("Status",json!("exited")),("Pid",json!("0")),("StartedAt",json!("2026-01-01T00:00:00Z")),("Paused",Value::Null)] {
            let mut changed = observed.clone();
            changed["State"][name] = value;
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
        let mut changed = observed.clone();
        changed["Id"] = json!("f".repeat(64));
        assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err());
        let mut changed = observed.clone();
        changed["Path"] = json!("/unexpected");
        assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err());
        let mut changed = observed.clone();
        changed["Args"] = json!([]);
        assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err());
        assert!(validate_runner_inspect_v12(&observed, &expected, "short").is_err());
    }

    #[test]
    fn bind_and_network_input_language_is_closed() {
        let (_, observed) = fixture();
        let valid = vec!["/owned/output:/opt/results:rw".into(), "/owned/source:/opt/serverware/src:ro".into()];
        for mode in ["host", "bridge", "container:other", "swv12-net-ABC", ""] {
            assert!(execution_host_config_v12(&bounds(), valid.clone(), mode).is_err());
        }
        assert!(execution_host_config_v12(&bounds(), valid, "swv12-net-0123456789abcdef0123").is_ok());
        for bind in ["/owned/source:/run/source:ro", "/owned/source:/opt/results:ro", "volume:/opt/source:ro", "/owned/source:/opt/source:ro,rshared"] {
            let mut invalid = vec!["/owned/output:/opt/results:rw".into(), bind.into()];
            invalid.sort();
            assert!(execution_host_config_v12(&bounds(), invalid, "none").is_err());
        }
        assert_eq!(observed["HostConfig"]["Tmpfs"].as_object().unwrap().len(), 3);
    }

    #[test]
    fn prestart_network_inventory_is_empty_or_exact_private_unallocated_endpoint() {
        let (mut expected, mut observed) = fixture();
        let private = "swv12-net-0123456789abcdef0123";
        let endpoint = json!({
            "IPAMConfig":null, "Links":null, "Aliases":null, "DNSNames":null,
            "MacAddress":"", "NetworkID":"", "EndpointID":"", "Gateway":"", "IPAddress":"",
            "IPPrefixLen":0, "IPv6Gateway":"", "GlobalIPv6Address":"", "GlobalIPv6PrefixLen":0,
            "DriverOpts":null
        });
        let mut unexpected = observed.clone();
        unexpected["NetworkSettings"]["Networks"][private] = endpoint.clone();
        assert!(validate_runner_inspect_v12(&unexpected, &expected, ID).is_err());
        expected["HostConfig"]["NetworkMode"] = json!(private);
        expected["NetworkDisabled"] = json!(false);
        observed["HostConfig"]["NetworkMode"] = json!(private);
        observed["Config"].as_object_mut().unwrap().remove("NetworkDisabled");
        observed["NetworkSettings"]["Networks"][private] = endpoint.clone();
        validate_runner_inspect_v12(&observed, &expected, ID).unwrap();
        let mut extra = observed.clone();
        extra["NetworkSettings"]["Networks"]["bridge"] = endpoint;
        assert!(validate_runner_inspect_v12(&extra, &expected, ID).is_err());
        for (name, value) in [("SandboxID",json!("allocated")),("Ports",json!({"5432/tcp":[]}))] {
            let mut changed = observed.clone();
            changed["NetworkSettings"][name] = value;
            assert!(validate_runner_inspect_v12(&changed, &expected, ID).is_err(), "{name}");
        }
        observed["NetworkSettings"]["Networks"][private]["DriverOpts"] = json!({"anything":"unexpected"});
        assert!(validate_runner_inspect_v12(&observed, &expected, ID).is_err());
    }
}
