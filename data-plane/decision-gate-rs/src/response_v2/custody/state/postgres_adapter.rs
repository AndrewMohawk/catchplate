use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{
    FileTypeExt, MetadataExt, OpenOptionsExt,
};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use sha2::{Digest as _, Sha256};

use super::super::super::state_authority::{
    AuthorityError, AuthorityResult, BootClock, BootDeadline, BootInstant,
    CgroupObservation, CgroupObserver, CgroupOwner, Digest, Identifier,
    ImmutableObjectStore, PgRow, PgValue, PostgresBackend,
    PostgresTransaction, ReconciliationDomain,
};
use super::super::super::state_authority::postgres::statements;

const POSTGRES_PROTOCOL_V3: i32 = 196_608;
const MAX_POSTGRES_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_EXACT_OBJECT_BYTES: u64 = 34_603_008;
const MAX_BOOT_ID_BYTES: usize = 128;
const MAX_PROC_RECORD_BYTES: usize = 64 * 1024;
const MAX_CGROUP_EVENTS_BYTES: usize = 4 * 1024;
const CLOCK_NAME: &str = "CLOCK_BOOTTIME";
const SYSTEM_CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Clone, Copy, Default)]
pub(crate) struct LinuxBootClock;

impl LinuxBootClock {
    pub(crate) fn new() -> AuthorityResult<Self> {
        let clock = Self;
        clock.current_boot_instant()?;
        Ok(clock)
    }

    pub(crate) fn deadline_after(
        &self,
        timeout: Duration,
    ) -> AuthorityResult<BootDeadline> {
        let instant = self.current_boot_instant()?;
        let timeout_millis =
            u64::try_from(timeout.as_millis()).map_err(|_| {
                pg_error(
                    "boottime_deadline_overflow",
                    "timeout exceeds response-v2 integer bounds",
                )
            })?;
        let deadline_boot_millis = instant
            .boot_millis
            .checked_add(timeout_millis)
            .ok_or_else(|| {
                pg_error(
                    "boottime_deadline_overflow",
                    "CLOCK_BOOTTIME deadline overflow",
                )
            })?;
        let deadline = BootDeadline {
            clock: CLOCK_NAME.to_owned(),
            boot_id: instant.boot_id,
            deadline_boot_millis,
        };
        deadline.validate()?;
        Ok(deadline)
    }
}

impl BootClock for LinuxBootClock {
    fn current_boot_instant(&self) -> AuthorityResult<BootInstant> {
        #[cfg(not(target_os = "linux"))]
        {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "linux_clock_boottime_unavailable".to_owned(),
                ],
            });
        }
        #[cfg(target_os = "linux")]
        {
            let boot_id_bytes = fs::read(
                "/proc/sys/kernel/random/boot_id",
            )
            .map_err(|error| {
                pg_error("boot_id_unavailable", error.to_string())
            })?;
            if boot_id_bytes.is_empty()
                || boot_id_bytes.len() > MAX_BOOT_ID_BYTES
            {
                return Err(pg_error(
                    "boot_id_invalid",
                    "kernel boot ID is outside the fixed bound",
                ));
            }
            let boot_id = std::str::from_utf8(&boot_id_bytes)
                .map_err(|_| {
                    pg_error(
                        "boot_id_invalid",
                        "kernel boot ID is not UTF-8",
                    )
                })?
                .trim();
            let boot_id = Identifier(boot_id.to_owned());
            boot_id.validate("bootClock.bootId", MAX_BOOT_ID_BYTES)?;
            let mut value = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: value is a valid writable timespec.
            if unsafe {
                libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value)
            } != 0
                || value.tv_sec < 0
                || value.tv_nsec < 0
                || value.tv_nsec >= 1_000_000_000
            {
                return Err(pg_error(
                    "clock_boottime_unavailable",
                    std::io::Error::last_os_error().to_string(),
                ));
            }
            let seconds =
                u64::try_from(value.tv_sec).map_err(|_| {
                    pg_error(
                        "clock_boottime_invalid",
                        "negative CLOCK_BOOTTIME seconds",
                    )
                })?;
            let nanos =
                u64::try_from(value.tv_nsec).map_err(|_| {
                    pg_error(
                        "clock_boottime_invalid",
                        "negative CLOCK_BOOTTIME nanoseconds",
                    )
                })?;
            let boot_millis = seconds
                .checked_mul(1_000)
                .and_then(|millis| millis.checked_add(nanos / 1_000_000))
                .ok_or_else(|| {
                    pg_error(
                        "clock_boottime_overflow",
                        "CLOCK_BOOTTIME exceeds response-v2 bounds",
                    )
                })?;
            Ok(BootInstant {
                clock: CLOCK_NAME.to_owned(),
                boot_id,
                boot_millis,
            })
        }
    }
}

pub(crate) struct LinuxCgroupV2Observer {
    root: PathBuf,
    clock: LinuxBootClock,
}

impl LinuxCgroupV2Observer {
    pub(crate) fn new(root: PathBuf) -> AuthorityResult<Self> {
        if !root.is_absolute()
            || root.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::Prefix(_)
                )
            })
        {
            return Err(pg_error(
                "cgroup_root_invalid",
                "cgroup-v2 root must be an absolute normal path",
            ));
        }
        let metadata = fs::symlink_metadata(&root).map_err(|error| {
            pg_error("cgroup_root_unavailable", error.to_string())
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || !root.join("cgroup.controllers").is_file()
        {
            return Err(pg_error(
                "cgroup_v2_unavailable",
                "configured cgroup root is not a concrete cgroup-v2 directory",
            ));
        }
        Ok(Self {
            root,
            clock: LinuxBootClock::new()?,
        })
    }

    pub(crate) fn system_root() -> AuthorityResult<Self> {
        Self::new(PathBuf::from(SYSTEM_CGROUP_ROOT))
    }

    fn relative_path(
        &self,
        cgroup_id: &Identifier,
    ) -> AuthorityResult<PathBuf> {
        cgroup_id.validate("cgroupOwner.cgroupId", 256)?;
        let value = cgroup_id
            .0
            .strip_prefix("cgroupv2:")
            .unwrap_or(&cgroup_id.0)
            .trim_start_matches('/');
        let relative = Path::new(value);
        if value.is_empty()
            || relative.is_absolute()
            || relative.components().any(|component| {
                !matches!(component, Component::Normal(_))
            })
        {
            return Err(pg_error(
                "cgroup_id_invalid",
                "cgroup ID must identify one normal relative cgroup-v2 path",
            ));
        }
        Ok(relative.to_path_buf())
    }
}

impl CgroupObserver for LinuxCgroupV2Observer {
    fn observe(
        &self,
        owner: &CgroupOwner,
        deadline: &BootDeadline,
    ) -> AuthorityResult<CgroupObservation> {
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        owner
            .process_id
            .validate("cgroupOwner.processId", 128)?;
        if owner.pid == 0 || owner.process_start_time_ticks == 0 {
            return Err(pg_error(
                "cgroup_owner_invalid",
                "owner PID and process start time must be nonzero",
            ));
        }
        let relative = self.relative_path(&owner.cgroup_id)?;
        let cgroup_path = self.root.join(&relative);
        if !cgroup_path.starts_with(&self.root) {
            return Err(pg_error(
                "cgroup_path_escape",
                "cgroup path escapes the configured authority root",
            ));
        }
        let metadata =
            fs::symlink_metadata(&cgroup_path).map_err(|error| {
                pg_error("cgroup_unavailable", error.to_string())
            })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
        {
            return Err(pg_error(
                "cgroup_invalid",
                "authority cgroup is not a concrete directory",
            ));
        }

        let stat_path = format!("/proc/{}/stat", owner.pid);
        let owner_death_observed = match bounded_read(
            Path::new(&stat_path),
            MAX_PROC_RECORD_BYTES,
        ) {
            Ok(stat) => {
                parse_process_start_time_ticks(&stat)?
                    != owner.process_start_time_ticks
            }
            Err(AuthorityError::Backend {
                code: "bounded_file_missing",
                ..
            }) => true,
            Err(error) => return Err(error),
        };
        if !owner_death_observed {
            let process_cgroup_path =
                format!("/proc/{}/cgroup", owner.pid);
            let process_cgroup = bounded_read(
                Path::new(&process_cgroup_path),
                MAX_PROC_RECORD_BYTES,
            )?;
            if parse_process_cgroup_v2_path(&process_cgroup)?
                != relative
            {
                return Err(pg_error(
                    "cgroup_owner_binding_mismatch",
                    "live PID is not in the expected cgroup-v2 path",
                ));
            }
        }

        let events = bounded_read(
            &cgroup_path.join("cgroup.events"),
            MAX_CGROUP_EVENTS_BYTES,
        )?;
        let cgroup_empty_observed =
            parse_cgroup_populated(&events)? == 0;
        let observation = CgroupObservation {
            owner_death_observed,
            cgroup_empty_observed,
            cgroup_death_observed:
                owner_death_observed && cgroup_empty_observed,
        };
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        Ok(observation)
    }
}

#[derive(Clone)]
pub(crate) struct PostgresUdsBackend {
    socket_path: PathBuf,
    database: String,
    user: String,
    timeout: Duration,
    cgroup_root: PathBuf,
}

impl PostgresUdsBackend {
    pub(crate) fn from_signed_backend_socket(
        backend_socket_path: &Path,
        service_id: &str,
        timeout: Duration,
    ) -> AuthorityResult<Self> {
        validate_postgres_socket_path(backend_socket_path)?;
        if service_id.is_empty() || timeout.is_zero() {
            return Err(pg_error(
                "postgres_configuration_invalid",
                "PostgreSQL service identity and timeout are required",
            ));
        }
        Ok(Self {
            socket_path: backend_socket_path.to_path_buf(),
            database: "serverware_response_v2".to_owned(),
            user: service_id.to_owned(),
            timeout,
            cgroup_root: PathBuf::from(SYSTEM_CGROUP_ROOT),
        })
    }

    pub(crate) fn from_signed_process(
        state_directory: &Path,
        service_id: &str,
        timeout: Duration,
    ) -> Self {
        Self {
            socket_path: state_directory
                .join("postgres")
                .join(".s.PGSQL.5432"),
            database: "serverware_response_v2".to_owned(),
            user: service_id.to_owned(),
            timeout,
            cgroup_root: PathBuf::from(SYSTEM_CGROUP_ROOT),
        }
    }

    pub(crate) fn with_cgroup_root(
        mut self,
        cgroup_root: PathBuf,
    ) -> AuthorityResult<Self> {
        LinuxCgroupV2Observer::new(cgroup_root.clone())?;
        self.cgroup_root = cgroup_root;
        Ok(self)
    }

    pub(crate) fn reconciliation_readiness(
        &self,
        generation_id: &str,
    ) -> AuthorityResult<(u64, String)> {
        let clock = LinuxBootClock::new()?;
        let deadline = clock.deadline_after(self.timeout)?;
        let mut transaction =
            self.begin_serializable(&deadline)?;
        let generation = transaction
            .query_optional(
                "SELECT status FROM response_v2_state_authority.provider_generations WHERE generation_id = $1 FOR SHARE",
                &[PgValue::Text(generation_id.to_owned())],
            )?
            .ok_or_else(|| AuthorityError::NotReady {
                blockers: vec!["provider_generation_missing".to_owned()],
            })?;
        if generation.require_text("status")? != "READY" {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "provider_generation_not_ready".to_owned(),
                ],
            });
        }
        let jobs = transaction.query_many(
            "SELECT domain, state, authoritative_cursor, COALESCE(blocker_code, '') AS blocker_code FROM response_v2_state_authority.reconciliation_jobs WHERE generation_id = $1 ORDER BY domain FOR SHARE",
            &[PgValue::Text(generation_id.to_owned())],
        )?;
        let required = ReconciliationDomain::REQUIRED
            .into_iter()
            .map(ReconciliationDomain::as_str)
            .collect::<BTreeSet<_>>();
        if jobs.len() != required.len() {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "reconciliation_domain_set_incomplete".to_owned(),
                ],
            });
        }
        let mut high_water = u64::MAX;
        let mut hasher = Sha256::new();
        let mut seen = BTreeSet::new();
        hasher.update(
            b"serverware.response-v2/postgres-reconciliation/v1",
        );
        for job in jobs {
            let domain_name = job.require_text("domain")?;
            let domain = ReconciliationDomain::REQUIRED
                .into_iter()
                .find(|candidate| {
                    candidate.as_str() == domain_name
                })
                .ok_or_else(|| AuthorityError::NotReady {
                    blockers: vec![format!(
                        "unknown_reconciliation_domain:{domain_name}"
                    )],
                })?;
            let state = job.require_text("state")?;
            let cursor = job.require_u64("authoritative_cursor")?;
            let blocker = job.require_text("blocker_code")?;
            let current_cursor = transaction
                .query_optional(
                    reconciliation_cursor_statement(domain),
                    &[PgValue::Text(generation_id.to_owned())],
                )?
                .ok_or_else(|| AuthorityError::NotReady {
                    blockers: vec![format!(
                        "reconciliation_cursor_missing:{domain_name}"
                    )],
                })?
                .require_u64("authoritative_cursor")?;
            if !required.contains(domain_name.as_str())
                || !seen.insert(domain_name.clone())
                || state != "COMPLETE"
                || !blocker.is_empty()
                || cursor == 0
                || cursor != current_cursor
            {
                return Err(AuthorityError::NotReady {
                    blockers: vec![format!(
                        "reconciliation_domain_not_ready:{domain_name}"
                    )],
                });
            }
            let cursor_bytes = cursor.to_be_bytes();
            for value in [
                domain_name.as_bytes(),
                state.as_bytes(),
                cursor_bytes.as_slice(),
            ] {
                hasher.update((value.len() as u64).to_be_bytes());
                hasher.update(value);
            }
            high_water = high_water.min(cursor);
        }
        if seen.len() != required.len() {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "reconciliation_domain_set_mismatch".to_owned(),
                ],
            });
        }
        let blockers = transaction.query_many(
            statements::READINESS_BLOCKERS_SQL,
            &[
                PgValue::Text(generation_id.to_owned()),
                PgValue::Text("readiness-probe".to_owned()),
            ],
        )?;
        if !blockers.is_empty() {
            return Err(AuthorityError::NotReady {
                blockers: blockers
                    .iter()
                    .map(|row| row.require_text("code"))
                    .collect::<AuthorityResult<Vec<_>>>()?,
            });
        }
        transaction.commit(&deadline)?;
        if high_water == 0 || high_water == u64::MAX {
            return Err(AuthorityError::NotReady {
                blockers: vec![
                    "reconciliation_high_water_invalid".to_owned(),
                ],
            });
        }
        Ok((
            high_water,
            format!("sha256:{:x}", hasher.finalize()),
        ))
    }
}

fn reconciliation_cursor_statement(
    domain: ReconciliationDomain,
) -> &'static str {
    match domain {
        ReconciliationDomain::ProviderGenerations => {
            statements::PROVIDER_GENERATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::RoleIdentities => {
            statements::ROLE_IDENTITIES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Operations => {
            statements::OPERATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Attempts => {
            statements::ATTEMPTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ReplayLedger => {
            statements::REPLAY_LEDGER_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TerminalSettlements => {
            statements::TERMINAL_SETTLEMENTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TargetEffects => {
            statements::TARGET_EFFECTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Fences => {
            statements::FENCES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Releases => {
            statements::RELEASES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::CredentialUses => {
            statements::CREDENTIAL_USES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::PolicyDecisions => {
            statements::POLICY_DECISIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Evidence => {
            statements::EVIDENCE_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ImmutableInspections => {
            statements::INSPECTIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Finalizations => {
            statements::FINALIZATIONS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::ImmutableObjects => {
            statements::IMMUTABLE_OBJECTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::Archives => {
            statements::ARCHIVES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::PublisherOutbox => {
            statements::PUBLISHER_OUTBOX_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TransparencyLeaves => {
            statements::TRANSPARENCY_LEAVES_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TransparencyCheckpoints => {
            statements::
                TRANSPARENCY_CHECKPOINTS_RECONCILIATION_CURSOR_SQL
        }
        ReconciliationDomain::TrustedTimeHighwater => {
            statements::TRUSTED_TIME_RECONCILIATION_CURSOR_SQL
        }
    }
}

impl BootClock for PostgresUdsBackend {
    fn current_boot_instant(&self) -> AuthorityResult<BootInstant> {
        LinuxBootClock.current_boot_instant()
    }
}

impl CgroupObserver for PostgresUdsBackend {
    fn observe(
        &self,
        owner: &CgroupOwner,
        deadline: &BootDeadline,
    ) -> AuthorityResult<CgroupObservation> {
        LinuxCgroupV2Observer::new(self.cgroup_root.clone())?
            .observe(owner, deadline)
    }
}

impl PostgresBackend for PostgresUdsBackend {
    fn begin_serializable(
        &self,
        deadline: &BootDeadline,
    ) -> AuthorityResult<Box<dyn PostgresTransaction + '_>> {
        let clock = LinuxBootClock::new()?;
        deadline.ensure_current(&clock.current_boot_instant()?)?;
        validate_postgres_socket_path(&self.socket_path)?;
        let mut connection = PgConnection::connect(
            &self.socket_path,
            &self.user,
            &self.database,
            self.timeout,
        )?;
        connection.simple_query(
            "BEGIN ISOLATION LEVEL SERIALIZABLE; SET LOCAL synchronous_commit = on",
        )?;
        deadline.ensure_current(&clock.current_boot_instant()?)?;
        Ok(Box::new(PgTransaction {
            connection: Some(connection),
            clock,
        }))
    }
}

struct PgTransaction {
    connection: Option<PgConnection>,
    clock: LinuxBootClock,
}

impl PostgresTransaction for PgTransaction {
    fn execute(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<u64> {
        let response = self.connection()?.extended_query(sql, parameters)?;
        Ok(response.affected_rows)
    }

    fn query_optional(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<Option<PgRow>> {
        let mut response =
            self.connection()?.extended_query(sql, parameters)?;
        if response.rows.len() > 1 {
            return Err(pg_error(
                "postgres_cardinality_mismatch",
                "query_optional returned more than one row",
            ));
        }
        Ok(response.rows.pop())
    }

    fn query_many(
        &mut self,
        sql: &'static str,
        parameters: &[PgValue],
    ) -> AuthorityResult<Vec<PgRow>> {
        Ok(self
            .connection()?
            .extended_query(sql, parameters)?
            .rows)
    }

    fn commit(
        mut self: Box<Self>,
        deadline: &BootDeadline,
    ) -> AuthorityResult<()> {
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        let mut connection = self.connection.take().ok_or_else(|| {
            pg_error(
                "postgres_transaction_closed",
                "transaction connection is already closed",
            )
        })?;
        connection.simple_query("COMMIT")?;
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        Ok(())
    }
}

impl PgTransaction {
    fn connection(&mut self) -> AuthorityResult<&mut PgConnection> {
        self.connection.as_mut().ok_or_else(|| {
            pg_error(
                "postgres_transaction_closed",
                "transaction connection is already closed",
            )
        })
    }
}

impl Drop for PgTransaction {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.as_mut() {
            let _ = connection.simple_query("ROLLBACK");
        }
    }
}

fn validate_postgres_socket_path(
    socket_path: &Path,
) -> AuthorityResult<()> {
    if !socket_path.is_absolute()
        || socket_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_)
            )
        })
        || !socket_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".s.PGSQL."))
    {
        return Err(pg_error(
            "postgres_socket_path_invalid",
            "signed PostgreSQL backend must be an absolute normal server socket path",
        ));
    }
    let metadata = fs::symlink_metadata(socket_path).map_err(|error| {
        pg_error("postgres_socket_unavailable", error.to_string())
    })?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
    {
        return Err(pg_error(
            "postgres_socket_identity_invalid",
            "signed PostgreSQL backend is not a single-link Unix socket",
        ));
    }
    Ok(())
}

fn bounded_read(
    path: &Path,
    maximum_bytes: usize,
) -> AuthorityResult<Vec<u8>> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(pg_error(
                "bounded_file_missing",
                path.display().to_string(),
            ))
        }
        Err(error) => {
            return Err(pg_error(
                "bounded_file_unavailable",
                format!("{}: {error}", path.display()),
            ))
        }
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            pg_error(
                "bounded_file_read_failed",
                format!("{}: {error}", path.display()),
            )
        })?;
    if bytes.len() > maximum_bytes {
        return Err(pg_error(
            "bounded_file_too_large",
            path.display().to_string(),
        ));
    }
    Ok(bytes)
}

fn parse_process_start_time_ticks(
    stat: &[u8],
) -> AuthorityResult<u64> {
    let stat = std::str::from_utf8(stat).map_err(|_| {
        pg_error("proc_stat_invalid", "process stat is not UTF-8")
    })?;
    let command_end = stat.rfind(')').ok_or_else(|| {
        pg_error(
            "proc_stat_invalid",
            "process stat omits the command terminator",
        )
    })?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| {
            pg_error(
                "proc_stat_invalid",
                "process stat is truncated",
            )
        })?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| {
            pg_error(
                "proc_stat_invalid",
                "process stat omits start-time ticks",
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            pg_error(
                "proc_stat_invalid",
                "process start-time ticks are invalid",
            )
        })
}

fn parse_process_cgroup_v2_path(
    cgroup: &[u8],
) -> AuthorityResult<PathBuf> {
    let cgroup = std::str::from_utf8(cgroup).map_err(|_| {
        pg_error(
            "proc_cgroup_invalid",
            "process cgroup record is not UTF-8",
        )
    })?;
    let mut unified = None;
    for line in cgroup.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            if unified.is_some() {
                return Err(pg_error(
                    "proc_cgroup_invalid",
                    "process has duplicate cgroup-v2 records",
                ));
            }
            let path = path.trim_start_matches('/');
            let path = Path::new(path);
            if path.as_os_str().is_empty()
                || path.components().any(|component| {
                    !matches!(component, Component::Normal(_))
                })
            {
                return Err(pg_error(
                    "proc_cgroup_invalid",
                    "process cgroup-v2 path is not normal",
                ));
            }
            unified = Some(path.to_path_buf());
        }
    }
    unified.ok_or_else(|| {
        pg_error(
            "proc_cgroup_invalid",
            "process has no cgroup-v2 record",
        )
    })
}

fn parse_cgroup_populated(events: &[u8]) -> AuthorityResult<u8> {
    let events = std::str::from_utf8(events).map_err(|_| {
        pg_error(
            "cgroup_events_invalid",
            "cgroup.events is not UTF-8",
        )
    })?;
    let mut populated = None;
    for line in events.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next() else {
            return Err(pg_error(
                "cgroup_events_invalid",
                "cgroup.events contains a partial record",
            ));
        };
        if fields.next().is_some() {
            return Err(pg_error(
                "cgroup_events_invalid",
                "cgroup.events contains surplus fields",
            ));
        }
        if name == "populated" {
            if populated.is_some() || !matches!(value, "0" | "1") {
                return Err(pg_error(
                    "cgroup_events_invalid",
                    "cgroup.events populated record is not unique and binary",
                ));
            }
            populated = Some(if value == "1" { 1 } else { 0 });
        }
    }
    populated.ok_or_else(|| {
        pg_error(
            "cgroup_events_invalid",
            "cgroup.events omits populated",
        )
    })
}

struct PgConnection {
    stream: UnixStream,
}

struct QueryResponse {
    rows: Vec<PgRow>,
    affected_rows: u64,
}

#[derive(Clone)]
struct ColumnDescription {
    name: String,
    type_oid: u32,
}

impl PgConnection {
    fn connect(
        socket_path: &Path,
        user: &str,
        database: &str,
        timeout: Duration,
    ) -> AuthorityResult<Self> {
        if !socket_path.is_absolute()
            || user.is_empty()
            || database.is_empty()
            || user.as_bytes().contains(&0)
            || database.as_bytes().contains(&0)
        {
            return Err(pg_error(
                "postgres_configuration_invalid",
                "PostgreSQL UDS, user, and database must be closed values",
            ));
        }
        let stream = UnixStream::connect(socket_path).map_err(|error| {
            pg_error(
                "postgres_unavailable",
                format!("connect signed PostgreSQL UDS: {error}"),
            )
        })?;
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|_| stream.set_write_timeout(Some(timeout)))
            .map_err(|error| {
                pg_error(
                    "postgres_timeout_configuration_failed",
                    error.to_string(),
                )
            })?;
        let mut connection = Self { stream };
        connection.startup(user, database)?;
        Ok(connection)
    }

    fn startup(
        &mut self,
        user: &str,
        database: &str,
    ) -> AuthorityResult<()> {
        let mut body = Vec::new();
        body.extend_from_slice(&POSTGRES_PROTOCOL_V3.to_be_bytes());
        for (name, value) in [
            ("user", user),
            ("database", database),
            ("application_name", "serverware-response-v2-state-authority"),
            ("client_encoding", "UTF8"),
        ] {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        let length = body
            .len()
            .checked_add(4)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| {
                pg_error(
                    "postgres_message_too_large",
                    "startup message length overflow",
                )
            })?;
        self.stream
            .write_all(&length.to_be_bytes())
            .and_then(|_| self.stream.write_all(&body))
            .map_err(pg_io_error)?;
        loop {
            let (message_type, payload) = self.read_message()?;
            match message_type {
                b'R' => {
                    if payload.len() != 4
                        || i32::from_be_bytes(
                            payload[..4].try_into().unwrap_or([0; 4]),
                        ) != 0
                    {
                        return Err(pg_error(
                            "postgres_peer_auth_required",
                            "state authority permits only PostgreSQL AuthenticationOk over the signed local UDS",
                        ));
                    }
                }
                b'S' | b'K' | b'N' => {}
                b'E' => return Err(parse_error_response(&payload)),
                b'Z' if payload.len() == 1 => return Ok(()),
                _ => {
                    return Err(pg_error(
                        "postgres_protocol_violation",
                        "unexpected startup response",
                    ))
                }
            }
        }
    }

    fn simple_query(&mut self, sql: &str) -> AuthorityResult<()> {
        if sql.as_bytes().contains(&0) {
            return Err(pg_error(
                "postgres_query_invalid",
                "query contains NUL",
            ));
        }
        let mut payload = sql.as_bytes().to_vec();
        payload.push(0);
        self.write_message(b'Q', &payload)?;
        self.read_query_response().map(|_| ())
    }

    fn extended_query(
        &mut self,
        sql: &str,
        parameters: &[PgValue],
    ) -> AuthorityResult<QueryResponse> {
        if sql.as_bytes().contains(&0)
            || parameters.len() > i16::MAX as usize
        {
            return Err(pg_error(
                "postgres_query_invalid",
                "query or parameter count exceeds the closed protocol",
            ));
        }
        let mut parse = Vec::new();
        parse.push(0);
        parse.extend_from_slice(sql.as_bytes());
        parse.push(0);
        parse.extend_from_slice(&0_i16.to_be_bytes());
        self.write_message(b'P', &parse)?;

        let mut bind = Vec::new();
        bind.push(0);
        bind.push(0);
        bind.extend_from_slice(&0_i16.to_be_bytes());
        bind.extend_from_slice(
            &(parameters.len() as i16).to_be_bytes(),
        );
        for parameter in parameters {
            match encode_parameter(parameter)? {
                None => bind.extend_from_slice(&(-1_i32).to_be_bytes()),
                Some(bytes) => {
                    let length = i32::try_from(bytes.len()).map_err(|_| {
                        pg_error(
                            "postgres_parameter_too_large",
                            "parameter exceeds PostgreSQL protocol bounds",
                        )
                    })?;
                    bind.extend_from_slice(&length.to_be_bytes());
                    bind.extend_from_slice(&bytes);
                }
            }
        }
        bind.extend_from_slice(&0_i16.to_be_bytes());
        self.write_message(b'B', &bind)?;
        self.write_message(b'D', &[b'P', 0])?;
        self.write_message(b'E', &[0, 0, 0, 0, 0])?;
        self.write_message(b'S', &[])?;
        self.read_query_response()
    }

    fn read_query_response(&mut self) -> AuthorityResult<QueryResponse> {
        let mut columns = Vec::new();
        let mut rows = Vec::new();
        let mut affected_rows = 0;
        loop {
            let (message_type, payload) = self.read_message()?;
            match message_type {
                b'1' | b'2' | b'3' | b'n' | b's' | b'N' => {}
                b'T' => columns = parse_row_description(&payload)?,
                b'D' => rows.push(parse_data_row(&payload, &columns)?),
                b'C' => {
                    affected_rows =
                        parse_command_row_count(&payload)?;
                }
                b'E' => return Err(parse_error_response(&payload)),
                b'Z' if payload.len() == 1 => {
                    return Ok(QueryResponse {
                        rows,
                        affected_rows,
                    })
                }
                _ => {
                    return Err(pg_error(
                        "postgres_protocol_violation",
                        "unexpected query response",
                    ))
                }
            }
        }
    }

    fn write_message(
        &mut self,
        message_type: u8,
        payload: &[u8],
    ) -> AuthorityResult<()> {
        let length = payload
            .len()
            .checked_add(4)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| {
                pg_error(
                    "postgres_message_too_large",
                    "frontend message length overflow",
                )
            })?;
        self.stream
            .write_all(&[message_type])
            .and_then(|_| self.stream.write_all(&length.to_be_bytes()))
            .and_then(|_| self.stream.write_all(payload))
            .map_err(pg_io_error)
    }

    fn read_message(&mut self) -> AuthorityResult<(u8, Vec<u8>)> {
        let mut message_type = [0u8; 1];
        let mut length = [0u8; 4];
        self.stream
            .read_exact(&mut message_type)
            .and_then(|_| self.stream.read_exact(&mut length))
            .map_err(pg_io_error)?;
        let length = i32::from_be_bytes(length);
        if length < 4
            || length as usize > MAX_POSTGRES_MESSAGE_BYTES
        {
            return Err(pg_error(
                "postgres_message_invalid",
                "backend message length is outside the fixed bound",
            ));
        }
        let mut payload = vec![0u8; length as usize - 4];
        self.stream
            .read_exact(&mut payload)
            .map_err(pg_io_error)?;
        Ok((message_type[0], payload))
    }
}

fn encode_parameter(value: &PgValue) -> AuthorityResult<Option<Vec<u8>>> {
    Ok(match value {
        PgValue::Null => None,
        PgValue::Text(value) => Some(value.as_bytes().to_vec()),
        PgValue::I64(value) => Some(value.to_string().into_bytes()),
        PgValue::U64(value) => {
            i64::try_from(*value).map_err(|_| {
                pg_error(
                    "postgres_integer_out_of_range",
                    "u64 exceeds PostgreSQL bigint",
                )
            })?;
            Some(value.to_string().into_bytes())
        }
        PgValue::Bool(value) => {
            Some(if *value {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            })
        }
        PgValue::Bytes(value) => {
            Some(format!("\\x{}", hex::encode(value)).into_bytes())
        }
        PgValue::Json(value) => Some(
            serde_json::to_vec(value).map_err(|error| {
                pg_error("postgres_json_invalid", error.to_string())
            })?,
        ),
    })
}

fn parse_row_description(
    payload: &[u8],
) -> AuthorityResult<Vec<ColumnDescription>> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.read_i16()?;
    if count < 0 || count as usize > 1024 {
        return Err(pg_error(
            "postgres_row_description_invalid",
            "column count exceeds the fixed bound",
        ));
    }
    let mut columns = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let name = cursor.read_cstring()?;
        cursor.skip(4 + 2)?;
        let type_oid = cursor.read_u32()?;
        cursor.skip(2 + 4 + 2)?;
        columns.push(ColumnDescription { name, type_oid });
    }
    cursor.finish()?;
    Ok(columns)
}

fn parse_data_row(
    payload: &[u8],
    columns: &[ColumnDescription],
) -> AuthorityResult<PgRow> {
    let mut cursor = Cursor::new(payload);
    let count = cursor.read_i16()?;
    if count < 0 || count as usize != columns.len() {
        return Err(pg_error(
            "postgres_data_row_invalid",
            "data row does not match row description",
        ));
    }
    let mut values = BTreeMap::new();
    for column in columns {
        let length = cursor.read_i32()?;
        let value = if length == -1 {
            PgValue::Null
        } else if length < 0 {
            return Err(pg_error(
                "postgres_data_row_invalid",
                "negative field length is invalid",
            ));
        } else {
            decode_column(
                column.type_oid,
                cursor.take(length as usize)?,
            )?
        };
        if values.insert(column.name.clone(), value).is_some() {
            return Err(pg_error(
                "postgres_column_duplicate",
                "result contains duplicate column names",
            ));
        }
    }
    cursor.finish()?;
    Ok(PgRow { columns: values })
}

fn decode_column(type_oid: u32, bytes: &[u8]) -> AuthorityResult<PgValue> {
    let text = || {
        std::str::from_utf8(bytes).map_err(|_| {
            pg_error(
                "postgres_text_invalid",
                "backend returned non-UTF-8 text",
            )
        })
    };
    match type_oid {
        16 => match text()? {
            "t" => Ok(PgValue::Bool(true)),
            "f" => Ok(PgValue::Bool(false)),
            _ => Err(pg_error(
                "postgres_boolean_invalid",
                "backend returned invalid boolean",
            )),
        },
        17 => {
            let encoded = text()?.strip_prefix("\\x").ok_or_else(|| {
                pg_error(
                    "postgres_bytea_invalid",
                    "bytea output is not canonical hex",
                )
            })?;
            Ok(PgValue::Bytes(hex::decode(encoded).map_err(
                |_| {
                    pg_error(
                        "postgres_bytea_invalid",
                        "bytea output contains invalid hex",
                    )
                },
            )?))
        }
        20 | 21 | 23 | 26 => {
            let value = text()?.parse::<i64>().map_err(|_| {
                pg_error(
                    "postgres_integer_invalid",
                    "backend returned invalid integer",
                )
            })?;
            Ok(PgValue::I64(value))
        }
        114 | 3802 => Ok(PgValue::Json(
            serde_json::from_slice(bytes).map_err(|_| {
                pg_error(
                    "postgres_json_invalid",
                    "backend returned invalid JSON",
                )
            })?,
        )),
        _ => Ok(PgValue::Text(text()?.to_owned())),
    }
}

fn parse_command_row_count(payload: &[u8]) -> AuthorityResult<u64> {
    let tag = payload.strip_suffix(&[0]).ok_or_else(|| {
        pg_error(
            "postgres_command_tag_invalid",
            "command tag is not NUL terminated",
        )
    })?;
    let tag = std::str::from_utf8(tag).map_err(|_| {
        pg_error(
            "postgres_command_tag_invalid",
            "command tag is not UTF-8",
        )
    })?;
    Ok(tag
        .split_ascii_whitespace()
        .next_back()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0))
}

fn parse_error_response(payload: &[u8]) -> AuthorityError {
    let mut fields = BTreeMap::new();
    let mut offset = 0;
    while offset < payload.len() && payload[offset] != 0 {
        let kind = payload[offset];
        offset += 1;
        let Some(end) = payload[offset..].iter().position(|byte| *byte == 0)
        else {
            return pg_error(
                "postgres_error_invalid",
                "backend error response is truncated",
            );
        };
        let value = String::from_utf8_lossy(
            &payload[offset..offset + end],
        )
        .into_owned();
        fields.insert(kind, value);
        offset += end + 1;
    }
    let code = fields.get(&b'C').map(String::as_str).unwrap_or("");
    let message = fields
        .get(&b'M')
        .cloned()
        .unwrap_or_else(|| "PostgreSQL rejected the operation".to_owned());
    let stable_code = match code {
        "40001" => "postgres_serialization_failure",
        "40P01" => "postgres_deadlock_detected",
        "55P03" => "postgres_lock_not_available",
        "57014" => "postgres_statement_timeout",
        _ => "postgres_operation_failed",
    };
    pg_error(stable_code, message)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> AuthorityResult<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or_else(|| {
            pg_error(
                "postgres_message_invalid",
                "message cursor overflow",
            )
        })?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            pg_error(
                "postgres_message_invalid",
                "message is truncated",
            )
        })?;
        self.offset = end;
        Ok(value)
    }

    fn skip(&mut self, length: usize) -> AuthorityResult<()> {
        self.take(length).map(|_| ())
    }

    fn read_i16(&mut self) -> AuthorityResult<i16> {
        Ok(i16::from_be_bytes(
            self.take(2)?.try_into().unwrap_or([0; 2]),
        ))
    }

    fn read_i32(&mut self) -> AuthorityResult<i32> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().unwrap_or([0; 4]),
        ))
    }

    fn read_u32(&mut self) -> AuthorityResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().unwrap_or([0; 4]),
        ))
    }

    fn read_cstring(&mut self) -> AuthorityResult<String> {
        let end = self.bytes[self.offset..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| {
                pg_error(
                    "postgres_message_invalid",
                    "cstring is not terminated",
                )
            })?;
        let bytes = self.take(end)?;
        self.skip(1)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| {
            pg_error(
                "postgres_message_invalid",
                "cstring is not UTF-8",
            )
        })
    }

    fn finish(&self) -> AuthorityResult<()> {
        if self.offset != self.bytes.len() {
            return Err(pg_error(
                "postgres_message_surplus",
                "message has surplus bytes",
            ));
        }
        Ok(())
    }
}

pub(crate) struct LedgerObjectStore {
    root: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
    clock: LinuxBootClock,
}

impl LedgerObjectStore {
    pub(crate) fn new(
        root: PathBuf,
        owner_uid: u32,
        owner_gid: u32,
    ) -> AuthorityResult<Self> {
        if !root.is_absolute()
            || root.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::Prefix(_)
                )
            })
            || owner_uid == 0
            || owner_gid == 0
        {
            return Err(pg_error(
                "immutable_cas_configuration_invalid",
                "immutable CAS requires an absolute root and non-root signed owner",
            ));
        }
        let metadata = fs::symlink_metadata(&root).map_err(|error| {
            pg_error("immutable_cas_unavailable", error.to_string())
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != owner_uid
            || metadata.gid() != owner_gid
            || metadata.mode() & 0o022 != 0
        {
            return Err(pg_error(
                "immutable_cas_root_unsafe",
                "immutable CAS root must be a concrete non-group-writable directory owned by the signed ledger identity",
            ));
        }
        Ok(Self {
            root,
            owner_uid,
            owner_gid,
            clock: LinuxBootClock::new()?,
        })
    }
}

impl ImmutableObjectStore for LedgerObjectStore {
    fn retrieve_exact(
        &self,
        generation_id: &Identifier,
        object_id: &Identifier,
        storage_locator: &str,
        immutable_storage_receipt_sha256: &Digest,
        expected_content_sha256: &Digest,
        expected_content_length: u64,
        deadline: &BootDeadline,
    ) -> AuthorityResult<Vec<u8>> {
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        generation_id.validate("immutableObject.generationId", 128)?;
        object_id.validate("immutableObject.objectId", 128)?;
        immutable_storage_receipt_sha256.validate(
            "immutableObject.immutableStorageReceiptSha256",
        )?;
        expected_content_sha256
            .validate("immutableObject.contentSha256")?;
        if expected_content_length == 0
            || expected_content_length > MAX_EXACT_OBJECT_BYTES
        {
            return Err(pg_error(
                "immutable_object_length_invalid",
                "immutable object length is outside the response-v2 bound",
            ));
        }
        let expected_locator = immutable_cas_locator(
            generation_id,
            object_id,
            immutable_storage_receipt_sha256,
            expected_content_sha256,
        );
        if storage_locator != expected_locator {
            return Err(pg_error(
                "immutable_object_provenance_mismatch",
                "storage locator does not bind generation, object, immutable receipt, and content digest",
            ));
        }
        let locator = Path::new(storage_locator);
        if locator.is_absolute()
            || locator.components().any(|component| {
                !matches!(component, Component::Normal(_))
            })
        {
            return Err(pg_error(
                "immutable_object_locator_invalid",
                "storage locator is not a normal relative CAS path",
            ));
        }
        let path = self.root.join(locator);
        if !path.starts_with(&self.root) {
            return Err(pg_error(
                "immutable_object_locator_invalid",
                "storage locator escapes the signed ledger root",
            ));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            pg_error(
                "immutable_object_unavailable",
                error.to_string(),
            )
        })?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.len() != expected_content_length
            || metadata.uid() != self.owner_uid
            || metadata.gid() != self.owner_gid
            || metadata.mode() & 0o222 != 0
        {
            return Err(pg_error(
                "immutable_object_metadata_mismatch",
                "immutable object is not a read-only single-link file with exact signed ownership and length",
            ));
        }
        let mut file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| {
                pg_error(
                    "immutable_object_unavailable",
                    error.to_string(),
                )
            })?;
        let opened_metadata = file.metadata().map_err(|error| {
            pg_error(
                "immutable_object_metadata_unavailable",
                error.to_string(),
            )
        })?;
        if opened_metadata.dev() != metadata.dev()
            || opened_metadata.ino() != metadata.ino()
            || opened_metadata.mode() != metadata.mode()
            || opened_metadata.uid() != metadata.uid()
            || opened_metadata.gid() != metadata.gid()
            || opened_metadata.len() != metadata.len()
        {
            return Err(pg_error(
                "immutable_object_identity_changed",
                "opened CAS object does not match its authenticated path metadata",
            ));
        }
        let mut bytes = Vec::with_capacity(expected_content_length as usize);
        (&mut file)
            .take(expected_content_length + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                pg_error("immutable_object_read_failed", error.to_string())
            })?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        if bytes.len() as u64 != expected_content_length
            || digest != expected_content_sha256.0
        {
            return Err(pg_error(
                "immutable_object_digest_mismatch",
                "immutable object bytes do not match the authority record",
            ));
        }
        let final_metadata = file.metadata().map_err(|error| {
            pg_error(
                "immutable_object_metadata_unavailable",
                error.to_string(),
            )
        })?;
        if final_metadata.dev() != opened_metadata.dev()
            || final_metadata.ino() != opened_metadata.ino()
            || final_metadata.mode() != opened_metadata.mode()
            || final_metadata.uid() != opened_metadata.uid()
            || final_metadata.gid() != opened_metadata.gid()
            || final_metadata.len() != opened_metadata.len()
        {
            return Err(pg_error(
                "immutable_object_changed_during_read",
                "CAS object metadata changed during exact retrieval",
            ));
        }
        deadline.ensure_current(
            &self.clock.current_boot_instant()?,
        )?;
        Ok(bytes)
    }
}

fn immutable_cas_locator(
    generation_id: &Identifier,
    object_id: &Identifier,
    immutable_storage_receipt_sha256: &Digest,
    expected_content_sha256: &Digest,
) -> String {
    let generation =
        format!("{:x}", Sha256::digest(generation_id.0.as_bytes()));
    let object =
        format!("{:x}", Sha256::digest(object_id.0.as_bytes()));
    let receipt = immutable_storage_receipt_sha256
        .0
        .strip_prefix("sha256:")
        .unwrap_or(&immutable_storage_receipt_sha256.0);
    let content = expected_content_sha256
        .0
        .strip_prefix("sha256:")
        .unwrap_or(&expected_content_sha256.0);
    format!(
        "v1/{generation}/{object}/{receipt}/{content}.blob"
    )
}

fn pg_io_error(error: std::io::Error) -> AuthorityError {
    pg_error("postgres_io_failed", error.to_string())
}

fn pg_error(
    code: &'static str,
    reason: impl Into<String>,
) -> AuthorityError {
    AuthorityError::Backend {
        code,
        reason: reason.into(),
    }
}
