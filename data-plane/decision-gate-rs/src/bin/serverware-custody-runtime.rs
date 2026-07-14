use serverware_decision_gate::{
    read_frame, write_frame, CustodyRuntime, IO_DEADLINE, MAX_CONCURRENT_CONNECTIONS,
};
use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

const DEFAULT_SOCKET_PATH: &str = "/tmp/serverware-custody-runtime.sock";

fn main() -> Result<(), Box<dyn Error>> {
    let socket_path = parse_socket_path(env::args().skip(1))?;
    run(&socket_path)
}

fn parse_socket_path<I>(mut arguments: I) -> Result<PathBuf, String>
where
    I: Iterator<Item = String>,
{
    let mut socket_path = env::var_os("SERVERWARE_CUSTODY_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => {
                socket_path = arguments
                    .next()
                    .map(PathBuf::from)
                    .ok_or("--socket requires a path")?;
            }
            "--help" | "-h" => {
                return Err(format!(
                    "usage: serverware-custody-runtime [--socket PATH]\n\
                     environment: SERVERWARE_CUSTODY_SOCKET\n\
                     default: {DEFAULT_SOCKET_PATH}"
                ));
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if socket_path.as_os_str().is_empty() {
        return Err("custody socket path must not be empty".to_string());
    }
    Ok(socket_path)
}

fn run(socket_path: &Path) -> Result<(), Box<dyn Error>> {
    remove_stale_socket(socket_path)?;
    let umask = UmaskGuard::restrict();
    let listener = UnixListener::bind(socket_path)?;
    drop(umask);
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    let _socket_cleanup = SocketCleanup::new(socket_path)?;
    let runtime = Arc::new(CustodyRuntime::generate()?);
    let active_connections = Arc::new(AtomicUsize::new(0));

    eprintln!(
        "serverware custody runtime listening socket={} transport=uds-development hardwareProof=false bootId={}",
        socket_path.display(),
        runtime.boot_id()
    );

    for accepted in listener.incoming() {
        let stream = match accepted {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("custody runtime accept failed: {error}");
                continue;
            }
        };
        let Some(permit) = ConnectionPermit::try_acquire(Arc::clone(&active_connections)) else {
            eprintln!(
                "custody runtime rejected connection: max concurrent connections ({MAX_CONCURRENT_CONNECTIONS}) reached"
            );
            drop(stream);
            continue;
        };
        let runtime = Arc::clone(&runtime);
        thread::spawn(move || {
            let _permit = permit;
            if let Err(error) = serve_connection(stream, &runtime) {
                eprintln!("custody runtime rejected request: {error}");
            }
        });
    }
    Ok(())
}

fn serve_connection(
    mut stream: UnixStream,
    runtime: &CustodyRuntime,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let request = read_frame(&mut stream, IO_DEADLINE)?;
    let response = runtime.handle_canonical_request(&request)?;
    write_frame(&mut stream, &response, IO_DEADLINE)?;
    Ok(())
}

fn remove_stale_socket(socket_path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(socket_path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            match UnixStream::connect(socket_path) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("custody socket {} is already active", socket_path.display()),
                )),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(socket_path)
                }
                Err(error) => Err(error),
            }
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to replace non-socket path {}",
                socket_path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl ConnectionPermit {
    fn try_acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < MAX_CONCURRENT_CONNECTIONS).then_some(current + 1)
            })
            .ok()?;
        Some(Self { active })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn restrict() -> Self {
        // The runtime has not started worker threads yet, so this process-wide change is scoped
        // to the socket bind and immediately restored by the guard.
        Self(unsafe { libc::umask(0o177) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        unsafe {
            libc::umask(self.0);
        }
    }
}

struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketCleanup {
    fn new(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use serde_json::{json, Value};
    use serverware_decision_gate::{
        canonical_json_bytes, decode_canonical_json, read_frame, write_frame, HELLO_OPERATION,
        MAX_FRAME_BYTES, PROTOCOL_API_VERSION,
    };
    use std::io::Write;
    use std::net::Shutdown;
    use std::time::Duration;

    fn request_id(byte: u8) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode([byte; 32])
    }

    #[test]
    fn serves_a_canonical_hello_frame_over_a_unix_socket() {
        let runtime = Arc::new(CustodyRuntime::generate().expect("runtime"));
        let (mut client, server) = UnixStream::pair().expect("socket pair");
        let server_runtime = Arc::clone(&runtime);
        let worker = thread::spawn(move || serve_connection(server, &server_runtime));
        let request = canonical_json_bytes(&json!({
            "apiVersion": PROTOCOL_API_VERSION,
            "bootId": null,
            "operation": HELLO_OPERATION,
            "params": {},
            "requestId": request_id(1),
        }))
        .expect("request");
        write_frame(&mut client, &request, Duration::from_secs(1)).expect("write request");
        worker
            .join()
            .expect("worker join")
            .expect("serve connection");
        let response = read_frame(&mut client, Duration::from_secs(1)).expect("read response");
        let response: Value = decode_canonical_json(&response).expect("canonical response");
        assert_eq!(response["ok"], true);
        assert_eq!(response["result"]["hardwareProof"], false);
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client
            .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .expect("write oversized length");
        assert!(read_frame(&mut server, Duration::from_secs(1))
            .expect_err("oversized frame")
            .to_string()
            .contains("exceeds"));

        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client.write_all(&8u32.to_be_bytes()).expect("write length");
        client.write_all(b"abc").expect("write partial payload");
        client.shutdown(Shutdown::Write).expect("shutdown writer");
        assert!(read_frame(&mut server, Duration::from_secs(1))
            .expect_err("truncated frame")
            .to_string()
            .contains("truncated frame"));
    }

    #[test]
    fn rejects_a_slow_partial_frame_on_the_absolute_deadline() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        client.write_all(&8u32.to_be_bytes()).expect("write length");
        client.write_all(b"a").expect("write first byte");
        let started = std::time::Instant::now();
        let error =
            read_frame(&mut server, Duration::from_millis(75)).expect_err("slow partial frame");
        assert!(error.to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn concurrency_permits_are_strictly_bounded_and_released() {
        let active = Arc::new(AtomicUsize::new(0));
        let permits = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|_| ConnectionPermit::try_acquire(Arc::clone(&active)).expect("permit"))
            .collect::<Vec<_>>();
        assert!(ConnectionPermit::try_acquire(Arc::clone(&active)).is_none());
        drop(permits);
        assert_eq!(active.load(Ordering::Acquire), 0);
        assert!(ConnectionPermit::try_acquire(active).is_some());
    }

    #[test]
    fn refuses_to_replace_a_non_socket_path() {
        let path = env::temp_dir().join(format!(
            "serverware-custody-runtime-test-{}",
            std::process::id()
        ));
        fs::write(&path, b"not a socket").expect("write fixture");
        let error = remove_stale_socket(&path).expect_err("non-socket path");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        fs::remove_file(path).expect("remove fixture");
    }

    #[test]
    fn refuses_to_replace_an_active_socket() {
        let path = env::temp_dir().join(format!(
            "serverware-custody-runtime-active-test-{}",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).expect("bind fixture socket");
        let error = remove_stale_socket(&path).expect_err("active socket");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        drop(listener);
        fs::remove_file(path).expect("remove fixture socket");
    }
}
