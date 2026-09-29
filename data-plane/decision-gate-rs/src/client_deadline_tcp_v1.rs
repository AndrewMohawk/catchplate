//! Path-loaded, owned TCP transport under one nonrenewing client deadline.
//!
//! The caller supplies one literal endpoint and bounded aggregate byte limits;
//! this module supplies no DNS, retries, proxy selection or admission policy.
//! Timeouts are recomputed per call and late results are rejected. This is not
//! a hard kernel watchdog or cancellation of an already blocked syscall.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MAX_IO_BYTES: usize = 16 * 1024;
const MAX_WIRE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const CONNECT_LIMIT: Duration = Duration::from_secs(3);

pub(super) struct DeadlineTcp {
    socket: TcpStream,
    owner_pid: u32,
    deadline: Instant,
    read_limit: u64,
    write_limit: u64,
    read_bytes: u64,
    written_bytes: u64,
}

fn remaining(owner_pid: u32, deadline: Instant) -> io::Result<Duration> {
    if std::process::id() != owner_pid {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied,
            "client TCP transport crossed its creating process"));
    }
    deadline.checked_duration_since(Instant::now()).filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut,
            "client TCP transport original deadline expired"))
}

pub(super) fn connect(endpoint: SocketAddr, deadline: Instant,
    read_limit: u64, write_limit: u64) -> Result<DeadlineTcp, String> {
    if !(1..=MAX_WIRE_BYTES).contains(&read_limit)
        || !(1..=MAX_WIRE_BYTES).contains(&write_limit)
    {
        return Err("client TCP aggregate byte limits must be in 1..=2GiB".to_owned());
    }
    let owner_pid = std::process::id();
    let timeout = remaining(owner_pid, deadline)
        .map_err(|error| error.to_string())?.min(CONNECT_LIMIT);
    // One literal-address attempt, never a resolver or alternate endpoint.
    let socket = TcpStream::connect_timeout(&endpoint, timeout)
        .map_err(|_| "client TCP connect failed".to_owned())?;
    let socket = DeadlineTcp {
        socket, owner_pid, deadline, read_limit, write_limit,
        read_bytes: 0, written_bytes: 0,
    };
    socket.check().map_err(|error| error.to_string())?;
    if socket.socket.peer_addr().map_err(|_| "client TCP peer is unavailable")? != endpoint {
        return Err("client TCP peer differs from its fixed endpoint".to_owned());
    }
    socket.check().map_err(|error| error.to_string())?;
    Ok(socket)
}

impl DeadlineTcp {
    pub(super) fn check(&self) -> io::Result<()> {
        remaining(self.owner_pid, self.deadline).map(|_| ())
    }

    /// Observe the actual retained socket, never its configured destination.
    pub(super) fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.check()?;
        let address = self.socket.peer_addr()?;
        self.check()?;
        Ok(address)
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let timeout = remaining(self.owner_pid, self.deadline)?;
        if output.is_empty() { return Ok(0); }
        let remaining_bytes = self.read_limit - self.read_bytes;
        let count = output.len().min(MAX_IO_BYTES)
            .min(remaining_bytes.min(MAX_IO_BYTES as u64) as usize);
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "client TCP input exceeds its aggregate bound"));
        }
        self.socket.set_read_timeout(Some(timeout))?;
        self.check()?;
        let result = self.socket.read(&mut output[..count]);
        self.check()?;
        let count = result?;
        self.read_bytes += count as u64;
        Ok(count)
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let timeout = remaining(self.owner_pid, self.deadline)?;
        if input.is_empty() { return Ok(0); }
        let remaining_bytes = self.write_limit - self.written_bytes;
        let count = input.len().min(MAX_IO_BYTES)
            .min(remaining_bytes.min(MAX_IO_BYTES as u64) as usize);
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "client TCP output exceeds its aggregate bound"));
        }
        self.socket.set_write_timeout(Some(timeout))?;
        self.check()?;
        let result = self.socket.write(&input[..count]);
        self.check()?;
        let count = result?;
        self.written_bytes += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.socket.flush();
        self.check()?;
        result
    }
}

impl Drop for DeadlineTcp {
    fn drop(&mut self) {
        if std::process::id() == self.owner_pid {
            let _ = self.socket.shutdown(Shutdown::Both);
        }
        // TcpStream drops the owned descriptor in every process. A forked copy
        // must not shutdown the shared connection in the original process.
    }
}
