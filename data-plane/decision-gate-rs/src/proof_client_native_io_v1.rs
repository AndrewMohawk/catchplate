//! Native deadline checks at the inner plaintext boundary, including buffered TLS.
//!
//! The outer native transport also checks every actual socket call. These cheap
//! checks prevent already-buffered inner TLS bytes from bypassing the original
//! process/deadline guard; they do not re-read configuration per byte or claim
//! to interrupt filesystem writes, cryptography or blocked kernel operations.

use super::proof_client_native_session_v1::NativeCaptureSessionV1;
use super::proof_client_policy_expectations_v1::PolicyAwareExpectations;
use std::io::{self, Read, Write};

pub(super) struct CaptureIo<'a, T> {
    inner: &'a mut T,
    native: Option<&'a NativeCaptureSessionV1>,
    policy_aware: Option<&'a PolicyAwareExpectations>,
}

impl<'a, T> CaptureIo<'a, T> {
    pub(super) fn new(inner: &'a mut T, native: Option<&'a NativeCaptureSessionV1>) -> Self {
        Self { inner, native, policy_aware: None }
    }

    pub(super) fn new_with_policy(inner: &'a mut T, native: Option<&'a NativeCaptureSessionV1>,
        policy_aware: Option<&'a PolicyAwareExpectations>) -> Self {
        Self { inner, native, policy_aware }
    }

    fn check(&self) -> io::Result<()> {
        if self.native.is_some() && self.policy_aware.is_some() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "response capture profiles cannot mix"));
        }
        if let Some(owner) = self.policy_aware {
            owner.check_live().map_err(|message| io::Error::new(io::ErrorKind::PermissionDenied, message))?;
        }
        match self.native {
            Some(owner) => owner.check_live()
                .map_err(|message| io::Error::new(io::ErrorKind::PermissionDenied, message)),
            None => Ok(()),
        }
    }
}

impl<T: Read> Read for CaptureIo<'_, T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.inner.read(output);
        self.check()?;
        result
    }
}

impl<T: Write> Write for CaptureIo<'_, T> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.inner.write(input);
        self.check()?;
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.inner.flush();
        self.check()?;
        result
    }
}
