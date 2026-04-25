use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::{AttestationReport, Error, Result};

/// Builder for invoking NVIDIA attestation tooling and parsing its JSON output.
#[derive(Debug, Clone)]
pub struct NvAttestRunner {
    program: OsString,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
}

impl NvAttestRunner {
    /// Create a runner for a custom command.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
        }
    }

    /// Create a runner for the common `nvattest` executable name.
    pub fn nvattest() -> Self {
        Self::new("nvattest")
    }

    /// Convenience helper for the common local GPU attestation command shape.
    ///
    /// NVIDIA tooling flags may change. If your installed tool uses different
    /// flags, use [`Self::new`] with [`Self::arg`] / [`Self::args`] instead.
    pub fn local_gpu_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::nvattest()
            .args([
                "--format",
                "json",
                "attest",
                "--device",
                "gpu",
                "--verifier",
                "local",
                "--nonce",
            ])
            .arg(nonce_hex)
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    /// Run the command and parse stdout as NVIDIA verifier JSON.
    ///
    /// NVAT exits non-zero for unsuccessful attestations while still emitting a
    /// JSON result. In that case this method returns the parsed report so the
    /// caller can make the policy decision and retain the failure details.
    pub fn run(&self) -> Result<AttestationReport> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        let output = command.output()?;
        if !output.stdout.is_empty() {
            if let Ok(report) = AttestationReport::from_json_slice(&output.stdout) {
                return Ok(report);
            }
        }

        if !output.status.success() {
            return Err(Error::CommandFailed {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            });
        }

        AttestationReport::from_json_slice(output.stdout)
    }
}
