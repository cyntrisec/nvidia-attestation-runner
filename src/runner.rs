use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Output};

use crate::{AttestationReport, Error, NvidiaAttestationBackend, NvidiaEvidenceBundle, Result};

/// Builder for invoking NVIDIA attestation tooling and parsing its JSON output.
#[must_use]
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

    /// Convenience helper for the common remote NRAS GPU attestation command shape.
    pub fn remote_gpu_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::nvattest()
            .args([
                "--format",
                "json",
                "attest",
                "--device",
                "gpu",
                "--verifier",
                "remote",
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

    /// Return the command line as lossy UTF-8 for evidence metadata.
    pub fn command_line(&self) -> Vec<String> {
        std::iter::once(&self.program)
            .chain(self.args.iter())
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    /// Run the command and parse stdout as NVIDIA verifier JSON.
    ///
    /// NVAT exits non-zero for unsuccessful attestations while still emitting a
    /// JSON result. In that case this method returns the parsed report so the
    /// caller can make the policy decision and retain the failure details.
    pub fn run(&self) -> Result<AttestationReport> {
        Ok(self
            .run_bundle_with_backend(NvidiaAttestationBackend::CustomJson)?
            .into_report())
    }

    /// Run the command and return a bundle with command metadata and stable hashes.
    pub fn run_bundle_with_backend(
        &self,
        backend: NvidiaAttestationBackend,
    ) -> Result<NvidiaEvidenceBundle> {
        let output = self.output()?;
        let report = parse_json_output(&output)?;
        Ok(NvidiaEvidenceBundle::new(
            backend,
            self.command_line(),
            output.status.code(),
            report,
        ))
    }

    /// Run a local GPU `nvattest` JSON command and return bundle metadata.
    pub fn run_local_gpu_bundle(&self) -> Result<NvidiaEvidenceBundle> {
        self.run_bundle_with_backend(NvidiaAttestationBackend::NvAttestLocalJson)
    }

    /// Run a remote GPU `nvattest` JSON command and return bundle metadata.
    pub fn run_remote_gpu_bundle(&self) -> Result<NvidiaEvidenceBundle> {
        self.run_bundle_with_backend(NvidiaAttestationBackend::NvAttestRemoteJson)
    }

    fn output(&self) -> Result<Output> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        Ok(command.output()?)
    }
}

fn parse_json_output(output: &Output) -> Result<AttestationReport> {
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

    AttestationReport::from_json_slice(&output.stdout)
}
