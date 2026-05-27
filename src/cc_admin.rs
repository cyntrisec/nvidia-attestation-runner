use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{json, Value};

use crate::{
    sha256_hex, AttestationReport, Error, NvidiaAttestationBackend, NvidiaEvidenceBundle, Result,
};

/// Builder for invoking NVIDIA's Python `verifier.cc_admin` local GPU verifier.
///
/// This path is intentionally modeled as a transcript adapter. NVIDIA's Python
/// tool performs the certificate, RIM, SPDM, and measurement verification. This
/// crate normalizes the textual transcript so callers can bind it into evidence
/// bundles and evaluate an explicit policy.
#[must_use]
#[derive(Debug, Clone)]
pub struct CcAdminRunner {
    program: OsString,
    args: Vec<OsString>,
    current_dir: Option<PathBuf>,
}

impl CcAdminRunner {
    /// Create a runner for a custom executable.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
        }
    }

    /// Convenience helper for `python3 -m verifier.cc_admin --verbose --nonce <hex>`.
    pub fn python_module_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::new("python3")
            .args(["-m", "verifier.cc_admin", "--verbose", "--nonce"])
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

    /// Run `cc_admin` and normalize stdout into an [`AttestationReport`].
    ///
    /// If the command exits non-zero but prints a transcript, the transcript is
    /// still returned so policy can reject it with the captured verifier detail.
    pub fn run(&self) -> Result<AttestationReport> {
        Ok(self.run_bundle()?.into_report())
    }

    /// Run `cc_admin` and return a bundle with command metadata and stable hashes.
    pub fn run_bundle(&self) -> Result<NvidiaEvidenceBundle> {
        self.run_bundle_with_backend(NvidiaAttestationBackend::CcAdminTranscript)
    }

    /// Run `cc_admin` and tag the bundle with an explicit transcript backend.
    pub fn run_bundle_with_backend(
        &self,
        backend: NvidiaAttestationBackend,
    ) -> Result<NvidiaEvidenceBundle> {
        let mut command = Command::new(&self.program);
        command.args(&self.args);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        let output = command.output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stdout.trim().is_empty() {
            let report = report_from_cc_admin_transcript(&stdout, &stderr, output.status.code());
            return Ok(NvidiaEvidenceBundle::new(
                backend,
                self.command_line(),
                output.status.code(),
                report,
            ));
        }

        if !output.status.success() {
            return Err(Error::CommandFailed {
                status: output.status,
                stderr: stderr.into_owned(),
                stdout: stdout.into_owned(),
            });
        }

        let report = report_from_cc_admin_transcript(&stdout, &stderr, output.status.code());
        Ok(NvidiaEvidenceBundle::new(
            backend,
            self.command_line(),
            output.status.code(),
            report,
        ))
    }
}

/// Normalize NVIDIA `verifier.cc_admin --verbose` text output.
pub fn report_from_cc_admin_transcript(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> AttestationReport {
    let parsed = ParsedCcAdmin::parse(stdout);
    let command_succeeded = exit_code.map(|code| code == 0).unwrap_or(true);
    let attestation_success = command_succeeded && parsed.attestation_success;
    let result_code = if attestation_success {
        0
    } else {
        exit_code.filter(|code| *code != 0).unwrap_or(1)
    };
    let result_message = if attestation_success {
        "Ok"
    } else {
        "GPU Attestation failed"
    };

    let mut claims = vec![
        claim_value("x-nvidia-device-type", json!("GPU")),
        claim_result("x-nvidia-overall-att-result", attestation_success),
        claim_result(
            "x-nvidia-gpu-attestation-report-parsed",
            parsed.report_parsed,
        ),
        claim_result(
            "x-nvidia-gpu-attestation-report-signature-verified",
            parsed.report_signature_verified,
        ),
        claim_result(
            "x-nvidia-gpu-attestation-report-nonce-match",
            parsed.nonce_match,
        ),
        claim_result("x-nvidia-gpu-measres", parsed.measurements_success),
        claim_result(
            "x-nvidia-gpu-driver-rim-signature-verified",
            parsed.driver_rim_signature_verified,
        ),
        claim_result(
            "x-nvidia-gpu-vbios-rim-signature-verified",
            parsed.vbios_rim_signature_verified,
        ),
    ];

    if let Some(nonce) = &parsed.request_nonce {
        claims.push(claim_value("nonce", json!(nonce)));
        claims.push(claim_value(
            "x-nvidia-gpu-attestation-report-nonce",
            json!(nonce),
        ));
    }
    if let Some(driver_version) = &parsed.driver_version {
        claims.push(claim_value(
            "x-nvidia-gpu-driver-version",
            json!(driver_version),
        ));
    }
    if let Some(vbios_version) = &parsed.vbios_version {
        claims.push(claim_value(
            "x-nvidia-gpu-vbios-version",
            json!(vbios_version),
        ));
    }
    if let Some(feature_flag) = &parsed.feature_flag {
        claims.push(claim_value("x-nvidia-gpu-mode", json!(feature_flag)));
    }
    if let Some(ready_state) = &parsed.ready_state {
        claims.push(claim_value("x-nvidia-gpu-ready-state", json!(ready_state)));
    }

    let gpus = parsed
        .gpu_uuid
        .as_ref()
        .map(|uuid| {
            json!([{
                "uuid": uuid,
                "driver_version": parsed.driver_version,
                "vbios_version": parsed.vbios_version,
                "feature_flag": parsed.feature_flag,
                "ready_state": parsed.ready_state
            }])
        })
        .unwrap_or_else(|| json!([]));

    AttestationReport::from_value(json!({
        "source": "nvidia_cc_admin_verbose",
        "result_code": result_code,
        "result_message": result_message,
        "transcript_sha256": sha256_hex(stdout),
        "stderr_sha256": if stderr.is_empty() { Value::Null } else { json!(sha256_hex(stderr)) },
        "claims": claims,
        "gpus": gpus,
        "cc_admin": {
            "gpu_uuid": parsed.gpu_uuid,
            "driver_version": parsed.driver_version,
            "vbios_version": parsed.vbios_version,
            "request_nonce": parsed.request_nonce,
            "report_nonce": parsed.report_nonce,
            "feature_flag": parsed.feature_flag,
            "ready_state": parsed.ready_state,
            "measurement_blocks": parsed.measurement_blocks,
            "stdout_line_count": stdout.lines().count()
        }
    }))
}

#[derive(Debug, Default)]
struct ParsedCcAdmin {
    attestation_success: bool,
    report_parsed: bool,
    report_signature_verified: bool,
    nonce_match: bool,
    measurements_success: bool,
    driver_rim_signature_verified: bool,
    vbios_rim_signature_verified: bool,
    gpu_uuid: Option<String>,
    driver_version: Option<String>,
    vbios_version: Option<String>,
    request_nonce: Option<String>,
    report_nonce: Option<String>,
    feature_flag: Option<String>,
    ready_state: Option<String>,
    measurement_blocks: BTreeMap<String, String>,
}

impl ParsedCcAdmin {
    fn parse(stdout: &str) -> Self {
        let lower = stdout.to_ascii_lowercase();
        let mut parsed = Self {
            attestation_success: lower.contains("gpu attestation is successful"),
            report_parsed: lower.contains("get measurement response message")
                && lower.contains("attestation report verification successful"),
            report_signature_verified: lower
                .contains("attestation report signature verification successful"),
            nonce_match: lower
                .contains("nonce in the spdm get measurement request message is matching"),
            measurements_success: lower
                .contains("runtime measurements are matching with the golden measurements"),
            driver_rim_signature_verified: lower
                .contains("driver rim signature verification successful")
                || lower.contains("driver rim verification successful"),
            vbios_rim_signature_verified: lower
                .contains("vbios rim signature verification successful")
                || lower.contains("vbios rim verification successful"),
            ..Self::default()
        };

        let mut current_measurement_index: Option<String> = None;
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(value) = value_after(trimmed, "Verifying GPU:") {
                parsed.gpu_uuid = Some(value.to_owned());
            } else if let Some(value) = value_after(trimmed, "Driver version fetched :") {
                parsed
                    .driver_version
                    .get_or_insert_with(|| value.to_owned());
            } else if let Some(value) = value_after(trimmed, "VBIOS version fetched :") {
                parsed.vbios_version.get_or_insert_with(|| value.to_owned());
            } else if let Some(value) = value_after(
                trimmed,
                "Driver version fetched from the attestation report :",
            ) {
                parsed.driver_version = Some(value.to_owned());
            } else if let Some(value) = value_after(
                trimmed,
                "VBIOS version fetched from the attestation report :",
            ) {
                parsed.vbios_version = Some(value.to_owned());
            } else if let Some(value) = value_after(trimmed, "OPAQUE_FIELD_ID_FEATURE_FLAG :") {
                parsed.feature_flag = Some(value.to_owned());
            } else if trimmed.contains("GPU Ready State is already READY")
                || trimmed.contains("GPU Ready state is already READY")
                || trimmed.contains("Setting the GPU Ready State to READY")
            {
                parsed.ready_state = Some("READY".to_owned());
            } else if let Some(value) = value_after(trimmed, "Measurement Block index :") {
                current_measurement_index = Some(value.to_owned());
            } else if let Some(value) = value_after(trimmed, "DMTFSpecMeasurementValue     :") {
                if let Some(index) = current_measurement_index.take() {
                    parsed.measurement_blocks.insert(index, value.to_owned());
                }
            } else if let Some(value) = value_after(trimmed, "Nonce               :") {
                parsed.request_nonce.get_or_insert_with(|| value.to_owned());
            } else if let Some(value) = value_after(trimmed, "Nonce :") {
                parsed.report_nonce.get_or_insert_with(|| value.to_owned());
            }
        }

        parsed
    }
}

fn claim_result(name: &str, result: bool) -> Value {
    json!({ "name": name, "result": result })
}

fn claim_value(name: &str, value: Value) -> Value {
    json!({ "name": name, "value": value })
}

fn value_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
