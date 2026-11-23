use crate::report::value_as_bool;
use crate::AttestationReport;
use serde::Serialize;

/// Claim names under which NVIDIA tooling reports the measurement result.
pub(crate) const MEASUREMENT_RESULT_CLAIMS: [&str; 3] =
    ["x-nvidia-gpu-measres", "measres", "measurement_result"];

/// Claim names under which NVIDIA tooling reports the debug status.
pub(crate) const DEBUG_STATUS_CLAIMS: [&str; 3] = ["x-nvidia-gpu-dbgstat", "dbgstat", "debug"];

/// Invalid expected nonce configuration.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PolicyConfigurationError {
    #[error("expected nonce must be 32 bytes, got {actual_len} bytes")]
    InvalidNonceLength { actual_len: usize },

    #[error("expected nonce is not valid hex: {0}")]
    InvalidNonceHex(#[from] hex::FromHexError),
}

/// A failed policy requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyFailure {
    pub code: &'static str,
    pub message: String,
}

/// Policy evaluation result.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyVerdict {
    pub accepted: bool,
    pub failures: Vec<PolicyFailure>,
}

impl PolicyVerdict {
    fn accepted() -> Self {
        Self {
            accepted: true,
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, code: &'static str, message: impl Into<String>) {
        self.accepted = false;
        self.failures.push(PolicyFailure {
            code,
            message: message.into(),
        });
    }
}

/// Verifier-side requirements for NVIDIA attestation output.
#[must_use]
#[derive(Debug, Clone, Default)]
pub struct Policy {
    expected_nonce: Option<Vec<u8>>,
    require_attestation_success: bool,
    require_gpu_evidence: bool,
    require_report_parsed: bool,
    require_report_signature_verified: bool,
    require_measurements_success: bool,
    require_secure_boot: bool,
    require_debug_disabled: bool,
    require_rim_signature_verified: bool,
    require_gpu_confidential_mode: bool,
    require_gpu_ready_state: bool,
}

impl Policy {
    /// Conservative baseline for confidential GPU evidence produced by NVIDIA tooling.
    pub fn nvidia_cc_baseline() -> Self {
        Self {
            require_attestation_success: true,
            require_gpu_evidence: true,
            require_report_parsed: true,
            require_report_signature_verified: true,
            require_measurements_success: true,
            require_secure_boot: true,
            require_debug_disabled: true,
            require_rim_signature_verified: true,
            ..Self::default()
        }
    }

    /// Baseline for normalized `verifier.cc_admin --verbose` transcripts.
    ///
    /// The Python `cc_admin` transcript does not expose every claim that the
    /// JSON NVAT/EAT path can expose. Keep the native JSON baseline stricter,
    /// and use this profile only when the trust input is the NVIDIA verifier's
    /// human-readable transcript.
    pub fn nvidia_cc_admin_transcript_baseline() -> Self {
        Self {
            require_attestation_success: true,
            require_gpu_evidence: true,
            require_report_parsed: true,
            require_report_signature_verified: true,
            require_measurements_success: true,
            require_rim_signature_verified: true,
            require_gpu_confidential_mode: true,
            require_gpu_ready_state: true,
            ..Self::default()
        }
    }

    pub fn expected_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.expected_nonce = Some(nonce.into());
        self
    }

    pub fn require_attestation_success(mut self, required: bool) -> Self {
        self.require_attestation_success = required;
        self
    }

    pub fn expected_nonce_hex(mut self, nonce_hex: &str) -> Result<Self, PolicyConfigurationError> {
        let nonce = hex::decode(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex))?;
        if nonce.len() != 32 {
            return Err(PolicyConfigurationError::InvalidNonceLength {
                actual_len: nonce.len(),
            });
        }

        self.expected_nonce = Some(nonce);
        Ok(self)
    }

    pub fn require_gpu_evidence(mut self, required: bool) -> Self {
        self.require_gpu_evidence = required;
        self
    }

    pub fn require_report_parsed(mut self, required: bool) -> Self {
        self.require_report_parsed = required;
        self
    }

    pub fn require_report_signature_verified(mut self, required: bool) -> Self {
        self.require_report_signature_verified = required;
        self
    }

    pub fn require_measurements_success(mut self, required: bool) -> Self {
        self.require_measurements_success = required;
        self
    }

    pub fn require_secure_boot(mut self, required: bool) -> Self {
        self.require_secure_boot = required;
        self
    }

    pub fn require_debug_disabled(mut self, required: bool) -> Self {
        self.require_debug_disabled = required;
        self
    }

    pub fn require_rim_signature_verified(mut self, required: bool) -> Self {
        self.require_rim_signature_verified = required;
        self
    }

    pub fn require_gpu_confidential_mode(mut self, required: bool) -> Self {
        self.require_gpu_confidential_mode = required;
        self
    }

    pub fn require_gpu_ready_state(mut self, required: bool) -> Self {
        self.require_gpu_ready_state = required;
        self
    }

    pub fn evaluate(&self, report: &AttestationReport) -> PolicyVerdict {
        let mut verdict = PolicyVerdict::accepted();

        // Claim accessors read the first matching claim only. Accepting an
        // answer that covers several devices would mean checking one of them.
        let claim_sets = report.device_claim_set_count();
        if claim_sets > 1 {
            verdict.fail(
                "multiple_device_claim_sets_unsupported",
                format!(
                    "verifier output holds claim sets for {claim_sets} devices; \
                     this policy evaluates a single device, so the answer is rejected"
                ),
            );
        }

        if self.require_attestation_success {
            require_attestation_success(&mut verdict, report);
        }

        if self.require_gpu_evidence && !report.has_gpu_evidence() {
            verdict.fail("gpu_evidence_missing", "no NVIDIA GPU evidence was found");
        }

        if self.require_report_parsed {
            require_bool(
                &mut verdict,
                report,
                &[
                    "x-nvidia-gpu-attestation-report-parsed",
                    "attestation_report_parsed",
                    "report_parsed",
                ],
                true,
                "report_not_parsed",
                "attestation report was not parsed successfully",
            );
        }

        if self.require_report_signature_verified {
            require_bool(
                &mut verdict,
                report,
                &[
                    "x-nvidia-gpu-attestation-report-signature-verified",
                    "attestation_report_signature_verified",
                    "report_signature_verified",
                ],
                true,
                "report_signature_unverified",
                "attestation report signature was not verified",
            );
        }

        if self.require_measurements_success {
            require_measurements_success(&mut verdict, report);
        }

        if self.require_secure_boot {
            require_bool(
                &mut verdict,
                report,
                &["x-nvidia-gpu-secboot", "secboot", "secure_boot"],
                true,
                "secure_boot_not_enabled",
                "secure boot is not enabled",
            );
        }

        if self.require_debug_disabled {
            require_debug_disabled(&mut verdict, report);
        }

        if self.require_rim_signature_verified {
            require_bool(
                &mut verdict,
                report,
                &[
                    "x-nvidia-gpu-driver-rim-signature-verified",
                    "x-nvidia-gpu-driver-vbios-rim-signature-verified",
                    "rim_signature_verified",
                ],
                true,
                "driver_rim_signature_unverified",
                "driver RIM signature was not verified",
            );
            require_bool(
                &mut verdict,
                report,
                &["x-nvidia-gpu-vbios-rim-signature-verified"],
                true,
                "vbios_rim_signature_unverified",
                "VBIOS RIM signature was not verified",
            );
        }

        if self.require_gpu_confidential_mode {
            require_gpu_confidential_mode(&mut verdict, report);
        }

        if self.require_gpu_ready_state {
            require_gpu_ready_state(&mut verdict, report);
        }

        if let Some(expected_nonce) = &self.expected_nonce {
            require_nonce(&mut verdict, report, expected_nonce);
        }

        verdict
    }
}

fn require_attestation_success(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    if let Some(code) = report.result_code() {
        if code != 0 {
            verdict.fail(
                "nvidia_attestation_failed",
                format!("NVIDIA verifier returned result_code {code}"),
            );
            return;
        }

        if let Some(false) = report.claim_bool(&[
            "x-nvidia-overall-att-result",
            "overall_attestation_result",
            "attestation_result",
        ]) {
            verdict.fail(
                "nvidia_attestation_failed",
                "NVIDIA verifier reported an unsuccessful attestation result",
            );
            return;
        }

        return;
    }

    if let Some(success) = report.claim_bool(&[
        "x-nvidia-overall-att-result",
        "overall_attestation_result",
        "attestation_result",
    ]) {
        if success {
            return;
        }

        verdict.fail(
            "nvidia_attestation_failed",
            "NVIDIA verifier reported an unsuccessful attestation result",
        );
        return;
    }

    if let Some(message) = report.result_message() {
        if message.eq_ignore_ascii_case("ok") {
            return;
        }

        verdict.fail(
            "nvidia_attestation_failed",
            format!("NVIDIA verifier returned result_message {message:?}"),
        );
        return;
    }

    verdict.fail(
        "nvidia_attestation_result_missing",
        "NVIDIA verifier result_code/result_message was not present",
    );
}

fn require_bool(
    verdict: &mut PolicyVerdict,
    report: &AttestationReport,
    names: &[&str],
    expected: bool,
    code: &'static str,
    message: &'static str,
) {
    match report.claim_bool(names) {
        Some(value) if value == expected => {}
        _ => verdict.fail(code, message),
    }
}

fn require_measurements_success(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    if report
        .claim("x-nvidia-mismatch-measurement-records")
        .and_then(serde_json::Value::as_array)
        .map(|records| !records.is_empty())
        .unwrap_or(false)
    {
        verdict.fail(
            "measurement_mismatch_records_present",
            "NVIDIA reported one or more runtime measurement mismatches",
        );
    }

    if !measurements_reported_successful(report) {
        verdict.fail(
            "measurements_not_successful",
            "GPU measurements were not reported as successful",
        );
    }
}

/// Return true when a measurement-result claim reports success.
///
/// The redacted summary uses the same predicate, so the status it exports
/// cannot disagree with the verdict.
pub(crate) fn measurements_reported_successful(report: &AttestationReport) -> bool {
    MEASUREMENT_RESULT_CLAIMS.iter().any(|name| {
        report.claim(name).is_some_and(|value| {
            value_as_bool(value).unwrap_or_else(|| {
                value
                    .as_str()
                    .map(|value| {
                        matches!(
                            value.trim().to_ascii_lowercase().as_str(),
                            "success" | "successful" | "pass" | "passed" | "valid"
                        )
                    })
                    .unwrap_or(false)
            })
        })
    })
}

fn require_debug_disabled(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    if !debug_reported_disabled(report) {
        verdict.fail("debug_not_disabled", "debug mode is not disabled");
    }
}

/// Return true when a debug-status claim reports that debug is disabled.
///
/// The redacted summary uses the same predicate, so the status it exports
/// cannot disagree with the verdict.
pub(crate) fn debug_reported_disabled(report: &AttestationReport) -> bool {
    DEBUG_STATUS_CLAIMS.iter().any(|name| {
        report.claim(name).is_some_and(|value| match value {
            serde_json::Value::Bool(enabled) => !enabled,
            serde_json::Value::Number(number) => number.as_i64() == Some(0),
            serde_json::Value::String(value) => matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "disabled" | "false" | "0" | "off"
            ),
            _ => false,
        })
    })
}

fn require_gpu_confidential_mode(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    match report
        .claim("x-nvidia-gpu-mode")
        .or_else(|| report.claim("gpu_mode"))
        .or_else(|| report.claim("feature_flag"))
        .and_then(serde_json::Value::as_str)
        .map(|value| value.trim().to_ascii_uppercase())
    {
        Some(value) if value == "SPT" || value == "MPT" => {}
        _ => verdict.fail(
            "gpu_confidential_mode_missing",
            "GPU confidential-computing feature mode was not reported as SPT or MPT",
        ),
    }
}

fn require_gpu_ready_state(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    match report
        .claim("x-nvidia-gpu-ready-state")
        .or_else(|| report.claim("gpu_ready_state"))
        .and_then(serde_json::Value::as_str)
        .map(|value| value.trim().to_ascii_uppercase())
    {
        Some(value) if value == "READY" => {}
        _ => verdict.fail(
            "gpu_ready_state_missing",
            "GPU ready state was not reported as READY",
        ),
    }
}

fn require_nonce(verdict: &mut PolicyVerdict, report: &AttestationReport, expected_nonce: &[u8]) {
    let reported_match = report.claim_bool(&[
        "x-nvidia-gpu-attestation-report-nonce-match",
        "attestation_report_nonce_match",
        "nonce_match",
    ]);

    // A mismatch reported by the verifier is final, whatever nonce the output
    // echoes back.
    if reported_match == Some(false) {
        verdict.fail("nonce_mismatch", "attestation report nonce did not match");
        return;
    }

    let accepted = match report.eat_nonce() {
        Some(actual) => actual == expected_nonce,
        None => reported_match == Some(true),
    };

    if !accepted {
        verdict.fail(
            "nonce_missing_or_mismatch",
            "expected nonce was not present",
        );
    }
}
