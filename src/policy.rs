use crate::report::value_as_bool;
use crate::AttestationReport;

/// A failed policy requirement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFailure {
    pub code: &'static str,
    pub message: String,
}

/// Policy evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Default)]
pub struct Policy {
    expected_nonce: Option<Vec<u8>>,
    require_gpu_evidence: bool,
    require_report_parsed: bool,
    require_report_signature_verified: bool,
    require_measurements_success: bool,
    require_secure_boot: bool,
    require_debug_disabled: bool,
    require_rim_signature_verified: bool,
}

impl Policy {
    /// Conservative baseline for confidential GPU evidence produced by NVIDIA tooling.
    pub fn nvidia_cc_baseline() -> Self {
        Self {
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

    pub fn expected_nonce(mut self, nonce: impl Into<Vec<u8>>) -> Self {
        self.expected_nonce = Some(nonce.into());
        self
    }

    pub fn expected_nonce_hex(mut self, nonce_hex: &str) -> Result<Self, hex::FromHexError> {
        self.expected_nonce = Some(hex::decode(
            nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex),
        )?);
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

    pub fn evaluate(&self, report: &AttestationReport) -> PolicyVerdict {
        let mut verdict = PolicyVerdict::accepted();

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
                "rim_signature_unverified",
                "RIM signature was not verified",
            );
        }

        if let Some(expected_nonce) = &self.expected_nonce {
            require_nonce(&mut verdict, report, expected_nonce);
        }

        verdict
    }
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
    for name in ["x-nvidia-gpu-measres", "measres", "measurement_result"] {
        if let Some(value) = report.claim(name) {
            let ok = value_as_bool(value).unwrap_or_else(|| {
                value
                    .as_str()
                    .map(|value| {
                        matches!(
                            value.trim().to_ascii_lowercase().as_str(),
                            "success" | "successful" | "pass" | "passed" | "valid"
                        )
                    })
                    .unwrap_or(false)
            });

            if ok {
                return;
            }
        }
    }

    verdict.fail(
        "measurements_not_successful",
        "GPU measurements were not reported as successful",
    );
}

fn require_debug_disabled(verdict: &mut PolicyVerdict, report: &AttestationReport) {
    for name in ["x-nvidia-gpu-dbgstat", "dbgstat", "debug"] {
        if let Some(value) = report.claim(name) {
            let disabled = match value {
                serde_json::Value::Bool(enabled) => !enabled,
                serde_json::Value::Number(number) => number.as_i64() == Some(0),
                serde_json::Value::String(value) => matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "disabled" | "false" | "0" | "off"
                ),
                _ => false,
            };

            if disabled {
                return;
            }
        }
    }

    verdict.fail("debug_not_disabled", "debug mode is not disabled");
}

fn require_nonce(verdict: &mut PolicyVerdict, report: &AttestationReport, expected_nonce: &[u8]) {
    match report.claim_bool(&[
        "x-nvidia-gpu-attestation-report-nonce-match",
        "attestation_report_nonce_match",
        "nonce_match",
    ]) {
        Some(true) => return,
        Some(false) => {
            verdict.fail("nonce_mismatch", "attestation report nonce did not match");
            return;
        }
        None => {}
    }

    match report.eat_nonce() {
        Some(actual) if actual == expected_nonce => {}
        _ => verdict.fail(
            "nonce_missing_or_mismatch",
            "expected nonce was not present",
        ),
    }
}
