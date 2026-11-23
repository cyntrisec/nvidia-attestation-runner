use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::policy::{
    debug_reported_disabled, measurements_reported_successful, DEBUG_STATUS_CLAIMS,
    MEASUREMENT_RESULT_CLAIMS,
};
use crate::report::value_as_bool;
use crate::{
    sha256_hex, AttestationReport, NvidiaAttestationBackend, PolicyFailure, PolicyVerdict, Result,
};

/// Stable redacted summary schema emitted for AIR / SIEM integrations.
pub const NVIDIA_GPU_EVIDENCE_SUMMARY_V1: &str = "cyntrisec.nvidia.gpu_evidence_summary.v1";

/// Longest string copied from verifier output into the summary.
const MAX_SUMMARY_TEXT_LEN: usize = 64;

/// Redacted NVIDIA GPU evidence summary.
///
/// This type does not carry raw NVIDIA verifier JSON, transcripts, detached
/// EAT/JWT values, command lines, or host metadata. The `gpu` fields are a
/// fixed set of posture claims copied from the verifier output: model, mode,
/// measurement result, secure boot, debug status, driver and VBIOS versions.
/// A copied string is kept only when it is a single printable ASCII line of at
/// most 64 characters. Use [`crate::NvidiaEvidenceBundle`] when raw evidence
/// retention is required.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaGpuEvidenceSummaryV1 {
    pub schema_version: String,
    pub backend: NvidiaAttestationBackend,
    pub status: String,
    pub policy: NvidiaPolicySummary,
    pub evidence_hashes: BTreeMap<String, String>,
    pub gpu: NvidiaGpuSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result_code: Option<i64>,
}

impl NvidiaGpuEvidenceSummaryV1 {
    /// Return the SHA-256 hash of the summary's compact JSON serialization.
    ///
    /// The bytes hashed are the summary object without insignificant
    /// whitespace, fields in the order this type declares them and absent
    /// optional fields omitted. A consumer can recompute the hash from a
    /// written summary by compacting the `summary` object while keeping its
    /// key order, for example `jq -cj .summary file.json | sha256sum`. Sorting
    /// the keys gives a different hash.
    pub fn canonical_json_sha256_hex(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(sha256_hex(bytes))
    }
}

/// Policy verdict summary safe for SIEM/event export.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaPolicySummary {
    pub name: String,
    pub evaluated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failure_codes: Vec<String>,
}

/// Redacted GPU posture fields extracted from NVIDIA verifier output.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvidiaGpuSummary {
    pub vendor: String,
    pub evidence_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measres: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secboot: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbgstat: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rim_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_parsed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_signature_verified: Option<bool>,
}

pub(crate) fn build_summary(
    backend: NvidiaAttestationBackend,
    report: &AttestationReport,
    evidence_hashes: &BTreeMap<String, String>,
    policy_name: impl Into<String>,
    verdict: Option<&PolicyVerdict>,
) -> NvidiaGpuEvidenceSummaryV1 {
    let policy = policy_summary(policy_name, verdict);
    NvidiaGpuEvidenceSummaryV1 {
        schema_version: NVIDIA_GPU_EVIDENCE_SUMMARY_V1.to_owned(),
        backend,
        status: match policy.accepted {
            Some(true) => "pass",
            Some(false) => "fail",
            None => "not_evaluated",
        }
        .to_owned(),
        policy,
        evidence_hashes: evidence_hashes.clone(),
        gpu: gpu_summary(report),
        nonce_sha256: report.eat_nonce().map(sha256_hex),
        tool_result_code: report.result_code(),
    }
}

fn policy_summary(
    policy_name: impl Into<String>,
    verdict: Option<&PolicyVerdict>,
) -> NvidiaPolicySummary {
    let failure_codes = verdict
        .map(|verdict| verdict.failures.iter().map(failure_code).collect())
        .unwrap_or_default();

    NvidiaPolicySummary {
        name: policy_name.into(),
        evaluated: verdict.is_some(),
        accepted: verdict.map(|verdict| verdict.accepted),
        failure_codes,
    }
}

fn failure_code(failure: &PolicyFailure) -> String {
    failure.code.to_owned()
}

fn gpu_summary(report: &AttestationReport) -> NvidiaGpuSummary {
    NvidiaGpuSummary {
        vendor: "nvidia".to_owned(),
        evidence_present: report.has_gpu_evidence(),
        product: first_string_claim(
            report,
            &[
                "x-nvidia-gpu-product",
                "x-nvidia-gpu-model",
                "gpu_product",
                "gpu_model",
                "hwmodel",
                "arch",
            ],
        ),
        cc_mode: first_string_claim(report, &["x-nvidia-gpu-mode", "gpu_mode", "feature_flag"]),
        measres: measurement_status(report),
        secboot: report.claim_bool(&["x-nvidia-gpu-secboot", "secboot", "secure_boot"]),
        dbgstat: debug_status(report),
        driver_version: first_string_claim(
            report,
            &[
                "x-nvidia-gpu-driver-version",
                "driver_version",
                "OPAQUE_FIELD_ID_DRIVER_VERSION",
            ],
        ),
        vbios_version: first_string_claim(report, &["x-nvidia-gpu-vbios-version", "vbios_version"]),
        rim_status: rim_status(report),
        report_parsed: report.claim_bool(&[
            "x-nvidia-gpu-attestation-report-parsed",
            "attestation_report_parsed",
            "report_parsed",
        ]),
        report_signature_verified: report.claim_bool(&[
            "x-nvidia-gpu-attestation-report-signature-verified",
            "attestation_report_signature_verified",
            "report_signature_verified",
        ]),
    }
}

fn first_string_claim(report: &AttestationReport, names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| report.claim(name).and_then(value_to_string))
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => summary_text(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Return `"success"` when the policy's own predicate holds, otherwise the
/// first usable text the verifier reported.
fn measurement_status(report: &AttestationReport) -> Option<String> {
    if measurements_reported_successful(report) {
        return Some("success".to_owned());
    }
    first_status_text(report, &MEASUREMENT_RESULT_CLAIMS, "success", "fail")
}

/// Return `"disabled"` when the policy's own predicate holds, otherwise the
/// first usable text the verifier reported.
fn debug_status(report: &AttestationReport) -> Option<String> {
    if debug_reported_disabled(report) {
        return Some("disabled".to_owned());
    }
    first_status_text(report, &DEBUG_STATUS_CLAIMS, "enabled", "disabled")
}

fn first_status_text(
    report: &AttestationReport,
    names: &[&str],
    when_true: &str,
    when_false: &str,
) -> Option<String> {
    names.iter().find_map(|name| {
        let value = report.claim(name)?;
        value.as_str().and_then(summary_text).or_else(|| {
            let flag = value_as_bool(value)?;
            Some(if flag { when_true } else { when_false }.to_owned())
        })
    })
}

fn rim_status(report: &AttestationReport) -> Option<String> {
    let driver = report.claim_bool(&[
        "x-nvidia-gpu-driver-rim-signature-verified",
        "x-nvidia-gpu-driver-vbios-rim-signature-verified",
        "rim_signature_verified",
    ]);
    let vbios = report.claim_bool(&["x-nvidia-gpu-vbios-rim-signature-verified"]);

    match (driver, vbios) {
        (Some(true), Some(true)) => Some("verified".to_owned()),
        (Some(false), _) | (_, Some(false)) => Some("failed".to_owned()),
        (Some(true), None) | (None, Some(true)) => Some("partial".to_owned()),
        _ => None,
    }
}

/// Return a trimmed string when it is a short, single, printable ASCII line.
///
/// Summary fields are copied from verifier output. Anything that does not look
/// like a label or a version string is dropped instead of exported.
fn summary_text(value: &str) -> Option<String> {
    let value = value.trim();
    let printable = value.chars().all(|ch| ch.is_ascii_graphic() || ch == ' ');
    (!value.is_empty() && value.len() <= MAX_SUMMARY_TEXT_LEN && printable)
        .then(|| value.to_owned())
}
