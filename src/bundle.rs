use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::summary::build_summary;
use crate::{AttestationReport, NvidiaGpuEvidenceSummaryV1, PolicyVerdict, Result};

/// NVIDIA attestation backend used to produce a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NvidiaAttestationBackend {
    /// `nvattest --format json attest --device gpu --verifier local`.
    NvAttestLocalJson,
    /// `nvattest --format json attest --device gpu --verifier remote`.
    NvAttestRemoteJson,
    /// NVIDIA Python local verifier transcript: `python3 -m verifier.cc_admin --verbose`.
    CcAdminTranscript,
    /// Caller-supplied command expected to emit NVIDIA-compatible JSON.
    CustomJson,
    /// Caller-supplied command expected to emit a `cc_admin`-compatible transcript.
    CustomTranscript,
}

/// Bundle metadata returned by runner APIs.
#[must_use]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaEvidenceBundle {
    backend: NvidiaAttestationBackend,
    command: Vec<String>,
    exit_code: Option<i32>,
    report: AttestationReport,
    evidence_hashes: BTreeMap<String, String>,
}

impl NvidiaEvidenceBundle {
    pub fn new(
        backend: NvidiaAttestationBackend,
        command: Vec<String>,
        exit_code: Option<i32>,
        report: AttestationReport,
    ) -> Self {
        let evidence_hashes = report.evidence_hashes();
        Self {
            backend,
            command,
            exit_code,
            report,
            evidence_hashes,
        }
    }

    pub fn backend(&self) -> NvidiaAttestationBackend {
        self.backend
    }

    pub fn command(&self) -> &[String] {
        &self.command
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn report(&self) -> &AttestationReport {
        &self.report
    }

    pub fn into_report(self) -> AttestationReport {
        self.report
    }

    pub fn evidence_hashes(&self) -> &BTreeMap<String, String> {
        &self.evidence_hashes
    }

    pub fn gpu_evidence_summary(
        &self,
        policy_name: impl Into<String>,
        verdict: Option<&PolicyVerdict>,
    ) -> NvidiaGpuEvidenceSummaryV1 {
        build_summary(
            self.backend,
            &self.report,
            &self.evidence_hashes,
            policy_name,
            verdict,
        )
    }

    pub fn canonical_json_sha256_hex(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        Ok(crate::sha256_hex(bytes))
    }
}
