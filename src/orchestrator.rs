use std::ffi::OsString;

use crate::{
    CcAdminRunner, NvAttestRunner, NvidiaAttestationBackend, NvidiaEvidenceBundle, Result,
};

/// Unified runner for the supported NVIDIA attestation backends.
#[must_use]
#[derive(Debug, Clone)]
pub enum NvidiaAttestationRunner {
    NvAttestJson {
        backend: NvidiaAttestationBackend,
        runner: NvAttestRunner,
    },
    CcAdminTranscript {
        runner: CcAdminRunner,
    },
}

impl NvidiaAttestationRunner {
    pub fn local_gpu_json_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::NvAttestJson {
            backend: NvidiaAttestationBackend::NvAttestLocalJson,
            runner: NvAttestRunner::local_gpu_with_nonce_hex(nonce_hex),
        }
    }

    pub fn remote_gpu_json_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::NvAttestJson {
            backend: NvidiaAttestationBackend::NvAttestRemoteJson,
            runner: NvAttestRunner::remote_gpu_with_nonce_hex(nonce_hex),
        }
    }

    pub fn cc_admin_transcript_with_nonce_hex(nonce_hex: impl Into<OsString>) -> Self {
        Self::CcAdminTranscript {
            runner: CcAdminRunner::python_module_with_nonce_hex(nonce_hex),
        }
    }

    pub fn run_bundle(&self) -> Result<NvidiaEvidenceBundle> {
        match self {
            Self::NvAttestJson { backend, runner } => runner.run_bundle_with_backend(*backend),
            Self::CcAdminTranscript { runner } => runner.run_bundle(),
        }
    }
}
