//! Unofficial Rust wrapper for NVIDIA GPU attestation tooling.
//!
//! This crate is intentionally conservative: it does not claim to be a native
//! verifier for NVIDIA evidence. It runs NVIDIA's attestation tooling, parses
//! the verifier JSON, computes stable hashes for evidence binding, and applies
//! explicit policy checks that callers can inspect.

mod bundle;
mod cc_admin;
mod error;
mod hash;
mod orchestrator;
mod policy;
mod report;
mod runner;

pub use bundle::{NvidiaAttestationBackend, NvidiaEvidenceBundle};
pub use cc_admin::{report_from_cc_admin_transcript, CcAdminRunner};
pub use error::{Error, Result};
pub use hash::{sha256_hex, sha256_raw};
pub use orchestrator::NvidiaAttestationRunner;
pub use policy::{Policy, PolicyConfigurationError, PolicyFailure, PolicyVerdict};
pub use report::AttestationReport;
pub use runner::NvAttestRunner;
