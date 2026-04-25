//! Unofficial Rust wrapper for NVIDIA GPU attestation tooling.
//!
//! This crate is intentionally conservative: it does not claim to be a native
//! verifier for NVIDIA evidence. It runs NVIDIA's attestation tooling, parses
//! the verifier JSON, computes stable hashes for evidence binding, and applies
//! explicit policy checks that callers can inspect.

mod error;
mod hash;
mod policy;
mod report;
mod runner;

pub use error::{Error, Result};
pub use hash::{sha256_hex, sha256_raw};
pub use policy::{Policy, PolicyFailure, PolicyVerdict};
pub use report::AttestationReport;
pub use runner::NvAttestRunner;
