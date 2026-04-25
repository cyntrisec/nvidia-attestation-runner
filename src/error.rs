use std::process::ExitStatus;

/// Crate-local result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the runner, parser, and policy layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to run NVIDIA attestation command: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse NVIDIA attestation JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("NVIDIA attestation command failed with status {status}: {stderr}")]
    CommandFailed {
        status: ExitStatus,
        stderr: String,
        stdout: String,
    },
}
