use sha2::{Digest, Sha256};

/// Return the SHA-256 digest of `bytes`.
pub fn sha256_raw(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes.as_ref()).into()
}

/// Return the lowercase hex SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(sha256_raw(bytes))
}
