use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{sha256_hex, Result};

/// Parsed NVIDIA attestation verifier output.
///
/// The verifier JSON has changed across NVIDIA tooling versions. This type keeps
/// the raw JSON intact and exposes tolerant accessors for common claim shapes:
/// direct object fields, `claims` maps, `claims` arrays with name/value or
/// name/result pairs, and NVAT 1.2.0-style `claims` arrays containing one
/// object with direct claim-name keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    raw: Value,
}

impl AttestationReport {
    /// Parse verifier output from JSON bytes.
    pub fn from_json_slice(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self {
            raw: serde_json::from_slice(bytes.as_ref())?,
        })
    }

    /// Parse verifier output from a JSON string.
    pub fn from_json_str(json: impl AsRef<str>) -> Result<Self> {
        Self::from_json_slice(json.as_ref().as_bytes())
    }

    /// Return the original parsed JSON.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Serialize the report in serde_json's deterministic map order and hash it.
    pub fn canonical_json_sha256_hex(&self) -> Result<String> {
        let bytes = serde_json::to_vec(&self.raw)?;
        Ok(sha256_hex(bytes))
    }

    /// Return the first matching claim value by exact claim name.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        direct_field(&self.raw, name)
            .or_else(|| claim_from_object(self.raw.get("claims")?, name))
            .or_else(|| claim_from_array(self.raw.get("claims")?.as_array()?, name))
    }

    /// Return true when any claim name begins with the given prefix.
    pub fn has_claim_prefix(&self, prefix: &str) -> bool {
        self.claim_names()
            .iter()
            .any(|name| name.starts_with(prefix))
    }

    /// Return all visible claim names.
    pub fn claim_names(&self) -> Vec<String> {
        let mut names = Vec::new();

        if let Some(object) = self.raw.as_object() {
            names.extend(object.keys().cloned());
        }

        match self.raw.get("claims") {
            Some(Value::Object(object)) => names.extend(object.keys().cloned()),
            Some(Value::Array(items)) => {
                for item in items {
                    if let Some(object) = item.as_object() {
                        names.extend(object.keys().cloned());
                    }

                    if let Some(name) = claim_name(item) {
                        names.push(name.to_owned());
                    }
                }
            }
            _ => {}
        }

        names.sort();
        names.dedup();
        names
    }

    /// Return a boolean interpretation for the first matching claim name.
    pub fn claim_bool(&self, names: &[&str]) -> Option<bool> {
        names
            .iter()
            .find_map(|name| self.claim(name).and_then(value_as_bool))
    }

    /// Return true if the verifier output appears to contain per-GPU evidence.
    pub fn has_gpu_evidence(&self) -> bool {
        self.has_claim_prefix("x-nvidia-gpu-")
            || self
                .claim("x-nvidia-device-type")
                .and_then(Value::as_str)
                .map(|value| value.eq_ignore_ascii_case("gpu"))
                .unwrap_or(false)
            || self.raw.get("detached_eat").is_some()
            || self.raw.get("gpus").is_some()
    }

    /// Return the NVIDIA SDK top-level result code when present.
    pub fn result_code(&self) -> Option<i64> {
        match self.raw.get("result_code")? {
            Value::Number(number) => number.as_i64(),
            Value::String(value) => value.trim().parse().ok(),
            _ => None,
        }
    }

    /// Return the NVIDIA SDK top-level result message when present.
    pub fn result_message(&self) -> Option<&str> {
        self.raw.get("result_message").and_then(Value::as_str)
    }

    /// Extract an EAT nonce from common fields when present.
    pub fn eat_nonce(&self) -> Option<Vec<u8>> {
        self.claim("eat_nonce")
            .or_else(|| self.claim("nonce"))
            .or_else(|| self.claim("x-nvidia-gpu-attestation-report-nonce"))
            .and_then(value_as_bytes)
    }

    /// Return hashes for top-level evidence-bearing subdocuments.
    pub fn evidence_hashes(&self) -> BTreeMap<String, String> {
        let mut hashes = BTreeMap::new();
        if let Ok(hash) = self.canonical_json_sha256_hex() {
            hashes.insert("raw_json".to_owned(), hash);
        }

        for key in ["claims", "detached_eat", "gpus"] {
            if let Some(value) = self.raw.get(key) {
                if let Ok(bytes) = serde_json::to_vec(value) {
                    hashes.insert(format!("{key}_json"), sha256_hex(bytes));
                }
            }
        }

        hashes
    }
}

fn direct_field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object()?.get(name)
}

fn claim_from_object<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value.as_object()?.get(name)
}

fn claim_from_array<'a>(claims: &'a [Value], name: &str) -> Option<&'a Value> {
    for claim in claims {
        if let Some(value) = direct_field(claim, name) {
            return Some(value);
        }

        if claim_name(claim) == Some(name) {
            return claim
                .get("value")
                .or_else(|| claim.get("result"))
                .or_else(|| claim.get("status"))
                .or_else(|| claim.get("claim_value"));
        }
    }
    None
}

fn claim_name(value: &Value) -> Option<&str> {
    value
        .get("name")
        .or_else(|| value.get("claim"))
        .or_else(|| value.get("key"))
        .or_else(|| value.get("title"))
        .and_then(Value::as_str)
}

pub(crate) fn value_as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(number) => number.as_i64().map(|value| value != 0),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "ok" | "pass" | "passed" | "success" | "successful" | "valid"
            | "enabled" | "1" => Some(true),
            "false" | "no" | "fail" | "failed" | "error" | "invalid" | "disabled" | "0" => {
                Some(false)
            }
            _ => None,
        },
        _ => None,
    }
}

fn value_as_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(value) => decode_string_bytes(value),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_u64().and_then(|value| u8::try_from(value).ok()))
            .collect(),
        _ => None,
    }
}

fn decode_string_bytes(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.len() % 2 == 0 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex::decode(trimmed).ok()
    } else {
        Some(value.as_bytes().to_vec())
    }
}
