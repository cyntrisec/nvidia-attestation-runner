use nvidia_attestation_runner::{AttestationReport, Policy};

const GOOD_REPORT: &str = r#"{
  "claims": [
    {"name": "x-nvidia-device-type", "value": "GPU"},
    {"name": "x-nvidia-gpu-attestation-report-parsed", "result": true},
    {"name": "x-nvidia-gpu-attestation-report-signature-verified", "result": true},
    {"name": "x-nvidia-gpu-attestation-report-nonce-match", "result": true},
    {"name": "x-nvidia-gpu-secboot", "result": true},
    {"name": "x-nvidia-gpu-dbgstat", "result": "disabled"},
    {"name": "x-nvidia-gpu-measres", "result": "success"},
    {"name": "x-nvidia-gpu-driver-rim-signature-verified", "result": true}
  ],
  "detached_eat": {
    "GPU-0": "opaque-token"
  }
}"#;

#[test]
fn baseline_policy_accepts_successful_gpu_report() {
    let report = AttestationReport::from_json_str(GOOD_REPORT).unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex("00112233445566778899aabbccddeeff")
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
    assert!(report.evidence_hashes().contains_key("raw_json"));
}

#[test]
fn baseline_policy_rejects_failed_signature_validation() {
    let json = GOOD_REPORT.replace(
        r#"{"name": "x-nvidia-gpu-attestation-report-signature-verified", "result": true}"#,
        r#"{"name": "x-nvidia-gpu-attestation-report-signature-verified", "result": false}"#,
    );
    let report = AttestationReport::from_json_str(json).unwrap();
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "report_signature_unverified"));
}
