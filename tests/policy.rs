use nvidia_attestation_runner::{AttestationReport, NvAttestRunner, Policy};

const GOOD_REPORT: &str = r#"{
  "result_code": 0,
  "result_message": "Ok",
  "claims": [
    {"name": "x-nvidia-device-type", "value": "GPU"},
    {"name": "x-nvidia-gpu-attestation-report-parsed", "result": true},
    {"name": "x-nvidia-gpu-attestation-report-signature-verified", "result": true},
    {"name": "x-nvidia-gpu-attestation-report-nonce-match", "result": true},
    {"name": "x-nvidia-gpu-secboot", "result": true},
    {"name": "x-nvidia-gpu-dbgstat", "result": "disabled"},
    {"name": "x-nvidia-gpu-measres", "result": "success"},
    {"name": "x-nvidia-gpu-driver-rim-signature-verified", "result": true},
    {"name": "x-nvidia-gpu-vbios-rim-signature-verified", "result": true}
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

#[test]
fn real_h100_local_attestation_with_measurement_mismatch_is_rejected() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_local_attestation_measres_fail.json"
    ))
    .unwrap();

    assert!(report.has_gpu_evidence());
    assert_eq!(
        report.result_message(),
        Some("Overall Attestation Result is False")
    );
    assert_eq!(
        report
            .claim("x-nvidia-gpu-attestation-report-signature-verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report.claim("measres").and_then(serde_json::Value::as_str),
        Some("fail")
    );

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nvidia_attestation_failed"));
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "measurements_not_successful"));
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "measurement_mismatch_records_present"));
}

#[test]
fn real_h100_collect_evidence_output_has_stable_hashes() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_collect_evidence_ok_redacted.json"
    ))
    .unwrap();

    assert_eq!(report.result_code(), Some(0));
    assert_eq!(report.result_message(), Some("Ok"));
    assert!(report.evidence_hashes().contains_key("raw_json"));
}

#[test]
fn runner_returns_json_report_from_nonzero_attestation_exit() {
    let report = NvAttestRunner::new("sh")
        .args([
            "-c",
            "printf '%s' '{\"result_code\":12,\"result_message\":\"Overall Attestation Result is False\"}'; exit 12",
        ])
        .run()
        .unwrap();

    assert_eq!(report.result_code(), Some(12));
    assert_eq!(
        report.result_message(),
        Some("Overall Attestation Result is False")
    );
}
