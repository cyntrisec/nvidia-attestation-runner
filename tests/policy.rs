use nvidia_attestation_runner::{
    report_from_cc_admin_transcript, AttestationReport, CcAdminRunner, NvAttestRunner,
    NvidiaAttestationBackend, NvidiaAttestationRunner, NvidiaEvidenceBundle,
    NvidiaGpuEvidenceSummaryV1, Policy, NVIDIA_GPU_EVIDENCE_SUMMARY_V1,
};
use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_nvidia-attestation-runner");
const TEST_NONCE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const REAL_H100_NVATTEST_SUCCESS_NONCE: &str =
    "0b2e6e35691e26c9c1a4b19b22786364538c682833870cb0372d068767ce63f2";
const REAL_H100_DRV580_NVATTEST2_NONCE: &str =
    "1551ff51392ef1b1d0fceefee303971eff71a4bba384326d24bf936c5428b5b3";
const REAL_H100_DRV620_NVATTEST2_NONCE: &str =
    "2d38fa6e190a6ba439278f705344c5c6b5cd5c07bdb4dc92ad9c57da6ef0befa";

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
        .expected_nonce_hex(TEST_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
    assert!(report.evidence_hashes().contains_key("raw_json"));
}

#[test]
fn expected_nonce_hex_rejects_wrong_length() {
    let error = Policy::nvidia_cc_baseline()
        .expected_nonce_hex("00112233445566778899aabbccddeeff")
        .unwrap_err();

    assert_eq!(
        error.to_string(),
        "expected nonce must be 32 bytes, got 16 bytes"
    );
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
fn baseline_policy_rejects_contradictory_success_code_and_failed_overall_result() {
    let json = GOOD_REPORT.replace(
        r#"{"name": "x-nvidia-device-type", "value": "GPU"},"#,
        r#"{"name": "x-nvidia-device-type", "value": "GPU"},
    {"name": "x-nvidia-overall-att-result", "result": false},"#,
    );
    let report = AttestationReport::from_json_str(json).unwrap();
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nvidia_attestation_failed"));
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
fn real_h100_nvattest_local_success_fixture_is_accepted() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();

    assert!(report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(0));
    assert_eq!(report.result_message(), Some("Ok"));
    assert_eq!(
        report.claim("measres").and_then(serde_json::Value::as_str),
        Some("success")
    );
    assert_eq!(
        report.claim("secboot").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report
            .claim("x-nvidia-gpu-attestation-report-signature-verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report
            .claim("x-nvidia-gpu-driver-rim-signature-verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        report
            .claim("x-nvidia-gpu-vbios-rim-signature-verified")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(report
        .claim("x-nvidia-mismatch-measurement-records")
        .is_some_and(serde_json::Value::is_null));

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_NVATTEST_SUCCESS_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
    assert!(report.evidence_hashes().contains_key("claims_json"));
    assert!(report.evidence_hashes().contains_key("detached_eat_json"));
}

#[test]
fn real_h100_nvattest_local_success_summary_is_redacted_and_stable() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_NVATTEST_SUCCESS_NONCE)
        .unwrap()
        .evaluate(&report);
    let bundle = NvidiaEvidenceBundle::new(
        NvidiaAttestationBackend::NvAttestLocalJson,
        vec!["nvattest".to_owned()],
        Some(0),
        report,
    );
    let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", Some(&verdict));

    assert_eq!(summary.schema_version, NVIDIA_GPU_EVIDENCE_SUMMARY_V1);
    assert_eq!(summary.status, "pass");
    assert_eq!(summary.policy.accepted, Some(true));
    assert_eq!(summary.gpu.vendor, "nvidia");
    assert_eq!(summary.gpu.product.as_deref(), Some("GH100 A01 GSP BROM"));
    assert_eq!(summary.gpu.measres.as_deref(), Some("success"));
    assert_eq!(summary.gpu.secboot, Some(true));
    assert_eq!(summary.gpu.dbgstat.as_deref(), Some("disabled"));
    assert_eq!(summary.gpu.rim_status.as_deref(), Some("verified"));
    assert!(summary.evidence_hashes.contains_key("raw_json"));
    assert!(summary.evidence_hashes.contains_key("detached_eat_json"));
    assert!(summary.nonce_sha256.is_some());

    let summary_hash = summary.canonical_json_sha256_hex().unwrap();
    assert_eq!(summary_hash, summary.canonical_json_sha256_hex().unwrap());
    assert_eq!(summary_hash.len(), 64);

    let serialized = serde_json::to_string(&summary).unwrap();
    assert!(!serialized.contains("REDACTED_GPU_UNSIGNED_JWT"));
    assert!(!serialized.contains("REDACTED_OVERALL_UNSIGNED_JWT"));
    assert!(!serialized.contains("REDACTED_UEID"));
    assert!(!serialized.contains(REAL_H100_NVATTEST_SUCCESS_NONCE));
}

#[test]
fn failing_h100_summary_contains_policy_failure_codes_without_raw_measurements() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_local_attestation_measres_fail.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(TEST_NONCE)
        .unwrap()
        .evaluate(&report);
    let bundle = NvidiaEvidenceBundle::new(
        NvidiaAttestationBackend::NvAttestLocalJson,
        vec!["nvattest".to_owned()],
        Some(12),
        report,
    );
    let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", Some(&verdict));

    assert_eq!(summary.status, "fail");
    assert_eq!(summary.policy.accepted, Some(false));
    assert!(summary
        .policy
        .failure_codes
        .iter()
        .any(|code| code == "measurement_mismatch_records_present"));

    let serialized = serde_json::to_string(&summary).unwrap();
    assert!(!serialized.contains("REDACTED_RUNTIME_MEASUREMENT"));
    assert!(!serialized.contains("REDACTED_GOLDEN_MEASUREMENT"));
}

#[test]
fn real_h100_nvattest_local_success_rejects_wrong_expected_nonce() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(TEST_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nonce_missing_or_mismatch"));
}

#[test]
fn real_h100_nvattest_local_success_rejects_unverified_report_signature() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    *value
        .pointer_mut("/claims/0/x-nvidia-gpu-attestation-report-signature-verified")
        .unwrap() = serde_json::Value::Bool(false);
    let report = AttestationReport::from_value(value);
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "report_signature_unverified"));
}

#[test]
fn real_h100_nvattest_local_success_rejects_disabled_secure_boot() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    *value.pointer_mut("/claims/0/secboot").unwrap() = serde_json::Value::Bool(false);
    let report = AttestationReport::from_value(value);
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "secure_boot_not_enabled"));
}

#[test]
fn real_h100_nvattest_local_success_rejects_unverified_driver_rim() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    *value
        .pointer_mut("/claims/0/x-nvidia-gpu-driver-rim-signature-verified")
        .unwrap() = serde_json::Value::Bool(false);
    let report = AttestationReport::from_value(value);
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "driver_rim_signature_unverified"));
}

#[test]
fn real_h100_nvattest_local_success_rejects_mismatch_records() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_nvattest_local_success_redacted.json"
    ))
    .unwrap();
    *value
        .pointer_mut("/claims/0/x-nvidia-mismatch-measurement-records")
        .unwrap() = serde_json::json!([
        {
            "index": 9,
            "measurementSource": "Firmware",
            "runtimeValue": "REDACTED_RUNTIME_MEASUREMENT",
            "goldenValue": "REDACTED_GOLDEN_MEASUREMENT"
        }
    ]);
    let report = AttestationReport::from_value(value);
    let verdict = Policy::nvidia_cc_baseline().evaluate(&report);

    assert!(!verdict.accepted);
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
fn real_h100_nvattest2_local_success_fixture_is_accepted() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();

    assert!(report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(0));
    assert_eq!(report.result_message(), Some("Ok"));
    assert_eq!(
        report
            .claim("x-nvidia-gpu-claims-version")
            .and_then(serde_json::Value::as_str),
        Some("4.0")
    );
    assert_eq!(
        report.claim("measres").and_then(serde_json::Value::as_str),
        Some("success")
    );
    assert_eq!(
        report.claim("secboot").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(report
        .claim("x-nvidia-mismatch-measurement-records")
        .is_some_and(serde_json::Value::is_null));
    assert!(report
        .claim("x-nvidia-mismatch-opaque-data-records")
        .is_some_and(serde_json::Value::is_null));

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV580_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
    assert!(report.evidence_hashes().contains_key("claims_json"));
    assert!(report.evidence_hashes().contains_key("detached_eat_json"));
}

#[test]
fn real_h100_nvattest2_remote_success_fixture_is_accepted() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv580_nvattest2_remote_success_redacted.json"
    ))
    .unwrap();

    assert!(report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(0));
    assert_eq!(
        report.claim("hwmodel").and_then(serde_json::Value::as_str),
        Some("GH100")
    );
    assert_eq!(
        report.claim("measres").and_then(serde_json::Value::as_str),
        Some("success")
    );

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV580_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
}

#[test]
fn real_h100_nvattest2_success_fixture_rejects_wrong_expected_nonce() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv580_nvattest2_remote_success_redacted.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(TEST_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nonce_missing_or_mismatch"));
}

#[test]
fn real_h100_versioned_opaque_data_success_fixture_is_accepted() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv620_nvattest2_local_success_redacted.json"
    ))
    .unwrap();

    assert!(report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(0));
    assert_eq!(
        report
            .claim("x-nvidia-gpu-driver-version")
            .and_then(serde_json::Value::as_str),
        Some("620.70.06")
    );
    assert_eq!(
        report.claim("measres").and_then(serde_json::Value::as_str),
        Some("success")
    );

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV620_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
}

#[test]
fn real_h100_missing_reference_answer_is_rejected_without_gpu_evidence() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv595_nvattest2_local_rim_not_found.json"
    ))
    .unwrap();

    assert!(!report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(104));
    assert_eq!(report.result_message(), Some("RIM Not Found"));

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(TEST_NONCE)
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
        .any(|failure| failure.code == "gpu_evidence_missing"));
}

#[test]
fn real_h100_old_tool_on_versioned_opaque_data_is_rejected() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv620_nvattest1_local_evidence_invalid.json"
    ))
    .unwrap();

    assert!(!report.has_gpu_evidence());
    assert_eq!(report.result_code(), Some(503));
    assert_eq!(report.result_message(), Some("GPU Evidence Invalid"));

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV620_NVATTEST2_NONCE)
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
        .any(|failure| failure.code == "gpu_evidence_missing"));
}

#[test]
fn empty_failed_answer_summary_reports_no_gpu_evidence() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv595_nvattest2_local_rim_not_found.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(TEST_NONCE)
        .unwrap()
        .evaluate(&report);
    let bundle = NvidiaEvidenceBundle::new(
        NvidiaAttestationBackend::NvAttestLocalJson,
        vec!["nvattest".to_owned()],
        Some(104),
        report,
    );
    let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", Some(&verdict));

    assert_eq!(summary.status, "fail");
    assert_eq!(summary.policy.accepted, Some(false));
    assert!(!summary.gpu.evidence_present);
    assert_eq!(summary.tool_result_code, Some(104));
    assert!(summary
        .policy
        .failure_codes
        .iter()
        .any(|code| code == "gpu_evidence_missing"));
}

#[test]
fn empty_evidence_containers_do_not_count_as_gpu_evidence() {
    for json in [
        r#"{"result_code": 0, "result_message": "Ok", "claims": {}, "detached_eat": {}}"#,
        r#"{"result_code": 0, "result_message": "Ok", "claims": [], "detached_eat": []}"#,
        r#"{"result_code": 0, "result_message": "Ok", "detached_eat": null, "gpus": []}"#,
        r#"{"result_code": 0, "result_message": "Ok", "detached_eat": {"GPU-0": ""}}"#,
    ] {
        let report = AttestationReport::from_json_str(json).unwrap();
        assert!(!report.has_gpu_evidence(), "{json}");

        let verdict = Policy::nvidia_cc_baseline().evaluate(&report);
        assert!(!verdict.accepted, "{json}");
        assert!(
            verdict
                .failures
                .iter()
                .any(|failure| failure.code == "gpu_evidence_missing"),
            "{json}"
        );
    }
}

#[test]
fn detached_eat_with_a_token_counts_as_gpu_evidence() {
    let report = AttestationReport::from_json_str(
        r#"{"result_code": 0, "result_message": "Ok", "detached_eat": {"GPU-0": "opaque-token"}}"#,
    )
    .unwrap();

    assert!(report.has_gpu_evidence());
}

#[test]
fn real_h100_nvattest2_success_fixture_rejects_reported_nonce_mismatch() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();
    *value
        .pointer_mut("/claims/0/x-nvidia-gpu-attestation-report-nonce-match")
        .unwrap() = serde_json::Value::Bool(false);
    let report = AttestationReport::from_value(value);
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV580_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nonce_mismatch"));
}

#[test]
fn answers_with_several_device_claim_sets_are_rejected() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();
    let second_device = value.pointer("/claims/0").unwrap().clone();
    value
        .pointer_mut("/claims")
        .and_then(serde_json::Value::as_array_mut)
        .unwrap()
        .push(second_device);
    let report = AttestationReport::from_value(value);

    assert_eq!(report.device_claim_set_count(), 2);

    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV580_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "multiple_device_claim_sets_unsupported"));
}

#[test]
fn device_claim_sets_are_counted_by_shape() {
    let single_device = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();
    let name_value_claims = AttestationReport::from_json_str(GOOD_REPORT).unwrap();
    let failed_answer = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv595_nvattest2_local_rim_not_found.json"
    ))
    .unwrap();

    assert_eq!(single_device.device_claim_set_count(), 1);
    assert_eq!(name_value_claims.device_claim_set_count(), 0);
    assert_eq!(failed_answer.device_claim_set_count(), 0);
}

#[test]
fn passing_summary_round_trips_through_json() {
    let report = AttestationReport::from_json_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();
    let verdict = Policy::nvidia_cc_baseline()
        .expected_nonce_hex(REAL_H100_DRV580_NVATTEST2_NONCE)
        .unwrap()
        .evaluate(&report);
    let bundle = NvidiaEvidenceBundle::new(
        NvidiaAttestationBackend::NvAttestLocalJson,
        vec!["nvattest".to_owned()],
        Some(0),
        report,
    );
    let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", Some(&verdict));

    assert_eq!(summary.status, "pass");
    assert!(summary.policy.failure_codes.is_empty());

    let json = serde_json::to_string(&summary).unwrap();
    let parsed: NvidiaGpuEvidenceSummaryV1 = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed, summary);
}

#[test]
fn summary_drops_text_that_is_not_a_short_printable_line() {
    let mut value: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/h100_drv580_nvattest2_local_success_redacted.json"
    ))
    .unwrap();
    *value.pointer_mut("/claims/0/hwmodel").unwrap() =
        serde_json::Value::String("serial 0123456789\nhost: internal.example".to_owned());
    *value
        .pointer_mut("/claims/0/x-nvidia-gpu-driver-version")
        .unwrap() = serde_json::Value::String("9".repeat(200));
    let report = AttestationReport::from_value(value);
    let bundle = NvidiaEvidenceBundle::new(
        NvidiaAttestationBackend::NvAttestLocalJson,
        vec!["nvattest".to_owned()],
        Some(0),
        report,
    );
    let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", None);

    assert_eq!(summary.status, "not_evaluated");
    assert_eq!(summary.gpu.product, None);
    assert_eq!(summary.gpu.driver_version, None);
    assert_eq!(summary.gpu.vbios_version.as_deref(), Some("96.00.DB.00.02"));
}

#[test]
fn summary_status_fields_agree_with_the_policy_verdict() {
    for claims in [
        r#"{"measres": "success", "dbgstat": "disabled"}"#,
        r#"{"measres": "fail", "dbgstat": "enabled"}"#,
        r#"{"x-nvidia-gpu-measres": "fail", "measres": "success", "dbgstat": "off"}"#,
        r#"{"measres": true, "debug": false}"#,
        "{}",
    ] {
        let report = AttestationReport::from_json_str(format!(
            r#"{{"result_code": 0, "result_message": "Ok", "claims": [{claims}]}}"#
        ))
        .unwrap();
        let verdict = Policy::nvidia_cc_baseline().evaluate(&report);
        let bundle = NvidiaEvidenceBundle::new(
            NvidiaAttestationBackend::CustomJson,
            vec!["tool".to_owned()],
            Some(0),
            report,
        );
        let summary = bundle.gpu_evidence_summary("nvidia_cc_baseline", Some(&verdict));

        let measurements_accepted = !verdict
            .failures
            .iter()
            .any(|failure| failure.code == "measurements_not_successful");
        let debug_accepted = !verdict
            .failures
            .iter()
            .any(|failure| failure.code == "debug_not_disabled");

        assert_eq!(
            summary.gpu.measres.as_deref() == Some("success"),
            measurements_accepted,
            "{claims}"
        );
        assert_eq!(
            summary.gpu.dbgstat.as_deref() == Some("disabled"),
            debug_accepted,
            "{claims}"
        );
    }
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

#[test]
fn json_runner_bundle_preserves_backend_command_exit_and_hashes() {
    let bundle = NvAttestRunner::new("sh")
        .args([
            "-c",
            "printf '%s' '{\"result_code\":0,\"result_message\":\"Ok\"}'",
        ])
        .run_bundle_with_backend(NvidiaAttestationBackend::CustomJson)
        .unwrap();

    assert_eq!(bundle.backend(), NvidiaAttestationBackend::CustomJson);
    assert_eq!(bundle.exit_code(), Some(0));
    assert_eq!(bundle.command()[0], "sh");
    assert_eq!(bundle.report().result_code(), Some(0));
    assert!(bundle.evidence_hashes().contains_key("raw_json"));
    assert!(!bundle.canonical_json_sha256_hex().unwrap().is_empty());
}

#[test]
fn cli_custom_json_emits_bundle_and_policy_verdict() {
    let compact_report: String = GOOD_REPORT.lines().map(str::trim).collect();
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-json",
            "--nonce",
            TEST_NONCE,
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            &format!("printf '%s' '{compact_report}'"),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json.pointer("/policy/accepted")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        json.pointer("/bundle/backend")
            .and_then(serde_json::Value::as_str),
        Some("custom_json")
    );
    assert!(json
        .pointer("/bundle_sha256")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert!(json
        .pointer("/summary_sha256")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert_eq!(
        json.pointer("/summary/schema_version")
            .and_then(serde_json::Value::as_str),
        Some(NVIDIA_GPU_EVIDENCE_SUMMARY_V1)
    );
}

#[test]
fn cli_summary_only_emits_redacted_summary_without_raw_bundle() {
    let compact_report: String = GOOD_REPORT.lines().map(str::trim).collect();
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-json",
            "--nonce",
            TEST_NONCE,
            "--summary-only",
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            &format!("printf '%s' '{compact_report}'"),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json.pointer("/bundle").is_none());
    assert!(json
        .pointer("/summary_sha256")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert_eq!(
        json.pointer("/summary/schema_version")
            .and_then(serde_json::Value::as_str),
        Some(NVIDIA_GPU_EVIDENCE_SUMMARY_V1)
    );
    assert_eq!(
        json.pointer("/summary/status")
            .and_then(serde_json::Value::as_str),
        Some("pass")
    );
}

#[test]
fn cli_summary_file_writes_redacted_summary_from_same_run() {
    let compact_report: String = GOOD_REPORT.lines().map(str::trim).collect();
    let summary_path = std::env::temp_dir().join(format!(
        "nvidia-attestation-runner-summary-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&summary_path);
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-json",
            "--nonce",
            TEST_NONCE,
            "--summary-file",
            summary_path.to_str().unwrap(),
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            &format!("printf '%s' '{compact_report}'"),
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let summary_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&summary_path).unwrap()).unwrap();
    let _ = std::fs::remove_file(summary_path);

    assert!(summary_json
        .pointer("/summary_sha256")
        .and_then(serde_json::Value::as_str)
        .is_some());
    assert_eq!(
        summary_json
            .pointer("/summary/schema_version")
            .and_then(serde_json::Value::as_str),
        Some(NVIDIA_GPU_EVIDENCE_SUMMARY_V1)
    );
}

#[test]
fn cli_prints_evidence_even_when_summary_file_cannot_be_written() {
    let compact_report: String = GOOD_REPORT.lines().map(str::trim).collect();
    let summary_path = std::env::temp_dir()
        .join(format!(
            "nvidia-attestation-runner-missing-dir-{}",
            std::process::id()
        ))
        .join("summary.json");
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-json",
            "--nonce",
            TEST_NONCE,
            "--summary-file",
            summary_path.to_str().unwrap(),
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            &format!("printf '%s' '{compact_report}'"),
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json.pointer("/policy/accepted")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(json.pointer("/bundle").is_some());
}

#[test]
fn cli_custom_transcript_emits_bundle_and_policy_verdict() {
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-transcript",
            "--nonce",
            "4501e578785ed75e29c3c327893ce4fbcb8f0c0e51f090dc79e5a26906450211",
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            "cat tests/fixtures/cc_admin_h100_success_excerpt.txt",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json.pointer("/policy/accepted")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        json.pointer("/bundle/backend")
            .and_then(serde_json::Value::as_str),
        Some("custom_transcript")
    );
    assert!(json
        .pointer("/bundle/evidence_hashes/cc_admin_stdout")
        .and_then(serde_json::Value::as_str)
        .is_some());
}

#[test]
fn cli_policy_rejection_exits_two_after_printing_json() {
    let output = Command::new(CLI)
        .args([
            "--backend",
            "custom-json",
            "--nonce",
            TEST_NONCE,
            "--program",
            "sh",
            "--arg",
            "-c",
            "--arg",
            "printf '%s' '{\"result_code\":12,\"result_message\":\"Overall Attestation Result is False\"}'",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        json.pointer("/policy/accepted")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
}

#[test]
fn nvattest_remote_helper_builds_expected_command_shape() {
    let command = NvAttestRunner::remote_gpu_with_nonce_hex("abcd").command_line();

    assert_eq!(command[0], "nvattest");
    assert!(command
        .windows(2)
        .any(|item| item == ["--verifier", "remote"]));
    assert!(command.windows(2).any(|item| item == ["--nonce", "abcd"]));
}

#[test]
fn cc_admin_h100_success_transcript_normalizes_and_passes_transcript_policy() {
    let report = report_from_cc_admin_transcript(
        include_str!("fixtures/cc_admin_h100_success_excerpt.txt"),
        "",
        Some(0),
    );

    assert_eq!(report.result_code(), Some(0));
    assert_eq!(report.result_message(), Some("Ok"));
    assert_eq!(
        report
            .claim("x-nvidia-gpu-driver-version")
            .and_then(serde_json::Value::as_str),
        Some("580.159.03")
    );
    assert_eq!(
        report
            .claim("x-nvidia-gpu-vbios-version")
            .and_then(serde_json::Value::as_str),
        Some("96.00.cf.00.01")
    );
    assert_eq!(
        report
            .raw()
            .pointer("/cc_admin/measurement_blocks/9")
            .and_then(serde_json::Value::as_str),
        Some("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
    );

    let verdict = Policy::nvidia_cc_admin_transcript_baseline()
        .expected_nonce_hex("4501e578785ed75e29c3c327893ce4fbcb8f0c0e51f090dc79e5a26906450211")
        .unwrap()
        .evaluate(&report);

    assert!(verdict.accepted, "{:?}", verdict.failures);
    assert!(report.evidence_hashes().contains_key("cc_admin_stdout"));
}

#[test]
fn cc_admin_transcript_policy_rejects_wrong_expected_nonce() {
    let report = report_from_cc_admin_transcript(
        include_str!("fixtures/cc_admin_h100_success_excerpt.txt"),
        "",
        Some(0),
    );

    let verdict = Policy::nvidia_cc_admin_transcript_baseline()
        .expected_nonce_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .unwrap()
        .evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nonce_missing_or_mismatch"));
}

#[test]
fn cc_admin_transcript_policy_rejects_nonzero_exit_even_with_success_text() {
    let report = report_from_cc_admin_transcript(
        include_str!("fixtures/cc_admin_h100_success_excerpt.txt"),
        "",
        Some(1),
    );
    let verdict = Policy::nvidia_cc_admin_transcript_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "nvidia_attestation_failed"));
}

#[test]
fn cc_admin_transcript_policy_rejects_missing_rim_signature_signal() {
    let transcript = include_str!("fixtures/cc_admin_h100_success_excerpt.txt")
        .replace("driver RIM signature verification successful.", "")
        .replace("Driver RIM verification successful", "");
    let report = report_from_cc_admin_transcript(&transcript, "", Some(0));
    let verdict = Policy::nvidia_cc_admin_transcript_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "driver_rim_signature_unverified"));
}

#[test]
fn cc_admin_transcript_policy_rejects_missing_ready_state() {
    let transcript = include_str!("fixtures/cc_admin_h100_success_excerpt.txt")
        .replace("GPU Ready State is already READY", "");
    let report = report_from_cc_admin_transcript(&transcript, "", Some(0));
    let verdict = Policy::nvidia_cc_admin_transcript_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "gpu_ready_state_missing"));
}

#[test]
fn cc_admin_transcript_policy_rejects_measurement_failure_text() {
    let transcript = include_str!("fixtures/cc_admin_h100_success_excerpt.txt")
        .replace(
            "The runtime measurements are matching with the golden measurements.",
            "",
        )
        .replace("GPU Attestation is Successful.", "GPU Attestation failed.");
    let report = report_from_cc_admin_transcript(&transcript, "", Some(1));
    let verdict = Policy::nvidia_cc_admin_transcript_baseline().evaluate(&report);

    assert!(!verdict.accepted);
    assert!(verdict
        .failures
        .iter()
        .any(|failure| failure.code == "measurements_not_successful"));
}

#[test]
fn cc_admin_runner_returns_transcript_report_from_nonzero_exit() {
    let report = CcAdminRunner::new("sh")
        .args(["-c", "printf '%s' 'GPU Attestation failed.'; exit 1"])
        .run()
        .unwrap();

    assert_eq!(report.result_code(), Some(1));
    assert!(
        !Policy::nvidia_cc_admin_transcript_baseline()
            .evaluate(&report)
            .accepted
    );
}

#[test]
fn cc_admin_bundle_preserves_transcript_backend_and_hashes() {
    let bundle = CcAdminRunner::new("sh")
        .args(["-c", "printf '%s' 'GPU Attestation failed.'; exit 1"])
        .run_bundle()
        .unwrap();

    assert_eq!(
        bundle.backend(),
        NvidiaAttestationBackend::CcAdminTranscript
    );
    assert_eq!(bundle.exit_code(), Some(1));
    assert!(bundle.evidence_hashes().contains_key("cc_admin_stdout"));
    assert_eq!(bundle.report().result_code(), Some(1));
}

#[test]
fn unified_runner_can_select_cc_admin_transcript_backend() {
    match NvidiaAttestationRunner::cc_admin_transcript_with_nonce_hex("abcd") {
        NvidiaAttestationRunner::CcAdminTranscript { runner } => {
            assert_eq!(runner.command_line()[0], "python3");
            assert!(runner
                .command_line()
                .contains(&"verifier.cc_admin".to_owned()));
        }
        other => panic!("unexpected runner: {other:?}"),
    }
}
