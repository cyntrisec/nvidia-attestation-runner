use nvidia_attestation_runner::{
    report_from_cc_admin_transcript, AttestationReport, CcAdminRunner, NvAttestRunner,
    NvidiaAttestationBackend, NvidiaAttestationRunner, Policy,
};
use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_nvidia-attestation-runner");
const TEST_NONCE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

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
