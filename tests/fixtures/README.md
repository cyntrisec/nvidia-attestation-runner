# Fixtures

Fixtures are intentionally small and mostly redacted. They are for parser and policy regression tests, not for reproducing a full NVIDIA attestation appraisal.

| Fixture | Kind | Meaning |
|---|---|---|
| `h100_local_attestation_measres_fail.json` | Real, redacted `nvattest` JSON | GCP A3/H100 local attestation failure with `result_code = 12`, `measres = "fail"`, firmware measurement mismatch. The default JSON policy must reject it. |
| `h100_nvattest_local_success_redacted.json` | Real, redacted `nvattest` JSON | GCP A3/H100 local attestation success from 2026-05-27 with `result_code = 0`, `measres = "success"`, secure boot enabled, report signature verified, driver/VBIOS RIM signatures verified, and no mismatch records. The default JSON policy must accept it. |
| `h100_collect_evidence_ok_redacted.json` | Real, redacted `nvattest` JSON | Evidence collection succeeded, but this is not a verifier pass. Used only for hash-shape testing. |
| `h100_drv580_nvattest2_local_success_redacted.json` | Real, redacted `nvattest` 2.0.0 JSON | GCP A3/H100 local attestation success from 2026-11-23, driver `580.178.04`, VBIOS `96.00.DB.00.02`, claims version `4.0`. The default JSON policy must accept it. |
| `h100_drv580_nvattest2_remote_success_redacted.json` | Real, redacted `nvattest` 2.0.0 JSON | The same host and nonce through NVIDIA's remote verifier. The default JSON policy must accept it. |
| `h100_drv620_nvattest2_local_success_redacted.json` | Real, redacted `nvattest` 2.0.0 JSON | Local attestation success from 2026-11-23 with driver `620.70.06`, which emits the versioned opaque data format. The driver was built through DKMS with a one-line source change and ran with UEFI Secure Boot off; see `SUPPORTED.md`. The default JSON policy must accept it. |
| `h100_drv595_nvattest2_local_rim_not_found.json` | Real `nvattest` 2.0.0 JSON, nothing to redact | Driver `595.99.02`, for which NVIDIA's RIM service has no reference: `result_code = 104`, "RIM Not Found", empty `claims` and `detached_eat`. The default JSON policy must reject it and report `gpu_evidence_missing`. |
| `h100_drv620_nvattest1_local_evidence_invalid.json` | Real `nvattest` 1.2.2 JSON, nothing to redact | The older tool on the versioned opaque data format: `result_code = 503`, "GPU Evidence Invalid", empty `claims` and `detached_eat`. The default JSON policy must reject it. |
| `cc_admin_h100_success_excerpt.txt` | Real transcript excerpt | GCP A3/H100 `cc_admin --verbose` pass from 2026-05-27. It is an excerpt that preserves the important success markers, driver/VBIOS versions, nonce, feature flag, ready state, and measurement block 9. |

Redaction policy: keep claim names, booleans, result codes, driver/VBIOS versions, nonce values used by tests, and RIM status fields. Replace device-unique identifiers and JWT bodies with `REDACTED_*` placeholders before committing. The `ueid` claim identifies the attesting device and is replaced in every fixture.
