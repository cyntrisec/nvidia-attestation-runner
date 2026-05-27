# Fixtures

Fixtures are intentionally small and mostly redacted. They are for parser and policy regression tests, not for reproducing a full NVIDIA attestation appraisal.

| Fixture | Kind | Meaning |
|---|---|---|
| `h100_local_attestation_measres_fail.json` | Real, redacted `nvattest` JSON | GCP A3/H100 local attestation failure with `result_code = 12`, `measres = "fail"`, firmware measurement mismatch. The default JSON policy must reject it. |
| `h100_nvattest_local_success_redacted.json` | Real, redacted `nvattest` JSON | GCP A3/H100 local attestation success from 2026-05-27 with `result_code = 0`, `measres = "success"`, secure boot enabled, report signature verified, driver/VBIOS RIM signatures verified, and no mismatch records. The default JSON policy must accept it. |
| `h100_collect_evidence_ok_redacted.json` | Real, redacted `nvattest` JSON | Evidence collection succeeded, but this is not a verifier pass. Used only for hash-shape testing. |
| `cc_admin_h100_success_excerpt.txt` | Real transcript excerpt | GCP A3/H100 `cc_admin --verbose` pass from 2026-05-27. It is an excerpt that preserves the important success markers, driver/VBIOS versions, nonce, feature flag, ready state, and measurement block 9. |

Redaction policy: keep claim names, booleans, result codes, driver/VBIOS versions, nonce values used by tests, and RIM status fields. Replace device-unique identifiers and JWT bodies with `REDACTED_*` placeholders before committing.
