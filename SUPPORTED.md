# NVIDIA Attestation Runner Support Matrix

This matrix records what has actually been exercised. It is not a vendor support statement.

All rows are Google Cloud `a3-highgpu-1g` Confidential VMs (Intel TDX) with one NVIDIA H100 80GB HBM3 in CC mode, unless the row says otherwise.

## Run of 2026-11-23, VBIOS `96.00.DB.00.02`, kernel `7.0.0-1017-gcp`

| Driver | Tool path | Status | Evidence |
|---|---|---:|---|
| `580.178.04`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 2.0.0, `--verifier local` | PASS | Fixture `h100_drv580_nvattest2_local_success_redacted.json`. `result_code = 0`, `measres = "success"`, claims version `4.0`. Default JSON policy accepts. |
| `580.178.04`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 2.0.0, `--verifier remote` | PASS | Fixture `h100_drv580_nvattest2_remote_success_redacted.json`. First run of the remote path through this crate. Default JSON policy accepts. |
| `580.178.04`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 1.2.2, local and remote | PASS | Not committed as fixture. Same claim names as the 2026-05-27 fixture, claims version `3.0`. Default JSON policy accepts. |
| `615.71.09`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 1.2.2 and 2.0.0, local and remote | PASS | Not committed as fixture. Default JSON policy accepts the 2.0.0 answers. |
| `595.99.02`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 2.0.0, `--verifier local` | FAIL | Fixture `h100_drv595_nvattest2_local_rim_not_found.json`. NVIDIA's RIM service has no reference for this driver version: `result_code = 104`, "RIM Not Found", empty `claims` and `detached_eat`. Default JSON policy rejects. `nvattest` 1.2.2 fails the same way. |
| `595.99.02`, Ubuntu-signed, UEFI Secure Boot on | `nvattest` 1.2.2 and 2.0.0, `--verifier remote` | FAIL | Not committed as fixture. `result_code = 2`, "Internal Error"; the reason appears only in the tool's log. Default JSON policy rejects. |
| `620.70.06`, versioned opaque data format (see note) | `nvattest` 2.0.0, `--verifier local` | PASS | Fixture `h100_drv620_nvattest2_local_success_redacted.json`. The remote verifier passes too. Default JSON policy accepts. |
| `620.70.06`, versioned opaque data format (see note) | `nvattest` 1.2.2, `--verifier local` | FAIL | Fixture `h100_drv620_nvattest1_local_evidence_invalid.json`. `result_code = 503`, "GPU Evidence Invalid". The remote verifier returns `result_code = 2`, "Internal Error". Default JSON policy rejects. |

Note on `620.70.06`: the driver came from NVIDIA's apt repository through DKMS, needed a one-line source change to compile against kernel `7.0.0-1017-gcp`, and ran with UEFI Secure Boot off, on a second physical card. It shows how the two tool versions handle the new evidence format. It is not a reference configuration.

## Earlier runs, VBIOS `96.00.CF.00.01`

| Driver | Tool path | Status | Evidence |
|---|---|---:|---|
| `580.159.03` | `nvattest --format json ... --verifier local` | PASS | 2026-05-27 fixture `h100_nvattest_local_success_redacted.json`. `result_code = 0`, `measres = "success"`. Default JSON policy accepts. |
| `580.159.03` | `python3 -m verifier.cc_admin --verbose` | PASS | 2026-05-27 transcript excerpt fixture. NVIDIA tool reported `GPU Attestation is Successful.`, RIM signatures verified, runtime measurements matched, GPU ready state `READY`, feature flag `SPT`. |
| `580.126.09` | `nvattest --format json ... --verifier local` | FAIL | Redacted JSON fixture `h100_local_attestation_measres_fail.json`. NVIDIA tool returned `result_code = 12`, `measres = "fail"`, firmware measurement index 9 mismatch. |
| `590.48.01` | `nvattest --format json ...` | FAIL, not committed as fixture | Local artifacts showed the same index-9 mismatch class. |

## Not validated

| Platform | Tool path | Status | Evidence |
|---|---|---:|---|
| GCP Confidential Space with H100 | `cc_admin` inside workload container | NOT VALIDATED | Launcher/container constraints blocked a comparable verifier transcript during the 2026-05-27 retest. Do not infer support from `nvidia_gpu.cc_mode=ON` alone. |
| GCP G4 RTX PRO 6000 Confidential VM | Any NVIDIA verifier path | NOT VALIDATED | Quota / allowlist blocked launch at the time of this matrix. |
| AMD SEV-SNP hosts, other clouds | Any NVIDIA verifier path | NOT VALIDATED | Never run with this crate. |
| Multi-GPU hosts | Any NVIDIA verifier path | NOT SUPPORTED | `nvattest` emits one claim set per device; this crate reads one. The policy rejects such answers with `multiple_device_claim_sets_unsupported`. Never run on hardware. |
| `nvattest collect-evidence-v2` / `attest-v2` (experimental in 2.0.0) | CoRIM verifier | NOT SUPPORTED BY THIS CRATE | On the H100 the experimental verifier answered `contraindicated`, "no RIM reference values to appraise against". This crate does not call these commands. |

## Claim Rules

- Use `nvattest` 2.0.0 or later. NVIDIA states that drivers released with CUDA 13.5 and later emit a versioned opaque data format that older verifiers cannot process.
- A driver that the distribution ships is not necessarily a driver NVIDIA has published reference measurements for. Check that a RIM exists for the exact driver version before relying on a host.
- A pass through the local verifier yields an unsigned detached EAT (`alg: none`). Only the remote verifier returns a signed token. This crate hashes the token; it does not verify its signature.
- A `cc_admin` transcript pass means NVIDIA's Python local verifier reported success for that tested stack. It does not make this crate a native NVIDIA verifier. NVIDIA has deprecated that verifier; prefer the `nvattest` JSON backends.
- `nvidia-smi` CC status alone is not enough for this crate's policy.
- Confidential Space token fields such as GPU `cc_mode=ON` are not a substitute for NVIDIA GPU-device appraisal.
- Model identity is out of scope for this crate. Bind model identity separately in the application/AIR evidence layer.
