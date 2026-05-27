# NVIDIA Attestation Runner Support Matrix

This matrix records what has actually been exercised. It is not a vendor support statement.

| Platform | Tool path | Status | Evidence |
|---|---|---:|---|
| GCP A3 H100 Confidential VM, Intel TDX, driver `580.159.03`, VBIOS `96.00.CF.00.01` | `python3 -m verifier.cc_admin --verbose` | PASS | 2026-05-27 transcript excerpt fixture. NVIDIA tool reported `GPU Attestation is Successful.`, RIM signatures verified, runtime measurements matched, GPU ready state `READY`, feature flag `SPT`. |
| GCP A3 H100 Confidential VM, Intel TDX, driver `580.126.09`, VBIOS `96.00.CF.00.01` | `nvattest --format json ... --verifier local` | FAIL | Redacted JSON fixture. NVIDIA tool returned `result_code = 12`, `measres = "fail"`, firmware measurement index 9 mismatch. |
| GCP A3 H100 Confidential VM, Intel TDX, driver `590.48.01`, VBIOS `96.00.CF.00.01` | `nvattest --format json ...` | FAIL, not committed as fixture | Local artifacts showed same index-9 mismatch class. Not included in this crate to avoid expanding fixture scope before a public green JSON fixture exists. |
| GCP Confidential Space with H100 | `cc_admin` inside workload container | NOT VALIDATED | Launcher/container constraints blocked a comparable verifier transcript during the 2026-05-27 retest. Do not infer support from `nvidia_gpu.cc_mode=ON` alone. |
| GCP G4 RTX PRO 6000 Confidential VM | Any NVIDIA verifier path | NOT VALIDATED | Quota / allowlist blocked launch at the time of this matrix. |

## Claim Rules

- A `cc_admin` transcript pass means NVIDIA's Python local verifier reported success for that tested stack. It does not make this crate a native NVIDIA verifier.
- A `nvattest` JSON pass should be preferred when available because the Python local verifier emits a deprecation warning and points users toward the C++ SDK.
- `nvidia-smi` CC status alone is not enough for this crate's policy.
- Confidential Space token fields such as GPU `cc_mode=ON` are not a substitute for NVIDIA GPU-device appraisal.
- Model identity is out of scope for this crate. Bind model identity separately in the application/AIR evidence layer.
