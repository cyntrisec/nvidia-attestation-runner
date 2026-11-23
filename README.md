# nvidia-attestation-runner

[![CI](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Unofficial Rust runner and policy layer for NVIDIA GPU attestation evidence.

> **Status:** early scaffold, exercised on real hardware. On 2026-11-23 it ran
> with `nvattest` 1.2.2 and 2.0.0 on a GCP A3/H100 Confidential VM, through both
> the local and the remote verifier. It remains an unofficial wrapper: an
> evidence-normalization and policy layer around NVIDIA tooling, not a native
> NVIDIA verifier.

This crate is designed for two use cases:

- Applications that want to invoke NVIDIA attestation tooling from Rust and apply explicit verifier policy.
- Systems such as AIR/platform evidence bundles that need a stable hash of GPU attestation output to bind CPU, GPU, and application evidence together.

It is not an NVIDIA project and does not currently implement a native NVIDIA verifier. The first version deliberately wraps NVIDIA tooling output instead of reimplementing certificate, RIM, or token validation logic.
See [`SUPPORTED.md`](SUPPORTED.md) for the exact hardware/tooling matrix that has been exercised.

NVIDIA publishes its own attestation SDK with a C API, the `nvattest` CLI, and Rust bindings: <https://github.com/NVIDIA/attestation-sdk>. Use that when you need an in-process verifier. This crate shells out to the `nvattest` CLI and adds two things on top: a fail-closed policy over the verifier's answer, and stable hashes plus a redacted summary for binding GPU evidence into other evidence.

**Use `nvattest` 2.0.0 or later.** NVIDIA states that drivers released with CUDA 13.5 and later emit a versioned opaque data format that older verifiers cannot process ([format description](https://docs.nvidia.com/attestation/specs/latest/opaque-data-format.html)). On an H100 with driver `620.70.06`, `nvattest` 1.2.2 failed with "GPU Evidence Invalid" and 2.0.0 passed.

## Example

```rust
use nvidia_attestation_runner::{NvAttestRunner, Policy};

let report = NvAttestRunner::local_gpu_with_nonce_hex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
)
    .run()?;

let verdict = Policy::nvidia_cc_baseline()
    .expected_nonce_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")?
    .evaluate(&report);

assert!(verdict.accepted, "{:?}", verdict.failures);

let hashes = report.evidence_hashes();
println!("raw GPU evidence hash: {}", hashes["raw_json"]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

For the NVIDIA Python local verifier transcript path:

```rust
use nvidia_attestation_runner::{CcAdminRunner, Policy};

let nonce = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
let report = CcAdminRunner::python_module_with_nonce_hex(nonce).run()?;
let verdict = Policy::nvidia_cc_admin_transcript_baseline()
    .expected_nonce_hex(nonce)?
    .evaluate(&report);

assert!(verdict.accepted, "{:?}", verdict.failures);
println!("cc_admin transcript hash: {}", report.evidence_hashes()["cc_admin_stdout"]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

For one API that can choose a backend explicitly:

```rust
use nvidia_attestation_runner::{NvidiaAttestationRunner, Policy};

let nonce = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
let bundle = NvidiaAttestationRunner::remote_gpu_json_with_nonce_hex(nonce).run_bundle()?;
let verdict = Policy::nvidia_cc_baseline()
    .expected_nonce_hex(nonce)?
    .evaluate(bundle.report());

println!("backend: {:?}", bundle.backend());
println!("bundle hash: {}", bundle.canonical_json_sha256_hex()?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Design Boundaries

- The crate keeps NVIDIA verifier JSON intact and exposes tolerant accessors for common claim shapes.
- The policy layer is fail-closed: required claims must be present and successful.
- `nvattest` can exit non-zero while still emitting JSON failure details; the runner returns that parsed JSON so callers can make an explicit policy decision.
- When attestation fails before any claim is produced, `nvattest` returns empty `claims` and `detached_eat` objects. The policy reports `gpu_evidence_missing` unless the answer holds GPU claims or non-empty `detached_eat` / `gpus` content. This is a presence check; it does not validate the tokens it finds.
- `nvattest` emits one claim set per attested device, and the accessors here read the first matching claim only. An answer with claim sets for more than one device is rejected with `multiple_device_claim_sets_unsupported`. Multi-GPU hosts are not supported yet.
- A nonce mismatch reported by the verifier is final, even when the output echoes the expected nonce.
- Several requirements accept more than one historical claim name. For the measurement result and the debug status, any name that reports the good state satisfies the requirement. An answer that repeats a claim under two names with different values is not treated as contradictory.
- The local verifier's detached EAT is unsigned (`alg: none`); only the remote verifier returns a signed token. This crate hashes the token and does not verify its signature. `nvattest verify-token` (2.0.0) verifies tokens issued by NVIDIA's remote service and can check the nonce.
- `verifier.cc_admin --verbose` is normalized as a transcript. NVIDIA's tool remains the verifier; this crate records the transcript hash and exposes only the claims present in the text. The normalizer creates the GPU claim names itself, so `gpu_evidence_missing` cannot fire on this path; the other checks carry the decision.
- `NvidiaEvidenceBundle` records the backend, command line, exit code, normalized report, and stable evidence hashes for AIR/platform-evidence binding.
- Hashes are for evidence binding. They do not by themselves prove that GPU evidence was appraised correctly.
- AIR v1/v2 integrations should bind this crate's GPU evidence hash into a separate canonical platform-evidence bundle unless and until the AIR receipt schema directly supports composite CPU/GPU evidence.

## Hardware validation

All runs so far are on Google Cloud `a3-highgpu-1g` Confidential VMs (Intel TDX) with one NVIDIA H100 80GB HBM3 in CC mode. The full matrix is in [`SUPPORTED.md`](SUPPORTED.md), and every row marked with a fixture has a real, redacted answer under `tests/fixtures/`.

Run of 2026-11-23, VBIOS `96.00.DB.00.02`:

- Drivers `580.178.04` and `615.71.09` (Ubuntu-signed modules, UEFI Secure Boot on): `nvattest` 1.2.2 and 2.0.0 both pass through the local and the remote verifier. The default JSON policy accepts; for `615.71.09` it was run on the 2.0.0 answers only.
- Driver `595.99.02` (Ubuntu-signed, UEFI Secure Boot on): NVIDIA's RIM service has no reference for this version. The local verifier returns `result_code = 104` ("RIM Not Found"), the remote one `result_code = 2` ("Internal Error"). The policy rejects.
- Driver `620.70.06` emits the versioned opaque data format. `nvattest` 1.2.2 cannot parse it (`result_code = 503`, "GPU Evidence Invalid"); `nvattest` 2.0.0 passes through the local and the remote verifier. The policy follows the tool in both cases.

The `620.70.06` run is a format check, not a reference configuration: the driver came from NVIDIA's apt repository through DKMS, needed a one-line source change to compile against kernel `7.0.0-1017-gcp`, and ran with UEFI Secure Boot off.

Earlier runs, VBIOS `96.00.CF.00.01`:

- 2026-05-27, driver `580.159.03`: `nvattest` local JSON pass, and a pass of NVIDIA's Python local verifier (`python3 -m verifier.cc_admin --verbose`), kept as a transcript excerpt.
- April 2026, drivers `580.126.09` and `590.48.01`: local attestation failed with `result_code = 12`, `measres = "fail"`, firmware measurement index 9 mismatch. The default JSON policy rejects it fail-closed.

NVIDIA has deprecated the Python SDK and the Local GPU Verifier in favour of the C++ SDK and its CLI ([notice](https://github.com/NVIDIA/nvtrust)). The `cc_admin` transcript backend is kept for existing transcripts; new integrations should use the `nvattest` JSON backends.

Not validated: Confidential Space, RTX PRO 6000, AMD SEV-SNP hosts, and any cloud other than Google Cloud. Multi-GPU hosts are rejected by the policy. Do not use a synthetic fixture for production claim language.

## CLI

The crate also ships a small dependency-free CLI for hardware runs and integration scripts. It emits one JSON object containing:

- `bundle_sha256`
- `summary_sha256`
- `summary`
- `policy`
- `bundle.backend`
- `bundle.command`
- `bundle.exit_code`
- `bundle.report`
- `bundle.evidence_hashes`

Examples:

```bash
nvidia-attestation-runner \
  --backend nvattest-local-json \
  --nonce 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --pretty
```

```bash
nvidia-attestation-runner \
  --backend cc-admin-transcript \
  --nonce 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --pretty
```

For test harnesses or custom tool paths:

```bash
nvidia-attestation-runner \
  --backend custom-json \
  --nonce 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --program /path/to/tool \
  --arg --format \
  --arg json
```

Policy rejection exits with status `2` after printing the JSON body. Use `--allow-policy-failure` when collecting failing fixtures intentionally.

For AIR/platform-evidence or SIEM integrations, prefer the redacted summary
contract instead of ingesting the raw bundle:

```bash
nvidia-attestation-runner \
  --backend nvattest-local-json \
  --nonce 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --summary-only \
  --pretty
```

The summary schema is `cyntrisec.nvidia.gpu_evidence_summary.v1`. It contains
policy status, stable evidence hashes, and a fixed set of GPU posture fields
copied from the verifier output: model, mode, measurement result, secure boot,
debug status, driver and VBIOS versions. A copied string is kept only when it
is a single printable ASCII line of at most 64 characters. The summary has no
field for raw NVIDIA verifier JSON, detached EAT/JWT values, command lines,
GPU UUIDs, or transcripts.

`summary_sha256` is the SHA-256 of the `summary` object in compact form with
its keys in the order written. To recompute it from a written summary:

```bash
jq -cj .summary nvattest-local.summary.json | sha256sum
```

With `--summary-file`, the summary is written after the JSON body has been
printed, so a failed write exits with status `1` without discarding the
evidence on stdout.

## Capturing hardware evidence

For a VM that already has the NVIDIA driver, GPU CC mode, and `nvattest`
installed, use the capture helper:

```bash
scripts/capture_nvattest_json.sh --backend local
```

It writes an ignored `artifacts/nvattest-*/` directory with the nonce, host/GPU
metadata, wrapper JSON bundle, redacted summary JSON, stderr, exit status, and
SHA-256 manifest. Use `--backend both` to capture local and remote verifier paths, and use
`--allow-policy-failure` only when intentionally preserving a failing fixture.
With that flag the runner exits `0` even when the policy rejects, so read the
verdict from `policy.accepted` in the bundle or `status` in the summary.

Review and redact raw output before committing any fixture. The bundle preserves
the NVIDIA verifier JSON under `bundle.report.raw` and may contain GPU UUIDs,
driver/VBIOS versions, host-specific metadata, or cloud-environment identifiers.
The `.summary.json` files are the intended redacted handoff artifact for
EphemeralML platform-evidence binding.

## Status

Early scaffold. The public API is expected to change before `1.0`.

## Security

Please report vulnerabilities privately. See [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))
