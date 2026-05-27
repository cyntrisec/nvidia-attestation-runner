# nvidia-attestation-runner

[![CI](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Unofficial Rust runner and policy layer for NVIDIA GPU attestation evidence.

> **Status:** early scaffold. A passing NVIDIA local-verifier transcript fixture
> is now captured for a GCP A3/H100 Confidential VM run on 2026-05-27, but this
> crate remains an unofficial wrapper. Treat it as an evidence-normalization and
> policy layer around NVIDIA tooling, not as a native NVIDIA verifier.

This crate is designed for two use cases:

- Applications that want to invoke NVIDIA attestation tooling from Rust and apply explicit verifier policy.
- Systems such as AIR/platform evidence bundles that need a stable hash of GPU attestation output to bind CPU, GPU, and application evidence together.

It is not an NVIDIA project and does not currently implement a native NVIDIA verifier. The first version deliberately wraps NVIDIA tooling output instead of reimplementing certificate, RIM, or token validation logic.
See [`SUPPORTED.md`](SUPPORTED.md) for the exact hardware/tooling matrix that has been exercised.

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
- `verifier.cc_admin --verbose` is normalized as a transcript. NVIDIA's tool remains the verifier; this crate records the transcript hash and exposes only the claims present in the text.
- `NvidiaEvidenceBundle` records the backend, command line, exit code, normalized report, and stable evidence hashes for AIR/platform-evidence binding.
- Hashes are for evidence binding. They do not by themselves prove that GPU evidence was appraised correctly.
- AIR v1/v2 integrations should bind this crate's GPU evidence hash into a separate canonical platform-evidence bundle unless and until the AIR receipt schema directly supports composite CPU/GPU evidence.

## Hardware validation

The crate has been exercised against NVIDIA `nvattest 1.2.0` on a Google Cloud `a3-highgpu-1g` Confidential VM with an H100 GPU in CC mode. The older fixture captures a real local-attestation failure (`result_code = 12`, `measres = "fail"`, firmware measurement index 9 mismatch) and the default JSON policy rejects it fail-closed.

On 2026-05-27, a fresh GCP A3/H100 Confidential VM run using NVIDIA's Python local verifier (`python3 -m verifier.cc_admin --verbose`) passed:

- GPU: NVIDIA H100 80GB HBM3
- Driver: `580.159.03`
- VBIOS: `96.00.CF.00.01`
- Result: `GPU Attestation is Successful.`
- Runtime measurements matched the golden measurements.
- Measurement block index 9 was all zeros in the passing transcript.

The passing fixture is intentionally a `cc_admin` transcript excerpt, not a replacement for NVIDIA's JSON/EAT output. The Python local verifier also emits a deprecation warning pointing users toward the C++ SDK before September 15, 2026, so long-term integrations should prefer `nvattest` / SDK JSON where available.

The repo does not yet contain a real passing `nvattest` / C++ SDK JSON fixture. Add one when the next hardware run captures it; do not use a synthetic fixture for production claim language.

## CLI

The crate also ships a small dependency-free CLI for hardware runs and integration scripts. It emits one JSON object containing:

- `bundle_sha256`
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

## Status

Early scaffold. The public API is expected to change before `1.0`.

## Security

Please report vulnerabilities privately. See [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))
