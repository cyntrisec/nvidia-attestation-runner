# nvidia-attestation-runner

[![CI](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml/badge.svg)](https://github.com/cyntrisec/nvidia-attestation-runner/actions/workflows/ci.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

Unofficial Rust runner and policy layer for NVIDIA GPU attestation evidence.

> **Status:** early scaffold. Do not use this crate as the sole basis for
> production GPU trust decisions until a passing NVIDIA verifier fixture is
> captured and the policy surface is reviewed against NVIDIA-supported NVAT
> behavior.

This crate is designed for two use cases:

- Applications that want to invoke NVIDIA attestation tooling from Rust and apply explicit verifier policy.
- Systems such as AIR/platform evidence bundles that need a stable hash of GPU attestation output to bind CPU, GPU, and application evidence together.

It is not an NVIDIA project and does not currently implement a native NVIDIA verifier. The first version deliberately wraps NVIDIA tooling output instead of reimplementing certificate, RIM, or token validation logic.

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

## Design Boundaries

- The crate keeps NVIDIA verifier JSON intact and exposes tolerant accessors for common claim shapes.
- The policy layer is fail-closed: required claims must be present and successful.
- `nvattest` can exit non-zero while still emitting JSON failure details; the runner returns that parsed JSON so callers can make an explicit policy decision.
- Hashes are for evidence binding. They do not by themselves prove that GPU evidence was appraised correctly.
- AIR v1/v2 integrations should bind this crate's GPU evidence hash into a separate canonical platform-evidence bundle unless and until the AIR receipt schema directly supports composite CPU/GPU evidence.

## Hardware validation

The crate has been exercised against NVIDIA `nvattest 1.2.0` on a Google Cloud `a3-highgpu-1g` Confidential VM with an H100 GPU in CC mode. Evidence collection succeeded, but local attestation returned `result_code = 12`, `measres = "fail"`, and one firmware measurement mismatch. That real output is included as a redacted fixture so the default policy rejects it fail-closed.

Do not treat this crate as release-ready for production GPU trust decisions until a green NVIDIA local attestation run is captured and added as a passing fixture.

## Status

Early scaffold. The public API is expected to change before `1.0`.

## Security

Please report vulnerabilities privately. See [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of:

- Apache License, Version 2.0 ([`LICENSE-APACHE`](LICENSE-APACHE))
- MIT license ([`LICENSE-MIT`](LICENSE-MIT))
