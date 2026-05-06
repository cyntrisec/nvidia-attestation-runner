# Security Policy

`nvidia-attestation-runner` is an early-stage wrapper and policy layer for
NVIDIA GPU attestation evidence. It is not an NVIDIA project and does not
implement a native NVIDIA verifier.

## Supported Versions

No production-stable versions are currently supported. The `main` branch is the
only supported development target.

## Reporting Vulnerabilities

Please do not open a public issue for security vulnerabilities.

Report vulnerabilities through GitHub Security Advisories for this repository,
or contact the maintainer privately through GitHub.

Include:

- affected commit or version;
- description of the issue;
- steps to reproduce or a minimal proof of concept;
- expected impact on evidence collection, evidence parsing, policy evaluation,
  or evidence-hash binding.

## Design Boundary

This repository only parses and policy-checks output from NVIDIA attestation
tooling. Hashes produced by this crate are useful for evidence binding, but do
not by themselves prove that NVIDIA GPU evidence was appraised correctly.
