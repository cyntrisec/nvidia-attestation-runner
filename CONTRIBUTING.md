# Contributing

Keep changes small and evidence-oriented. This crate is security-adjacent, so
new behavior needs tests and explicit failure-mode coverage.

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
```

Guidelines:

- Do not replace NVIDIA verifier semantics with local guesses.
- Preserve raw verifier JSON when possible so callers can inspect the original
  evidence.
- Policy checks should fail closed when required fields are missing or malformed.
- Do not add real cloud account IDs, instance IDs, hostnames, serial numbers, or
  unredacted attestation artifacts to fixtures.
- Add both positive and negative tests for new policy behavior.
