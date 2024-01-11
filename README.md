# TEE TOOLS

It contains severals libraries to handle:

- the Intel SGX quote: generation, parsing and verification
- the Intel TDX quote: generation, parsing and verification
- the AMD SEV quote: generation, parsing and verification
- a TPM quote: generation, parsing and verification
- RATLS certificate: generation and verification

## Compile and test

See [TPM README.md](crate/tpm_quote/README.md) for prerequisite installations.

Also, install `libssl-dev`.

Then:

```console
$ cargo build
$ cargo test -- --nocapture
```
