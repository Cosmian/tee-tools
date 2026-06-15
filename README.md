# TEE Tools

Collection of Rust libraries for local and remote attestation of Intel SGX/TDX, AMD SEV-SNP and TPM.

## Crates

| Crate | Description |
|-------|-------------|
| [azure_cvm](crate/azure_cvm/) | Parsing of HCL report from vTPM on Microsoft Azure Confidential VM |
| [maa_client](crate/maa_client/) | High-level API for Microsoft Azure Attestation service |
| [pccs_client](crate/pccs_client/) | High-level API for Intel Provisioning Certification Cache Service |
| [ratls](crate/ratls/) | Remote Attestation integration with Transport Layer Security |
| [sev_quote](crate/sev_quote/) | Generation and verification of AMD SEV-SNP attestation report |
| [sgx_pck_extension](crate/sgx_pck_extension/) | Parsing of Intel SGX Provisioning Certification Key ASN.1 extension |
| [sgx_quote](crate/sgx_quote/) | Generation and verification of Intel SGX attestation report |
| [tdx_quote](crate/tdx_quote/) | Generation and verification of Intel TDX attestation report |
| [tee_attestation](crate/tee_attestation/) | High-level library to detect and attest Intel SGX, TDX or AMD SEV-SNP |
| [tls_cert](crate/tls_cert/) | Fetch TLS peer certificate without verification |
| [tpm_quote](crate/tpm_quote/) | Quote generation and verification of TPM 2.0 PCR registers |

## Compilation

See [.devcontainer/Dockerfile](.devcontainer/Dockerfile) for dependencies requirements.

```console
cargo build
```

## Tests

```console
# unit tests
cargo test --lib -- --nocapture
# integration tests running on machine configured with a TEE
cargo test --tests -- --nocapture
```
