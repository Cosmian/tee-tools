# TEE TOOLS

It contains severals libraries to handle the Intel SGX/TDX and AMD SEV quote: generation, parsing and verification. 

It also contains `ratls_certtool` to:
- Generate a RATLS certificate 
- Verify a RATLS certificate

## Compile

```console
$ cargo build
```

## Usage

```console
# Require an SGX enclave/SEV VM to run:
$ ratls_certtool generate --help

# On any hosts:
$ ratls_certtool verify --help
```