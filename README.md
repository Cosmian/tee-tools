# SGX DCAP RATLS 

TODO: rename the project

It contains severals libraries to handle the SGX quote, the quote verification and the ratls certificate.

It also contains `ratls_certtool` to:
- Generate a RATLS certificate 
- Verify a RATLS certificate

## Compile

```console
$ cargo build
```

## Usage
```console
# Require an SGX enclave to run:
$ ratls_certtool generate --help
# On any hosts:
$ ratls_certtool verify --help
```