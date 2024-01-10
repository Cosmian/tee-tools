# TPM Quote

# Overview

## Prerequisite

Install [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)

```console
# Ubuntu
sudo apt-get install tpm2-tools libtss2-dev
# RedHat like
sudo dnf install tpm2-tools tpm2-tss-devel
```

then

```console
# create EK and make it persistent
sudo tpm2_createek --ek-context=/tmp/ek.ctx --key-algorithm=ecc --public=/tmp/ek.pub --format=pem
sudo tpm2_evictcontrol --hierarchy=o --object-context=/tmp/ek.ctx --output=/tmp/ek.handle
# create AK and make it persistent
sudo tpm2_createak --ek-context=/tmp/ek.handle --ak-context=/tmp/ak.ctx --key-algorithm=ecc --hash-algorithm=sha256 --public=/tmp/ak.pub --format pem --ak-name=/tmp/ak.name
sudo tpm2_evictcontrol --hierarchy=o --object-context=/tmp/ak.ctx --output=/tmp/ak.handle
```

check that it works

```console
# Generate PCR quote
sudo tpm2_quote \
    --key-context=/tmp/ak.ctx \
    --pcr-list=sha1:10+sha256:10 \
    --message=pcr_quote.plain \
    --signature=pcr_quote.sig \
    --hash-algorithm=sha256
# Verify PCR quote
sudo tpm2_checkquote \
    --public=/tmp/ak.pub \
    --message=pcr_quote.plain \
    --signature=pcr_quote.sig \
    --hash-algorithm=sha256
```

Set env variable depending on your TPM device

```console
export TCTI="device:​/dev/tpmrm0​"
```
