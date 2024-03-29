use p256::ecdsa::VerifyingKey;

use sha2::{Digest, Sha256};
use spki::DecodePublicKey;
use std::str::FromStr;
use tee_attestation::{verify_quote, TeePolicy};

use crate::{
    error::Error,
    extension::{
        AMD_SEV_RATLS_EXTENSION_OID, INTEL_SGX_RATLS_EXTENSION_OID, INTEL_TDX_RATLS_EXTENSION_OID,
    },
};
use x509_parser::{
    oid_registry::Oid,
    prelude::{parse_x509_pem, X509Certificate},
};

/// Build the report data from ratls public key and some extra data
///
/// The first 32 bytes are the sha256 of the ratls public key
/// The last 32 bytes are the extra data if some
pub fn forge_report_data(
    ratls_public_key: &ecdsa::VerifyingKey<p256::NistP256>,
    extra_data: Option<[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    let mut hasher = Sha256::new();

    // Hash the public key of the certificate
    hasher.update(&ratls_public_key.to_sec1_bytes());

    let mut user_report_data = hasher.finalize()[..].to_vec();

    // Concat additional data if any
    user_report_data.extend(extra_data.unwrap_or([0u8; 32]));

    Ok(user_report_data)
}

/// Verify the RATLS certificate.
///
/// The verification includes:
/// - The MRenclave
/// - The MRsigner
/// - The report data content
/// - The quote collaterals
pub fn verify_ratls(pem_ratls_cert: &[u8], policy: Option<&mut TeePolicy>) -> Result<(), Error> {
    let (rem, pem) = parse_x509_pem(pem_ratls_cert)?;

    if !rem.is_empty() || &pem.label != "CERTIFICATE" {
        return Err(Error::InvalidFormat(
            "Not a certificate or certificate is malformed".to_owned(),
        ));
    }

    let ratls_cert = pem
        .parse_x509()
        .map_err(|e| Error::X509ParserError(e.into()))?;
    let pk = VerifyingKey::from_public_key_der(ratls_cert.public_key().raw)?;

    // Get the quote from the certificate
    let raw_quote = extract_quote(&ratls_cert)?;

    let policy = if let Some(policy) = policy {
        let expected_report_data = forge_report_data(&pk, None)?;
        policy.set_report_data(&expected_report_data)?;
        Some(policy)
    } else {
        None
    };

    Ok(verify_quote(&raw_quote, policy.as_deref())?)
}

/// Extract the quote from an RATLS certificate
fn extract_quote(ratls_cert: &X509Certificate) -> Result<Vec<u8>, Error> {
    let intel_sgx_ext_oid =
        Oid::from_str(INTEL_SGX_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;
    let intel_tdx_ext_oid =
        Oid::from_str(INTEL_TDX_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;
    let amd_sev_ext_oid =
        Oid::from_str(AMD_SEV_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;

    // Try to extract SGX quote
    if let Some(quote) = ratls_cert.get_extension_unique(&intel_sgx_ext_oid)? {
        return Ok(quote.value.to_vec());
    }

    // Try to extract TDX quote
    if let Some(quote) = ratls_cert.get_extension_unique(&intel_tdx_ext_oid)? {
        return Ok(quote.value.to_vec());
    }

    // Try to extract SEV quote
    if let Some(quote) = ratls_cert.get_extension_unique(&amd_sev_ext_oid)? {
        return Ok(quote.value.to_vec());
    }

    // Not a RATLS certificate
    Err(Error::InvalidFormat(
        "This is not an RATLS certificate".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tee_attestation::{
        SevQuoteVerificationPolicy, SgxQuoteVerificationPolicy, TdxQuoteVerificationPolicy,
    };

    #[test]
    fn test_ratls_sgx_verify_ratls() {
        let cert = include_bytes!("../data/sgx-cert.ratls.pem");

        let mrenclave =
            hex::decode(b"72009e6e7ddebcb7a8cf6b000b40aa20fd15d2c4fd524e85e80df6e8e0841d10")
                .unwrap();
        let mrenclave = mrenclave.as_slice().try_into().unwrap();
        let public_signer_key = include_str!("../data/signer-key.pem");

        verify_ratls(
            cert,
            Some(&mut TeePolicy::Sgx(
                SgxQuoteVerificationPolicy::new(mrenclave, public_signer_key).unwrap(),
            )),
        )
        .unwrap();
    }

    #[test]
    fn test_ratls_sev_verify_ratls() {
        let cert = include_bytes!("../data/sev-cert.ratls.pem");

        let measurement =
            hex::decode(b"c2c84b9364fc9f0f54b04534768c860c6e0e386ad98b96e8b98eca46ac8971d05c531ba48373f054c880cfd1f4a0a84e")
                .unwrap().try_into().unwrap();

        verify_ratls(
            cert,
            Some(&mut TeePolicy::Sev(SevQuoteVerificationPolicy::new(
                measurement,
            ))),
        )
        .unwrap();
    }

    #[test]
    fn test_ratls_tdx_verify_ratls() {
        let cert = include_bytes!("../data/tdx-cert.ratls.pem");

        verify_ratls(
            cert,
            Some(&mut TeePolicy::Tdx(TdxQuoteVerificationPolicy::new())),
        )
        .unwrap();
    }
}
