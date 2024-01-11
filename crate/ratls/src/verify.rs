use p256::ecdsa::VerifyingKey;

use rustls::{
    client::ServerCertVerified,
    client::{ServerCertVerifier, ServerName},
    Certificate, Error as RustTLSError,
};
use sha2::{Digest, Sha256};
use spki::DecodePublicKey;
use std::io::Write;
use std::{str::FromStr, time::SystemTime};
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

pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _: &Certificate,                    // end_entity
        _: &[Certificate],                  // intermediates
        _: &ServerName,                     // server_name
        _: &mut dyn Iterator<Item = &[u8]>, // scts
        _: &[u8],                           // ocsp_response
        _: SystemTime,                      // now
    ) -> Result<ServerCertVerified, RustTLSError> {
        Ok(ServerCertVerified::assertion())
    }
}

/// Get the RATLS certificate from a `host`:`port`
pub fn get_server_certificate(host: &str, port: u32) -> Result<Vec<u8>, Error> {
    let root_store = rustls::RootCertStore::empty();
    let mut socket = std::net::TcpStream::connect(format!("{host}:{port}"))
        .map_err(|_| Error::ConnectionError)?;

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(NoVerifier));

    let rc_config = std::sync::Arc::new(config);
    let dns_name = host.try_into().map_err(|_| Error::DNSNameError)?;

    let mut client =
        rustls::ClientConnection::new(rc_config, dns_name).map_err(|_| Error::ConnectionError)?;

    let mut stream = rustls::Stream::new(&mut client, &mut socket);
    stream.write_all(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n")?;

    let certificates = client
        .peer_certificates()
        .ok_or(Error::ServerCertificateError)?;

    Ok(certificates
        .first()
        .ok_or(Error::ServerCertificateError)?
        .as_ref()
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use tee_attestation::{
        SevQuoteVerificationPolicy, SgxQuoteVerificationPolicy, TdxQuoteVerificationPolicy,
    };

    #[test]
    fn test_ratls_get_server_certificate() {
        let server_cert = get_server_certificate("self-signed.badssl.com", 443).unwrap();

        let b64_server_cert = r#"
        MIIDeTCCAmGgAwIBAgIJAMrlEvmXqB1TMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
        BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
        c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0y
        MzExMjkyMjM0MDRaFw0yNTExMjgyMjM0MDRaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
        VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK
        DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB
        BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2
        PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW
        hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A
        xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve
        ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY
        QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T
        BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI
        hvcNAQELBQADggEBAJYrbHPC6Yor7oi3aimJAPnnTh9Z7sQyaGfZ4I1ZIayWGIF7
        +9dq/VtCYxEeq7bZELvqcK6LMtQQ7xGoJ5yCgJWjO/SbLaSy1AEa5m9im3Gg2k4w
        h1AE8Z3CQUEdazVTsLKxdCp+eN62jQAzTY8xQ6yKDaWmTUhvSgErJyBv/H+vTQ+9
        L5ghqMrDUZTkxgwlXs3OyJi/S/Rfv9OGiEua/T+h3yHEzOL53d+IiagOUCjUg7mP
        5g4MP8zks3VcxERVjtzOahBH7fvhsMuJ/i+lSiNMMVaOr/U9Y1Y9kq96YIPax6Re
        Jok9KYiYJsWbiimaCxWFT/HbLvD+qri7lD2Gm8A=
        "#
        .replace(['\n', ' '], "");
        let expected_server_cert = general_purpose::STANDARD.decode(b64_server_cert).unwrap();
        assert_eq!(expected_server_cert, server_cert);
        assert!(x509_parser::parse_x509_certificate(&server_cert).is_ok());
    }

    #[test]
    fn test_ratls_sgx_verify_ratls() {
        let cert = include_bytes!("../data/sgx-cert.ratls.pem");

        let mrenclave =
            hex::decode(b"72009e6e7ddebcb7a8cf6b000b40aa20fd15d2c4fd524e85e80df6e8e0841d10")
                .unwrap();
        let mrenclave = mrenclave.as_slice().try_into().unwrap();
        let public_signer_key = include_str!("../data/signer-key.pem");

        assert!(verify_ratls(
            cert,
            Some(&mut TeePolicy::Sgx(
                SgxQuoteVerificationPolicy::new(mrenclave, public_signer_key).unwrap()
            ))
        )
        .is_ok());
    }

    #[test]
    fn test_ratls_sev_verify_ratls() {
        let cert = include_bytes!("../data/sev-cert.ratls.pem");

        let measurement =
            hex::decode(b"c2c84b9364fc9f0f54b04534768c860c6e0e386ad98b96e8b98eca46ac8971d05c531ba48373f054c880cfd1f4a0a84e")
                .unwrap().try_into().unwrap();

        assert!(verify_ratls(
            cert,
            Some(&mut TeePolicy::Sev(SevQuoteVerificationPolicy::new(
                measurement
            )))
        )
        .is_ok());
    }

    #[test]
    fn test_ratls_tdx_verify_ratls() {
        let cert = include_bytes!("../data/tdx-cert.ratls.pem");

        assert!(verify_ratls(
            cert,
            Some(&mut TeePolicy::Tdx(TdxQuoteVerificationPolicy::new()))
        )
        .is_ok());
    }
}
