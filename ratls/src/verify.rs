use p256::ecdsa::VerifyingKey;

use rustls::{
    client::ServerCertVerified,
    client::{ServerCertVerifier, ServerName},
    Certificate, Error as RustTLSError,
};
use spki::DecodePublicKey;
use std::io::Write;
use std::{str::FromStr, time::SystemTime};
use tee_attestation::{verify_quote, TeeMeasurement};

use crate::{
    error::Error,
    extension::{AMD_RATLS_EXTENSION_OID, INTEL_RATLS_EXTENSION_OID},
    generate::forge_report_data,
};
use x509_parser::{
    oid_registry::Oid,
    prelude::{parse_x509_pem, X509Certificate},
};

/// Verify the RATLS certificate.
///
/// The verification includes:
/// - The MRenclave
/// - The MRsigner
/// - The report data content
/// - The quote collaterals
pub fn verify_ratls(pem_ratls_cert: &[u8], measurement: TeeMeasurement) -> Result<(), Error> {
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
    let expected_report_data = forge_report_data(&pk, None)?;

    Ok(verify_quote(
        &raw_quote,
        &expected_report_data,
        measurement,
    )?)
}

/// Extract the quote from an RATLS certificate
fn extract_quote(ratls_cert: &X509Certificate) -> Result<Vec<u8>, Error> {
    let intel_ext_oid = Oid::from_str(INTEL_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;
    let amd_ext_oid = Oid::from_str(AMD_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;

    // Try to extract SGX quote
    if let Some(quote) = ratls_cert.get_extension_unique(&intel_ext_oid)? {
        return Ok(quote.value.to_vec());
    }

    // Try to extract SEV quote
    if let Some(quote) = ratls_cert.get_extension_unique(&amd_ext_oid)? {
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
        .get(0)
        .ok_or(Error::ServerCertificateError)?
        .as_ref()
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
    use tee_attestation::{SevMeasurement, SgxMeasurement};

    #[test]
    fn test_get_server_certificate() {
        let server_cert = get_server_certificate("self-signed.badssl.com", 443).unwrap();

        let b64_server_cert = r#"
        MIIDeTCCAmGgAwIBAgIJAKvqfFfMqQaUMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
        BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp
        c2NvMQ8wDQYDVQQKDAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTAeFw0y
        MzA3MjEyMTU2MTJaFw0yNTA3MjAyMTU2MTJaMGIxCzAJBgNVBAYTAlVTMRMwEQYD
        VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQK
        DAZCYWRTU0wxFTATBgNVBAMMDCouYmFkc3NsLmNvbTCCASIwDQYJKoZIhvcNAQEB
        BQADggEPADCCAQoCggEBAMIE7PiM7gTCs9hQ1XBYzJMY61yoaEmwIrX5lZ6xKyx2
        PmzAS2BMTOqytMAPgLaw+XLJhgL5XEFdEyt/ccRLvOmULlA3pmccYYz2QULFRtMW
        hyefdOsKnRFSJiFzbIRMeVXk0WvoBj1IFVKtsyjbqv9u/2CVSndrOfEk0TG23U3A
        xPxTuW1CrbV8/q71FdIzSOciccfCFHpsKOo3St/qbLVytH5aohbcabFXRNsKEqve
        ww9HdFxBIuGa+RuT5q0iBikusbpJHAwnnqP7i/dAcgCskgjZjFeEU4EFy+b+a1SY
        QCeFxxC7c3DvaRhBB0VVfPlkPz0sw6l865MaTIbRyoUCAwEAAaMyMDAwCQYDVR0T
        BAIwADAjBgNVHREEHDAaggwqLmJhZHNzbC5jb22CCmJhZHNzbC5jb20wDQYJKoZI
        hvcNAQELBQADggEBAKRIesYfOhb7rH1+Aw0B391ZHGkarzcSguAA3iKhhc8uzEf0
        bOzByITqm2Fxdvrn8b1AJw4f3MnbbE3y4bWTbipdChEerou2qcjYPjJqOUH9lP+G
        rn2OxtPzlznOrU5KlvHV6RMe5zvJMCXiTC4SuuKG7aBMz3jSfmP+Nf+n5q31g7xl
        7tfnPfjnbYHyNcK/Y75uvl/IICYx6iaP6DJB8Ya4T/NlwKbpW1Av6zWQTi1GM5Cb
        U4e00ZmGEr4Rtk+GIYmQ/hWY/IuerFXfnGOXdWPWAzZYwDtIc0bF5llfEABjfLjM
        V5Yw9bcQWLPtjK/umfxzYB+jf7kjI9dLTCxJptE=
        "#
        .replace(['\n', ' '], "");
        let expected_server_cert = general_purpose::STANDARD.decode(b64_server_cert).unwrap();
        assert_eq!(expected_server_cert, server_cert);
        let (_rem, cert) = x509_parser::parse_x509_certificate(&server_cert).unwrap();
        println!("{:?}", cert);
    }

    #[test]
    fn test_sgx_verify_ratls() {
        let cert = include_bytes!("../data/sgx-cert.ratls.pem");

        let mrenclave =
            hex::decode(b"958e39c89abec8cfb5ce01961a50860c770c75b01e64ed77847097f9705ed7bd")
                .unwrap()
                .try_into()
                .unwrap();
        let public_signer_key = include_str!("../data/signer-key.pem");

        assert!(verify_ratls(
            cert,
            TeeMeasurement {
                sev: None,
                sgx: Some(SgxMeasurement {
                    public_signer_key_pem: public_signer_key.to_string(),
                    mr_enclave: mrenclave
                })
            }
        )
        .is_ok());
    }

    #[test]
    fn test_sev_verify_ratls() {
        let cert = include_bytes!("../data/sev-cert.ratls.pem");

        let measurement =
            hex::decode(b"c2c84b9364fc9f0f54b04534768c860c6e0e386ad98b96e8b98eca46ac8971d05c531ba48373f054c880cfd1f4a0a84e")
                .unwrap()
                .try_into()
                .unwrap();

        assert!(verify_ratls(
            cert,
            TeeMeasurement {
                sev: Some(SevMeasurement(measurement)),
                sgx: None
            }
        )
        .is_ok());
    }
}