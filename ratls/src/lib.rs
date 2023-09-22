use der::{asn1::Ia5String, pem::LineEnding, EncodePem};

use ecdsa::elliptic_curve::ScalarPrimitive;
use p256::ecdsa::{DerSignature, VerifyingKey};
use p256::pkcs8::EncodePrivateKey;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;
use rustls::{
    client::ServerCertVerified,
    client::{ServerCertVerifier, ServerName},
    Certificate, Error as RustTLSError,
};
use sev_quote::{self, quote::SEVQuote};
use sha2::{Digest, Sha256};
use spki::{DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfoOwned};
use std::{
    convert::TryFrom,
    io::Write,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use std::{str::FromStr, time::SystemTime};
use x509_cert::ext::pkix::BasicConstraints;

use crate::{
    error::Error,
    extension::{
        AMDRatlsSExtension, IntelRatlsExtension, RatlsExtension, AMD_RATLS_EXTENSION_OID,
        INTEL_RATLS_EXTENSION_OID,
    },
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::asn1::OctetString,
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use x509_parser::{
    oid_registry::Oid,
    prelude::{parse_x509_pem, X509Certificate},
};

pub mod error;
pub mod extension;

pub enum TeeType {
    Sgx,
    Sev,
}

pub enum TeeMeasurement {
    Sgx {
        mr_signer: [u8; 32],
        mr_enclave: [u8; 32],
    },
    Sev([u8; 48]),
}

/// Tell whether the platform is an SGX or an SEV processor
pub fn guess_tee() -> Result<TeeType, Error> {
    if sev_quote::is_sev() {
        return Ok(TeeType::Sev);
    }

    if sgx_quote::is_sgx() {
        return Ok(TeeType::Sgx);
    }

    Err(Error::UnsupportedTeeError)
}

/// Verify the RATLS certificate.
///
/// The verification includes:
/// - The MRenclave
/// - The MRsigner
/// - The report data content
/// - The quote collaterals
pub fn verify_ratls(
    pem_ratls_cert: &[u8],
    measurement: Option<TeeMeasurement>,
) -> Result<(), Error> {
    let (rem, pem) = parse_x509_pem(pem_ratls_cert)?;

    if !rem.is_empty() || &pem.label != "CERTIFICATE" {
        return Err(Error::InvalidFormat(
            "Not a certificate or certificate is malformed".to_owned(),
        ));
    }

    let ratls_cert = pem
        .parse_x509()
        .map_err(|e| Error::X509ParserError(e.into()))?;

    // Get the quote from the certificate
    let (raw_quote, tee_type) = extract_quote(&ratls_cert)?;

    match tee_type {
        TeeType::Sev => {
            let quote: SEVQuote = bincode::deserialize(&raw_quote).map_err(|_| {
                Error::InvalidFormat("Can't deserialize the SEV quote bytes".to_owned())
            })?;

            verify_report_data(&quote.report.report_data, &ratls_cert)?;

            let measurement = if let Some(TeeMeasurement::Sev(m)) = measurement {
                Some(m)
            } else {
                None
            };

            // Verify the quote itself
            Ok(sev_quote::quote::verify_quote(
                &quote.report,
                &quote.certs,
                measurement,
            )?)
        }
        TeeType::Sgx => {
            let (quote, _, _, _) = sgx_quote::quote::parse_quote(&raw_quote)?;

            verify_report_data(&quote.report_body.report_data, &ratls_cert)?;

            let (mr_enclave, mr_signer) = if let Some(TeeMeasurement::Sgx {
                mr_signer: s,
                mr_enclave: e,
            }) = measurement
            {
                (Some(e), Some(s))
            } else {
                (None, None)
            };

            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                &raw_quote, mr_enclave, mr_signer,
            )?)
        }
    }
}

/// Verify the first bytes of the report data
/// It should be the fingerprint of the certificate public key (DER format)
fn verify_report_data(report_data: &[u8], ratls_cert: &X509Certificate) -> Result<(), Error> {
    let mut hasher = Sha256::new();

    let public_key = ratls_cert.public_key().raw;
    let pk = VerifyingKey::from_public_key_der(public_key)?;
    let public_key = pk.to_sec1_bytes();
    hasher.update(public_key);

    let expected_digest = &hasher.finalize()[..];

    if &report_data[0..32] != expected_digest {
        return Err(Error::VerificationFailure(
            "Failed to verify the RA-TLS public key fingerprint".to_owned(),
        ));
    }

    Ok(())
}

/// Extract the quote from an RATLS certificate
fn extract_quote(ratls_cert: &X509Certificate) -> Result<(Vec<u8>, TeeType), Error> {
    let intel_ext_oid = Oid::from_str(INTEL_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;
    let amd_ext_oid = Oid::from_str(AMD_RATLS_EXTENSION_OID).map_err(|_| Error::Asn1Error)?;

    // Try to extract SGX quote
    if let Some(quote) = ratls_cert.get_extension_unique(&intel_ext_oid)? {
        return Ok((quote.value.to_vec(), TeeType::Sgx));
    }

    // Try to extract SEV quote
    if let Some(quote) = ratls_cert.get_extension_unique(&amd_ext_oid)? {
        return Ok((quote.value.to_vec(), TeeType::Sev));
    }

    // Not a RATLS certificate
    Err(Error::InvalidFormat(
        "This is not an RATLS certificate".to_owned(),
    ))
}

/// Generate the RATLS X509 extension containg the quote
///
/// The quote report data contains the sha256 of the certificate public key
/// and some 32 arbitrary extra bytes.
pub fn get_ratls_extension(
    ratls_public_key: &[u8],
    extra_data: Option<[u8; 32]>,
) -> Result<RatlsExtension, Error> {
    let mut hasher = Sha256::new();

    // Hash the public key of the certificate
    hasher.update(ratls_public_key);

    let mut user_report_data = hasher.finalize()[..].to_vec();

    // Concat additional data if any
    if let Some(extra_data) = extra_data {
        user_report_data.extend(extra_data);
    }

    match guess_tee()? {
        TeeType::Sev => {
            let quote = sev_quote::quote::get_quote(&user_report_data)?;
            let quote = bincode::serialize(&quote)
                .map_err(|_| Error::InvalidFormat("Can't serialize the SEV quote".to_owned()))?;

            Ok(RatlsExtension::AMDTee(AMDRatlsSExtension::from(
                OctetString::new(&quote[..]).map_err(|_| Error::UnsupportedTeeError)?,
            )))
        }
        TeeType::Sgx => {
            let quote = sgx_quote::quote::get_quote(&user_report_data)?;
            Ok(RatlsExtension::IntelTee(IntelRatlsExtension::from(
                OctetString::new(&quote[..]).map_err(|_| Error::UnsupportedTeeError)?,
            )))
        }
    }
}

/// Generate a ratls certificate
///
/// The RATLS certificate contains the sgx quote
#[allow(clippy::too_many_arguments)]
pub fn generate_ratls_cert(
    subject: &str,
    subject_alternative_names: Vec<&str>,
    days_before_expiration: u64,
    quote_extra_data: Option<[u8; 32]>,
    deterministic: bool,
) -> Result<(String, String), Error> {
    let mut csrng = ChaChaRng::from_entropy();

    let serial_number = SerialNumber::from(csrng.next_u32());
    let validity = Validity::from_now(Duration::new(days_before_expiration * 24 * 60 * 60, 0))
        .map_err(|_| Error::RatlsError("unexpected expiration validity".to_owned()))?;

    let subject =
        Name::from_str(subject).map_err(|_| Error::RatlsError("can't parse subject".to_owned()))?;

    let secret_key = if !deterministic {
        // Randomly generated the secret key
        p256::SecretKey::random(&mut csrng)
    } else {
        // Derive the secret key from the tee measurements
        // No salt are used: the key will always be the same for a given measurement
        let secret = match guess_tee()? {
            TeeType::Sgx => sgx_quote::key::get_key(false)?,
            TeeType::Sev => sev_quote::key::get_key(false)?,
        };

        let sk = ScalarPrimitive::from_slice(&secret)?;
        p256::SecretKey::new(sk)
    };

    let pem_sk = secret_key
        .clone()
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| Error::RatlsError("can't convert secret key to PEM".to_owned()))?
        .to_string();

    let signer = p256::ecdsa::SigningKey::from(secret_key);
    let pk_der = signer.verifying_key().to_public_key_der()?;
    let spki = SubjectPublicKeyInfoOwned::try_from(pk_der.as_bytes()).map_err(|e| {
        Error::RatlsError(format!(
            "can't create SubjectPublicKeyInfo from public key: {e:?}"
        ))
    })?;
    let mut builder = CertificateBuilder::new(
        Profile::Manual { issuer: None },
        serial_number,
        validity,
        subject,
        spki,
        &signer,
    )
    .map_err(|_| Error::RatlsError("failed to create certificate builder".to_owned()))?;

    match get_ratls_extension(&signer.verifying_key().to_sec1_bytes(), quote_extra_data)? {
        RatlsExtension::AMDTee(amd_ext) => builder
            .add_extension(&amd_ext)
            .map_err(|_| Error::RatlsError("can't create RA-TLS AMD extension".to_owned()))?,
        RatlsExtension::IntelTee(intel_ext) => builder
            .add_extension(&intel_ext)
            .map_err(|_| Error::RatlsError("can't create RA-TLS Intel extension".to_owned()))?,
    };

    if !subject_alternative_names.is_empty() {
        let subject_alternative_names = subject_alternative_names
            .iter()
            .map(|san| match san.parse::<Ipv4Addr>() {
                Ok(ip) => GeneralName::from(IpAddr::V4(ip)),
                Err(_) => GeneralName::DnsName(
                    Ia5String::try_from(san.to_string())
                        .expect("SAN contains non-ascii characters"),
                ),
            })
            .collect::<Vec<GeneralName>>();

        builder
            .add_extension(&SubjectAltName(subject_alternative_names))
            .map_err(|_| Error::RatlsError("can't create SAN extension".to_owned()))?;
    }

    builder
        .add_extension(&BasicConstraints {
            ca: true,
            path_len_constraint: None,
        })
        .map_err(|_| Error::RatlsError("failed to add basic constraint CA:true".to_owned()))?;

    let certificate = builder
        .build::<DerSignature>()
        .map_err(|_| Error::RatlsError("can't build RA-TLS certificate".to_owned()))?;
    let pem_cert = certificate
        .to_pem(LineEnding::LF)
        .map_err(|_| Error::RatlsError("failed to convert certificate to PEM".to_owned()))?;

    Ok((pem_sk, pem_cert))
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
        let mrsigner =
            hex::decode(b"c1c161d0dd996e8a9847de67ea2c00226761f7715a2c422d3012ac10795a1ef5")
                .unwrap()
                .try_into()
                .unwrap();

        assert!(verify_ratls(
            cert,
            Some(TeeMeasurement::Sgx {
                mr_signer: mrsigner,
                mr_enclave: mrenclave
            })
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

        assert!(verify_ratls(cert, Some(TeeMeasurement::Sev(measurement))).is_ok());
    }
}
