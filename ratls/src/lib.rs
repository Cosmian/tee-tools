use crate::error::Error;
use asn1_rs::oid;
use openssl::{
    asn1::{Asn1Object, Asn1OctetString, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::{PKey, Private, Public},
    sha::Sha256,
    x509::{
        extension::{BasicConstraints, SubjectAlternativeName},
        X509Builder, X509Extension, X509,
    },
};
use rustls::{
    client::ServerCertVerified,
    client::{ServerCertVerifier, ServerName},
    Certificate, Error as RustTLSError,
};
use sev_quote::{self, quote::SEVQuote};

use std::time::SystemTime;
use std::{io::Write, net::Ipv4Addr};
use x509_parser::{
    oid_registry::Oid,
    prelude::{parse_x509_pem, X509Certificate},
};

pub mod error;

const SGX_RATLS_EXTENSION_OOID: Oid = oid!(1.2.840 .113741 .1337 .6);
const SEV_RATLS_EXTENSION_OOID: Oid = oid!(1.2.840 .113741 .1337 .7); // TODO: find a proper value?

pub enum PlatformType {
    Sgx,
    Sev,
}

/// Tell whether the platform is an SGX or an SEV processor
pub fn guess_platform() -> Result<PlatformType, Error> {
    if sev_quote::is_sev() {
        return Ok(PlatformType::Sev);
    }

    if sgx_quote::is_sgx() {
        return Ok(PlatformType::Sgx);
    }

    Err(Error::InvalidPlatform)
}

/// Verify the RATLS certificate.
///
/// The verification includes:
/// - The MRenclave
/// - The MRsigner
/// - The report data content
/// - The quote collaterals
pub async fn verify_ratls(
    pem_ratls_cert: &[u8],
    sev_measurement: Option<[u8; 48]>,
    mr_enclave: Option<[u8; 32]>,
    mr_signer: Option<[u8; 32]>,
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
    let (quote, platform) = extract_quote(&ratls_cert)?;

    match platform {
        PlatformType::Sev => {
            let quote: SEVQuote = bincode::deserialize(&quote).map_err(|_| {
                Error::InvalidFormat("Can't deserialize the SEV quote bytes".to_owned())
            })?;

            verify_report_data(&quote.report.report_data[0..32], &ratls_cert)?;

            // Verify the quote itself
            Ok(
                sev_quote::quote::verify_quote(&quote.report, &quote.certs, sev_measurement)
                    .await?,
            )
        }
        PlatformType::Sgx => {
            let (quote, _, _, _) = sgx_quote::quote::parse_quote(&quote)?;
            verify_report_data(&quote.report_body.report_data[0..32], &ratls_cert)?;

            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                &quote, mr_enclave, mr_signer,
            )?)
        }
    }
}

/// Verify the first bytes of the report data
/// It should be the fingerprint of the certificate public key (DER format)
fn verify_report_data(report_data: &[u8], ratls_cert: &X509Certificate) -> Result<(), Error> {
    let public_key = ratls_cert.public_key().raw;
    let expected_digest = digest_ratls_public_key(public_key);

    if report_data != expected_digest {
        return Err(Error::VerificationFailure(
            "Failed to verify the RA-TLS public key fingerprint".to_owned(),
        ));
    }

    Ok(())
}

/// Extract the quote from an RATLS certificate
fn extract_quote(ratls_cert: &X509Certificate) -> Result<(Vec<u8>, PlatformType), Error> {
    // Try to extract SGX quote
    if let Some(quote) = ratls_cert.get_extension_unique(&SGX_RATLS_EXTENSION_OOID)? {
        return Ok((quote.value.to_vec(), PlatformType::Sgx));
    }

    // Try to extract SEV quote
    if let Some(quote) = ratls_cert.get_extension_unique(&SEV_RATLS_EXTENSION_OOID)? {
        return Ok((quote.value.to_vec(), PlatformType::Sev));
    }

    // Not a RATLS certificate
    Err(Error::InvalidFormat(
        "This is not an RATLS certificate".to_owned(),
    ))
}

/// Compute the fingerprint of the ratls public key
fn digest_ratls_public_key(ratls_public_key: &[u8]) -> [u8; 32] {
    let mut pubkey_hash = Sha256::new();
    pubkey_hash.update(ratls_public_key);
    pubkey_hash.finish()
}

/// Generate the RATLS X509 extension containg the quote
///
/// The quote report data contains the sha256 of the certificate public key
/// and some 32 arbitrary extra bytes.
pub fn get_ratls_extension(
    ratls_public_key: &[u8],
    extra_data: Option<[u8; 32]>,
) -> Result<X509Extension, Error> {
    // Hash the public key of the certificate
    let pubkey_hash = digest_ratls_public_key(ratls_public_key);

    // Create the report data
    let user_report_data = extra_data.map_or_else(
        || pubkey_hash.to_vec(),
        |extra_data| [pubkey_hash, extra_data].concat(),
    );

    // Generate the quote
    let (quote, extension_ooid) = match guess_platform()? {
        PlatformType::Sev => {
            let quote = sev_quote::quote::get_quote(&user_report_data)?;
            (
                bincode::serialize(&quote).map_err(|_| {
                    Error::InvalidFormat("Can't serialize the SEV quote".to_owned())
                })?,
                SEV_RATLS_EXTENSION_OOID,
            )
        }
        PlatformType::Sgx => (
            sgx_quote::quote::get_quote(&user_report_data)?,
            SGX_RATLS_EXTENSION_OOID,
        ),
    };

    // Create the custom RATLS extension X509
    Ok(X509Extension::new_from_der(
        Asn1Object::from_str(&extension_ooid.to_string())?.as_ref(),
        false,
        Asn1OctetString::new_from_bytes(&quote)?.as_ref(),
    )?)
}

/// Generate a ratls certificate
///
/// The RATLS certificate contains the sgx quote
#[allow(clippy::too_many_arguments)]
pub fn generate_ratls_cert(
    country: Option<&str>,
    state: Option<&str>,
    city: Option<&str>,
    organization: Option<&str>,
    common_name: Option<&str>,
    subject_alternative_names: Vec<&str>,
    days_before_expiration: u32,
    quote_extra_data: Option<[u8; 32]>,
) -> Result<(PKey<Private>, X509), Error> {
    let nid = Nid::X9_62_PRIME256V1; // NIST P-256 curve
    let group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&group)?;
    let public_ec_key = ec_key.public_key_to_der()?;

    // We need to convert these keys to PKey objects to use in certificates
    let private_key = PKey::from_ec_key(ec_key)?;
    let public_key = PKey::<Public>::public_key_from_der(&public_ec_key)?;

    // Prepare certificate attributes
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(days_before_expiration)?;
    let mut x509_name = openssl::x509::X509NameBuilder::new()?;
    if let Some(country) = country {
        x509_name.append_entry_by_text("C", country)?;
    }
    if let Some(state) = state {
        x509_name.append_entry_by_text("ST", state)?;
    }
    if let Some(city) = city {
        x509_name.append_entry_by_text("L", city)?;
    }
    if let Some(organization) = organization {
        x509_name.append_entry_by_text("O", organization)?;
    }
    if let Some(common_name) = common_name {
        x509_name.append_entry_by_text("CN", common_name)?;
    }
    let x509_name = x509_name.build();

    let alternative_name = {
        let mut alt_name = SubjectAlternativeName::new();
        for san in subject_alternative_names {
            match san.parse::<Ipv4Addr>() {
                Ok(_) => alt_name.ip(san),
                Err(_) => alt_name.dns(san),
            };
        }
        alt_name
    };

    // Create a new X509 builder.
    let mut builder = X509Builder::new()?;
    builder.set_serial_number(&serial_number)?;
    builder.set_pubkey(&public_key)?;
    builder.set_not_after(&not_after)?;
    builder.set_not_before(&not_before)?;
    builder.set_subject_name(&x509_name)?;
    builder.set_issuer_name(&x509_name)?;

    // Set the TLS extensions
    builder.append_extension(alternative_name.build(&builder.x509v3_context(None, None))?)?;
    builder.append_extension(BasicConstraints::new().ca().critical().build()?)?;
    builder.append_extension(get_ratls_extension(&public_ec_key, quote_extra_data)?)?;

    builder.sign(&private_key, openssl::hash::MessageDigest::sha256())?;

    // now build the certificate
    let cert = builder.build();

    Ok((private_key, cert))
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

/// Get the RATLS certificate from a `domain`:`port`
pub fn get_server_certificate(domain: &str, port: u32) -> Result<Vec<u8>, Error> {
    let root_store = rustls::RootCertStore::empty();

    let mut socket = std::net::TcpStream::connect(format!("{domain}:{port}"))
        .map_err(|_| Error::ConnectionError)?;

    let mut config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(NoVerifier));

    let rc_config = std::sync::Arc::new(config);
    let dns_name = domain.try_into().map_err(|_| Error::DNSNameError)?;
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
    fn it_works() {
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
}
