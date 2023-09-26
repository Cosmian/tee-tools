use der::{asn1::Ia5String, pem::LineEnding, EncodePem};

use ecdsa::elliptic_curve::ScalarPrimitive;
use p256::ecdsa::DerSignature;
use p256::pkcs8::EncodePrivateKey;
use rand::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaChaRng;

use sha2::{Digest, Sha256};
use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use std::str::FromStr;
use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use x509_cert::ext::pkix::BasicConstraints;

use crate::{
    error::Error,
    extension::{AMDRatlsSExtension, IntelRatlsExtension, RatlsExtension},
};
use crate::{guess_tee, TeeType};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::asn1::OctetString,
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

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
