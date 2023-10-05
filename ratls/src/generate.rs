use der::{asn1::Ia5String, pem::LineEnding, EncodePem};

use ecdsa::elliptic_curve::ScalarPrimitive;
use p256::ecdsa::DerSignature;
use p256::pkcs8::EncodePrivateKey;
use p256::SecretKey;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use spki::{EncodePublicKey, SubjectPublicKeyInfoOwned};
use std::str::FromStr;
use std::{
    convert::TryFrom,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tee_attestation::{get_key, get_quote, guess_tee, TeeType};
use x509_cert::ext::pkix::BasicConstraints;

use crate::verify::forge_report_data;
use crate::{
    error::Error,
    extension::{AMDRatlsSExtension, IntelRatlsExtension, RatlsExtension},
};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    der::asn1::OctetString,
    ext::pkix::{name::GeneralName, SubjectAltName},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

/// Define the way to generate the RATLS secret key
pub enum RatlsKeyGenerationType {
    /// Randomly generated
    Random,
    /// Derived from the tee parameters (if None: the key is fully deterministic)
    InstanceBounded(Option<Vec<u8>>),
}

impl RatlsKeyGenerationType {
    pub fn generate_key(&self) -> Result<SecretKey, Error> {
        let mut rng = ChaCha20Rng::from_entropy();

        Ok(match self {
            RatlsKeyGenerationType::Random => p256::SecretKey::random(&mut rng),
            RatlsKeyGenerationType::InstanceBounded(salt) => {
                // Derive the secret key from the tee measurements
                // No salt are used: the key will always be the same for a given measurement
                let secret = get_key(salt.as_deref())?;
                let sk = ScalarPrimitive::from_slice(&secret)?;
                p256::SecretKey::new(sk)
            }
        })
    }
}

/// Generate the RATLS X509 extension containg the quote
///
/// The quote report data contains the sha256 of the certificate public key
/// and some 32 arbitrary extra bytes.
pub fn get_ratls_extension(
    ratls_public_key: &ecdsa::VerifyingKey<p256::NistP256>,
    extra_data: Option<[u8; 32]>,
) -> Result<RatlsExtension, Error> {
    let user_report_data = forge_report_data(ratls_public_key, extra_data)?;
    let quote = get_quote(&user_report_data)?;

    match guess_tee()? {
        /* TODO: remove that after sgx::get_quote refactor */
        TeeType::Sev => Ok(RatlsExtension::AMDTee(AMDRatlsSExtension::from(
            OctetString::new(quote).map_err(|_| Error::UnsupportedTeeError)?,
        ))),
        TeeType::Sgx => Ok(RatlsExtension::IntelTee(IntelRatlsExtension::from(
            OctetString::new(quote).map_err(|_| Error::UnsupportedTeeError)?,
        ))),
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
    key_generation_type: RatlsKeyGenerationType,
) -> Result<(String, String), Error> {
    let mut rng = ChaCha20Rng::from_entropy();

    let serial_number = SerialNumber::from(rng.next_u32());
    let validity = Validity::from_now(Duration::new(days_before_expiration * 24 * 60 * 60, 0))
        .map_err(|_| Error::RatlsError("unexpected expiration validity".to_owned()))?;

    let subject =
        Name::from_str(subject).map_err(|_| Error::RatlsError("can't parse subject".to_owned()))?;

    let secret_key = key_generation_type.generate_key()?;

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

    match get_ratls_extension(signer.verifying_key(), quote_extra_data)? {
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
