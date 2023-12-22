use crate::error::Error;
use p256::pkcs8::EncodePublicKey;
use tss_esapi::{
    interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
    structures::{EccScheme, Public},
};

pub fn ecc_public_to_point(public_key: &Public) -> Result<([u8; 32], [u8; 32]), Error> {
    match public_key {
        Public::Ecc {
            object_attributes: _,
            name_hashing_algorithm,
            auth_policy: _,
            parameters,
            unique,
        } => {
            if *name_hashing_algorithm != HashingAlgorithm::Sha256 {
                return Err(Error::VerificationError(
                    "only SHA256 is supported".to_owned(),
                ));
            }

            if parameters.ecc_curve() != EccCurve::NistP256 {
                return Err(Error::VerificationError(
                    "only NIST P-256 curve is supported".to_owned(),
                ));
            }

            match parameters.ecc_scheme() {
                EccScheme::EcDsa(hash_scheme) => {
                    if hash_scheme.hashing_algorithm() != HashingAlgorithm::Sha256 {
                        return Err(Error::VerificationError(
                            "unsupported hash scheme in ECDSA".to_owned(),
                        ));
                    }
                }
                _ => {
                    return Err(Error::VerificationError(
                        "unsupported signature scheme".to_owned(),
                    ));
                }
            }

            let (x, y): ([u8; 32], [u8; 32]) = (
                unique.x().value().try_into().map_err(|_| {
                    Error::VerificationError("failed to get X in public key".to_owned())
                })?,
                unique.y().value().try_into().map_err(|_| {
                    Error::VerificationError("failed to get Y in public key".to_owned())
                })?,
            );

            Ok((x, y))
        }
        _ => Err(Error::VerificationError(
            "unsupported public key".to_owned(),
        )),
    }
}

pub fn ecc_public_to_pem(public_key: &Public) -> Result<String, Error> {
    let (x, y) = ecc_public_to_point(public_key)?;

    let mut point = vec![0x04_u8];
    point.extend(&x[..]);
    point.extend(&y[..]);

    let pk = p256::PublicKey::from_sec1_bytes(&point)
        .map_err(|_| Error::CryptoError(" P-256 public key".to_owned()))?;

    pk.to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|_| Error::CryptoError("failed to convert public key to PEM".to_owned()))
}
