use crate::error::Error;

use std::convert::TryInto;

use p256::ecdsa::{signature::Verifier, VerifyingKey};
use tss_esapi::{
    interface_types::{
        algorithm::HashingAlgorithm, ecc::EccCurve, structure_tags::AttestationType,
    },
    structures::{Attest, EccScheme, Public, Signature},
    traits::Marshall,
};

pub(crate) fn verify_quote_signature(
    attestation_data: &Attest,
    signature: &Signature,
    pk: &Public,
) -> Result<Vec<u8>, Error> {
    if attestation_data.attestation_type() != AttestationType::Quote {
        return Err(Error::VerificationError(
            "attestation is not a quote".to_owned(),
        ));
    }

    let message = attestation_data.marshall()?;
    let signature = match signature {
        Signature::EcDsa(ecc_sig) => Ok(ecc_sig),
        _ => Err(Error::VerificationError(
            "signature is not ECDSA".to_owned(),
        )),
    }?;
    let nonce = attestation_data.extra_data().to_vec();

    let (r, s): ([u8; 32], [u8; 32]) = (
        signature
            .signature_r()
            .value()
            .try_into()
            .map_err(|_| Error::VerificationError("failed to get R in signature".to_owned()))?,
        signature
            .signature_s()
            .value()
            .try_into()
            .map_err(|_| Error::VerificationError("failed to get S in signature".to_owned()))?,
    );

    let (x, y) = match pk {
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
    }?;

    let mut point = vec![0x04_u8];
    point.extend(&x[..]);
    point.extend(&y[..]);

    let verifier = VerifyingKey::from_sec1_bytes(&point)?;
    let signature = p256::ecdsa::Signature::from_scalars(r, s)?;
    verifier
        .verify(&message[..], &signature)
        .map_err(|_| Error::CryptoError("failed to verify quote signature".to_owned()))?;

    Ok(nonce)
}
