use crate::error::Error;
use crate::quote::{EcdsaSigData, QUOTE_HEADER_SIZE, QUOTE_REPORT_BODY_SIZE};

use chrono::{NaiveDateTime, Utc};
use elliptic_curve::pkcs8::DecodePublicKey;
use log::debug;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{AffinePoint, EncodedPoint};
use reqwest::blocking::get;
use rsa::signature::hazmat::PrehashVerifier;
use serde::Deserialize;
use sgx_pck_extension::SgxPckExtension;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{FromDer, Pem};
use x509_parser::revocation_list::CertificateRevocationList;

use elliptic_curve::sec1::FromEncodedPoint;

pub(crate) fn verify_quote_signature(
    raw_quote: &[u8],
    signature: &EcdsaSigData,
) -> Result<(), Error> {
    debug!("Verifying Header and TD Quote Body using attestation key and signature present in the quote");
    let pubkey = [vec![0x04], signature.attest_pub_key.to_vec()].concat();
    let pubkey = EncodedPoint::from_bytes(pubkey).map_err(|e| Error::CryptoError(e.to_string()))?;
    let point = Option::from(AffinePoint::from_encoded_point(&pubkey)).ok_or_else(|| {
        Error::CryptoError("Can't build an affine point from the provided public key".to_owned())
    })?;
    let mut message = Sha256::new();
    message.update(&raw_quote[..(QUOTE_HEADER_SIZE + QUOTE_REPORT_BODY_SIZE)]);
    let ecdsa_attestation_pk = VerifyingKey::from_affine(point)?;

    ecdsa_attestation_pk.verify_prehash(
        &message.finalize()[..],
        &Signature::from_slice(&signature.signature)?,
    )?;

    debug!("Verifying QE Report Data");
    let mut pubkey_hash = Sha256::new();
    pubkey_hash.update(signature.attest_pub_key);
    pubkey_hash.update(
        &signature
            .certification_data
            .qe_report_certification_data
            .qe_auth_data
            .qe_auth_data,
    );

    let expected_qe_report_data = &pubkey_hash.finalize()[..];

    if &signature
        .certification_data
        .qe_report_certification_data
        .qe_report
        .report_data[..32]
        != expected_qe_report_data
    {
        return Err(Error::VerificationFailure(
            "Unexpected REPORTDATA in QE report".to_owned(),
        ));
    }

    Ok(())
}
