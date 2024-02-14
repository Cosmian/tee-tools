pub mod api;
pub mod error;
pub mod jwk;
pub mod utils;

use std::{ops::Deref, str::FromStr};

use crate::{
    api::{maa_attest_sgx_enclave, maa_certificates},
    error::Error,
    utils::base64url_serde,
};

use base64::{engine::general_purpose, Engine};
use jose_jws::{General, Protected, Unprotected};
use jwk::MaaJwks;
use jwt_simple::{
    common::VerificationOptions,
    prelude::{RS256PublicKey, RSAPublicKeyLike},
    reexports::rand::{self, Rng as _},
};
use serde::{Deserialize, Serialize};

/// Sub-structure of [`SgxClaim`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxCollateral {
    #[serde(with = "hex::serde")]
    pub qeidcertshash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub qeidcrlhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub qeidhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub quotehash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfocertshash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfocrlhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfohash: Vec<u8>,
}

/// Sub-structure of [`SgxClaim`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxPolicy {
    pub is_debuggable: bool,
    pub product_id: u32,
    #[serde(with = "hex::serde")]
    pub sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sgx_mrsigner: Vec<u8>,
    pub svn: u32,
    pub tee: String,
}

/// SGX claim returned by MAA API.
///
/// # External documentation
///
/// See [`Examples of an attestation token`].
///
/// [`Examples of an attestation token`]: https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxClaim {
    #[serde(with = "base64url_serde")]
    pub maa_ehd: Vec<u8>,
    pub is_debuggable: bool,
    pub maa_attestationcollateral: SgxCollateral,
    pub product_id: u64,
    #[serde(with = "hex::serde")]
    pub sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sgx_mrsigner: Vec<u8>,
    pub svn: u32,
    pub tee: String,
    pub x_ms_attestation_type: String,
    pub x_ms_policy: SgxPolicy,
    pub x_ms_policy_hash: String,
    pub x_ms_sgx_collateral: SgxCollateral,
    pub x_ms_sgx_is_debuggable: bool,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrsigner: Vec<u8>,
    pub x_ms_sgx_product_id: u16,
    pub x_ms_sgx_svn: u16,
    pub x_ms_ver: String,
}

/// Verify the JWS issued by MAA.
///
/// # Returns
///
/// Either [`SgxClaim`] if success, [`Error`] otherwise.
///
/// # External documentation
///
/// See [`Examples of an attestation token`].
///
/// [`Examples of an attestation token`]: https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
pub fn verify_jws(token: &str, jwks: MaaJwks, nonce: Option<&[u8]>) -> Result<SgxClaim, Error> {
    let jws = General::from_str(token)
        .map_err(|_| Error::DecodeError("can't deserialize JWS".to_owned()))?;

    if jws.payload.is_none() {
        return Err(Error::DecodeError("payload not found in JWS".to_owned()));
    }

    if jws.signatures.len() != 1 {
        return Err(Error::DecodeError("multiple signatures in JWS".to_owned()));
    }

    let signature = &jws.signatures[0];

    let Some(header) = &signature.protected else {
        return Err(Error::DecodeError("no header found in JWS".to_owned()));
    };

    let Protected { oth, .. } = header.deref();
    let Unprotected { kid, .. } = oth;

    let Some(expected_kid) = kid else {
        return Err(Error::DecodeError("no kid in JWS".to_owned()));
    };
    let jwk = jwks
        .find(expected_kid)
        .ok_or(Error::MaaResponseError("kid not found in JWKS".to_owned()))?;
    let pk: RS256PublicKey = jwk.try_into()?;

    let options = nonce.map(|nonce| VerificationOptions {
        required_nonce: Some(general_purpose::URL_SAFE_NO_PAD.encode(nonce)),
        ..Default::default()
    });

    let claim = pk
        .verify_token::<SgxClaim>(token, options)
        .map_err(|_| Error::MaaResponseError("failed to verify JWS token".to_string()))?;

    Ok(claim.custom)
}

/// Verify SGX quote on MAA service.
///
/// # Arguments
///
/// * `maa_url` - Attestation instance base URI, for example https://mytenant.attest.azure.net.
/// * `quote` - Raw SGX quote.
/// * `enclave_held_data` - SHA-256(enclave_held_data) digest expected in REPORT_DATA of SGX quote.
/// * `mr_enclave` - Expected MRENCLAVE value in SGX quote.
/// * `mr_signer` - Expected MRSIGNER value in SGX quote.
///
/// # Returns
///
/// Either [`SgxClaim`] if success, [`Error`] otherwise.
pub fn verify_quote(
    maa_url: &str,
    quote: &[u8],
    enclave_held_data: Option<&[u8]>,
    mr_enclave: Option<&[u8]>,
    mr_signer: Option<&[u8]>,
) -> Result<SgxClaim, Error> {
    let mut rng = rand::thread_rng();

    let jwks = maa_certificates(maa_url)?;
    let nonce: [u8; 32] = rng.gen();
    let token = maa_attest_sgx_enclave(maa_url, &nonce, quote, enclave_held_data)?;
    let claim = verify_jws(&token, jwks, Some(&nonce))?;

    if claim.tee != "sgx" {
        return Err(Error::SgxVerificationError(format!(
            "Not an SGX enclave: {}",
            claim.tee
        )));
    }

    if claim.is_debuggable {
        return Err(Error::SgxVerificationError(
            "SGX enclave in debug mode".to_owned(),
        ));
    }

    if let Some(mr_enclave) = mr_enclave {
        if mr_enclave.len() == claim.sgx_mrenclave.len() && mr_enclave != claim.sgx_mrenclave {
            return Err(Error::SgxVerificationError(format!(
                "MRENCLAVE differs: {:?} != {:?}",
                mr_enclave, claim.sgx_mrenclave
            )));
        }
    }

    if let Some(mr_signer) = mr_signer {
        if mr_signer.len() == claim.sgx_mrsigner.len() && mr_signer != claim.sgx_mrsigner {
            return Err(Error::SgxVerificationError(format!(
                "MRSIGNER differs: {:?} != {:?}",
                mr_signer, claim.sgx_mrsigner
            )));
        }
    }

    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maa_certs() {
        let maa_url = "https://sharedneu.neu.attest.azure.net";
        let jwks = maa_certificates(maa_url).unwrap();

        assert!(!jwks.keys.is_empty());
    }

    #[test]
    fn test_verify_sgx_quote() {
        let maa_url = "https://sharedneu.neu.attest.azure.net";
        let quote = include_bytes!("../data/quote.dat");
        let mrenclave =
            hex::decode("c8028b8d8c455030ff2f8a295a29f42942f018f49e7df68393749a9733743831")
                .unwrap();
        let mrsigner =
            hex::decode("8f33288f9e63565fc11bbfe50b06c57814275aff49d70d63d71e4c0d5c462958")
                .unwrap();
        let enclave_held_data = hex::decode("0433e2ac6ec6f7f74c3d9ebb501dd630845314d076ee62d7a1ab1b93cc247cb02e2718c106452bb5e874f277c8f58ed4e1b9b9d494c2da0670d8a21b5c2225476b").unwrap();

        let _ = verify_quote(
            maa_url,
            quote,
            Some(&enclave_held_data),
            Some(&mrenclave),
            Some(&mrsigner),
        )
        .unwrap();
        // println!("{:?}", claim);
    }
}
