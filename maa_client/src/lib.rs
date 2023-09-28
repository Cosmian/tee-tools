pub mod api;
pub mod error;

use crate::{
    api::{maa_attest_sgx_enclave, maa_certificates},
    error::Error,
};

use jsonwebtoken_rustcrypto::{
    jwk::{JWKDecodingKeySet, JWKS},
    Algorithm, TokenData, Validation,
};
use serde::{Deserialize, Serialize};

/// Sub-structure of [`SgxClaim`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// SGX claim returned by MAA API.
///
/// # External documentation
///
/// See [`Examples of an attestation token`].
///
/// [`Examples of an attestation token`]: https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SgxClaim {
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
    pub jti: String,
    pub nbf: u64,
    pub x_ms_attestation_type: String,
    pub x_ms_policy_hash: String,
    pub x_ms_sgx_collateral: SgxCollateral,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_ehd: Vec<u8>,
    pub x_ms_sgx_is_debuggable: bool,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrsigner: Vec<u8>,
    pub x_ms_sgx_product_id: u16,
    pub x_ms_sgx_svn: u16,
    pub x_ms_ver: String,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_config_id: Vec<u8>,
    pub x_ms_sgx_config_svn: u16,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_isv_extended_product_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_isv_family_id: Vec<u8>,
}

/// Verify the JWS issued by MAA.
///
/// # Returns
///
/// Either [`SgxClaims`] if success, [`Error`] otherwise.
///
/// # External documentation
///
/// See [`Examples of an attestation token`].
///
/// [`Examples of an attestation token`]: https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
pub fn verify_jws(token: &str, jwks: JWKS) -> Result<SgxClaim, Error> {
    let key_set: JWKDecodingKeySet = jwks
        .try_into()
        .map_err(|_| Error::UnexpectedError("bad key in JWKS".to_owned()))?;

    let validation = Validation {
        validate_nbf: true,
        validate_exp: true,
        algorithms: vec![Algorithm::RS256],
        leeway: 15,
        sub: None,
        aud: None,
        iss: None,
    };

    let token_data: TokenData<SgxClaim> = key_set
        .verify(token, &validation)
        .map_err(|e| Error::UnexpectedError(format!("failed to verify token: {e}")))?;

    Ok(token_data.claims)
}

/// Verify SGX quote on MAA service.
///
/// # Arguments
///
/// * `maa_url` - Attestation instance base URI, for example https://mytenant.attest.azure.net.
/// * `quote` - Raw SGX quote.
/// * `report_data` - Expected REPORT_DATA value in SGX quote (32 bytes only).
/// * `mr_enclave` - Expected MRENCLAVE value in SGX quote.
/// * `mr_signer` - Expected MRSIGNER value in SGX quote.
///
/// # Returns
///
/// Either [`SgxClaims`] if success, [`Error`] otherwise.
pub fn verify_quote(
    maa_url: &str,
    quote: &[u8],
    report_data: Option<&[u8]>,
    mr_enclave: Option<&[u8]>,
    mr_signer: Option<&[u8]>,
) -> Result<SgxClaim, Error> {
    let jwks = maa_certificates(maa_url)?;
    let token = maa_attest_sgx_enclave(maa_url, quote, report_data)?;
    let claim = verify_jws(&token, jwks)?;

    if claim.x_ms_attestation_type != "sgx" {
        return Err(Error::SgxVerificationError(format!(
            "Not an SGX enclave: {}",
            claim.x_ms_attestation_type
        )));
    }

    if claim.x_ms_sgx_is_debuggable {
        return Err(Error::SgxVerificationError(
            "SGX enclave in debug mode".to_owned(),
        ));
    }

    if let Some(mr_enclave) = mr_enclave {
        if mr_enclave.len() == claim.x_ms_sgx_mrenclave.len()
            && mr_enclave != claim.x_ms_sgx_mrenclave
        {
            return Err(Error::SgxVerificationError(format!(
                "MRENCLAVE differs: {:?} != {:?}",
                mr_enclave, claim.x_ms_sgx_mrenclave
            )));
        }
    }

    if let Some(mr_signer) = mr_signer {
        if mr_signer.len() == claim.x_ms_sgx_mrsigner.len() && mr_signer != claim.x_ms_sgx_mrsigner
        {
            return Err(Error::SgxVerificationError(format!(
                "MRSIGNER differs: {:?} != {:?}",
                mr_signer, claim.x_ms_sgx_mrsigner
            )));
        }
    }

    Ok(claim)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let maa_url = "https://sharedneu.neu.attest.azure.net";
        let _jwks = maa_certificates(maa_url).unwrap();

        // TODO: find quote from an Azure's SGX enclave
        // let quote = include_bytes!("../data/quote.dat");
        // let token = maa_attest_sgx_enclave(maa_url, quote, None).unwrap();

        // let claim = verify_quote(maa_url, quote, None, None, None).unwrap();
    }
}
