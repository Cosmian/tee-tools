pub mod api;
pub mod claim;
pub mod error;
pub mod jwk;
pub mod utils;

use std::str::FromStr;

use crate::{
    api::{maa_attest_sev_cvm, maa_attest_sgx_enclave, maa_attest_tdx_cvm, maa_certificates},
    claim::{SevClaim, SgxClaim, TdxClaim},
    error::Error,
};

use base64::{engine::general_purpose, Engine};
use jose_jws::{General, Protected, Unprotected};
use jwk::MaaJwks;
use jwt_simple::{
    common::VerificationOptions,
    prelude::{RS256PublicKey, RSAPublicKeyLike},
    reexports::rand::{self, Rng as _},
};

/// Verify JSON Web Signature (JWS) using JSON Web Key Set (JWKS).
///
/// # Returns
///
/// Either [`serde_json::Value`] if success, [`Error`] otherwise.
pub fn verify_rs256_jws(
    token: &str,
    jwks: MaaJwks,
    nonce: Option<&[u8]>,
) -> Result<serde_json::Value, Error> {
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

    let Protected { oth, .. } = &**header;
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

    let claim: jwt_simple::prelude::JWTClaims<serde_json::Value> = pk
        .verify_token::<serde_json::Value>(token, options)
        .map_err(|e| Error::MaaResponseError(format!("failed to verify JWS token: {e}")))?;

    Ok(claim.custom)
}

/// Verify Intel SGX quote on MAA service.
///
/// # Arguments
///
/// * `maa_url` - Attestation instance base URI, for example https://mytenant.attest.azure.net.
/// * `quote` - Raw SGX quote.
/// * `enclave_held_data` - SHA-256(enclave_held_data) digest expected in `REPORT_DATA` of SGX quote.
/// * `mr_enclave` - Expected MRENCLAVE value in SGX quote.
/// * `mr_signer` - Expected MRSIGNER value in SGX quote.
///
/// # Returns
///
/// Either [`SgxClaim`] if success, [`Error`] otherwise.
pub fn verify_sgx_quote(
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
    let payload = verify_rs256_jws(&token, jwks, Some(&nonce))?;
    let sgx_claim = serde_json::from_value::<SgxClaim>(payload).unwrap();

    if sgx_claim.tee != "sgx" {
        return Err(Error::SgxVerificationError(format!(
            "Not an SGX enclave: {}",
            sgx_claim.tee
        )));
    }

    if sgx_claim.is_debuggable {
        return Err(Error::SgxVerificationError(
            "SGX enclave in debug mode".to_owned(),
        ));
    }

    if let Some(mr_enclave) = mr_enclave {
        if mr_enclave.len() == sgx_claim.sgx_mrenclave.len()
            && mr_enclave != sgx_claim.sgx_mrenclave
        {
            return Err(Error::SgxVerificationError(format!(
                "MRENCLAVE differs: {:?} != {:?}",
                mr_enclave, sgx_claim.sgx_mrenclave
            )));
        }
    }

    if let Some(mr_signer) = mr_signer {
        if mr_signer.len() == sgx_claim.sgx_mrsigner.len() && mr_signer != sgx_claim.sgx_mrsigner {
            return Err(Error::SgxVerificationError(format!(
                "MRSIGNER differs: {:?} != {:?}",
                mr_signer, sgx_claim.sgx_mrsigner
            )));
        }
    }

    Ok(sgx_claim)
}

/// Verify AMD SEV-SNP attestation report on MAA service.
///
/// # Arguments
///
/// * `maa_url` - Attestation instance base URI, for example https://mytenant.attest.azure.net.
/// * `report` - AMD SEV-SNP attestation report.
/// * `amd_cert_chain` - AMD certificate chain composed of VCEK, AMD SEV CA and AMD root CA.
///
/// # Returns
///
/// Either [`CvmClaim`] if success, [`Error`] otherwise.
pub fn verify_sev_quote(
    maa_url: &str,
    report: &[u8],
    amd_cert_chain: &[u8],
) -> Result<SevClaim, Error> {
    let mut rng = rand::thread_rng();

    let jwks = maa_certificates(maa_url)?;
    let nonce: [u8; 32] = rng.gen();
    let payload = serde_json::json!({"SnpReport": general_purpose::URL_SAFE_NO_PAD.encode(report), "VcekCertChain": general_purpose::URL_SAFE_NO_PAD.encode(amd_cert_chain)}).to_string();
    let token = maa_attest_sev_cvm(maa_url, &nonce, payload.as_bytes(), None)?;
    let jws_payload = verify_rs256_jws(&token, jwks, Some(&nonce))?;

    Ok(serde_json::from_value::<SevClaim>(jws_payload)?)
}

/// Verify Intel TDX quote on MAA service.
///
/// # Arguments
///
/// * `maa_url` - Attestation instance base URI, for example https://mytenant.attest.azure.net.
/// * `quote` - SEV-SNP attestation report.
///
/// # Returns
///
/// Either [`CvmClaim`] if success, [`Error`] otherwise.
pub fn verify_tdx_quote(maa_url: &str, quote: &[u8]) -> Result<TdxClaim, Error> {
    let mut rng = rand::thread_rng();

    let jwks = maa_certificates(maa_url)?;
    let nonce: [u8; 32] = rng.gen();
    let token = maa_attest_tdx_cvm(maa_url, &nonce, quote, None)?;
    let jws_payload = verify_rs256_jws(&token, jwks, Some(&nonce))?;

    Ok(serde_json::from_value::<TdxClaim>(jws_payload)?)
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
        let maa_url: &str = "https://sharedneu.neu.attest.azure.net";
        let quote = include_bytes!("../data/az_sgx_quote.dat");
        let mrenclave =
            hex::decode("c8028b8d8c455030ff2f8a295a29f42942f018f49e7df68393749a9733743831")
                .unwrap();
        let mrsigner =
            hex::decode("8f33288f9e63565fc11bbfe50b06c57814275aff49d70d63d71e4c0d5c462958")
                .unwrap();
        let enclave_held_data = hex::decode("0433e2ac6ec6f7f74c3d9ebb501dd630845314d076ee62d7a1ab1b93cc247cb02e2718c106452bb5e874f277c8f58ed4e1b9b9d494c2da0670d8a21b5c2225476b").unwrap();

        let _ = verify_sgx_quote(
            maa_url,
            quote,
            Some(&enclave_held_data),
            Some(&mrenclave),
            Some(&mrsigner),
        )
        .unwrap();
    }

    #[test]
    fn test_verify_sev_quote() {
        let maa_url: &str = "https://sharedweu.weu.attest.azure.net";
        let report = include_bytes!("../data/az_sev_report.bin");
        let certs = include_bytes!("../data/vcek.pem");
        let _ = verify_sev_quote(maa_url, report, certs).unwrap();
    }

    #[test]
    fn test_verify_sev_quote_with_cert_chain() {
        let maa_url: &str = "https://sharedweu.weu.attest.azure.net";
        let report_and_certs = include_bytes!("../data/az_sev_report_with_chain.bin");
        let report = &report_and_certs[..1184];
        let amd_cert_chain = utils::parse_certificate_chain(report_and_certs).join("");
        let _ = verify_sev_quote(maa_url, report, amd_cert_chain.as_bytes()).unwrap();
    }

    #[test]
    fn test_verify_tdx_quote() {
        let maa_url: &str = "https://sharedweu.weu.attest.azure.net";
        let quote = include_bytes!("../data/az_tdx_quote.bin");
        let _ = verify_tdx_quote(maa_url, quote).unwrap();
    }
}
