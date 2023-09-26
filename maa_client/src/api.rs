use std::str::FromStr;

use crate::error::Error;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as Base64Url, Engine};
use jsonwebtoken_rustcrypto::jwk::JWKS;
use reqwest::StatusCode;
use serde_json::{json, Map, Value};

/// Fetch Microsoft certificates for Microsoft Azure Attestation (MAA) service.
///
/// # Returns
///
/// Either JSON Web Key Set [`JWKS`] or [`Error`].
///
/// # External documentation
///
/// See [`Signing Certificates from MAA API`].
///
/// [`Signing Certificates from MAA API`]: https://learn.microsoft.com/en-us/rest/api/attestation/signing-certificates/get
pub fn maa_certificates(maa_url: &str) -> Result<JWKS, Error> {
    let url = reqwest::Url::from_str(&format!("{maa_url}/certs"))
        .map_err(|e| Error::BadURLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;

    match r.status() {
        StatusCode::OK => {
            let jwks: JWKS = r
                .json()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;

            Ok(jwks)
        }
        s => {
            let body: Map<String, Value> = r
                .json()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;
            let error = body.get("error").ok_or(Error::MaaResponseError(
                "can't get error in response".to_owned(),
            ))?;
            let code = error.get("code").ok_or(Error::MaaResponseError(
                "can't get code in error response".to_owned(),
            ))?;
            let message = error.get("messge").ok_or(Error::MaaResponseError(
                "can't get message in error response".to_owned(),
            ))?;

            Err(Error::MaaResponseError(format!(
                "code: {}, message: {}, HTTP status code: {}",
                code.to_owned(),
                message.to_owned(),
                s
            )))
        }
    }
}

/// Request MAA service to attest SGX enclave from parameter.
///
/// # Returns
///
/// Either [`String`] within RS256 JWT token to be verified or [`Error`].
///
/// # External documentation
///
/// See [`Attest Sgx Enclave from MAA API`].
///
/// [`Attest Sgx Enclave from MAA API`]: https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sgx-enclave
pub fn maa_attest_sgx_enclave(
    maa_url: &str,
    quote: &[u8],
    enclave_held_data: Option<&[u8]>,
) -> Result<String, Error> {
    let url = reqwest::Url::parse_with_params(
        &format!("{maa_url}/attest/SgxEnclave"),
        &[("api-version", "2022-08-01")],
    )
    .map_err(|e| Error::BadURLError(e.to_string()))?;

    let mut payload = json!({"quote": Base64Url.encode(quote)});

    if let Some(enclave_held_data) = enclave_held_data {
        let root_object = payload.as_object_mut().expect("no object found in JSON");
        root_object.insert(
            String::from("runtimeData"),
            json!({"data": Base64Url.encode(enclave_held_data), "dataType": "Binary"}),
        );
    }

    let r = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?
        .post(url)
        .json(&payload)
        .send()?;

    match r.status() {
        StatusCode::OK => {
            let body = r
                .json::<Map<String, Value>>()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;

            let token = body.get("token").ok_or(Error::MaaResponseError(
                "failed to get token field in MAA response".to_owned(),
            ))?;

            Ok(token.to_string())
        }
        s => {
            let body = r
                .json::<Map<String, Value>>()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;
            let error = body.get("error").ok_or(Error::MaaResponseError(
                "can't get error in response".to_owned(),
            ))?;
            let code = error.get("code").ok_or(Error::MaaResponseError(
                "can't get code in error response".to_owned(),
            ))?;
            let message = error.get("messge").ok_or(Error::MaaResponseError(
                "can't get message in error response".to_owned(),
            ))?;

            Err(Error::MaaResponseError(format!(
                "code: {}, message: {}, HTTP status code: {}",
                code.to_owned(),
                message.to_owned(),
                s
            )))
        }
    }
}
