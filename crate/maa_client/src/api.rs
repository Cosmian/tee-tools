use std::str::FromStr;

use crate::{error::Error, jwk::MaaJwks};

use base64::{engine::general_purpose, Engine as _};
use reqwest::StatusCode;
use serde_json::{json, Map, Value};

/// Fetch Microsoft certificates from Microsoft Azure Attestation (MAA) API.
///
/// # Returns
///
/// Either JSON Web Key Set [`MaaJwks`] or [`Error`].
///
/// # External documentation
///
/// See [`Signing Certificates from MAA API`].
///
/// [`Signing Certificates from MAA API`]: https://learn.microsoft.com/en-us/rest/api/attestation/signing-certificates/get
pub fn maa_certificates(maa_url: &str) -> Result<MaaJwks, Error> {
    let url = reqwest::Url::from_str(&format!("{maa_url}/certs"))
        .map_err(|e| Error::BadURLError(e.to_string()))?;

    let response = reqwest::blocking::get(url)?;

    match response.status() {
        StatusCode::OK => {
            let jwks = response
                .json::<MaaJwks>()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;

            Ok(jwks)
        }
        s => {
            let body: Map<String, Value> = response
                .json()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;
            let error = body.get("error").ok_or(Error::MaaResponseError(
                "can't get error in response".to_owned(),
            ))?;
            let code = error.get("code").ok_or(Error::MaaResponseError(
                "can't get code in error response".to_owned(),
            ))?;
            let message = error.get("message").ok_or(Error::MaaResponseError(
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

/// Generic call to retrieve JWT token from Microsoft Azure Attestation (MAA) API.
///
/// # Returns
///
/// Either JWT as [`String`] or [`Error`].
fn maa_attest(
    maa_url: &str,
    endpoint: &str,
    url_params: &[(&str, &str)],
    json_params: Value,
) -> Result<String, Error> {
    let url = reqwest::Url::parse_with_params(&format!("{maa_url}{endpoint}"), url_params)
        .map_err(|e| Error::BadURLError(e.to_string()))?;

    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?
        .post(url)
        .json(&json_params)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send()?;

    match response.status() {
        StatusCode::OK => {
            let body = response
                .json::<Map<String, Value>>()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;

            let token = body.get("token").ok_or(Error::MaaResponseError(
                "failed to get token field in MAA response".to_owned(),
            ))?;

            Ok(token
                .as_str()
                .ok_or(Error::DecodeError(
                    "Failed to decode JSON key 'token'".to_owned(),
                ))?
                .to_owned())
        }
        s => {
            let body = response
                .json::<Map<String, Value>>()
                .map_err(|_| Error::DecodeError("can't deserialize JSON".to_owned()))?;
            let error = body.get("error").ok_or(Error::MaaResponseError(
                "can't get error in response".to_owned(),
            ))?;
            let code = error.get("code").ok_or(Error::MaaResponseError(
                "can't get code in error response".to_owned(),
            ))?;
            let message = error.get("message").ok_or(Error::MaaResponseError(
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

/// Request MAA service to attest SGX enclave from parameters.
///
/// # Returns
///
/// Either [`String`] with RS256 JWT token or [`Error`].
///
/// # External documentation
///
/// See [`Attest Sgx Enclave from MAA API`].
///
/// [`Attest Sgx Enclave from MAA API`]: https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sgx-enclave
pub fn maa_attest_sgx_enclave(
    maa_url: &str,
    nonce: &[u8],
    quote: &[u8],
    runtime_data: Option<&[u8]>,
) -> Result<String, Error> {
    let mut payload = json!({"quote": general_purpose::URL_SAFE_NO_PAD.encode(quote)});

    let json_root_object = payload
        .as_object_mut()
        .expect("no root object found in JSON");

    json_root_object.insert(
        "nonce".to_owned(),
        Value::from(general_purpose::URL_SAFE_NO_PAD.encode(nonce)),
    );

    if let Some(runtime_data) = runtime_data {
        let root_object = payload.as_object_mut().expect("no object found in JSON");
        root_object.insert(
            String::from("runtimeData"),
            json!({"data": general_purpose::URL_SAFE_NO_PAD.encode(runtime_data), "dataType": "Binary"}),
        );
    }

    maa_attest(
        maa_url,
        "/attest/SgxEnclave",
        &[("api-version", "2022-08-01")],
        payload,
    )
}

/// Request MAA service to attest AMD SEV-SNP CVM from parameters.
///
/// # Returns
///
/// Either [`String`] with RS256 JWT token or [`Error`].
///
/// # External documentation
///
/// See [`Attest Sev Snp VM from MAA API`].
///
/// [`Attest Sev Snp VM from MAA API`]: https://learn.microsoft.com/en-us/rest/api/attestation/attestation/attest-sev-snp-vm
pub fn maa_attest_sev_cvm(
    maa_url: &str,
    nonce: &[u8],
    report: &[u8],
    runtime_data: Option<&[u8]>,
) -> Result<String, Error> {
    let mut payload = json!({"report": general_purpose::URL_SAFE_NO_PAD.encode(report)});
    let json_root_object = payload
        .as_object_mut()
        .expect("no root object found in JSON");

    json_root_object.insert(
        "nonce".to_owned(),
        Value::from(general_purpose::URL_SAFE_NO_PAD.encode(nonce)),
    );

    if let Some(runtime_data) = runtime_data {
        json_root_object.insert(
            "runtimeData".to_owned(),
            json!({"data": general_purpose::URL_SAFE_NO_PAD.encode(runtime_data), "dataType": "Binary"}),
        );
    }

    maa_attest(
        maa_url,
        "/attest/SevSnpVm",
        &[("api-version", "2022-08-01")],
        payload,
    )
}

/// Request MAA service to attest Intel TDX CVM from parameters.
///
/// # Returns
///
/// Either [`String`] with RS256 JWT token or [`Error`].
///
/// # External documentation
///
/// See Microsoft attestation tools Python's code [`CVM Attestation Tools`].
///
/// [`CVM Attestation Tools`]: https://github.com/Azure/cvm-attestation-tools/blob/main/cvm-attestation/src/verifier.py#L14
pub fn maa_attest_tdx_cvm(
    maa_url: &str,
    nonce: &[u8],
    quote: &[u8],
    runtime_data: Option<&[u8]>,
) -> Result<String, Error> {
    let mut payload = json!({"quote": general_purpose::URL_SAFE_NO_PAD.encode(quote)});
    let json_root_object = payload
        .as_object_mut()
        .expect("no root object found in JSON");

    json_root_object.insert(
        "nonce".to_owned(),
        Value::from(general_purpose::URL_SAFE_NO_PAD.encode(nonce)),
    );

    if let Some(runtime_data) = runtime_data {
        json_root_object.insert(
            "runtimeData".to_owned(),
            json!({"data": general_purpose::URL_SAFE_NO_PAD.encode(runtime_data), "dataType": "Binary"}),
        );
    }

    maa_attest(
        maa_url,
        "/attest/TdxVm",
        &[("api-version", "2023-04-01-preview")],
        payload,
    )
}
