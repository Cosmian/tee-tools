// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::str::FromStr;

use crate::{attestation_report::TdReport, error::Error};

use base64::{engine::general_purpose, Engine as _};
use zerocopy::IntoBytes;

// IMDS endpoint for VCEK certificate, AMD SEV CA and AMD Root CA
const IMDS_THIM_ENDPOINT: &str = "http://169.254.169.254/metadata/THIM/amd/certification";
// IMDS endpoint for Intel TD quote
const IMDS_TDX_ENDPOINT: &str = "http://169.254.169.254/acc/tdquote";

/// Retrieves a TDX quote from the Azure Instance Metadata Service (IMDS) using a provided TD
/// report.
pub fn get_td_quote(td_report: &TdReport) -> Result<Vec<u8>, Error> {
    let payload = serde_json::json!({"report": general_purpose::URL_SAFE_NO_PAD.encode(td_report.as_bytes())});
    let url =
        reqwest::Url::from_str(IMDS_TDX_ENDPOINT).map_err(|e| Error::BadURLError(e.to_string()))?;

    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?
        .post(url)
        .json(&payload)
        .send()?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let body = response
                .json::<serde_json::Map<String, serde_json::Value>>()
                .map_err(|_| Error::JsonDecodeError("can't deserialize JSON".to_owned()))?;

            let value = body.get("quote").ok_or(Error::ImdsResponseError(
                "failed to get TD quote".to_owned(),
            ))?;
            let quote = general_purpose::URL_SAFE_NO_PAD.decode(value.as_str().ok_or(
                Error::JsonDecodeError("JSON value not a string at JSON key 'quote'".to_owned()),
            )?)?;

            Ok(quote)
        }
        s => {
            let body = response
                .json::<serde_json::Map<String, serde_json::Value>>()
                .map_err(|_| Error::JsonDecodeError("can't deserialize JSON".to_owned()))?;
            let error = body.get("error").ok_or(Error::ImdsResponseError(
                "can't get error in response".to_owned(),
            ))?;
            let code = error.get("code").ok_or(Error::ImdsResponseError(
                "can't get code in error response".to_owned(),
            ))?;
            let message = error.get("message").ok_or(Error::ImdsResponseError(
                "can't get message in error response".to_owned(),
            ))?;

            Err(Error::ImdsResponseError(format!(
                "code: {}, message: {}, HTTP status code: {}",
                code.to_owned(),
                message.to_owned(),
                s
            )))
        }
    }
}

pub fn get_amd_cert_chain() -> Result<Vec<u8>, Error> {
    let url = reqwest::Url::from_str(IMDS_THIM_ENDPOINT)
        .map_err(|e| Error::ImdsResponseError(e.to_string()))?;

    let response = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?
        .get(url)
        .header("Metadata", "true")
        .send()?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let body = response
                .json::<serde_json::Map<String, serde_json::Value>>()
                .map_err(|_| Error::ImdsResponseError("can't deserialize JSON".to_owned()))?;

            // AMD SEV CA + AMD Root CA
            let cert_chain = body
                .get("certificateChain")
                .ok_or(Error::ImdsResponseError(
                    "failed to get certificate chain in IMDS response".to_owned(),
                ))?
                .as_str()
                .ok_or(Error::ImdsResponseError(
                    "Certificate chain is not a PEM string".to_owned(),
                ))?;

            // Version Chip-Endorsement Key (VCEK)
            // Certified by AMD SEV CA and signs the attestation report.
            let vcek = body
                .get("vcekCert")
                .ok_or(Error::ImdsResponseError(
                    "failed to get VCEK certificate in IMDS response".to_owned(),
                ))?
                .as_str()
                .ok_or(Error::ImdsResponseError(
                    "VCEK certificate is not a PEM string".to_owned(),
                ))?;

            Ok(format!("{vcek}{cert_chain}").as_bytes().to_vec())
        }
        s => Err(Error::ImdsResponseError(format!(
            "HTTP status code: {}, Body: {}",
            s,
            response.text()?
        ))),
    }
}
