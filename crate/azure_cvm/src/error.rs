use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("AkPub not found")]
    AkPubNotFound,
    #[error("BadURLError: {0}")]
    BadURLError(String),
    #[error("binary parse error")]
    BinaryParseError(#[from] bincode::Error),
    #[error("DecodeError: {0}")]
    DecodeError(#[from] base64::DecodeError),
    #[error("ImdsResponseError: {0}")]
    ImdsResponseError(String),
    #[error("invalid report type")]
    InvalidReportType,
    #[error("JsonDecodeError: {0}")]
    JsonDecodeError(String),
    #[error("JSON parse error")]
    JsonParseError(#[from] serde_json::Error),
    #[error("ReqwestError: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Tss2Error: {0}")]
    Tss2Error(#[from] tss_esapi::Error),
}
