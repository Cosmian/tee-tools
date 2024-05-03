use thiserror::Error;

/// Error type.
#[derive(Error, Debug)]
pub enum Error {
    #[error("BadURLError: {0}")]
    BadURLError(String),
    #[error("CvmVerificationError: {0}")]
    CvmVerificationError(String),
    #[error("DecodeError: {0}")]
    DecodeError(String),
    #[error("DeserError: {0}")]
    DeserError(#[from] serde_json::Error),
    #[error("MaaResponseError: {0}")]
    MaaResponseError(String),
    #[error("RequestError: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("SgxVerificationError: {0}")]
    SgxVerificationError(String),
    #[error("UnexpectedError: {0}")]
    UnexpectedError(String),
}
