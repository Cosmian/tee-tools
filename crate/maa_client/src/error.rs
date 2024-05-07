use thiserror::Error;

/// Error type.
#[derive(Error, Debug)]
pub enum Error {
    #[error("RequestError: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("MaaResponseError: {0}")]
    MaaResponseError(String),
    #[error("UnexpectedError: {0}")]
    UnexpectedError(String),
    #[error("DecodeError: {0}")]
    DecodeError(String),
    #[error("BadURLError: {0}")]
    BadURLError(String),
    #[error("SgxVerificationError: {0}")]
    SgxVerificationError(String),
}
