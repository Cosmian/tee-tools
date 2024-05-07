use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("RequestError: {0}")]
    RequestError(#[from] reqwest::Error),
    #[error("PccsResponseError: {0}")]
    PccsResponseError(String),
    #[error("UnexpectedError: {0}")]
    UnexpectedError(String),
    #[error("DecodeError: {0}")]
    DecodeError(String),
    #[error("URLError: {0}")]
    URLError(String),
}
