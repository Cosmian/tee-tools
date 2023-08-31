use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] openssl::error::ErrorStack),
    #[error("{0}")]
    InvalidFormat(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ReadError(#[from] scroll::Error),
    #[error("{0}")]
    Unimplemented(String),
    #[error("{0}")]
    VerificationFailure(String),
}
