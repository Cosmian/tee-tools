use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    DriverError(String),
    #[error("{0}")]
    CryptoError(String),
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
    #[error(transparent)]
    CryptoP256Error(#[from] p256::ecdsa::Error),
    #[error(transparent)]
    NixError(#[from] nix::errno::Errno),
    #[error(transparent)]
    SgxError(#[from] sgx_quote::error::Error),
}
