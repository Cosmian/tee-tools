use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    InvalidFormat(String),
    #[error(transparent)]
    SEVQuoteError(#[from] sev_quote::error::Error),
    #[error(transparent)]
    SGXQuoteError(#[from] sgx_quote::error::Error),
    #[error(transparent)]
    TDXQuoteError(#[from] tdx_quote::error::Error),
    #[error("Unsupported TEE type")]
    UnsupportedTeeError,
    #[error("VerificationFailure: {0}")]
    VerificationFailure(String),
}
