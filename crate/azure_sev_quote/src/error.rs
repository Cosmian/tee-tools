use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    QuoteError(String),
    #[error("{0}")]
    TpmError(String),
    #[error("Tss2Error: {0}")]
    Tss2Error(#[from] tss_esapi::Error),
}
