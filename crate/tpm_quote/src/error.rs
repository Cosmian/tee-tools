use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("AttestationError: {0}")]
    AttestationError(String),
    #[error("CryptoError: {0}")]
    CryptoError(String),
    #[error("QuoteError: {0}")]
    QuoteError(String),
    #[error("SignatureError: {0}")]
    SignatureError(#[from] p256::ecdsa::signature::Error),
    #[error("TpmError: {0}")]
    TpmError(String),
    #[error("Tss2Error: {0}")]
    Tss2Error(#[from] tss_esapi::Error),
    #[error("VerificationError: {0}")]
    VerificationError(String),
}
