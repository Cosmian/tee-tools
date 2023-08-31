use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] openssl::error::ErrorStack),
    #[error("{0}")]
    InvalidFormat(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The attestation report is malformed")]
    QuoteMalformed,
    #[error(transparent)]
    RequestAPIError(#[from] reqwest::Error),
    #[error("{0}")]
    ResponseAPIError(String),
    #[error(transparent)]
    SevError(#[from] sev::error::UserApiError),
    #[error("{0}")]
    Unimplemented(String),
    #[error("{0}")]
    VerificationFailure(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
}
