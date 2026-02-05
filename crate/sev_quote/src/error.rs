use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    CryptoError(String),
    #[error("{0}")]
    InvalidFormat(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("The attestation report is malformed")]
    QuoteError,
    #[error("Failed to parse certificates in quote")]
    QuoteCertError,
    #[error(transparent)]
    RequestAPIError(#[from] reqwest::Error),
    #[error("{0}")]
    ResponseAPIError(String),
    #[error(transparent)]
    SevError(#[from] sev::error::UserApiError),
    #[error("{0}")]
    Unimplemented(String),
    #[error("URLError: {0}")]
    URLError(String),
    #[error("{0}")]
    VerificationFailure(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error(transparent)]
    X509DerParserError(#[from] asn1_rs::Err<x509_parser::error::X509Error>),
}
