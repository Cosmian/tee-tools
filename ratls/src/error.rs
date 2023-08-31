use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ConnectionError")]
    ConnectionError,
    #[error(transparent)]
    CryptoError(#[from] openssl::error::ErrorStack),
    #[error("DNSNameError")]
    DNSNameError,
    #[error("Can't guess the current platform type")]
    InvalidPlatform,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("{0}")]
    InvalidFormat(String),
    #[error("ServerCertificateError")]
    ServerCertificateError,
    #[error(transparent)]
    SEVQuoteError(#[from] sev_quote::error::Error),
    #[error(transparent)]
    SGXQuoteError(#[from] sgx_quote::error::Error),
    #[error("{0}")]
    VerificationFailure(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
}
