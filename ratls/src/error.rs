use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    CryptoError(#[from] openssl::error::ErrorStack),
    #[error("{0}")]
    InvalidFormat(String),
    #[error("{0}")]
    VerificationFailure(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error(transparent)]
    SGXQuoteError(#[from] sgx_quote::error::Error),
    #[error("ConnectionError")]
    ConnectionError,
    #[error("DNSNameError")]
    DNSNameError,
    #[error("ServerCertificateError")]
    ServerCertificateError,
}
