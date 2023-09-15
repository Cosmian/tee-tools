use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ConnectionError")]
    ConnectionError,
    #[error("DNSNameError")]
    DNSNameError,
    #[error("Unsupported TEE type")]
    UnsupportedTeeError,
    #[error("Unsupported TEE type")]
    Asn1Error,
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
    #[error("VerificationFailure: {0}")]
    VerificationFailure(String),
    #[error("RatlsError: {0}")]
    RatlsError(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
}
