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
    #[error("Invalid quote report data length")]
    InvalidQuoteReportData,
    #[error("ServerCertificateError")]
    ServerCertificateError,
    #[error(transparent)]
    TeeAttestationError(#[from] tee_attestation::error::Error),
    #[error("VerificationFailure: {0}")]
    VerificationFailure(String),
    #[error("RatlsError: {0}")]
    RatlsError(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error(transparent)]
    SpkiParserError(#[from] spki::Error),
    #[error(transparent)]
    EcdsaError(#[from] ecdsa::elliptic_curve::Error),
}
