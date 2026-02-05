use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    CryptoError(String),
    #[error("{0}")]
    InvalidFormat(String),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    PccsClientError(#[from] pccs_client::error::Error),
    #[error(transparent)]
    ReadError(#[from] scroll::Error),
    #[error("{0}")]
    ResponseAPIError(String),
    #[error("{0}")]
    Unimplemented(String),
    #[error("{0}")]
    VerificationFailure(String),
    #[error(transparent)]
    X509PemParserError(#[from] x509_parser::nom::Err<x509_parser::error::PEMError>),
    #[error(transparent)]
    X509DerParserError(#[from] x509_parser::der_parser::error::Error),
    #[error(transparent)]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error(transparent)]
    SgxPckExtensionError(#[from] sgx_pck_extension::error::SgxPckExtensionError),
    #[error(transparent)]
    CryptoP256Error(#[from] p256::ecdsa::Error),
    #[error(transparent)]
    SpkiError(#[from] spki::Error),
    #[error(transparent)]
    PemError(#[from] pem::PemError),
}
