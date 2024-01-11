use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SgxPckExtensionError {
    PEMParsingError,
    SgxPckExtensionNotFoundError,
    SgxPckParsingError,
    X509ParsingError,
}

impl fmt::Display for SgxPckExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PEMParsingError => "PEM parsing failed",
            Self::X509ParsingError => "X.509 parsing failed",
            Self::SgxPckExtensionNotFoundError => "SGX PCK extension not found",
            Self::SgxPckParsingError => "SGX PCK parsing failed",
        };
        write!(f, "{}", s)
    }
}
