use std::fmt;

#[derive(Debug)]
pub enum SGXQuoteError {
    ParsingHeaderError,
    ParsingReportBodyError,
    ParsingEcdsaSigDataError,
    ParsingAuthDataError,
    ParsingCertDataError,
}

impl fmt::Display for SGXQuoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ParsingHeaderError => "parsing quote header failed",
            Self::ParsingReportBodyError => "parsing quote report body failed",
            Self::ParsingEcdsaSigDataError => "parsing ECDSA sig data failed",
            Self::ParsingAuthDataError => "parsing quote auth data failed",
            Self::ParsingCertDataError => "parsing quote certification data failed",
        };
        write!(f, "{}", s)
    }
}
