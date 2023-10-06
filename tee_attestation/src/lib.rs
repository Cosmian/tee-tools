use error::Error;
use sev_quote::quote::SEVQuote;
use sgx_quote::quote::Quote as SGXQuote;

pub mod error;

pub enum TeeType {
    Sgx,
    Sev,
}

pub enum TeeQuote {
    Sev(Box<SEVQuote>),
    Sgx(Box<SGXQuote>),
}

#[derive(Debug)]
pub struct SgxMeasurement {
    pub public_signer_key_pem: String,
    pub mr_enclave: [u8; 32],
}

#[derive(Debug)]
pub struct SevMeasurement(pub [u8; 48]);

#[derive(Default, Debug)]
pub struct TeeMeasurement {
    pub sgx: Option<SgxMeasurement>,
    pub sev: Option<SevMeasurement>,
}

/// Tell whether the platform is an SGX or an SEV processor
pub fn guess_tee() -> Result<TeeType, Error> {
    if sev_quote::is_sev() {
        return Ok(TeeType::Sev);
    }

    if sgx_quote::is_sgx() {
        return Ok(TeeType::Sgx);
    }

    Err(Error::UnsupportedTeeError)
}

/// Tell whether the current platform is a tee
pub fn is_running_inside_tee() -> bool {
    guess_tee().is_ok()
}

/// Parse a quote
pub fn parse_quote(raw_quote: &[u8]) -> Result<TeeQuote, Error> {
    if let Ok(quote) = bincode::deserialize(raw_quote) {
        return Ok(TeeQuote::Sev(Box::new(quote)));
    }

    if let Ok((quote, _, _, _)) = sgx_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Sgx(Box::new(quote)));
    }

    Err(Error::UnsupportedTeeError)
}

// Generate a quote for the current tee
#[cfg(target_os = "linux")]
pub fn get_quote(report_data: &[u8]) -> Result<Vec<u8>, Error> {
    match guess_tee()? {
        TeeType::Sev => {
            let quote = sev_quote::quote::get_quote(report_data)?;
            bincode::serialize(&quote)
                .map_err(|_| Error::InvalidFormat("Can't serialize the SEV quote".to_owned()))
        }
        TeeType::Sgx => Ok(sgx_quote::quote::get_quote(report_data)?),
    }
}

/// Verify a quote
pub fn verify_quote(
    raw_quote: &[u8],
    expected_report_data: &[u8],
    measurement: TeeMeasurement,
) -> Result<(), Error> {
    let quote = parse_quote(raw_quote)?;
    let report_data_length = expected_report_data.len();

    match quote {
        TeeQuote::Sev(quote) => {
            if &quote.report.report_data[..report_data_length] != expected_report_data {
                return Err(Error::VerificationFailure(
                    "Failed to verify the quote report data".to_owned(),
                ));
            }

            let measurement = if let Some(SevMeasurement(m)) = measurement.sev {
                Some(m)
            } else {
                None
            };

            // Verify the quote itself
            Ok(sev_quote::quote::verify_quote(
                &quote.report,
                &quote.certs,
                measurement,
            )?)
        }
        TeeQuote::Sgx(quote) => {
            if &quote.report_body.report_data[..report_data_length] != expected_report_data {
                return Err(Error::VerificationFailure(
                    "Failed to verify the quote report data".to_owned(),
                ));
            }

            let (mr_enclave, public_signer_key_pem) = if let Some(SgxMeasurement {
                public_signer_key_pem: s,
                mr_enclave: e,
            }) = measurement.sgx
            {
                (Some(e), Some(s))
            } else {
                (None, None)
            };

            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                raw_quote,
                mr_enclave,
                public_signer_key_pem.as_deref(),
            )?)
        }
    }
}

/// Get a key from the tee
#[cfg(target_os = "linux")]
pub fn get_key(salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    match guess_tee()? {
        TeeType::Sgx => Ok(sgx_quote::key::get_key(salt)?),
        TeeType::Sev => Ok(sev_quote::key::get_key(salt)?),
    }
}
