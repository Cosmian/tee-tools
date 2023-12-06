use error::Error;
// Reexport sev policies
pub use sev_quote::policy::SevQuoteVerificationPolicy;
use sev_quote::quote::Quote as SevQuote;
// Reexport sgx policies
pub use sgx_quote::policy::{
    SgxQuoteBodyVerificationPolicy, SgxQuoteHeaderVerificationPolicy, SgxQuoteVerificationPolicy,
};
use sgx_quote::quote::Quote as SgxQuote;
use sha2::{Digest, Sha256};
// Reexport tdx policies
pub use tdx_quote::policy::{
    TdxQuoteBodyVerificationPolicy, TdxQuoteHeaderVerificationPolicy, TdxQuoteVerificationPolicy,
};
use tdx_quote::quote::Quote as TdxQuote;

use serde::{Deserialize, Serialize};

pub mod error;

pub enum TeeType {
    Sgx,
    Sev,
    Tdx,
}

pub enum TeeQuote {
    Sev(Box<SevQuote>),
    Sgx(Box<SgxQuote>),
    Tdx(Box<TdxQuote>),
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TeePolicy {
    pub sgx: Option<SgxQuoteVerificationPolicy>,
    pub sev: Option<SevQuoteVerificationPolicy>,
    pub tdx: Option<TdxQuoteVerificationPolicy>,
}

impl TeePolicy {
    pub fn set_report_data(&mut self, report_data: &[u8]) -> Result<(), Error> {
        if let Some(sgx) = &mut self.sgx {
            sgx.set_report_data(
                pad_report_data(report_data, sgx_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            )
        }

        if let Some(tdx) = &mut self.tdx {
            tdx.set_report_data(
                pad_report_data(report_data, tdx_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            )
        }

        if let Some(sev) = &mut self.sev {
            sev.set_report_data(
                pad_report_data(report_data, sev_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            )
        }

        Ok(())
    }
}

/// Build a TeePolicy from a given raw tee quote
impl TryFrom<&[u8]> for TeePolicy {
    type Error = Error;

    fn try_from(quote: &[u8]) -> Result<Self, Error> {
        let quote = parse_quote(quote)?;

        Ok(match quote {
            TeeQuote::Sev(quote) => TeePolicy {
                sev: Some(SevQuoteVerificationPolicy::from(quote.as_ref())),
                ..Default::default()
            },
            TeeQuote::Sgx(quote) => TeePolicy {
                sgx: Some(SgxQuoteVerificationPolicy::from(quote.as_ref())),
                ..Default::default()
            },
            TeeQuote::Tdx(quote) => TeePolicy {
                tdx: Some(TdxQuoteVerificationPolicy::from(quote.as_ref())),
                ..Default::default()
            },
        })
    }
}

/// Tell whether the platform is an SGX or an SEV processor
pub fn guess_tee() -> Result<TeeType, Error> {
    if sev_quote::is_sev() {
        return Ok(TeeType::Sev);
    }

    if tdx_quote::is_tdx() {
        return Ok(TeeType::Tdx);
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
    if let Ok(quote) = sev_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Sev(Box::new(quote)));
    }

    if let Ok((quote, _, _, _)) = sgx_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Sgx(Box::new(quote)));
    }

    if let Ok((quote, _)) = tdx_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Tdx(Box::new(quote)));
    }

    Err(Error::UnsupportedTeeError)
}

/// Forge a report data by using a 32-bytes nonce and a sha256(data)
pub fn forge_report_data_with_nonce(nonce: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, Error> {
    // user_report_data = ( sha256(data) || 32bytes_nonce )
    let mut user_report_data = nonce.to_vec();

    let mut hasher = Sha256::new();
    hasher.update(data);
    user_report_data.extend(hasher.finalize());

    Ok(user_report_data)
}

/// Generate a quote for the current tee
#[cfg(target_os = "linux")]
pub fn get_quote(report_data: &[u8]) -> Result<Vec<u8>, Error> {
    match guess_tee()? {
        TeeType::Sev => Ok(sev_quote::quote::get_quote(
            &pad_report_data(report_data, sev_quote::REPORT_DATA_SIZE)?
                .try_into()
                .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
        )?),
        TeeType::Sgx => Ok(sgx_quote::quote::get_quote(
            &pad_report_data(report_data, sgx_quote::REPORT_DATA_SIZE)?
                .try_into()
                .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
        )?),
        TeeType::Tdx => Ok(tdx_quote::quote::get_quote(
            &pad_report_data(report_data, tdx_quote::REPORT_DATA_SIZE)?
                .try_into()
                .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
        )?),
    }
}

fn pad_report_data(report_data: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if report_data.len() > length {
        return Err(Error::InvalidFormat(format!(
            "user_report_data must be at most {length} bytes"
        )));
    }

    let mut inner_user_report_data = vec![0u8; length];
    inner_user_report_data[0..report_data.len()].copy_from_slice(report_data);
    Ok(inner_user_report_data)
}

/// Verify a quote
pub fn verify_quote(raw_quote: &[u8], policy: &TeePolicy) -> Result<(), Error> {
    let quote = parse_quote(raw_quote)?;

    match quote {
        TeeQuote::Sev(quote) => {
            // Verify the quote itself
            Ok(sev_quote::quote::verify_quote(
                &quote,
                &policy
                    .sev
                    .as_ref()
                    .map_or_else(SevQuoteVerificationPolicy::default, |p| p.clone()),
            )?)
        }
        TeeQuote::Sgx(_) => {
            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                raw_quote,
                &policy
                    .sgx
                    .as_ref()
                    .map_or_else(SgxQuoteVerificationPolicy::default, |p| p.clone()),
            )?)
        }
        TeeQuote::Tdx(_) => {
            // Verify the quote itself
            Ok(tdx_quote::quote::verify_quote(
                raw_quote,
                &policy
                    .tdx
                    .as_ref()
                    .map_or_else(TdxQuoteVerificationPolicy::default, |p| p.clone()),
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
        TeeType::Tdx => Err(Error::UnsupportedTeeError),
    }
}
