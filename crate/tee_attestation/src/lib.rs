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

pub const REPORT_DATA_SIZE: usize = 64;

#[derive(Debug)]
pub enum TeeType {
    AzSev,
    AzTdx,
    Sev,
    Sgx,
    Tdx,
}

impl std::fmt::Display for TeeType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            TeeType::AzSev => write!(f, "Azure SEV"),
            TeeType::AzTdx => write!(f, "Azure TDX"),
            TeeType::Sev => write!(f, "SEV"),
            TeeType::Sgx => write!(f, "SGX"),
            TeeType::Tdx => write!(f, "TDX"),
        }
    }
}

#[derive(Debug)]
pub enum TeeQuote {
    Sev(Box<SevQuote>),
    Sgx(Box<SgxQuote>),
    Tdx(Box<TdxQuote>),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum TeePolicy {
    Sgx(SgxQuoteVerificationPolicy),
    Sev(SevQuoteVerificationPolicy),
    Tdx(TdxQuoteVerificationPolicy),
}

impl TeePolicy {
    pub fn set_report_data(&mut self, report_data: &[u8]) -> Result<(), Error> {
        match self {
            TeePolicy::Sgx(sgx) => sgx.set_report_data(
                pad_report_data(report_data, sgx_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            ),
            TeePolicy::Tdx(tdx) => tdx.set_report_data(
                pad_report_data(report_data, tdx_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            ),
            TeePolicy::Sev(sev) => sev.set_report_data(
                pad_report_data(report_data, sev_quote::REPORT_DATA_SIZE)?
                    .try_into()
                    .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
            ),
        };

        Ok(())
    }
}

/// Build a `TeePolicy` from a given raw tee quote
impl TryFrom<&[u8]> for TeePolicy {
    type Error = Error;

    fn try_from(quote: &[u8]) -> Result<Self, Error> {
        let quote = parse_quote(quote)?;

        Ok(match quote {
            TeeQuote::Sev(quote) => {
                TeePolicy::Sev(SevQuoteVerificationPolicy::from(quote.as_ref()))
            }

            TeeQuote::Sgx(quote) => {
                TeePolicy::Sgx(SgxQuoteVerificationPolicy::from(quote.as_ref()))
            }

            TeeQuote::Tdx(quote) => {
                TeePolicy::Tdx(TdxQuoteVerificationPolicy::from(quote.as_ref()))
            }
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

    if let Some(report_type) = azure_cvm::is_az_cvm() {
        match report_type {
            azure_cvm::ReportType::Snp => return Ok(TeeType::AzSev),
            azure_cvm::ReportType::Tdx => return Ok(TeeType::AzTdx),
        }
    }

    Err(Error::UnsupportedTeeError)
}

/// Tell whether the current platform is a tee
#[must_use]
pub fn is_running_inside_tee() -> bool {
    guess_tee().is_ok()
}

/// Parse a quote
pub fn parse_quote(raw_quote: &[u8]) -> Result<TeeQuote, Error> {
    if let Ok((quote, _, _, _)) = sgx_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Sgx(Box::new(quote)));
    }

    if let Ok((quote, _)) = tdx_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Tdx(Box::new(quote)));
    }

    if let Ok(quote) = sev_quote::quote::parse_quote(raw_quote) {
        return Ok(TeeQuote::Sev(Box::new(quote)));
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
pub fn get_quote(report_data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let report_data = if let Some(data) = report_data {
        pad_report_data(data, REPORT_DATA_SIZE)?
    } else {
        vec![0u8; REPORT_DATA_SIZE]
    };

    if let Ok(tee) = guess_tee() {
        match tee {
            TeeType::Sev => {
                return Ok(sev_quote::quote::get_quote(
                    &report_data
                        .try_into()
                        .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
                )?)
            }
            TeeType::Sgx => {
                return Ok(sgx_quote::quote::get_quote(
                    &report_data
                        .try_into()
                        .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
                )?)
            }
            TeeType::Tdx => {
                return Ok(tdx_quote::quote::get_quote(
                    &report_data
                        .try_into()
                        .map_err(|_| Error::InvalidFormat("Report data malformed".to_owned()))?,
                )?)
            }
            TeeType::AzSev | TeeType::AzTdx => {
                // No low-level access to the device on Microsoft Azure!
                // SEV or TDX quote is stored in the vTPM at boot time
                if let Ok(raw_hcl_report) = azure_cvm::tpm::get_hcl_report() {
                    let hcl_report = azure_cvm::HclReport::new(raw_hcl_report)?;

                    match hcl_report.report_type() {
                        azure_cvm::ReportType::Snp => {
                            let mut snp_report = hcl_report.report_slice().to_vec();
                            let amd_cert_chain = azure_cvm::imds::get_amd_cert_chain()?;
                            snp_report.extend(amd_cert_chain);
                            return Ok(snp_report);
                        }
                        azure_cvm::ReportType::Tdx => {
                            let td_report: azure_cvm::attestation_report::TdReport =
                                hcl_report.try_into().map_err(|_| {
                                    Error::InvalidFormat(
                                        "failed to parse Intel TD report".to_owned(),
                                    )
                                })?;
                            return Ok(azure_cvm::imds::get_td_quote(&td_report)?);
                        }
                    }
                } else {
                    return Err(Error::UnsupportedTeeError);
                }
            }
        }
    }

    Err(Error::UnsupportedTeeError)
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

pub fn az_verify_quote(raw_quote: &[u8], policy: &TeePolicy) -> Result<(), Error> {
    let maa_url: &str = "https://sharedweu.weu.attest.azure.net";

    match policy {
        TeePolicy::Sev(p) => {
            let report = &raw_quote[0..azure_cvm::SNP_REPORT_SIZE];
            let amd_cert_chain = maa_client::utils::parse_certificate_chain(raw_quote).join("");
            let sev_claim =
                maa_client::verify_sev_quote(maa_url, report, amd_cert_chain.as_bytes())?;

            if let Some(expected_report_data) = p.report_data {
                let report_data =
                    hex::decode(sev_claim.x_ms_sevsnpvm_reportdata).map_err(|_| {
                        Error::InvalidFormat(
                            "failed to decode hex value from MAA response".to_owned(),
                        )
                    })?;
                if expected_report_data != *report_data {
                    return Err(Error::VerificationFailure(
                        "REPORT_DATA doesn't match policy".to_owned(),
                    ));
                }
            }

            Ok(())
        }
        TeePolicy::Sgx(_) => Err(Error::UnsupportedTeeError),
        TeePolicy::Tdx(p) => {
            let tdx_claim = maa_client::verify_tdx_quote(maa_url, raw_quote)?;
            if let Some(expected_report_data) = p.body.report_data {
                let report_data = hex::decode(tdx_claim.tdx_report_data).map_err(|_| {
                    Error::InvalidFormat("failed to decode hex value from MAA response".to_owned())
                })?;
                if expected_report_data != *report_data {
                    return Err(Error::VerificationFailure(
                        "REPORT_DATA doesn't match policy".to_owned(),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// Verify a quote
pub fn verify_quote(raw_quote: &[u8], policy: Option<&TeePolicy>) -> Result<(), Error> {
    let quote = parse_quote(raw_quote)?;

    match (&quote, policy) {
        (TeeQuote::Sev(quote), None) => {
            // Verify the quote itself
            Ok(sev_quote::quote::verify_quote(
                quote,
                &SevQuoteVerificationPolicy::default(),
            )?)
        }
        (TeeQuote::Sev(quote), Some(TeePolicy::Sev(p))) => {
            // Verify the quote itself
            Ok(sev_quote::quote::verify_quote(quote, p)?)
        }
        (TeeQuote::Sgx(_), None) => {
            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                raw_quote,
                &SgxQuoteVerificationPolicy::default(),
            )?)
        }
        (TeeQuote::Sgx(_), Some(TeePolicy::Sgx(p))) => {
            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(raw_quote, p)?)
        }
        (TeeQuote::Tdx(_), None) => {
            // Verify the quote itself
            Ok(tdx_quote::quote::verify_quote(
                raw_quote,
                &TdxQuoteVerificationPolicy::default(),
            )?)
        }
        (TeeQuote::Tdx(_), Some(TeePolicy::Tdx(p))) => {
            // Verify the quote itself
            Ok(tdx_quote::quote::verify_quote(raw_quote, p)?)
        }
        (_, _) => Err(Error::VerificationFailure(format!(
            "Bad policy type provided for this quote: {quote:?}"
        ))),
    }
}

/// Get a key from the tee
#[cfg(target_os = "linux")]
pub fn get_key(salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    match guess_tee()? {
        TeeType::Sgx => Ok(sgx_quote::key::get_key(salt)?),
        TeeType::Sev => Ok(sev_quote::key::get_key(salt)?),
        TeeType::Tdx | TeeType::AzSev | TeeType::AzTdx => Err(Error::UnsupportedTeeError),
    }
}
