use error::Error;
use sev_quote::quote::SEVQuote;
use sgx_quote::{mrsigner::compute_mr_signer, quote::Quote as SGXQuote};
use sha2::{Digest, Sha256};
use tdx_quote::policy::TdxQuoteVerificationPolicy;
use tdx_quote::quote::Quote as TDXQuote;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub mod error;

pub enum TeeType {
    Sgx,
    Sev,
    Tdx,
}

pub enum TeeQuote {
    Sev(Box<SEVQuote>),
    Sgx(Box<SGXQuote>),
    Tdx(Box<TDXQuote>),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SgxMeasurement {
    pub mr_signer: [u8; 32],
    pub mr_enclave: [u8; 32],
}

impl TryFrom<(&[u8; 32], &str)> for SgxMeasurement {
    type Error = Error;
    fn try_from(attr: (&[u8; 32], &str)) -> Result<Self, Error> {
        Ok(SgxMeasurement {
            mr_enclave: *attr.0,
            mr_signer: compute_mr_signer(attr.1)?
                .as_slice()
                .try_into()
                .map_err(|e| {
                    Error::InvalidFormat(format!("MRSIGNER does not have the expected size: {e}"))
                })?,
        })
    }
}
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct SevMeasurement(
    #[serde(serialize_with = "as_hex", deserialize_with = "from_hex")] pub [u8; 48],
);

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct TeeMeasurement {
    pub sgx: Option<SgxMeasurement>,
    pub sev: Option<SevMeasurement>,
    pub tdx: Option<TdxQuoteVerificationPolicy>,
}

/// Serializes `buffer` to a lowercase hex string.
pub fn as_hex<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(buffer))
}

/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub fn from_hex<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        hex::decode(string)
            .map_err(|err| Error::custom(err.to_string()))?
            .try_into()
            .map_err(|_| Error::custom("Not enought bytes found when deserializing"))
    })
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

/// Return the expected measurement read from the quote
pub fn get_measurement(raw_quote: &[u8]) -> Result<TeeMeasurement, Error> {
    let quote = parse_quote(raw_quote)?;
    match quote {
        TeeQuote::Sev(quote) => Ok(TeeMeasurement {
            sev: Some(SevMeasurement(quote.report.measurement)),
            sgx: None,
        }),
        TeeQuote::Sgx(quote) => Ok(TeeMeasurement {
            sev: None,
            sgx: Some(SgxMeasurement {
                mr_signer: quote.report_body.mr_signer,
                mr_enclave: quote.report_body.mr_enclave,
            }),
        }),
    }
}

/// Parse a quote
pub fn parse_quote(raw_quote: &[u8]) -> Result<TeeQuote, Error> {
    if let Ok(quote) = bincode::deserialize(raw_quote) {
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
        TeeType::Sev => {
            let quote = sev_quote::quote::get_quote(report_data)?;
            bincode::serialize(&quote)
                .map_err(|_| Error::InvalidFormat("Can't serialize the SEV quote".to_owned()))
        }
        TeeType::Sgx => Ok(sgx_quote::quote::get_quote(report_data)?),
        TeeType::Tdx => Ok(tdx_quote::quote::get_quote(report_data)?),
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

            let (mr_enclave, mr_signer) = if let Some(SgxMeasurement {
                mr_signer: s,
                mr_enclave: e,
            }) = measurement.sgx
            {
                (Some(e), Some(s))
            } else {
                (None, None)
            };

            // Verify the quote itself
            Ok(sgx_quote::quote::verify_quote(
                raw_quote, mr_enclave, mr_signer,
            )?)
        }
        TeeQuote::Tdx(_) => {
            // Verify the quote itself
            Ok(tdx_quote::quote::verify_quote(
                raw_quote,
                &measurement
                    .tdx
                    .map_or_else(TdxQuoteVerificationPolicy::default, |m| m),
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
