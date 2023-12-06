use crate::{quote::Quote, REPORT_DATA_SIZE};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHexOpt, Strict};

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq)]
/// Values to compare with the sgx quote values
pub struct SevQuoteVerificationPolicy {
    #[serde(with = "SerHexOpt::<Strict>")]
    pub measurement: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_data: Option<[u8; REPORT_DATA_SIZE]>,
}

impl From<&Quote> for SevQuoteVerificationPolicy {
    fn from(quote: &Quote) -> Self {
        SevQuoteVerificationPolicy {
            measurement: Some(quote.report.measurement),
            report_data: Some(quote.report.report_data),
        }
    }
}

impl SevQuoteVerificationPolicy {
    pub fn new(measurement: [u8; 48]) -> Self {
        SevQuoteVerificationPolicy {
            measurement: Some(measurement),
            ..Default::default()
        }
    }

    pub fn set_report_data(&mut self, report_data: [u8; REPORT_DATA_SIZE]) {
        self.report_data = Some(report_data);
    }
}
