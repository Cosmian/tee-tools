use crate::{quote::Quote, REPORT_DATA_SIZE};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHexOpt, Strict};

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the sev quote values
pub struct SevQuoteVerificationPolicy {
    /// Did the hypervisor set the guest up as you expected?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub measurement: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_data: Option<[u8; REPORT_DATA_SIZE]>,
    /// Is this the image you expected?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub family_id: Option<[u8; 16]>,
    /// Is this the image you expected?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub image_id: Option<[u8; 16]>,
    /// Is this the image you expected?
    pub guest_svn: Option<u32>,
    ///Is this you?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub id_key_digest: Option<[u8; 48]>,
    /// Is this you?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub author_key_digest: Option<[u8; 48]>,
    /// Is the policy what you expected?
    pub policy: Option<u64>,
    /// Did you expect a migration agent to be bound to this guest?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_id: Option<[u8; 32]>,
    /// Does the migration agent's attestation report check out?
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_id_ma: Option<[u8; 32]>,
}

impl From<&Quote> for SevQuoteVerificationPolicy {
    fn from(quote: &Quote) -> Self {
        SevQuoteVerificationPolicy {
            measurement: Some(quote.report.measurement),
            report_data: Some(quote.report.report_data),
            family_id: Some(quote.report.family_id),
            image_id: Some(quote.report.image_id),
            guest_svn: Some(quote.report.guest_svn),
            id_key_digest: Some(quote.report.id_key_digest),
            author_key_digest: Some(quote.report.author_key_digest),
            policy: Some(quote.report.policy.0),
            report_id: Some(quote.report.report_id),
            report_id_ma: Some(quote.report.report_id_ma),
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
