use serde::{Deserialize, Serialize};
use serde_hex::{SerHexOpt, Strict};

use crate::{quote::Quote, REPORT_DATA_SIZE};

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the tdx quote header values
pub struct TdxQuoteHeaderVerificationPolicy {
    pub minimum_qe_svn: Option<u16>,
    pub minimum_pce_svn: Option<u16>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub qe_vendor_id: Option<[u8; 16]>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the tdx quote header values
pub struct TdxQuoteBodyVerificationPolicy {
    #[serde(with = "SerHexOpt::<Strict>")]
    pub minimum_tee_tcb_svn: Option<[u8; 16]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_seam: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub td_attributes: Option<[u8; 8]>,
    pub xfam: Option<u64>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_td: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_config_id: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_owner: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_owner_config: Option<[u8; 48]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_data: Option<[u8; REPORT_DATA_SIZE]>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the tdx quote values
pub struct TdxQuoteVerificationPolicy {
    pub header: TdxQuoteHeaderVerificationPolicy,
    pub body: TdxQuoteBodyVerificationPolicy,
}

impl From<&Quote> for TdxQuoteVerificationPolicy {
    fn from(quote: &Quote) -> Self {
        TdxQuoteVerificationPolicy {
            header: TdxQuoteHeaderVerificationPolicy {
                minimum_qe_svn: Some(quote.header.qe_svn),
                minimum_pce_svn: Some(quote.header.pce_svn),
                qe_vendor_id: Some(quote.header.vendor_id),
            },
            body: TdxQuoteBodyVerificationPolicy {
                minimum_tee_tcb_svn: Some(quote.report_body.tee_tcb_svn),
                mr_seam: Some(quote.report_body.mr_seam),
                td_attributes: Some(quote.report_body.td_attributes),
                xfam: Some(quote.report_body.xfam),
                mr_td: Some(quote.report_body.mr_td),
                mr_config_id: Some(quote.report_body.mr_config_id),
                mr_owner: Some(quote.report_body.mr_owner),
                mr_owner_config: Some(quote.report_body.mr_owner_config),
                report_data: Some(quote.report_body.report_data),
            },
        }
    }
}

impl TdxQuoteVerificationPolicy {
    pub fn new() -> Self {
        TdxQuoteVerificationPolicy {
            header: TdxQuoteHeaderVerificationPolicy::default(),
            body: TdxQuoteBodyVerificationPolicy {
                ..Default::default()
            },
        }
    }

    pub fn set_report_data(&mut self, report_data: [u8; REPORT_DATA_SIZE]) {
        self.body.report_data = Some(report_data);
    }
}
