use serde::{Deserialize, Serialize};
use serde_hex::{SerHexOpt, Strict};

use crate::{
    error::Error, mrsigner::compute_mr_signer, quote::Quote, MRENCLAVE_SIZE, MRSIGNER_SIZE,
    REPORT_DATA_SIZE,
};

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the sgx quote header values
pub struct SgxQuoteHeaderVerificationPolicy {
    pub minimum_qe_svn: Option<u16>,
    pub minimum_pce_svn: Option<u16>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub qe_vendor_id: Option<[u8; 16]>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the sgx quote header values
pub struct SgxQuoteBodyVerificationPolicy {
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_enclave: Option<[u8; MRENCLAVE_SIZE]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub mr_signer: Option<[u8; MRSIGNER_SIZE]>,
    #[serde(with = "SerHexOpt::<Strict>")]
    pub report_data: Option<[u8; REPORT_DATA_SIZE]>,
}

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Copy)]
/// Values to compare with the sgx quote values
pub struct SgxQuoteVerificationPolicy {
    pub header: SgxQuoteHeaderVerificationPolicy,
    pub body: SgxQuoteBodyVerificationPolicy,
}

impl From<&Quote> for SgxQuoteVerificationPolicy {
    fn from(quote: &Quote) -> Self {
        SgxQuoteVerificationPolicy {
            header: SgxQuoteHeaderVerificationPolicy {
                minimum_qe_svn: Some(quote.header.qe_svn),
                minimum_pce_svn: Some(quote.header.pce_svn),
                qe_vendor_id: Some(quote.header.vendor_id),
            },
            body: SgxQuoteBodyVerificationPolicy {
                mr_signer: Some(quote.report_body.mr_signer),
                mr_enclave: Some(quote.report_body.mr_enclave),
                report_data: Some(quote.report_body.report_data),
            },
        }
    }
}

impl SgxQuoteVerificationPolicy {
    pub fn new(
        mr_enclave: [u8; MRENCLAVE_SIZE],
        pem_public_enclave_cert: &str,
    ) -> Result<Self, Error> {
        Ok(SgxQuoteVerificationPolicy {
            header: SgxQuoteHeaderVerificationPolicy::default(),
            body: SgxQuoteBodyVerificationPolicy {
                mr_enclave: Some(mr_enclave),
                mr_signer: Some(compute_mr_signer(pem_public_enclave_cert)?),
                ..Default::default()
            },
        })
    }

    pub fn set_report_data(&mut self, report_data: [u8; REPORT_DATA_SIZE]) {
        self.body.report_data = Some(report_data);
    }
}
