#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg(feature = "wasm")]
use crate::quote::parse_quote;

#[cfg(feature = "wasm")]
#[wasm_bindgen(inspectable, getter_with_clone)]
#[derive(Clone)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub reserved: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub vendor_id: Vec<u8>,
    pub user_data: Vec<u8>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(inspectable, getter_with_clone)]
#[derive(Clone)]
pub struct ReportBody {
    pub cpu_svn: Vec<u8>,
    pub misc_select: u32,
    pub reserved1: Vec<u8>,
    pub isv_ext_prod_id: Vec<u8>,
    pub flags: u64,
    pub xfrm: u64,
    pub mr_enclave: Vec<u8>,
    pub reserved2: Vec<u8>,
    pub mr_signer: Vec<u8>,
    pub reserved3: Vec<u8>,
    pub config_id: Vec<u8>,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub config_svn: u16,
    pub reserved4: Vec<u8>,
    pub isv_family_id: Vec<u8>,
    pub report_data: Vec<u8>,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen(inspectable, getter_with_clone)]
#[derive(Clone)]
pub struct Quote {
    pub header: QuoteHeader,
    pub report_body: ReportBody,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl Quote {
    #[wasm_bindgen(constructor)]
    pub fn new(raw_quote: &[u8]) -> Result<Quote, JsValue> {
        let (quote, _, _, _) =
            parse_quote(raw_quote).map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(Quote {
            header: QuoteHeader {
                version: quote.header.version,
                att_key_type: quote.header.att_key_type,
                reserved: quote.header.reserved,
                qe_svn: quote.header.qe_svn,
                pce_svn: quote.header.pce_svn,
                vendor_id: quote.header.vendor_id.to_vec(),
                user_data: quote.header.user_data.to_vec(),
            },
            report_body: ReportBody {
                cpu_svn: quote.report_body.cpu_svn.to_vec(),
                misc_select: quote.report_body.misc_select,
                reserved1: quote.report_body.reserved1.to_vec(),
                isv_ext_prod_id: quote.report_body.isv_ext_prod_id.to_vec(),
                flags: quote.report_body.flags,
                xfrm: quote.report_body.xfrm,
                mr_enclave: quote.report_body.mr_enclave.to_vec(),
                reserved2: quote.report_body.reserved2.to_vec(),
                mr_signer: quote.report_body.mr_signer.to_vec(),
                reserved3: quote.report_body.reserved3.to_vec(),
                config_id: quote.report_body.config_id.to_vec(),
                isv_prod_id: quote.report_body.isv_prod_id,
                isv_svn: quote.report_body.isv_svn,
                config_svn: quote.report_body.config_svn,
                reserved4: quote.report_body.reserved4.to_vec(),
                isv_family_id: quote.report_body.isv_family_id.to_vec(),
                report_data: quote.report_body.report_data.to_vec(),
            },
        })
    }
}
