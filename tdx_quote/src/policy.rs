#[derive(Default, Debug)]
/// Values to compare with the tdx quote header values
pub struct TdxQuoteHeaderVerificationPolicy {
    pub minimum_qe_svn: Option<u16>,
    pub minimum_pce_svn: Option<u16>,
    pub qe_vendor_id: Option<[u8; 16]>,
}

#[derive(Default, Debug)]
/// Values to compare with the tdx quote header values
pub struct TdxQuoteBodyVerificationPolicy {
    pub minimum_tee_tcb_svn: Option<[u8; 16]>,
    pub mr_seam: Option<[u8; 48]>,
    pub td_attributes: Option<[u8; 8]>,
    pub xfam: Option<u64>,
    pub mr_td: Option<[u8; 48]>,
    pub mr_config_id: Option<[u8; 48]>,
    pub mr_owner: Option<[u8; 48]>,
    pub mr_owner_config: Option<[u8; 48]>,
    pub report_data: Option<[u8; 64]>,
}
#[derive(Default, Debug)]
/// Values to compare with the tdx quote values
pub struct TdxQuoteVerificationPolicy {
    pub header: TdxQuoteHeaderVerificationPolicy,
    pub body: TdxQuoteBodyVerificationPolicy,
}
