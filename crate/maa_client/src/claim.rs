use crate::utils::base64url_serde;

use serde::{Deserialize, Serialize};

/// Sub-structure of [`SgxClaim`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxCollateral {
    #[serde(with = "hex::serde")]
    pub qeidcertshash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub qeidcrlhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub qeidhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub quotehash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfocertshash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfocrlhash: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub tcbinfohash: Vec<u8>,
}

/// Sub-structure of [`SgxClaim`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxPolicy {
    pub is_debuggable: bool,
    pub product_id: u32,
    #[serde(with = "hex::serde")]
    pub sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sgx_mrsigner: Vec<u8>,
    pub svn: u32,
    pub tee: String,
}

/// SGX claim returned by MAA API.
///
/// # External documentation
///
/// See [`Examples of an attestation token`].
///
/// [`Examples of an attestation token`]: https://learn.microsoft.com/en-us/azure/attestation/attestation-token-examples
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SgxClaim {
    #[serde(with = "base64url_serde")]
    pub maa_ehd: Vec<u8>,
    pub is_debuggable: bool,
    pub maa_attestationcollateral: SgxCollateral,
    pub product_id: u64,
    #[serde(with = "hex::serde")]
    pub sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub sgx_mrsigner: Vec<u8>,
    pub svn: u32,
    pub tee: String,
    pub x_ms_attestation_type: String,
    pub x_ms_policy: SgxPolicy,
    pub x_ms_policy_hash: String,
    pub x_ms_sgx_collateral: SgxCollateral,
    pub x_ms_sgx_is_debuggable: bool,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrenclave: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub x_ms_sgx_mrsigner: Vec<u8>,
    pub x_ms_sgx_product_id: u16,
    pub x_ms_sgx_svn: u16,
    pub x_ms_ver: String,
}

/// AMD SEV-SNP claim returned by MAA API.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SevClaim {
    pub x_ms_attestation_type: String,
    #[serde(default)]
    pub x_ms_compliance_status: Option<String>,
    pub x_ms_policy_hash: String,
    pub x_ms_sevsnpvm_authorkeydigest: String,
    pub x_ms_sevsnpvm_bootloader_svn: u32,
    #[serde(rename = "x-ms-sevsnpvm-familyId")]
    pub x_ms_sevsnpvm_family_id: String,
    pub x_ms_sevsnpvm_guestsvn: u32,
    pub x_ms_sevsnpvm_hostdata: String,
    pub x_ms_sevsnpvm_idkeydigest: String,
    #[serde(rename = "x-ms-sevsnpvm-imageId")]
    pub x_ms_sevsnpvm_image_id: String,
    pub x_ms_sevsnpvm_is_debuggable: bool,
    pub x_ms_sevsnpvm_launchmeasurement: String,
    pub x_ms_sevsnpvm_microcode_svn: u32,
    pub x_ms_sevsnpvm_migration_allowed: bool,
    pub x_ms_sevsnpvm_reportdata: String,
    pub x_ms_sevsnpvm_reportid: String,
    pub x_ms_sevsnpvm_smt_allowed: bool,
    pub x_ms_sevsnpvm_snpfw_svn: u32,
    pub x_ms_sevsnpvm_tee_svn: u32,
    pub x_ms_sevsnpvm_vmpl: u32,
    pub x_ms_ver: String,
}

/// Intel TDX claim returned by MAA API.
#[derive(Debug, Serialize, Deserialize)]
pub struct TdxClaim {
    pub attester_tcb_status: String,
    pub dbgstat: String,
    pub eat_profile: String,
    pub intuse: String,
    pub tdx_mrconfigid: String,
    pub tdx_mrowner: String,
    pub tdx_mrownerconfig: String,
    pub tdx_mrseam: String,
    pub tdx_mrsignerseam: String,
    pub tdx_mrtd: String,
    pub tdx_report_data: String,
    pub tdx_rtmr0: String,
    pub tdx_rtmr1: String,
    pub tdx_rtmr2: String,
    pub tdx_rtmr3: String,
    pub tdx_seam_attributes: String,
    pub tdx_seamsvn: u32,
    pub tdx_td_attributes: String,
    pub tdx_td_attributes_debug: bool,
    pub tdx_td_attributes_key_locker: bool,
    pub tdx_td_attributes_perfmon: bool,
    pub tdx_td_attributes_protection_keys: bool,
    pub tdx_td_attributes_septve_disable: bool,
    pub tdx_tee_tcb_svn: String,
    pub tdx_xfam: String,
    #[serde(rename = "x-ms-attestation-type")]
    pub x_ms_attestation_type: String,
    #[serde(rename = "x-ms-compliance-status")]
    pub x_ms_compliance_status: String,
    #[serde(rename = "x-ms-policy-hash")]
    pub x_ms_policy_hash: String,
    #[serde(rename = "x-ms-ver")]
    pub x_ms_ver: String,
}
