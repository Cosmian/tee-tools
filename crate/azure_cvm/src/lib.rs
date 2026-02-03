// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{
    attestation_report::{SnpReport, TdReport},
    error::Error,
    tpm::get_hcl_report,
};
use serde::Deserialize;
use sev::parser::ByteParser;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::ops::Range;

pub mod attestation_report;
pub mod error;
pub mod imds;
pub mod tpm;

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
pub const TD_REPORT_SIZE: usize = std::mem::size_of::<TdReport>();
pub const SNP_REPORT_SIZE: usize = std::mem::size_of::<SnpReport>();
const HCL_HW_REPORT_AREA_SIZE: usize = 1184; // 1184 bytes for SEV-SNP, TDX report is padded inside
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;
const ATTESTATION_HEADER_SIZE: usize = 32;
const HW_REPORT_OFFSET: usize = ATTESTATION_HEADER_SIZE;
const IGVM_REQUEST_DATA_SIZE: usize = 20;
const IGVM_REQUEST_DATA_OFFSET: usize = HW_REPORT_OFFSET + HCL_HW_REPORT_AREA_SIZE;
const VAR_DATA_OFFSET: usize = IGVM_REQUEST_DATA_OFFSET + IGVM_REQUEST_DATA_SIZE;

const fn report_range(report_size: usize) -> Range<usize> {
    HW_REPORT_OFFSET..(HW_REPORT_OFFSET + report_size)
}
const TD_REPORT_RANGE: Range<usize> = report_range(TD_REPORT_SIZE);
const SNP_REPORT_RANGE: Range<usize> = report_range(SNP_REPORT_SIZE);

#[derive(Deserialize, Debug)]
struct VarDataKeys {
    keys: Vec<serde_json::Value>,
}

#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
enum IgvmHashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<u32> for IgvmHashType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IgvmHashType::Invalid),
            1 => Ok(IgvmHashType::Sha256),
            2 => Ok(IgvmHashType::Sha384),
            3 => Ok(IgvmHashType::Sha512),
            _ => Err(Error::InvalidFormat(format!(
                "invalid IGVM hash type: {value}"
            ))),
        }
    }
}

pub struct HclReport {
    bytes: Vec<u8>,
    report_type: ReportType,
    report_data_hash_type: IgvmHashType,
    variable_data_size: u32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReportType {
    Tdx,
    Snp,
}

pub enum HwReport {
    Tdx(Box<TdReport>),
    Snp(Box<SnpReport>),
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    let range = offset
        .checked_add(4)
        .ok_or_else(|| Error::InvalidFormat("offset overflow".to_owned()))?;
    let v = bytes
        .get(offset..range)
        .ok_or_else(|| Error::InvalidFormat("truncated report".to_owned()))?;
    Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
}

impl HclReport {
    /// Parse a HCL report from a byte slice.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < VAR_DATA_OFFSET {
            return Err(Error::InvalidFormat("HCL report too small".to_owned()));
        }

        let report_type_raw = read_u32_le(&bytes, IGVM_REQUEST_DATA_OFFSET + 8)?;
        let report_data_hash_type_raw = read_u32_le(&bytes, IGVM_REQUEST_DATA_OFFSET + 12)?;
        let variable_data_size = read_u32_le(&bytes, IGVM_REQUEST_DATA_OFFSET + 16)?;

        let report_type = match report_type_raw {
            TDX_REPORT_TYPE => ReportType::Tdx,
            SNP_REPORT_TYPE => ReportType::Snp,
            _ => return Err(Error::InvalidReportType),
        };

        let report_data_hash_type = IgvmHashType::try_from(report_data_hash_type_raw)?;

        let var_data_end = VAR_DATA_OFFSET
            .checked_add(variable_data_size as usize)
            .ok_or_else(|| Error::InvalidFormat("VarData size overflow".to_owned()))?;
        if var_data_end > bytes.len() {
            return Err(Error::InvalidFormat(
                "VarData section exceeds report length".to_owned(),
            ));
        }

        let report = Self {
            bytes,
            report_type,
            report_data_hash_type,
            variable_data_size,
        };
        Ok(report)
    }

    /// Get the type of the nested hardware report
    pub fn report_type(&self) -> ReportType {
        self.report_type
    }

    pub fn report_slice(&self) -> &[u8] {
        match self.report_type {
            ReportType::Tdx => self.bytes[TD_REPORT_RANGE].as_ref(),
            ReportType::Snp => self.bytes[SNP_REPORT_RANGE].as_ref(),
        }
    }

    /// Get the SHA256 hash of the VarData section
    pub fn var_data_sha256(&self) -> [u8; 32] {
        if self.report_data_hash_type != IgvmHashType::Sha256 {
            unimplemented!(
                "Only SHA256 is supported, got {:?}",
                self.report_data_hash_type
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(self.var_data_slice());
        let hash = hasher.finalize();
        hash.into()
    }

    /// Get the slice of the VarData section
    fn var_data_slice(&self) -> &[u8] {
        let var_data_end = VAR_DATA_OFFSET + self.variable_data_size as usize;
        &self.bytes[VAR_DATA_OFFSET..var_data_end]
    }

    /// Get the vTPM's AKpub from the VarData section
    pub fn ak_pub(&self) -> Result<serde_json::Value, Error> {
        let VarDataKeys { keys } = serde_json::from_slice(self.var_data_slice())?;
        let ak_pub = keys
            .into_iter()
            .find(|key| {
                key.get("kid")
                    .and_then(|v| v.as_str())
                    .map(|kid| kid == HCL_AKPUB_KEY_ID)
                    .unwrap_or(false)
            })
            .ok_or(Error::AkPubNotFound)?;
        Ok(ak_pub)
    }
}

impl TryFrom<&HclReport> for TdReport {
    type Error = Error;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Tdx {
            return Err(Error::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        let bytes = bytes
            .get(..TD_REPORT_SIZE)
            .ok_or_else(|| Error::InvalidFormat("TD report truncated".to_owned()))?;

        let mut td_report = std::mem::MaybeUninit::<TdReport>::uninit();
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                td_report.as_mut_ptr() as *mut u8,
                TD_REPORT_SIZE,
            );
            Ok(td_report.assume_init())
        }
    }
}

impl TryFrom<HclReport> for TdReport {
    type Error = Error;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

impl TryFrom<&HclReport> for SnpReport {
    type Error = Error;

    fn try_from(hcl_report: &HclReport) -> Result<Self, Self::Error> {
        if hcl_report.report_type != ReportType::Snp {
            return Err(Error::InvalidReportType);
        }
        let bytes = hcl_report.report_slice();
        let snp_report = SnpReport::from_bytes(bytes)?;
        Ok(snp_report)
    }
}

impl TryFrom<HclReport> for SnpReport {
    type Error = Error;

    fn try_from(hcl_report: HclReport) -> Result<Self, Self::Error> {
        (&hcl_report).try_into()
    }
}

pub fn is_az_cvm() -> Option<ReportType> {
    if let Ok(raw_hcl_report) = get_hcl_report() {
        if let Ok(hcl_report) = HclReport::new(raw_hcl_report) {
            return Some(hcl_report.report_type());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hcl_report() {
        let bytes: &[u8] = include_bytes!("../data/hcl_report_sev.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let ak = hcl_report.ak_pub().unwrap();
        println!("{:?}", hcl_report.report_type());
        println!("{:?}", ak);

        let bytes: &[u8] = include_bytes!("../data/hcl_report_tdx.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let ak = hcl_report.ak_pub().unwrap();
        println!("{:?}", hcl_report.report_type());
        println!("{:?}", ak);
    }
}
