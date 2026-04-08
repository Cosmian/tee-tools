// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::{convert::TryFrom, ops::Range};

use crate::{
    attestation_report::{SnpReport, TdReport},
    error::Error,
    tpm::get_hcl_report,
};

use jose_jwk::Jwk;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use sev::{
    firmware::host::{CertTableEntry, CertType},
    parser::ByteParser,
};

use sha2::{Digest, Sha256};
use zerocopy::{Immutable, KnownLayout, TryFromBytes};

pub mod attestation_report;
pub mod error;
pub mod imds;
pub mod tpm;

const HCL_AKPUB_KEY_ID: &str = "HCLAkPub";
pub const TD_REPORT_SIZE: usize = 1024;
pub const SNP_REPORT_SIZE: usize = 1184;
const MAX_REPORT_SIZE: usize = SNP_REPORT_SIZE; // 1184 bytes for SEV-SNP and 1024 bytes for TDX
const SNP_REPORT_TYPE: u32 = 2;
const TDX_REPORT_TYPE: u32 = 4;
const HW_REPORT_OFFSET: usize = memoffset::offset_of!(AttestationReport, hw_report);
const fn report_range(report_size: usize) -> Range<usize> {
    HW_REPORT_OFFSET..(HW_REPORT_OFFSET + report_size)
}
const TD_REPORT_RANGE: Range<usize> = report_range(TD_REPORT_SIZE);
const SNP_REPORT_RANGE: Range<usize> = report_range(SNP_REPORT_SIZE);

#[derive(Deserialize, Debug)]
struct VarDataKeys {
    keys: Vec<Jwk>,
}

#[repr(u32)]
#[derive(
    TryFromBytes, KnownLayout, Immutable, Copy, Clone, Debug, Serialize, Deserialize, PartialEq,
)]
enum IgvmHashType {
    Invalid = 0,
    Sha256,
    Sha384,
    Sha512,
}

#[repr(C)]
#[derive(TryFromBytes, KnownLayout, Immutable, Clone, Debug, Serialize, Deserialize, PartialEq)]
struct IgvmRequestData {
    data_size: u32,
    version: u32,
    report_type: u32,
    report_data_hash_type: IgvmHashType,
    variable_data_size: u32,
    variable_data: [u8; 0],
}

#[repr(C)]
#[derive(TryFromBytes, KnownLayout, Immutable, Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationHeader {
    signature: u32,
    version: u32,
    report_size: u32,
    request_type: u32,
    status: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(TryFromBytes, KnownLayout, Immutable, Clone, Debug, Serialize, Deserialize, PartialEq)]
struct AttestationReport {
    header: AttestationHeader,
    #[serde(with = "BigArray")]
    hw_report: [u8; MAX_REPORT_SIZE],
    hcl_data: IgvmRequestData,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReportType {
    Tdx,
    Snp,
}

pub struct HclReport {
    bytes: Vec<u8>,
    attestation_report: AttestationReport,
    report_type: ReportType,
}

impl HclReport {
    /// Parse a HCL report from a byte slice.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        // let attestation_report: AttestationReport = {
        //     let mut report = [0u8; size_of::<AttestationReport>()];
        //     report.copy_from_slice(&bytes);

        //     unsafe { transmute(report) }
        // };

        let attestation_report = AttestationReport::try_ref_from_prefix(&bytes)
            .map_err(|_| Error::InvalidReportType)?
            .0 // .0 is &AttestationReport, .1 would be the remaining bytes
            .to_owned();

        let report_type = match attestation_report.hcl_data.report_type {
            TDX_REPORT_TYPE => ReportType::Tdx,
            SNP_REPORT_TYPE => ReportType::Snp,
            _ => return Err(Error::InvalidReportType),
        };

        let report = Self {
            bytes,
            attestation_report,
            report_type,
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
        if self.attestation_report.hcl_data.report_data_hash_type != IgvmHashType::Sha256 {
            unimplemented!(
                "Only SHA256 is supported, got {:?}",
                self.attestation_report.hcl_data.report_data_hash_type
            );
        }
        let mut hasher = Sha256::new();
        hasher.update(self.var_data_slice());
        let hash = hasher.finalize();
        hash.into()
    }

    /// Get the slice of the VarData section
    fn var_data_slice(&self) -> &[u8] {
        let var_data_offset = memoffset::offset_of!(AttestationReport, hcl_data)
            + memoffset::offset_of!(IgvmRequestData, variable_data);
        let hcl_data = &self.attestation_report.hcl_data;
        let var_data_end = var_data_offset + hcl_data.variable_data_size as usize;
        &self.bytes[var_data_offset..var_data_end]
    }

    /// Get the vTPM's AKpub from the VarData section
    pub fn ak_pub(&self) -> Result<Jwk, Error> {
        let VarDataKeys { keys } = serde_json::from_slice(self.var_data_slice())?;
        let ak_pub = keys
            .into_iter()
            .find(|key| {
                let Some(ref key_id) = key.prm.kid else {
                    return false;
                };
                key_id == HCL_AKPUB_KEY_ID
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
        let td_report = TdReport::try_read_from_bytes(hcl_report.report_slice())
            .map_err(|_| Error::InvalidReportType)?;
        Ok(td_report)
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
        let snp_report = SnpReport::from_bytes(hcl_report.report_slice())?;
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
    if let Ok(raw_hcl_report) = get_hcl_report()
        && let Ok(hcl_report) = HclReport::new(raw_hcl_report)
    {
        return Some(hcl_report.report_type());
    }

    None
}

pub fn get_td_quote(report: HclReport) -> Result<Vec<u8>, Error> {
    match report.report_type() {
        ReportType::Tdx => {
            let td_report: TdReport = report.try_into()?;
            imds::get_td_quote(&td_report)
        }
        ReportType::Snp => Err(Error::InvalidReportType), // SEV-SNP quote is not applicable for TDX
    }
}

pub fn get_snp_quote(report: HclReport) -> Result<Vec<u8>, Error> {
    match report.report_type() {
        ReportType::Tdx => Err(Error::InvalidReportType),
        ReportType::Snp => {
            // let mut snp_report = report.report_slice().to_vec();
            let mut quote = sev_quote::quote::Quote::try_from(report.report_slice())?;

            let amd_cert_chain = imds::get_amd_cert_chain()?;

            let cert_table: Vec<CertTableEntry> = amd_cert_chain
                .iter()
                .zip([CertType::VCEK, CertType::ASK, CertType::ARK])
                .map(|(pem_bytes, cert_type)| {
                    let pem = pem::parse(pem_bytes).expect("invalid PEM");
                    CertTableEntry::new(cert_type, pem.contents().to_vec())
                })
                .collect();

            quote.certs = cert_table;

            Ok(quote.try_into()?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hcl_report() {
        // let bytes: &[u8] = include_bytes!("../data/hcl_report_sev.bin");
        // let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        // let ak = hcl_report.ak_pub().unwrap();
        // println!("{:?}", hcl_report.report_type());
        // println!("{:?}", hcl_report.attestation_report);
        // println!("{:?}", ak);

        let bytes: &[u8] = include_bytes!("../data/hcl_report_tdx.bin");
        let hcl_report = HclReport::new(bytes.to_vec()).unwrap();
        let ak = hcl_report.ak_pub().unwrap();
        println!("{:?}", hcl_report.report_type());
        println!("{:?}", hcl_report.attestation_report);
        println!("{:?}", ak);
    }
}
