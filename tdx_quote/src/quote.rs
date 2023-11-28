use crate::error::Error;

use core::fmt;

use crate::REPORT_DATA_SIZE;
use scroll::Pread;
use sgx_quote::quote::ReportBody;

pub const QUOTE_HEADER_SIZE: usize = 48;
pub const QUOTE_REPORT_BODY_SIZE: usize = 584;

pub const MRENCLAVE_SIZE: usize = 32;
pub const MRSIGNER_SIZE: usize = 32;

/// Header of Quote data structure (48 bytes)
#[repr(C)]
#[derive(Debug, Pread)]
pub struct QuoteHeader {
    /// Version 4 supported
    pub version: u16,
    /// Type of attestation key used by quoting enclave
    /// Values :
    /// 2 (ECDSA-256-with-P-256 curve)
    /// 3 (ECDSA-384-with-P-384 curve) (Currently not supported)
    pub att_key_type: u16,
    /// TEE for this attestation
    /// TDX : 0x00000081
    pub tee_type: u32,
    pub qe_svn: u16,
    pub pce_svn: u16,
    /// Unique vendor id of QE vendor
    pub vendor_id: [u8; 16],
    /// Custom user defined data
    pub user_data: [u8; 20],
}

impl fmt::Display for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Quote Header:
            \tVersion: {}
            \tAttestation Key Type: {}
            \tTee Type: {}
            \tQE SVN: {}
            \tPCE SVN: {}
            \tQE Vendor ID: {:X?}
            \tUser Data: {:X?}\n",
            self.version,
            self.att_key_type,
            self.tee_type,
            self.qe_svn,
            self.pce_svn,
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

/// Report Body of Quote data structure (584 bytes)
#[repr(C)]
#[derive(Debug, Pread)]
pub struct TdxReportBody {
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mr_signer_seam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: u64,
    pub mr_td: [u8; 48],
    pub mr_config_id: [u8; 48],
    pub mr_owner: [u8; 48],
    pub mr_owner_config: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    pub report_data: [u8; 64],
}

impl fmt::Display for TdxReportBody {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report Body:
            \tTEE TCB SVN: {:X?}
            \tMR_SEAM: {:X?}
            \tMR_SIGNER_SEAM: {:X?}
            \tTD_ATTRIBUTES: {:X?}
            \tXFAM: {}
            \tMR_TD: {:X?}
            \tMR_CONFIGID: {:X?}
            \tMR_OWNER: {:X?}
            \tMR_OWNER_CONFIG: {:X?}
            \tUser Data: {:X?}\n",
            hex::encode(self.tee_tcb_svn),
            hex::encode(self.mr_seam),
            hex::encode(self.mr_signer_seam),
            hex::encode(self.td_attributes),
            self.xfam,
            hex::encode(self.mr_td),
            hex::encode(self.mr_config_id),
            hex::encode(self.mr_owner),
            hex::encode(self.mr_owner_config),
            hex::encode(self.report_data)
        )
    }
}

#[repr(C)]
#[derive(Debug, Pread)]
/// Version 4 Quote
pub struct Quote {
    /// Quote header
    pub header: QuoteHeader,
    /// Report of the attested Independent Software Vendor (ISV) Enclave.
    pub report_body: TdxReportBody,
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n{}\n", self.header, self.report_body)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct EcdsaSigData {
    /// The ECDSA 256-bit signature
    pub signature: [u8; 64],
    /// The ECDSA 256-bit public key of the attestation key
    pub attest_pub_key: [u8; 64],
    /// The certification data
    pub certification_data: CertificationData,
}

impl fmt::Display for EcdsaSigData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "EcdsaSigData:
            \tSignature: {:X?}
            \tAttestPubKey: {:X?}
            \t{}\n",
            hex::encode(self.signature),
            hex::encode(self.attest_pub_key),
            self.certification_data
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct CertificationData {
    ///   Supported values:
    /// - 1 (PCK identifier: PPID in plain text,  CPUSVN and PCESVN)
    /// - 2 (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN and PCESVN)
    /// - 3 (PCK identifier: PPID encrypted using RSA-3072-OAEP, CPUSVN and PCESVN)
    /// - 4 (PCK Leaf Certificate in plain text,  currently not supported)
    /// - 5 (Concatenated PCK Cert Chain)
    /// - 6 (QE Report Certification Data)
    /// - 7 (PLATFORM_MANIFEST, currently  not supported)
    pub certificate_data_type: u16,
    // Size of Certification Data field
    pub certificate_data_size: u32,
    pub qe_report_certification_data: QEReportCertificationData,
}

impl fmt::Display for CertificationData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "CertificationData:
            \t\tCertificate_data_type: {}
            \t\tqe_report_certification_data.qe_report:{}
            \t\tqe_report_certification_data.qe_report_signature: {:X?}
            \t\tqe_report_certification_data.qe_auth_data: {:X?}
            \t\tqe_report_certification_data.pck_certificate_chain_data.type: {}
            \t\tqe_report_certification_data.pck_certificate_chain_data.cert: {}",
            self.certificate_data_type,
            self.qe_report_certification_data.qe_report,
            hex::encode(self.qe_report_certification_data.qe_report_signature),
            hex::encode(&self.qe_report_certification_data.qe_auth_data.qe_auth_data),
            self.qe_report_certification_data
                .pck_certificate_chain_data
                .pck_certificate_data_type,
            String::from_utf8_lossy(
                &self
                    .qe_report_certification_data
                    .pck_certificate_chain_data
                    .pck_certification_data
            )
        )
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct QEReportCertificationData {
    pub qe_report: ReportBody,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QEAuthData,
    pub pck_certificate_chain_data: PCKCertificateChainData,
}

#[repr(C)]
#[derive(Debug)]
pub struct QEAuthData {
    pub qe_auth_data_size: u16,
    pub qe_auth_data: Vec<u8>,
}

#[repr(C)]
#[derive(Debug)]
pub struct PCKCertificateChainData {
    ///   Supported values:
    /// - 1 (PCK identifier: PPID in plain text,  CPUSVN and PCESVN)
    /// - 2 (PCK identifier: PPID encrypted using RSA-2048-OAEP, CPUSVN and PCESVN)
    /// - 3 (PCK identifier: PPID encrypted using RSA-3072-OAEP, CPUSVN and PCESVN)
    /// - 4 (PCK Leaf Certificate in plain text,  currently not supported)
    /// - 5 (Concatenated PCK Cert Chain)
    /// - 6 (QE Report Certification Data)
    /// - 7 (PLATFORM_MANIFEST, currently  not supported)
    pub pck_certificate_data_type: u16,
    /// Size of Certification Data field
    pub pck_certificate_data_size: u32,
    pub pck_certification_data: Vec<u8>,
}

pub fn parse_quote(raw_quote: &[u8]) -> Result<(Quote, EcdsaSigData), Error> {
    let offset = &mut 0usize;

    let header = raw_quote
        .gread_with::<QuoteHeader>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse quote header failed: {e:?}")))?;

    let report_body = raw_quote
        .gread_with::<TdxReportBody>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse report body failed: {e:?}")))?;

    let signature_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse signature data length failed: {e:?}")))?;

    let mut signature = [0u8; 64];
    raw_quote.gread_inout(offset, &mut signature)?;

    let mut attest_pub_key = [0u8; 64];
    raw_quote.gread_inout(offset, &mut attest_pub_key)?;

    let certificate_data_type = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse certificate_data_type failed: {e:?}")))?;

    let certificate_data_size = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse certificate_data_size failed: {e:?}")))?;

    let qe_report = raw_quote
        .gread_with::<ReportBody>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse qe_report failed: {e:?}")))?;

    let mut qe_report_signature = [0u8; 64];
    raw_quote.gread_inout(offset, &mut qe_report_signature)?;

    let qe_auth_data_size = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse qe_auth_data_size failed: {e:?}")))?;

    let mut qe_auth_data = vec![0u8; qe_auth_data_size as usize];
    raw_quote.gread_inout(offset, &mut qe_auth_data)?;

    let pck_certificate_data_type = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse certificate_data_type failed: {e:?}")))?;

    let pck_certificate_data_size = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse certificate_data_size failed: {e:?}")))?;

    let mut pck_certification_data = vec![0u8; pck_certificate_data_size as usize];
    raw_quote.gread_inout(offset, &mut pck_certification_data)?;

    let ecdsa_sig_data = EcdsaSigData {
        signature,
        attest_pub_key,
        certification_data: CertificationData {
            certificate_data_type,
            certificate_data_size,
            qe_report_certification_data: QEReportCertificationData {
                qe_report,
                qe_report_signature,
                qe_auth_data: QEAuthData {
                    qe_auth_data_size,
                    qe_auth_data,
                },
                pck_certificate_chain_data: PCKCertificateChainData {
                    pck_certificate_data_type,
                    pck_certificate_data_size,
                    pck_certification_data,
                },
            },
        },
    };

    assert!(
        *offset - QUOTE_REPORT_BODY_SIZE - QUOTE_HEADER_SIZE - 4 == signature_data_len as usize,
        "bad signature length!"
    );

    Ok((
        Quote {
            header,
            report_body,
        },
        ecdsa_sig_data,
    ))
}

#[cfg(target_os = "linux")]
pub fn get_quote(user_report_data: &[u8]) -> Result<Vec<u8>, Error> {
    use crate::generate::_get_quote;

    if user_report_data.len() > REPORT_DATA_SIZE {
        return Err(Error::InvalidFormat(
            "user_report_data must be at most 64 bytes".to_owned(),
        ));
    }

    let mut inner_user_report_data = [0u8; REPORT_DATA_SIZE];
    inner_user_report_data[0..user_report_data.len()].copy_from_slice(user_report_data);

    _get_quote(&inner_user_report_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger::Target;

    fn init() {
        let mut builder = env_logger::builder();
        let builder = builder.is_test(true);
        let builder = builder.target(Target::Stdout);
        let _ = builder.try_init();
    }

    #[test]
    fn test_parse_quote() {
        init();
        let raw_quote = include_bytes!("../data/quote.dat");
        let (quote, ecdsa_sig_data) = parse_quote(raw_quote).unwrap();

        assert_eq!(quote.header.version, 4);
        assert_eq!(
            quote.header.vendor_id,
            [147, 154, 114, 51, 247, 156, 76, 169, 148, 10, 13, 179, 149, 127, 6, 7]
        );
        assert_eq!(
            quote.report_body.tee_tcb_svn,
            [3, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            quote.report_body.mr_seam,
            [
                47, 210, 121, 193, 97, 100, 169, 61, 213, 191, 55, 61, 131, 67, 40, 212, 96, 8,
                194, 182, 147, 175, 158, 187, 134, 91, 8, 178, 206, 211, 32, 201, 168, 155, 72,
                105, 169, 250, 182, 15, 190, 157, 12, 90, 83, 99, 198, 86
            ]
        );
        assert_eq!(quote.report_body.xfam, 231);
        assert_eq!(
            quote.report_body.report_data,
            [
                48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51,
                52, 53, 54, 55, 56, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52, 53,
                54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0
            ],
        );
        assert_eq!(
            ecdsa_sig_data.signature,
            [
                23, 208, 192, 86, 52, 157, 152, 65, 242, 124, 34, 245, 75, 55, 161, 53, 119, 60,
                197, 222, 62, 19, 87, 73, 214, 175, 181, 166, 167, 78, 38, 122, 102, 128, 150, 53,
                12, 77, 3, 133, 73, 82, 249, 146, 128, 129, 29, 56, 215, 143, 77, 6, 78, 198, 226,
                78, 31, 169, 186, 233, 77, 134, 163, 201
            ]
        );
        assert_eq!(
            ecdsa_sig_data.attest_pub_key,
            [
                123, 217, 109, 230, 17, 191, 57, 37, 26, 81, 31, 22, 203, 48, 209, 65, 48, 243, 47,
                249, 146, 29, 124, 183, 147, 186, 64, 251, 215, 86, 232, 178, 126, 108, 19, 45, 12,
                177, 229, 251, 198, 100, 208, 91, 246, 202, 199, 243, 91, 235, 240, 129, 98, 2, 79,
                183, 27, 103, 197, 162, 95, 63, 177, 202
            ]
        );

        assert_eq!(
            ecdsa_sig_data
                .certification_data
                .qe_report_certification_data
                .pck_certificate_chain_data
                .pck_certificate_data_type,
            5
        );

        assert_eq!(
            ecdsa_sig_data
                .certification_data
                .qe_report_certification_data
                .pck_certificate_chain_data
                .pck_certificate_data_size,
            3681
        );
    }
}