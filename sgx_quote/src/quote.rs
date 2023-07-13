use core::fmt;
use scroll::Pread;

use crate::error::SGXQuoteError;

pub const QUOTE_HEADER_SIZE: usize = 48;
pub const QUOTE_REPORT_BODY_SIZE: usize = 384;
pub const QUOTE_BODY_SIZE: usize = QUOTE_HEADER_SIZE + QUOTE_REPORT_BODY_SIZE;
pub const QUOTE_ECDSA_SIG_DATA_SIZE: usize = 576;

/// Header of Quote data structure (48 bytes).
/// See [sgx_quote_3.h#L165](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/DCAP_1.16/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L165).
#[repr(C)]
#[derive(Debug, Pread)]
pub struct QuoteHeader {
    ///< 0: Version of the Quote data structure.
    /// Supported value: 3
    pub version: u16,
    ///< 2: Type of the Attestation Key used by the Quoting Enclave.
    /// Supported value: 2 (ECDSA-256 with P-256 curve)
    pub att_key_type: u16,
    ///< 4: Reserved field.
    /// Supported value: 0 (SGX).
    pub reserved: u32,
    ///< 8: Security Version of the Quoting Enclave currently loaded on the platform.
    pub qe_svn: u16,
    ///< 10: Security Version of the Provisioning Certification Enclave currently loaded on
    /// the platform.
    pub pce_svn: u16,
    ///< 12: Unique identifier of the QE Vendor.
    /// Supported value: 939a7233f79c4ca9940a0db3957f0607
    pub vendor_id: [u8; 16],
    ///< 28: Custom user-defined data. The first 16 bytes contain a QE identifier that is used
    /// to link a PCK Cert to en Enc(PPID). The identifier is consistent for every quote
    /// generated with this QE on this platform.
    pub user_data: [u8; 20],
}

impl fmt::Display for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Quote Header:
            \tVersion: {:X?}
            \tAttestation Key Type: {:X?}
            \tReserved: {:X?}
            \tQE SVN: {:X?}
            \tPCE SVN: {:X?}
            \tQE Vendor ID: {:X?}
            \tUser Data: {:X?}\n",
            self.version,
            self.att_key_type,
            self.reserved,
            self.qe_svn,
            self.pce_svn,
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

/// Report Body of Quote data structure (384 bytes).
/// See [sgx_report.h#L93](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L93).
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody {
    ///< 0: Security Version of CPU.
    /// See [sgx_report.h#L95](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L95) and [sgx_key.h#L70](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_key.h#L70).
    pub cpu_svn: [u8; 16],
    ///< 16: State Save Area (SSA) frame extended feature set.
    /// See [sgx_report.h#L96](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L96) and [sgx_attributes.h#L64](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_attributes.h#L64).
    pub misc_select: u32,
    ///< 20: Reserved field.
    /// See [sgx_report.h#L97](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L97).
    pub reserved1: [u8; 12],
    ///< 32: ISV assigned Extended Product ID.
    /// See [sgx_report.h#L98](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L98) and [sgx_report.h#L66](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L66).
    pub isv_ext_prod_id: [u8; 16],
    ///< 48: Attributes. Set of flags describing attributes of the enclave.
    /// See [sgx_report.h#L99](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L99) and [sgx_attributes.h#L57](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_attributes.h#L57).
    pub flags: u64,
    pub xfrm: u64,
    ///< 64: Hash of enclave measurement.
    /// See [sgx_report.h#L100](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L100) and [sgx_report.h#L52](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L52).
    pub mr_enclave: [u8; 32],
    ///< 96: Reserved field.
    /// See [sgx_report.h#L101](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L101).
    pub reserved2: [u8; 32],
    ///< 128: Hash of enclave signing key.
    /// See [sgx_report.h#L102](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L102) and [sgx_report.h#L52](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L52).
    pub mr_signer: [u8; 32],
    ///< 160: Reserved field.
    /// See [sgx_report.h#L103](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L103).
    pub reserved3: [u8; 32],
    ///< 192: Enclave Configuration ID.
    /// See [sgx_report.h#L104](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L104) and [sgx_key.h#L67](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_key.h#L67).
    pub config_id: [u8; 64],
    ///< 256: Product ID of the Enclave.
    /// See [sgx_report.h#L105](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L105) and [sgx_report.h#L64](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L64).
    pub isv_prod_id: u16,
    ///< 258: Security Version of the enclave.
    /// See [sgx_report.h#L106](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L106) and [sgx_key.h#L65](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_key.h#L65).
    pub isv_svn: u16,
    ///< 260: Enclave Configuration Security Version.
    /// See [sgx_report.h#L107](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L107) and [sgx_key.h#L66](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_key.h#L66).
    pub config_svn: u16,
    ///< 262: Reserved field.
    /// See [sgx_report.h#L108](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L108).
    pub reserved4: [u8; 42],
    ///< 304: ISV assigned Family ID.
    /// See [sgx_report.h#L109](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L109) and [sgx_report.h#L67](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L67).
    pub isv_family_id: [u8; 16],
    ///< 320: Additional report data
    /// See [sgx_report.h#L110](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L110) and [sgx_report.h#L59](https://github.com/intel/linux-sgx/blob/sgx_2.19/common/inc/sgx_report.h#L59).
    pub report_data: [u8; 64],
}

impl fmt::Display for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report Body:
            \tCPU SVN: {:X?}
            \tAttributes: ({:X?}, {:X?})
            \tMRENCLAVE: {:X?}
            \tMRSIGNER: {:X?}
            \tISV ProdID: {:X?}
            \tISV SVN: {:X?}
            \tUser Data: {:X?}\n",
            hex::encode(self.cpu_svn),
            self.flags,
            self.xfrm,
            hex::encode(self.mr_enclave),
            hex::encode(self.mr_signer),
            self.isv_prod_id,
            self.isv_svn,
            hex::encode(self.report_data)
        )
    }
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct Quote {
    /// Quote header (48b)
    pub header: QuoteHeader,
    /// Report of the attested Independent Software Vendor (ISV) Enclave (384b).
    pub report_body: ReportBody,
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\n{}\n", self.header, self.report_body)
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct AuthData {
    pub auth_data: Vec<u8>,
}

#[repr(C)]
#[derive(Debug)]
pub struct CertificationData {
    pub cert_key_type: u16,
    pub certification_data: Vec<u8>,
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct EcdsaSigData {
    pub signature: [u8; 64],
    pub attest_pub_key: [u8; 64],
    pub qe_report: ReportBody,
    pub qe_report_signature: [u8; 64],
}

pub fn parse_quote(
    raw_quote: &[u8],
) -> Result<(Quote, EcdsaSigData, AuthData, CertificationData), SGXQuoteError> {
    let offset = &mut 0usize;

    let header = raw_quote
        .gread_with::<QuoteHeader>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingHeaderError)?;
    let report_body = raw_quote
        .gread_with::<ReportBody>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingReportBodyError)?;

    let signature_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingEcdsaSigDataError)?;

    let ecdsa_sig_data = raw_quote
        .gread_with::<EcdsaSigData>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingEcdsaSigDataError)?;

    let qe_auth_data_len = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingAuthDataError)?;
    let mut qe_auth_data: Vec<u8> = vec![0; qe_auth_data_len as usize];
    raw_quote
        .gread_inout(offset, &mut qe_auth_data)
        .map_err(|_| SGXQuoteError::ParsingAuthDataError)?;

    assert!(
        qe_auth_data.len() == qe_auth_data_len as usize,
        "unexpected qe_auth_data_len"
    );
    let qe_auth_data = AuthData {
        auth_data: qe_auth_data,
    };

    let certification_data_type = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingCertDataError)?;
    println!("certification_data_type: {}", certification_data_type);

    let certification_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|_| SGXQuoteError::ParsingCertDataError)?;
    let mut certification_data: Vec<u8> = vec![0; certification_data_len as usize];
    raw_quote
        .gread_inout(offset, &mut certification_data)
        .map_err(|_| SGXQuoteError::ParsingCertDataError)?;

    assert!(
        certification_data.len() == certification_data_len as usize,
        "unexpected certification_data_len"
    );
    let certification_data = CertificationData {
        cert_key_type: certification_data_type,
        certification_data,
    };

    assert!(
        *offset - QUOTE_REPORT_BODY_SIZE - QUOTE_HEADER_SIZE - 4 == signature_data_len as usize,
        "bad signature length!"
    );
    assert!(raw_quote.len() == *offset, "failed to parse quote!");

    Ok((
        Quote {
            header,
            report_body,
        },
        ecdsa_sig_data,
        qe_auth_data,
        certification_data,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_quote() {
        let raw_quote = include_bytes!("../data/quote.dat");
        let (_quote, _ecdsa_sig_data, _auth_data, _certification_data) =
            parse_quote(raw_quote).unwrap();
    }
}
