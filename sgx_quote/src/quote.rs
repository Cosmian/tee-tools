use crate::error::Error;
use crate::policy::SgxQuoteVerificationPolicy;
use crate::verify::{
    verify_collaterals, verify_quote_body_policy, verify_quote_header_policy,
    verify_quote_signature,
};

use core::fmt;
use log::debug;

use pccs_client::IntelTeeType;
use scroll::Pread;

use crate::{REPORT_DATA_SIZE, SGX_GUEST_PATH};
use std::{fs, io::Read};

pub const QUOTE_HEADER_SIZE: usize = 48;
pub const QUOTE_REPORT_BODY_SIZE: usize = 384;
pub const QUOTE_BODY_SIZE: usize = QUOTE_HEADER_SIZE + QUOTE_REPORT_BODY_SIZE;
pub const QUOTE_ECDSA_SIG_DATA_SIZE: usize = 576;
pub const QUOTE_AUTH_DATA_OFFSET: usize = QUOTE_BODY_SIZE + 4;
pub const QUOTE_QE_REPORT_OFFSET: usize = QUOTE_AUTH_DATA_OFFSET + 128;
pub const QUOTE_QE_REPORT_SIZE: usize = 384;

const QUOTE_MAX_SIZE: usize = 8192;

const PCCS_URL: &str = "https://pccs.staging.mse.cosmian.com";

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

/// Get the quote of the SGX enclave
pub fn get_quote(user_report_data: &[u8; REPORT_DATA_SIZE]) -> Result<Vec<u8>, Error> {
    debug!("Reading attestation_type...");
    let mut file = fs::File::open("/dev/attestation/attestation_type")?;
    let mut buf = [0; 32];
    let n = file.read(&mut buf[..])?;
    let s = String::from_utf8_lossy(&buf[..n]);

    if s.trim() != "dcap" {
        return Err(Error::Unimplemented(format!(
            "Only DCAP supported, found '{s}'"
        )));
    }

    debug!("Writing user_report_data...");
    fs::write("/dev/attestation/user_report_data", user_report_data)?;

    debug!("Reading quote...");
    let mut file = fs::File::open(SGX_GUEST_PATH)?;
    let mut buf = [0; QUOTE_MAX_SIZE];
    let size = file.read(&mut buf[..])?;

    Ok(buf[..size].to_vec())
}

/// Verify the quote
///
/// The verification includes:
/// - The MRenclave
/// - The MRsigner
/// - The quote collaterals
pub fn verify_quote(raw_quote: &[u8], policy: &SgxQuoteVerificationPolicy) -> Result<(), Error> {
    let (quote, signature, auth_data, certs) = parse_quote(raw_quote)?;

    verify_quote_header_policy(&quote.header, &policy.header)?;

    verify_quote_body_policy(&quote.report_body, &policy.body)?;

    verify_collaterals(
        &certs.certification_data,
        &signature.qe_report,
        raw_quote
            .get(QUOTE_QE_REPORT_OFFSET..QUOTE_QE_REPORT_SIZE + QUOTE_QE_REPORT_OFFSET)
            .ok_or_else(|| {
                Error::InvalidFormat(
                    "Bad offset extraction to check QE report signature".to_owned(),
                )
            })?,
        &signature.qe_report_signature,
        &signature.qe_report.report_data,
        &signature.attest_pub_key,
        &auth_data.auth_data,
        PCCS_URL,
        IntelTeeType::Sgx,
    )?;

    verify_quote_signature(raw_quote, &signature)?;

    debug!("Verification succeed");
    Ok(())
}

pub fn parse_quote(
    raw_quote: &[u8],
) -> Result<(Quote, EcdsaSigData, AuthData, CertificationData), Error> {
    let offset = &mut 0usize;

    let header = raw_quote
        .gread_with::<QuoteHeader>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse quote header failed: {e:?}")))?;
    let report_body = raw_quote
        .gread_with::<ReportBody>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse report body failed: {e:?}")))?;

    let signature_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse signature data length failed: {e:?}")))?;

    let ecdsa_sig_data = raw_quote
        .gread_with::<EcdsaSigData>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse ecdsa sig data failed: {e:?}")))?;

    let qe_auth_data_len = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| Error::InvalidFormat(format!("Parse QE auth data length failed: {e:?}")))?;
    let mut qe_auth_data: Vec<u8> = vec![0; qe_auth_data_len as usize];
    raw_quote.gread_inout(offset, &mut qe_auth_data)?;

    if qe_auth_data.len() != qe_auth_data_len as usize {
        return Err(Error::InvalidFormat(
            "Unexpected qe_auth_data_len".to_owned(),
        ));
    }

    let qe_auth_data = AuthData {
        auth_data: qe_auth_data,
    };

    let certification_data_type = raw_quote
        .gread_with::<u16>(offset, scroll::LE)
        .map_err(|e| {
            Error::InvalidFormat(format!("Parse certification data type failed: {e:?}"))
        })?;

    debug!("certification_data_type: {}", certification_data_type);

    let certification_data_len = raw_quote
        .gread_with::<u32>(offset, scroll::LE)
        .map_err(|e| {
            Error::InvalidFormat(format!("Parse certification data length failed: {e:?}"))
        })?;

    let mut certification_data: Vec<u8> = vec![0; certification_data_len as usize];
    raw_quote.gread_inout(offset, &mut certification_data)?;
    if certification_data.len() != certification_data_len as usize {
        return Err(Error::InvalidFormat(
            "Unexpected certification_data_len".to_owned(),
        ));
    }

    let certification_data = CertificationData {
        cert_key_type: certification_data_type,
        certification_data,
    };

    if *offset - QUOTE_REPORT_BODY_SIZE - QUOTE_HEADER_SIZE - 4 != signature_data_len as usize {
        return Err(Error::InvalidFormat("Bad signature length!".to_owned()));
    }

    if raw_quote.len() != *offset {
        return Err(Error::InvalidFormat("Failed to parse quote!".to_owned()));
    }

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
    use crate::{
        mrsigner::compute_mr_signer,
        policy::{SgxQuoteBodyVerificationPolicy, SgxQuoteHeaderVerificationPolicy},
    };

    use super::*;
    use env_logger::Target;

    fn init() {
        let mut builder = env_logger::builder();
        let builder = builder.is_test(true);
        let builder = builder.target(Target::Stdout);
        let _ = builder.try_init();
    }

    #[test]
    fn test_sgx_parse_quote() {
        init();
        let raw_quote = include_bytes!("../data/quote.dat");
        let (_quote, _ecdsa_sig_data, _auth_data, _certification_data) =
            parse_quote(raw_quote).unwrap();
    }

    #[test]
    fn test_sgx_verify_quote() {
        init();
        let raw_quote = include_bytes!("../data/quote.dat");

        let mrenclave =
            hex::decode(b"f07830d7d2f8c67f64438303f3bc1a2e29f603ad1ab60ef94fd41d2bf7231866")
                .unwrap()
                .try_into()
                .unwrap();
        let mr_signer = compute_mr_signer(include_str!("../data/signer-key.pem")).unwrap();

        assert!(verify_quote(
            raw_quote,
            &SgxQuoteVerificationPolicy {
                header: SgxQuoteHeaderVerificationPolicy::default(),
                body: SgxQuoteBodyVerificationPolicy {
                    mr_enclave: Some(mrenclave),
                    mr_signer: Some(mr_signer),
                    ..Default::default()
                }
            }
        )
        .is_ok());
    }
}
