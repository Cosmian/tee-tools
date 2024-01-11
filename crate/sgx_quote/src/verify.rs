use crate::error::Error;
use crate::policy::{SgxQuoteBodyVerificationPolicy, SgxQuoteHeaderVerificationPolicy};
use crate::quote::{EcdsaSigData, QuoteHeader, ReportBody, QUOTE_BODY_SIZE};

use chrono::{NaiveDateTime, Utc};

use log::debug;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::pkcs8::DecodePublicKey;
use p256::{AffinePoint, EncodedPoint};
use pccs_client::{
    get_pck_crl, get_qe_identity, get_root_ca_crl, get_root_ca_crl_from_uri, get_tcbinfo,
    IntelTeeType, PckCa,
};
use serde::{Deserialize, Serialize};
use serde_hex::{SerHex, StrictCap};
use sgx_pck_extension::SgxPckExtension;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::oid_registry::Oid;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{FromDer, Pem};
use x509_parser::revocation_list::CertificateRevocationList;

const CRL_DISTRIBUTION_POINTS_EXTENSION_OID: Oid = oid!(2.5.29 .31);

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct QeIdentity {
    pub enclave_identity: EnclaveIdentity,
    #[serde(with = "SerHex::<StrictCap>")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EnclaveIdentity {
    pub id: String,
    pub version: u32,
    pub issue_date: String,
    pub next_update: String,
    pub tcb_evaluation_data_number: u32,
    #[serde(with = "SerHex::<StrictCap>")]
    pub miscselect: [u8; 4],
    #[serde(with = "SerHex::<StrictCap>")]
    pub miscselect_mask: [u8; 4],
    #[serde(with = "SerHex::<StrictCap>")]
    pub attributes: [u8; 16],
    #[serde(with = "SerHex::<StrictCap>")]
    pub attributes_mask: [u8; 16],
    #[serde(with = "SerHex::<StrictCap>")]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Tcb {
    pub isvsvn: u16,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum TcbComponentStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: String,
    pub tcb_status: TcbComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    version: u32,
    id: String,
    next_update: String,
    #[serde(with = "SerHex::<StrictCap>")]
    pub pce_id: [u8; 2],
    #[serde(with = "SerHex::<StrictCap>")]
    pub fmspc: [u8; 6],
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfoData {
    tcb_info: TcbInfo,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfoDataRaw {
    tcb_info: serde_json::Value,
    #[serde(with = "SerHex::<StrictCap>")]
    pub signature: [u8; 64],
}

#[allow(clippy::too_many_arguments)]
/// Verify all the collaterals:
/// - TCB
/// - PCK cert chains
/// - QEIdentity
pub fn verify_collaterals(
    certification_data: &[u8],
    qe_report: &ReportBody,
    qe_report_raw: &[u8],
    qe_report_signature: &[u8],
    qe_report_data: &[u8],
    signature_attest_pub_key: &[u8],
    auth_data: &[u8],
    pccs_url: &str,
    tee_type: IntelTeeType,
) -> Result<(), Error> {
    debug!("Extracting certificate chain...");
    let chain = get_certificate_chain_from_pem(certification_data)?;

    if chain.len() != 3 {
        return Err(Error::InvalidFormat(
            "Certificate chain is incompleted".to_owned(),
        ));
    }

    debug!("Converting certs...");
    let (_, pck_cert) =
        parse_x509_certificate(&chain[0]).map_err(|e| Error::X509ParserError(e.into()))?;
    let (_, pck_ca_cert) =
        parse_x509_certificate(&chain[1]).map_err(|e| Error::X509ParserError(e.into()))?;
    let (_, root_ca_cert) =
        parse_x509_certificate(&chain[2]).map_err(|e| Error::X509ParserError(e.into()))?;

    verify_pck_certs(&pck_cert, &pck_ca_cert, &root_ca_cert)?;

    if tee_type == IntelTeeType::Sgx {
        debug!("Verifying root ca crl...");

        let root_ca_crl = get_root_ca_crl(pccs_url)?;
        verify_root_ca_crl(&root_ca_cert, &root_ca_crl)?;
    } else {
        let (qe_identity_issuer_chain, raw_qe_identity) = get_qe_identity(pccs_url, tee_type)?;
        let (qe_identity, crl_distribution_points) =
            verify_qe_identity(&qe_identity_issuer_chain, &raw_qe_identity, &root_ca_cert)?;

        verify_qe_report(qe_report, qe_identity)?;

        let mut all_error = true;
        for crl_url in &crl_distribution_points {
            if let Ok(ca_crl) = get_root_ca_crl_from_uri(crl_url) {
                all_error = false;
                verify_root_ca_crl(&root_ca_cert, &ca_crl)?;
            }
        }

        if all_error {
            return Err(Error::VerificationFailure(format!(
                "No root ca crl fetched with success from {crl_distribution_points:?}"
            )));
        }
    }

    debug!("Verifying pck crl...");
    let (pck_crl_issuer_chain, pck_crl) = get_pck_crl(pccs_url, get_pck_ca(&pck_ca_cert)?)?;
    verify_pck_cert_crl(&pck_crl_issuer_chain, &pck_crl, &root_ca_cert, &pck_ca_cert)?;

    debug!("Verifying tcb info...");
    let pck_extension = SgxPckExtension::from_pem_certificate_content(&chain[0])?;
    let (tcb_info_issuer_chain, raw_tcb_info) =
        get_tcbinfo(pccs_url, tee_type, &pck_extension.fmspc)?;
    verify_tcb_info(
        &tcb_info_issuer_chain,
        &raw_tcb_info,
        tee_type,
        &root_ca_cert,
        &pck_extension,
    )?;

    debug!("Verifying QE report signature...");
    verify_qe_report_signature(
        qe_report_raw,
        qe_report_signature,
        qe_report_data,
        pck_cert.public_key().raw,
        signature_attest_pub_key,
        auth_data,
    )?;

    Ok(())
}

fn verify_pck_certs(
    pck_cert: &X509Certificate,
    pck_ca_cert: &X509Certificate,
    root_ca_cert: &X509Certificate,
) -> Result<(), Error> {
    debug!("Verifying pck chain certificates signature...");
    root_ca_cert
        .verify_signature(Some(root_ca_cert.public_key()))
        .map_err(|_| {
            Error::VerificationFailure("The Intel Root CA is not self-signed".to_owned())
        })?;
    pck_ca_cert
        .verify_signature(Some(root_ca_cert.public_key()))
        .map_err(|_| {
            Error::VerificationFailure(
                "The Intel PCK CA cert is not signed by the Intel Root CA".to_owned(),
            )
        })?;
    pck_cert
        .verify_signature(Some(pck_ca_cert.public_key()))
        .map_err(|_| {
            Error::VerificationFailure(
                "The PCK cert is not signed by the Intel PCK CA cert".to_owned(),
            )
        })?;

    debug!("Verifying certificates validity...");
    if !root_ca_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel Root CA certificate has expired".to_owned(),
        ));
    }

    if !pck_ca_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel PCK CA certificate has expired".to_owned(),
        ));
    }

    if !pck_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel PCK certificate has expired".to_owned(),
        ));
    }

    Ok(())
}

/// - Verify the QE Report signature using PCK Leaf certificate
/// - Verify QE Report Data
fn verify_qe_report_signature(
    qe_report: &[u8],
    qe_report_signature: &[u8],
    qe_report_data: &[u8],
    pck_cert_der: &[u8],
    signature_attest_pub_key: &[u8],
    auth_data: &[u8],
) -> Result<(), Error> {
    debug!("Verifying the QE Report signature using PCK Leaf certificate");
    let pck_pk = VerifyingKey::from_public_key_der(pck_cert_der)?;
    pck_pk.verify(qe_report, &Signature::from_slice(qe_report_signature)?)?;

    debug!("Verifying QE Report Data");
    let mut pubkey_hash = Sha256::new();
    pubkey_hash.update(signature_attest_pub_key);
    pubkey_hash.update(auth_data);
    let expected_qe_report_data = &pubkey_hash.finalize()[..];

    if &qe_report_data[..32] != expected_qe_report_data {
        return Err(Error::VerificationFailure(
            "Unexpected REPORTDATA in QE report".to_owned(),
        ));
    }

    Ok(())
}

/// Verify Quote Body using attestation key and signature present in the quote
pub(crate) fn verify_quote_signature(
    raw_quote: &[u8],
    signature: &EcdsaSigData,
) -> Result<(), Error> {
    debug!("Verifying Quote Body using attestation key and signature present in the quote");
    let pubkey = [vec![0x04], signature.attest_pub_key.to_vec()].concat();
    let pubkey = EncodedPoint::from_bytes(pubkey).map_err(|e| Error::CryptoError(e.to_string()))?;
    let point = Option::from(AffinePoint::from_encoded_point(&pubkey)).ok_or_else(|| {
        Error::CryptoError("Can't build an affine point from the provided public key".to_owned())
    })?;

    let ecdsa_attestation_pk = VerifyingKey::from_affine(point)?;
    ecdsa_attestation_pk.verify(
        &raw_quote[..QUOTE_BODY_SIZE],
        &Signature::from_slice(&signature.signature)?,
    )?;

    Ok(())
}

fn verify_qe_report(qe_report: &ReportBody, qe_identity: QeIdentity) -> Result<(), Error> {
    debug!("Verifying QE Report against QE Identity");
    let miscselect_mask = u32::from_le_bytes(qe_identity.enclave_identity.miscselect_mask);
    let miscselect = u32::from_le_bytes(qe_identity.enclave_identity.miscselect);

    let miscselect_mask = qe_report.misc_select & miscselect_mask;

    if miscselect_mask != miscselect {
        return Err(Error::VerificationFailure("Miscselect value from Intel PCS's reported QE Identity is not equal to miscselect value from Quote QE Report".to_owned()));
    }

    let flags = u64::from_le_bytes(
        qe_identity.enclave_identity.attributes_mask[0..8]
            .try_into()
            .expect("Can't happen"),
    ) & qe_report.flags;
    let xfrm = u64::from_le_bytes(
        qe_identity.enclave_identity.attributes_mask[8..16]
            .try_into()
            .expect("Can't happen"),
    ) & qe_report.xfrm;

    if flags
        != u64::from_le_bytes(
            qe_identity.enclave_identity.attributes[0..8]
                .try_into()
                .expect("Can't happen"),
        )
    {
        return Err(Error::VerificationFailure("Flags value from Intel PCS's reported QE Identity is not equal to flags value from Quote QE Report".to_owned()));
    }

    if xfrm
        != u64::from_le_bytes(
            qe_identity.enclave_identity.attributes[8..16]
                .try_into()
                .expect("Can't happen"),
        )
    {
        return Err(Error::VerificationFailure("XFRM value from Intel PCS's reported QE Identity is not equal to flags value from Quote QE Report".to_owned()));
    }

    if qe_identity.enclave_identity.mrsigner != qe_report.mr_signer {
        return Err(Error::VerificationFailure("MRSigner value from Intel PCS's reported QE Identity is not equal to MRSigner value from Quote QE Report".to_owned()));
    }

    if qe_identity.enclave_identity.isvprodid != qe_report.isv_prod_id {
        return Err(Error::VerificationFailure("isv_prod_id value from Intel PCS's reported QE Identity is not equal to isv_prod_id value from Quote QE Report".to_owned()));
    }

    for tcb_level in qe_identity.enclave_identity.tcb_levels {
        if tcb_level.tcb.isvsvn < qe_report.isv_svn {
            if tcb_level.tcb_status != TcbComponentStatus::UpToDate {
                return Err(Error::VerificationFailure(
                    "TCB status from Intel PCS's reported QE Identity is not up to date".to_owned(),
                ));
            }
            break;
        }
    }

    Ok(())
}

fn verify_tcb_info(
    tcb_info_issuer_chain: &[u8],
    raw_tcb_info: &[u8],
    tee_type: IntelTeeType,
    root_ca_cert: &X509Certificate,
    sgx_pck_extension: &SgxPckExtension,
) -> Result<(), Error> {
    let tcb_info: TcbInfoData = serde_json::from_slice(raw_tcb_info)
        .map_err(|_| Error::InvalidFormat("TCBInfo is malformed".to_owned()))?;

    let tcb_info_raw: TcbInfoDataRaw = serde_json::from_slice(raw_tcb_info)
        .map_err(|_| Error::InvalidFormat("TCBInfo is malformed (raw parsing)".to_owned()))?;

    let chain = get_certificate_chain_from_pem(tcb_info_issuer_chain)?;

    if chain.len() != 2 {
        return Err(Error::InvalidFormat(
            "'TCB-Info-Issuer-Chain' header should contain exactly 2 certificates".to_owned(),
        ));
    }

    let (_, tcb_cert) =
        parse_x509_certificate(&chain[0]).map_err(|e| Error::X509ParserError(e.into()))?;

    let (_, local_root_ca_cert) =
        parse_x509_certificate(&chain[1]).map_err(|e| Error::X509ParserError(e.into()))?;

    if root_ca_cert != &local_root_ca_cert {
        return Err(Error::VerificationFailure(
            "PCCS returned different Intel SGX Root CA".to_owned(),
        ));
    }

    if tcb_info.tcb_info.version != 3 {
        return Err(Error::VerificationFailure(format!(
            "TCB version should be 3 (gets: {})",
            tcb_info.tcb_info.version,
        )));
    }

    if tcb_info.tcb_info.id != tee_type.as_str().to_uppercase() {
        return Err(Error::VerificationFailure(format!(
            "TCB Id should be '{}' (gets: {})",
            tee_type.as_str().to_uppercase(),
            tcb_info.tcb_info.id,
        )));
    }

    if sgx_pck_extension.fmspc != tcb_info.tcb_info.fmspc {
        return Err(Error::VerificationFailure(format!(
            "TCB FMSPC should be '{}' (gets: {})",
            hex::encode(tcb_info.tcb_info.fmspc),
            hex::encode(sgx_pck_extension.fmspc),
        )));
    }

    if sgx_pck_extension.pceid != tcb_info.tcb_info.pce_id {
        return Err(Error::VerificationFailure(format!(
            "TCB PCEID should be '{}' (gets: {})",
            hex::encode(tcb_info.tcb_info.pce_id),
            hex::encode(sgx_pck_extension.pceid),
        )));
    }

    if !is_in_the_future(&tcb_info.tcb_info.next_update)? {
        return Err(Error::VerificationFailure(format!(
            "TCB update is in the past (gets: {})",
            tcb_info.tcb_info.next_update,
        )));
    }

    tcb_cert.verify_signature(Some(root_ca_cert.public_key()))?;

    if !tcb_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel TCB certificate has expired".to_owned(),
        ));
    }

    let pubkey = VerifyingKey::from_public_key_der(tcb_cert.public_key().raw)?;
    pubkey.verify(
        &serde_json::to_vec(&tcb_info_raw.tcb_info)
            .map_err(|err| Error::InvalidFormat(format!("Can't serialize TCBInfo: {err}")))?,
        &Signature::from_slice(&tcb_info_raw.signature)?,
    )?;

    Ok(())
}

fn get_certificate_chain_from_pem(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut chain = Vec::new();

    for pem in Pem::iter_from_buffer(data) {
        match pem {
            Ok(pem) => {
                if &pem.label != "CERTIFICATE" {
                    return Err(Error::InvalidFormat(
                        "Not a certificate or certificate is malformed".to_owned(),
                    ));
                }

                chain.push(pem.contents);
            }

            Err(e) => {
                return Err(Error::InvalidFormat(format!(
                    "Not a certificate or certificate is malformed {e:?}"
                )));
            }
        }
    }

    Ok(chain)
}

fn verify_root_ca_crl(root_ca: &X509Certificate, root_ca_crl: &[u8]) -> Result<(), Error> {
    let (res, crl) = CertificateRevocationList::from_der(root_ca_crl)
        .map_err(|e| Error::X509ParserError(e.into()))?;

    if !res.is_empty() {
        return Err(Error::InvalidFormat(
            "Root CA CRL parsing failed".to_owned(),
        ));
    }

    crl.verify_signature(root_ca.public_key())?;

    let is_revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == root_ca.raw_serial());

    if is_revoked {
        return Err(Error::VerificationFailure(
            "Intel Root CA certificate is revoked".to_owned(),
        ));
    }

    Ok(())
}

/// Determine the value of the 'ca' parameter
fn get_pck_ca(pck_ca_cert: &X509Certificate) -> Result<PckCa, Error> {
    match pck_ca_cert.subject.iter_common_name().next() {
        Some(attr) => {
            let value = attr.attr_value().as_str()?;
            if value == "Intel SGX PCK Platform CA" {
                Ok(PckCa::Platform)
            } else if value == "Intel SGX PCK Processor CA" {
                Ok(PckCa::Processor)
            } else {
                Err(Error::InvalidFormat(
                    "Unknown CN in Intel SGX PCK Platform/Processor CA".to_string(),
                ))
            }
        }
        None => Err(Error::InvalidFormat(
            "Common name not found in pck ca cert".to_string(),
        )),
    }
}

fn verify_pck_cert_crl(
    pck_crl_issuer_chain: &[u8],
    pck_crl: &[u8],
    root_ca_cert: &X509Certificate,
    pck_ca_cert: &X509Certificate,
) -> Result<(), Error> {
    let (res, crl) = CertificateRevocationList::from_der(pck_crl)
        .map_err(|e| Error::X509ParserError(e.into()))?;

    if !res.is_empty() {
        return Err(Error::InvalidFormat("PCK CRL parsing failed".to_owned()));
    }

    crl.verify_signature(pck_ca_cert.public_key())
        .map_err(|_| {
            Error::VerificationFailure(
                "The PCK crl is not signed by the Intel PCK CA cert".to_owned(),
            )
        })?;

    let is_revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == pck_ca_cert.raw_serial());

    if is_revoked {
        return Err(Error::VerificationFailure(
            "Intel PCK CA certificate revoked".to_owned(),
        ));
    }

    // Verify the content of the sgx-pck-crl-issuer-chain header
    let chain = get_certificate_chain_from_pem(pck_crl_issuer_chain)?;

    if chain.len() != 2 {
        return Err(Error::InvalidFormat(
            "'sgx-pck-certificate-issuer-chain' header should contain exactly 2 certificates"
                .to_owned(),
        ));
    }

    let (_, local_root_ca_cert) =
        parse_x509_certificate(&chain[1]).map_err(|e| Error::X509ParserError(e.into()))?;

    let (_, local_pck_ca_cert) =
        parse_x509_certificate(&chain[0]).map_err(|e| Error::X509ParserError(e.into()))?;

    if root_ca_cert != &local_root_ca_cert {
        return Err(Error::VerificationFailure(
            "PCCS returned different Intel SGX Root CA".to_owned(),
        ));
    }

    if pck_ca_cert != &local_pck_ca_cert {
        return Err(Error::VerificationFailure(
            "PCCS returned different Intel SGX PCK Platform/Processor CA".to_owned(),
        ));
    }

    Ok(())
}

fn verify_qe_identity(
    qe_identity_issuer_chain: &[u8],
    raw_qe_identity: &[u8],
    root_ca_cert: &X509Certificate,
) -> Result<(QeIdentity, Vec<String>), Error> {
    debug!("Verifying QE Identity...");
    let qe_identity: QeIdentity = serde_json::from_slice(raw_qe_identity)
        .map_err(|e| Error::InvalidFormat(format!("QeIdentity is malformed: {e}")))?;

    let chain = get_certificate_chain_from_pem(qe_identity_issuer_chain)?;

    if chain.len() != 2 {
        return Err(Error::InvalidFormat(
            "'sgx-enclave-identity-issuer-chain' header should contain exactly 2 certificates"
                .to_owned(),
        ));
    }

    let (_, qe_identity_issuer_intermediate_cert) =
        parse_x509_certificate(&chain[1]).map_err(|e| Error::X509ParserError(e.into()))?;

    let (_, qe_identity_issuer_root_cert) =
        parse_x509_certificate(&chain[0]).map_err(|e| Error::X509ParserError(e.into()))?;

    qe_identity_issuer_intermediate_cert.verify_signature(Some(root_ca_cert.public_key()))?;

    if !qe_identity_issuer_intermediate_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel SGX TCB Signing has expired".to_owned(),
        ));
    }

    if !qe_identity_issuer_root_cert.validity().is_valid() {
        return Err(Error::VerificationFailure(
            "Intel SGX Root CA has expired".to_owned(),
        ));
    }

    if !is_in_the_future(&qe_identity.enclave_identity.next_update)? {
        return Err(Error::VerificationFailure(format!(
            "QE Identity update is in the past (gets: {})",
            qe_identity.enclave_identity.next_update,
        )));
    }

    let pubkey = VerifyingKey::from_public_key_der(qe_identity_issuer_root_cert.public_key().raw)?;
    pubkey.verify(
        &serde_json::to_vec(&qe_identity.enclave_identity)
            .map_err(|err| Error::InvalidFormat(format!("Can't serialize QEIdentity: {err}")))?,
        &Signature::from_slice(&qe_identity.signature)?,
    )?;

    let crl_distribution_points = qe_identity_issuer_root_cert
        .extensions_map()?
        .get(&CRL_DISTRIBUTION_POINTS_EXTENSION_OID)
        .ok_or(Error::InvalidFormat(
            "CRLDistributionPoints not found in qe_identity_issuer_root_cert".to_owned(),
        ))?
        .parsed_extension();

    if let ParsedExtension::CRLDistributionPoints(distribution_points, ..) = crl_distribution_points
    {
        let mut crl_distribution_points = vec![];
        for dp in distribution_points.iter() {
            if let Some(point_name) = &dp.distribution_point {
                match point_name {
                    x509_parser::extensions::DistributionPointName::FullName(names) => {
                        for name in names {
                            if let GeneralName::URI(uri) = name {
                                crl_distribution_points.push(uri.to_string())
                            } else {
                                return Err(Error::Unimplemented(format!("Name format ({name}) not supported for CRL distribution point")))
                            }
                        }
                    }
                    x509_parser::extensions::DistributionPointName::NameRelativeToCRLIssuer(_) => return Err(Error::Unimplemented("CRL distribution point name is relatived to crl issuer: not yet supported".to_owned())),
                }
            }
        }

        Ok((qe_identity, crl_distribution_points))
    } else {
        Err(Error::InvalidFormat(
            "CRLDistributionPoints found by invalid format in qe_identity_issuer_root_cert"
                .to_owned(),
        ))
    }
}

fn is_in_the_future(date: &str) -> Result<bool, Error> {
    Ok(Utc::now()
        <= NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%SZ")
            .map_err(|e| Error::InvalidFormat(format!("Invalid date format: {e:?}")))?
            .and_utc())
}

/// Verify the quote header against expected values
pub(crate) fn verify_quote_header_policy(
    header: &QuoteHeader,
    policy: &SgxQuoteHeaderVerificationPolicy,
) -> Result<(), Error> {
    debug!("Verifiying quote header against the policy...");

    if header.version != 3 {
        return Err(Error::VerificationFailure(format!(
            "Quote version '{}' is not supported",
            header.version
        )));
    }

    if header.att_key_type != 2 {
        // ECDSA-256-with-P-256 curve
        return Err(Error::VerificationFailure(format!(
            "Attestation key type '{}' is not supported",
            header.att_key_type
        )));
    }

    if let Some(minimum_qe_svn) = policy.minimum_qe_svn {
        if header.qe_svn < minimum_qe_svn {
            return Err(Error::VerificationFailure(format!(
                "Attestation QE security-version number '{}' is lower than the set value '{}'",
                header.qe_svn, minimum_qe_svn
            )));
        }
    }

    if let Some(minimum_pce_svn) = policy.minimum_pce_svn {
        if header.pce_svn < minimum_pce_svn {
            return Err(Error::VerificationFailure(format!(
                "Attestation PCE security-version number '{}' is lower than the set value '{}'",
                header.pce_svn, minimum_pce_svn
            )));
        }
    }

    if let Some(vendor_id) = policy.qe_vendor_id {
        if header.vendor_id != vendor_id {
            return Err(Error::VerificationFailure(format!(
                "Attestation QE Vendor ID '{}' is not equal to the set value '{}'",
                hex::encode(header.vendor_id),
                hex::encode(vendor_id)
            )));
        }
    }

    Ok(())
}

/// Verify the quote body against expected values
pub(crate) fn verify_quote_body_policy(
    body: &ReportBody,
    policy: &SgxQuoteBodyVerificationPolicy,
) -> Result<(), Error> {
    debug!("Verifiying quote body against the policy...");

    // Check the MRENCLAVE
    if let Some(mr_enclave) = policy.mr_enclave {
        if body.mr_enclave != mr_enclave {
            return Err(Error::VerificationFailure(format!(
                "MRENCLAVE miss-matches expected value ({})",
                hex::encode(body.mr_enclave),
            )));
        }
    }

    // Check the MRSIGNER
    if let Some(mr_signer) = policy.mr_signer {
        if body.mr_signer != mr_signer {
            return Err(Error::VerificationFailure(format!(
                "MRSIGNER miss-matches expected value ({})",
                hex::encode(body.mr_signer),
            )));
        }
    }

    if let Some(report_data) = &policy.report_data {
        if &body.report_data != report_data {
            return Err(Error::VerificationFailure(format!(
                "Attestation report data '{}' is not equal to the set value '{}'",
                hex::encode(body.report_data),
                hex::encode(report_data)
            )));
        }
    }

    Ok(())
}
