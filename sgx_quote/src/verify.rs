use crate::error::Error;
use crate::quote::{
    AuthData, EcdsaSigData, QUOTE_BODY_SIZE, QUOTE_QE_REPORT_OFFSET, QUOTE_QE_REPORT_SIZE,
};

use chrono::{NaiveDateTime, Utc};
use elliptic_curve::pkcs8::DecodePublicKey;
use log::debug;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{AffinePoint, EncodedPoint};
use reqwest::blocking::get;
use serde::Deserialize;
use sgx_pck_extension::SgxPckExtension;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::prelude::{FromDer, Pem};
use x509_parser::revocation_list::CertificateRevocationList;

use elliptic_curve::sec1::FromEncodedPoint;

pub(crate) fn verify_pck_chain_and_tcb(
    raw_quote: &[u8],
    certification_data: &[u8],
    qe_report_signature: &[u8],
    pccs_url: &str,
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

    debug!("Verifying certificates signature...");
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

    debug!("Verifying root ca crl");
    verify_root_ca_crl(pccs_url, &root_ca_cert)?;

    debug!("Verifying pck crl");
    verify_pck_cert_crl(pccs_url, &root_ca_cert, &pck_ca_cert)?;

    debug!("Verifying tcb info");
    verify_tcb_info(
        pccs_url,
        &root_ca_cert,
        &SgxPckExtension::from_pem_certificate_content(&chain[0])?,
    )?;

    debug!("Verifying QE report signature");
    let pck_pk = VerifyingKey::from_public_key_der(pck_cert.public_key().raw)?;
    pck_pk.verify(
        raw_quote
            .get(QUOTE_QE_REPORT_OFFSET..QUOTE_QE_REPORT_SIZE + QUOTE_QE_REPORT_OFFSET)
            .ok_or_else(|| {
                Error::InvalidFormat(
                    "Bad offset extraction to check QE report signature".to_owned(),
                )
            })?,
        &Signature::from_slice(qe_report_signature)?,
    )?;

    Ok(())
}

pub(crate) fn verify_quote_signature(
    raw_quote: &[u8],
    auth_data: &AuthData,
    signature: &EcdsaSigData,
) -> Result<(), Error> {
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

    let mut pubkey_hash = Sha256::new();
    pubkey_hash.update(signature.attest_pub_key);
    pubkey_hash.update(&auth_data.auth_data);
    let expected_qe_report_data = &pubkey_hash.finalize()[..];

    if &signature.qe_report.report_data[..32] != expected_qe_report_data {
        return Err(Error::VerificationFailure(
            "Unexpected REPORTDATA in QE report".to_owned(),
        ));
    }

    Ok(())
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    version: u32,
    id: String,
    next_update: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct TcbInfoData {
    tcb_info: TcbInfo,
}

pub(crate) fn verify_tcb_info(
    pccs_url: &str,
    root_ca_cert: &X509Certificate<'_>,
    sgx_pck_extension: &SgxPckExtension,
) -> Result<(), Error> {
    let url_str = format!("{pccs_url}/sgx/certification/v4/tcb");
    let params = [("fmspc", hex::encode(sgx_pck_extension.fmspc))];
    let url = reqwest::Url::parse_with_params(&url_str, &params)
        .map_err(|e| Error::InvalidFormat(e.to_string()))?;
    let rsp = get(url)?;
    let status = rsp.status();
    let (headers, body) = (rsp.headers().clone(), rsp.text()?);

    if !status.is_success() {
        return Err(Error::ResponseAPIError(format!(
            "Request to {url_str} returns a {status}: {body:?}",
        )));
    }

    let tcb_info: TcbInfoData = serde_json::from_str(&body)
        .map_err(|_| Error::InvalidFormat("TCBInfo is malformed".to_owned()))?;

    let chain = get_certificate_chain_from_pem(
        urlencoding::decode(
            headers
                .get("TCB-Info-Issuer-Chain")
                .ok_or_else(|| {
                    Error::InvalidFormat("'TCB-Info-Issuer-Chain' header not found".to_owned())
                })?
                .to_str()
                .map_err(|_| {
                    Error::InvalidFormat(
                        "Can't find 'TCB-Info-Issuer-Chain' in response header".to_owned(),
                    )
                })?,
        )
        .map_err(|_| Error::InvalidFormat("Can't decode 'TCB-Info-Issuer-Chain'".to_owned()))?
        .as_bytes(),
    )?;

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

    if tcb_info.tcb_info.id != "SGX" {
        return Err(Error::VerificationFailure(format!(
            "TCB Id should be 'SGX' (gets: {})",
            tcb_info.tcb_info.id,
        )));
    }

    if Utc::now()
        > NaiveDateTime::parse_from_str(&tcb_info.tcb_info.next_update, "%Y-%m-%dT%H:%M:%SZ")
            .map_err(|e| Error::InvalidFormat(format!("Invalid date format: {e:?}")))?
            .and_utc()
    {
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

    Ok(())
}

pub(crate) fn get_certificate_chain_from_pem(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut chain = Vec::new();

    for pem in Pem::iter_from_buffer(data) {
        match pem {
            Ok(pem) => {
                if &pem.label != "CERTIFICATE" {
                    return Err(Error::InvalidFormat(
                        "Not a certificate or certificate is malformed".to_owned(),
                    ));
                }

                chain.push(pem.contents.clone());
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

pub(crate) fn verify_root_ca_crl(
    pccs_url: &str,
    root_ca: &X509Certificate<'_>,
) -> Result<(), Error> {
    let url = format!("{pccs_url}/sgx/certification/v4/rootcacrl");
    let rsp = get(&url)?;
    let status = rsp.status();
    let body = rsp.bytes()?;

    if !status.is_success() {
        return Err(Error::ResponseAPIError(format!(
            "Request to  {url} returns a {status}: {}",
            String::from_utf8_lossy(&body),
        )));
    }

    let body = hex::decode(body).map_err(|e| Error::InvalidFormat(e.to_string()))?;

    let (res, crl) =
        CertificateRevocationList::from_der(&body).map_err(|e| Error::X509ParserError(e.into()))?;

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

pub(crate) fn verify_pck_cert_crl(
    pccs_url: &str,
    root_ca_cert: &X509Certificate<'_>,
    pck_ca_cert: &X509Certificate<'_>,
) -> Result<(), Error> {
    // Determine the value of the 'ca' parameter
    let ca = match pck_ca_cert.subject.iter_common_name().next() {
        Some(attr) => {
            let value = attr.attr_value().as_str()?;
            if value == "Intel SGX PCK Platform CA" {
                Ok("platform")
            } else if value == "Intel SGX PCK Processor CA" {
                Ok("processor")
            } else {
                Err(Error::InvalidFormat(
                    "Unknown CN in Intel SGX PCK Platform/Processor CA".to_string(),
                ))
            }
        }
        None => Err(Error::InvalidFormat(
            "Common name not found in pck ca cert".to_string(),
        )),
    }?;

    // Get the CRL
    let url_str = format!("{pccs_url}/sgx/certification/v4/pckcrl");
    let params = [("ca", ca), ("encoding", "der")];
    let url = reqwest::Url::parse_with_params(&url_str, &params)
        .map_err(|e| Error::InvalidFormat(e.to_string()))?;
    let rsp = get(url)?;
    let status = rsp.status();
    let (headers, body) = (rsp.headers().clone(), rsp.bytes()?);

    if !status.is_success() {
        return Err(Error::ResponseAPIError(format!(
            "Request to  {url_str} returns a {status}: {}",
            String::from_utf8_lossy(&body),
        )));
    }

    let (res, crl) =
        CertificateRevocationList::from_der(&body).map_err(|e| Error::X509ParserError(e.into()))?;

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
    let chain = get_certificate_chain_from_pem(
        urlencoding::decode(
            headers
                .get("sgx-pck-crl-issuer-chain")
                .ok_or_else(|| {
                    Error::InvalidFormat("(sgx-pck-crl-issuer-chain() header not found".to_owned())
                })?
                .to_str()
                .map_err(|_| {
                    Error::InvalidFormat(
                        "Can't find 'sgx-pck-crl-issuer-chain' in response header".to_owned(),
                    )
                })?,
        )
        .map_err(|_| Error::InvalidFormat("Can't decode 'sgx-pck-crl-issuer-chain'".to_owned()))?
        .as_bytes(),
    )?;

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
