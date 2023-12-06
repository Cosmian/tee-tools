use std::str::FromStr;

use crate::error::Error;

use reqwest::StatusCode;

pub mod error;

/// Identifier of the PCK CA that issued the PCK CRL.
pub enum PckCa {
    Processor,
    Platform,
}

impl std::fmt::Display for PckCa {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PckCa::Processor => write!(f, "processor"),
            PckCa::Platform => write!(f, "platform"),
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
pub enum IntelTeeType {
    Sgx,
    Tdx,
}

impl IntelTeeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IntelTeeType::Sgx => "sgx",
            IntelTeeType::Tdx => "tdx",
        }
    }
}

/// Fetch Intel SGX Root CA Certificate Revocation List (CRL) from PCCS URL.
///
/// # Returns
///
/// Either [`Vec<u8>`] within DER representation of Root CA CRL or [`Error`].
///
/// # External documentation
///
/// See section 3.7 of [`SGX_DCAP_Caching_Service_Design_Guide.pdf`].
///
/// [`SGX_DCAP_Caching_Service_Design_Guide.pdf`]: https://download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
pub fn get_root_ca_crl(pccs_url: &str) -> Result<Vec<u8>, Error> {
    let url = reqwest::Url::from_str(&format!("{pccs_url}/sgx/certification/v4/rootcacrl"))
        .map_err(|e| Error::URLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;

    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::PccsResponseError(
            "Root CA CRL cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::PccsResponseError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::PccsResponseError(
            "Unable to retrieve the collateral from the Intel PCS API".to_owned(),
        )),
        s => Err(Error::UnexpectedError(format!("HTTP status code {}", s))),
    }?;

    let root_ca_crl = hex::decode(body).map_err(|e| Error::DecodeError(e.to_string()))?;

    Ok(root_ca_crl)
}

/// Fetch Intel SGX Root CA Certificate Revocation List (CRL) from a given URI.
///
/// # Returns
///
/// Either [`Vec<u8>`] within DER representation of Root CA CRL or [`Error`].
pub fn get_root_ca_crl_from_uri(uri: &str) -> Result<Vec<u8>, Error> {
    let url = reqwest::Url::from_str(uri).map_err(|e| Error::URLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;

    match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::PccsResponseError(
            "Root CA CRL cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::PccsResponseError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::PccsResponseError(
            "Unable to retrieve the collateral from the Intel PCS API".to_owned(),
        )),
        s => Err(Error::UnexpectedError(format!("HTTP status code {}", s))),
    }
}

/// Fetch Intel SGX PCK Certificate Revocation List (CRL) and issuer chain
/// from PCCS URL. The CRL is issued either by Intel SGX Platform CA or
/// Intel SGX Processor CA which is issued by Intel SGX Root CA.
///
/// # Returns
///
/// Either ([`Vec<u8>`], [`Vec<u8>`]) the issuer chain and PCK CRL or [`Error`].
///
/// # External documentation
///
/// See section 3.2 of [`SGX_DCAP_Caching_Service_Design_Guide.pdf`].
///
/// [`SGX_DCAP_Caching_Service_Design_Guide.pdf`]: https://download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
pub fn get_pck_crl(pccs_url: &str, ca: PckCa) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let ca = ca.to_string();
    let url = reqwest::Url::parse_with_params(
        &format!("{pccs_url}/sgx/certification/v4/pckcrl"),
        &[("ca", ca.as_str()), ("encoding", "der")],
    )
    .map_err(|e| Error::URLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;
    let pck_crl_issuer_chain = urlencoding::decode(
        r.headers()
            .get("sgx-pck-crl-issuer-chain")
            .ok_or_else(|| {
                Error::UnexpectedError(
                    "sgx-pck-crl-issuer-chain not found in HTTP headers".to_owned(),
                )
            })?
            .to_str()
            .map_err(|_| {
                Error::UnexpectedError(
                    "string value expected in HTTP header sgx-pck-crl-issuer-chain".to_owned(),
                )
            })?,
    )
    .map_err(|_| {
        Error::UnexpectedError(
            "can't decode URL encoded header sgx-pck-crl-issuer-chain".to_owned(),
        )
    })?
    .as_bytes()
    .to_vec();

    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::PccsResponseError(
            "Root CA CRL cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::PccsResponseError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::PccsResponseError(
            "Unable to retrieve the collateral from the Intel PCS API".to_owned(),
        )),
        s => Err(Error::UnexpectedError(format!("HTTP status code {}", s))),
    }?;

    Ok((pck_crl_issuer_chain, body))
}

/// Fetch TCB info and issuer chain for the given `fmscp`.
///
/// # Returns
///
/// Either [([`Vec<u8>`], [`Vec<u8>`])], the issuer chain and JSON TCB Info V3
/// or [`Error`].
///
/// # External documentation
///
/// See section 3.3 of [`SGX_DCAP_Caching_Service_Design_Guide.pdf`] and
/// Appendix A: TCB Info V3 in [`PCS API documentation`].
//
/// [`SGX_DCAP_Caching_Service_Design_Guide.pdf`]: https://download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
/// [`PCS API documentation`]: https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3
pub fn get_tcbinfo(
    pccs_url: &str,
    tee: IntelTeeType,
    fmscp: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let url = reqwest::Url::parse_with_params(
        &format!("{pccs_url}/{}/certification/v4/tcb", tee.as_str()),
        &[("fmspc", hex::encode(fmscp))],
    )
    .map_err(|e| Error::URLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;
    let tcb_info_issuer_chain = urlencoding::decode(
        r.headers()
            .get("TCB-Info-Issuer-Chain")
            .ok_or_else(|| {
                Error::UnexpectedError("TCB-Info-Issuer-Chain not found in HTTP headers".to_owned())
            })?
            .to_str()
            .map_err(|_| {
                Error::UnexpectedError(
                    "string value expected in HTTP header TCB-Info-Issuer-Chain".to_owned(),
                )
            })?,
    )
    .map_err(|_| {
        Error::UnexpectedError("can't decode URL encoded header TCB-Info-Issuer-Chain".to_owned())
    })?
    .as_bytes()
    .to_vec();
    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::PccsResponseError(
            "Root CA CRL cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::PccsResponseError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::PccsResponseError(
            "Unable to retrieve the collateral from the Intel PCS API".to_owned(),
        )),
        s => Err(Error::UnexpectedError(format!("HTTP status code {}", s))),
    }?;

    Ok((tcb_info_issuer_chain, body))
}

/// Fetch QE identity.
///
/// # Returns
///
/// Either [([`Vec<u8>`], [`Vec<u8>`])], the issuer chain and JSON QE Identity V2
/// or [`Error`].
///
/// # External documentation
///
/// See section 3.4 of [`SGX_DCAP_Caching_Service_Design_Guide.pdf`] and
/// Appendix B: Enclave Identity V2 in [`PCS API documentation`].
//
/// [`SGX_DCAP_Caching_Service_Design_Guide.pdf`]: https://download.01.org/intel-sgx/sgx-dcap/1.18/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf
/// [`PCS API documentation`]: https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-model-v2
pub fn get_qe_identity(pccs_url: &str, tee: IntelTeeType) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let url = reqwest::Url::from_str(&format!(
        "{pccs_url}/{}/certification/v4/qe/identity",
        tee.as_str()
    ))
    .map_err(|e| Error::URLError(e.to_string()))?;

    let r = reqwest::blocking::get(url)?;
    let qe_identity_issuer_chain = urlencoding::decode(
        r.headers()
            .get("SGX-Enclave-Identity-Issuer-Chain")
            .ok_or_else(|| {
                Error::UnexpectedError(
                    "SGX-Enclave-Identity-Issuer-Chain not found in HTTP headers".to_owned(),
                )
            })?
            .to_str()
            .map_err(|_| {
                Error::UnexpectedError(
                    "string value expected in HTTP header SGX-Enclave-Identity-Issuer-Chain"
                        .to_owned(),
                )
            })?,
    )
    .map_err(|_| {
        Error::UnexpectedError(
            "can't decode URL encoded header SGX-Enclave-Identity-Issuer-Chain".to_owned(),
        )
    })?
    .as_bytes()
    .to_vec();
    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::PccsResponseError(
            "Root CA CRL cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::PccsResponseError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::PccsResponseError(
            "Unable to retrieve the collateral from the Intel PCS API".to_owned(),
        )),
        s => Err(Error::UnexpectedError(format!("HTTP status code {}", s))),
    }?;

    Ok((qe_identity_issuer_chain, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::{crl::CertificateList, der::Decode, Certificate};

    #[test]
    fn test_intel_root_ca_crl() {
        let root_ca_crl = get_root_ca_crl("https://pccs.mse.cosmian.com").unwrap();
        let root_ca_crl = CertificateList::from_der(&root_ca_crl).unwrap();
        assert_eq!(
            root_ca_crl.tbs_cert_list.issuer.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX Root CA"
        );
    }

    #[test]
    fn test_intel_pck_crl() {
        let (pck_issuer_chain, pck_crl) =
            get_pck_crl("https://pccs.mse.cosmian.com", PckCa::Platform).unwrap();
        let (pck_issuer_chain, pck_crl) = (
            Certificate::load_pem_chain(&pck_issuer_chain).unwrap(),
            CertificateList::from_der(&pck_crl).unwrap(),
        );

        assert_eq!(pck_issuer_chain.len(), 2);
        let (pck_ca, root_ca) = (&pck_issuer_chain[0], &pck_issuer_chain[1]);

        // self-signed Intel SGX Root CA
        assert_eq!(
            root_ca.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
        assert_eq!(
            root_ca.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX Root CA"
        );

        // Intel SGX PCK CA issued by Intel SGX Root CA
        assert_eq!(
            pck_ca.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
        assert_eq!(
            pck_ca.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX PCK Platform CA"
        );

        // Intel SGX PCK CRL issued by Intel SGX PCK CA
        assert_eq!(
            pck_crl.tbs_cert_list.issuer.to_string(),
            pck_ca.tbs_certificate.subject.to_string()
        );
    }

    #[test]
    fn test_tcb_info_sgx() {
        let fmspc = hex::decode("30606a000000").unwrap();
        let (tcb_info_issuer_chain, tcb_info) =
            get_tcbinfo("https://pccs.mse.cosmian.com", IntelTeeType::Sgx, &fmspc).unwrap();

        assert!(String::from_utf8(tcb_info).is_ok());

        let tcb_info_issuer_chain = Certificate::load_pem_chain(&tcb_info_issuer_chain).unwrap();
        assert_eq!(tcb_info_issuer_chain.len(), 2);
        let (tcb, root_ca) = (&tcb_info_issuer_chain[0], &tcb_info_issuer_chain[1]);
        assert_eq!(
            tcb.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX TCB Signing"
        );
        assert_eq!(
            tcb.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
    }

    #[test]
    fn test_tcb_info_tdx() {
        let fmspc = hex::decode("00806f050000").unwrap();
        let (tcb_info_issuer_chain, tcb_info) = get_tcbinfo(
            "https://api.trustedservices.intel.com",
            IntelTeeType::Tdx,
            &fmspc,
        )
        .unwrap();

        assert!(String::from_utf8(tcb_info).is_ok());

        let tcb_info_issuer_chain = Certificate::load_pem_chain(&tcb_info_issuer_chain).unwrap();
        assert_eq!(tcb_info_issuer_chain.len(), 2);
        let (tcb, root_ca) = (&tcb_info_issuer_chain[0], &tcb_info_issuer_chain[1]);
        assert_eq!(
            tcb.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX TCB Signing"
        );
        assert_eq!(
            tcb.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
    }

    #[test]
    fn test_qe_identity_sgx() {
        let (qe_identity_issuer_chain, qe_identity) =
            get_qe_identity("https://pccs.mse.cosmian.com", IntelTeeType::Sgx).unwrap();

        assert!(String::from_utf8(qe_identity).is_ok());

        let qe_identity_issuer_chain =
            Certificate::load_pem_chain(&qe_identity_issuer_chain).unwrap();
        assert_eq!(qe_identity_issuer_chain.len(), 2);
        let (tcb, root_ca) = (&qe_identity_issuer_chain[0], &qe_identity_issuer_chain[1]);
        assert_eq!(
            tcb.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX TCB Signing"
        );
        assert_eq!(
            tcb.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
    }

    #[test]
    fn test_qe_identity_tdx() {
        let (qe_identity_issuer_chain, qe_identity) =
            get_qe_identity("https://api.trustedservices.intel.com", IntelTeeType::Tdx).unwrap();

        assert!(String::from_utf8(qe_identity).is_ok());

        let qe_identity_issuer_chain =
            Certificate::load_pem_chain(&qe_identity_issuer_chain).unwrap();
        assert_eq!(qe_identity_issuer_chain.len(), 2);
        let (tcb, root_ca) = (&qe_identity_issuer_chain[0], &qe_identity_issuer_chain[1]);
        assert_eq!(
            tcb.tbs_certificate.subject.to_string(),
            "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Intel SGX TCB Signing"
        );
        assert_eq!(
            tcb.tbs_certificate.issuer.to_string(),
            root_ca.tbs_certificate.subject.to_string()
        );
    }
}
