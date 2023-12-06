use std::str::FromStr;

use crate::error::Error;

use log::debug;

use reqwest::{blocking::get, StatusCode, Url};
use sev::firmware::host::TcbVersion;

/// Identifier of the SEV prod name.
#[derive(PartialEq, Clone, Copy)]
pub enum SevProdName {
    Milan,
}

impl std::fmt::Display for SevProdName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SevProdName::Milan => write!(f, "Milan"),
        }
    }
}

const KDS_VCEK: &str = "/vcek/v1";
const KDS_VLEK: &str = "/vlek/v1";
const KDS_CERT_CHAIN: &str = "cert_chain";
const KDS_CRL: &str = "crl";

/// Fetch the AMD revocation list
pub(crate) fn fetch_revocation_list(
    kds_url: &str,
    sev_prod_name: SevProdName,
) -> Result<Vec<u8>, Error> {
    let url = Url::from_str(&format!("{kds_url}{KDS_VCEK}/{sev_prod_name}/{KDS_CRL}",))
        .map_err(|e| Error::URLError(e.to_string()))?;

    debug!("Requesting CRL from: {url}");

    let r = get(url)?;

    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::ResponseAPIError(
            "Revocation list cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::ResponseAPIError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::ResponseAPIError(
            "Unable to retrieve the collateral from the AMD KDS API".to_owned(),
        )),
        s => Err(Error::ResponseAPIError(format!("HTTP status code {}", s))),
    }?;

    Ok(body.to_vec())
}

/// Fetch the AMD cert chain which signed the VLEK certificate
pub(crate) fn fetch_amd_vlek_cert_chain(
    kds_url: &str,
    sev_prod_name: SevProdName,
) -> Result<Vec<u8>, Error> {
    let url = format!("{kds_url}{KDS_VLEK}/{sev_prod_name}/{KDS_CERT_CHAIN}",);
    fetch_amd_cert_chain(&url)
}

/// Fetch the AMD cert chain which signed the VCEK certificate
pub(crate) fn fetch_amd_vcek_cert_chain(
    kds_url: &str,
    sev_prod_name: SevProdName,
) -> Result<Vec<u8>, Error> {
    let url = format!("{kds_url}{KDS_VCEK}/{sev_prod_name}/{KDS_CERT_CHAIN}",);
    fetch_amd_cert_chain(&url)
}

/// Fetch the certificate-chain (AMD ASK + AMD ARK)
/// These may be used to verify the downloaded VCEK is authentic.
fn fetch_amd_cert_chain(full_url: &str) -> Result<Vec<u8>, Error> {
    // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
    let url = Url::from_str(full_url).map_err(|e| Error::URLError(e.to_string()))?;

    debug!("Requesting AMD certificate-chain from: {full_url}");

    let r = get(url)?;

    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::ResponseAPIError(
            "AMD certification chain cannot be found".to_owned(),
        )),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::ResponseAPIError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::ResponseAPIError(
            "Unable to retrieve the collateral from the AMD KDS API".to_owned(),
        )),
        s => Err(Error::ResponseAPIError(format!("HTTP status code {}", s))),
    }?;

    Ok(body.to_vec())
}

/// Fetch the VCEK for the specified chip and TCP
pub(crate) fn fetch_vcek(
    kds_url: &str,
    sev_prod_name: SevProdName,
    chip_id: [u8; 64],
    reported_tcb: TcbVersion,
) -> Result<Vec<u8>, Error> {
    let hw_id = hex::encode(chip_id);
    let url = Url::from_str(&format!(
        "{kds_url}{KDS_VCEK}/{sev_prod_name}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode
    ))
        .map_err(|e| Error::URLError(e.to_string()))?;

    debug!("Requesting VCEK from: {url}\n");

    let r = get(url)?;

    let body = match r.status() {
        StatusCode::OK => Ok(r.bytes()?[..].to_vec()),
        StatusCode::NOT_FOUND => Err(Error::ResponseAPIError("VCEK cannot be found".to_owned())),
        StatusCode::INTERNAL_SERVER_ERROR => Err(Error::ResponseAPIError(
            "Internal server error occurred".to_owned(),
        )),
        StatusCode::BAD_GATEWAY => Err(Error::ResponseAPIError(
            "Unable to retrieve the collateral from the AMD KDS API".to_owned(),
        )),
        s => Err(Error::ResponseAPIError(format!("HTTP status code {}", s))),
    }?;

    Ok(body.to_vec())
}
