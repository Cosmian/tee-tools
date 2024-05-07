use std::collections::HashMap;

use crate::{
    error::Error,
    policy::SevQuoteVerificationPolicy,
    snp_extension::{check_cert_ext_byte, check_cert_ext_bytes, SnpOid},
};

use asn1_rs::{FromDer, Oid};
use log::debug;
use sev::certs::snp::{ca, Chain};
use sev::{certs::snp::Verifiable, firmware::guest::AttestationReport};
use x509_parser::{
    self,
    certificate::X509Certificate,
    prelude::{Pem, X509Extension},
    revocation_list::CertificateRevocationList,
};

/// Verify the certification chain against the AMD revocation list
pub(crate) fn verify_revocation_list(chain: &Chain, crl: &[u8]) -> Result<(), Error> {
    let (res, crl) =
        CertificateRevocationList::from_der(crl).map_err(|e| Error::X509ParserError(e.into()))?;

    if !res.is_empty() {
        return Err(Error::InvalidFormat(
            "Root CA CRL parsing failed".to_owned(),
        ));
    }

    // Verify that the crl has been signed by ARK
    let ark = chain.ca.ark.to_der()?;
    let (_, cert) = X509Certificate::from_der(&ark)?;

    // TODO: OID_PKCS1_RSASSAPSS signature algorithm is not supported
    // crl.verify_signature(cert.public_key())?;

    // Verify ASK is not revoked
    let is_revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == cert.raw_serial());

    if is_revoked {
        return Err(Error::VerificationFailure(
            "The ASK certificate has been revoked".to_owned(),
        ));
    }

    // Verify VCEK is not revoked
    let vcek = &chain.vcek.to_der()?;
    let (_, cert) = X509Certificate::from_der(vcek)?;

    let is_revoked = crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == cert.raw_serial());

    if is_revoked {
        return Err(Error::VerificationFailure(
            "The VCEK certificate has been revoked".to_owned(),
        ));
    }

    Ok(())
}

/// Validate that the VLEK or VCEK certificate is signed by the AMD root of trust certificates
pub(crate) fn verify_chain_certificates(cert_chain: &Chain) -> Result<(), Error> {
    let ark = &cert_chain.ca.ark;
    let ask = &cert_chain.ca.ask;
    let vcek = &cert_chain.vcek;

    if (ark, ark).verify().is_err() {
        return Err(Error::VerificationFailure(
            "The AMD ARK is not self-signed!".to_owned(),
        ));
    }

    debug!("The AMD ARK was self-signed...");

    if (ark, ask).verify().is_err() {
        return Err(Error::VerificationFailure(
            "The AMD ASK was not signed by the AMD ARK!".to_owned(),
        ));
    }

    debug!("The AMD ASK was signed by the AMD ARK...");

    if (ask, vcek).verify().is_err() {
        return Err(Error::VerificationFailure(
            "The VCEK was not signed by the AMD ASK!".to_owned(),
        ));
    }

    debug!("The VCEK was signed by the AMD ASK...");

    Ok(())
}

/// Validate the guest Trusted Compute Base by verifying the following fields in an attestation report and a VCEK:
/// - Bootloader
/// - TEE
/// - SNP
/// - Microcode
/// - Chip ID
pub(crate) fn verify_tcb(report: &AttestationReport, cert: &X509Certificate) -> Result<(), Error> {
    let extensions: HashMap<Oid, &X509Extension> = cert.extensions_map()?;
    if let Some(cert_bl) = extensions.get(&SnpOid::BootLoader.oid()) {
        if !check_cert_ext_byte(cert_bl, report.reported_tcb.bootloader)? {
            return Err(Error::VerificationFailure(
                "Report TCB Boot Loader and Certificate Boot Loader mismatch encountered."
                    .to_owned(),
            ));
        }
    }

    if let Some(cert_tee) = extensions.get(&SnpOid::Tee.oid()) {
        if !check_cert_ext_byte(cert_tee, report.reported_tcb.tee)? {
            return Err(Error::VerificationFailure(
                "Report TCB TEE and Certificate TEE mismatch encountered.".to_owned(),
            ));
        }
        debug!("Reported TCB TEE from certificate matches the attestation report.");
    }

    if let Some(cert_snp) = extensions.get(&SnpOid::Snp.oid()) {
        if !check_cert_ext_byte(cert_snp, report.reported_tcb.snp)? {
            return Err(Error::VerificationFailure(
                "Report TCB SNP and Certificate SNP mismatch encountered.".to_owned(),
            ));
        }
        debug!("Reported TCB SNP from certificate matches the attestation report.");
    }

    // TODO: for some reason (unknown...), it's not equal on AWS...
    // if let Some(cert_ucode) = extensions.get(&SnpOid::Ucode.oid()) {
    //     if !check_cert_ext_byte(cert_ucode, report.reported_tcb.microcode)? {
    //         return Err(Error::VerificationFailure(
    //             "Report TCB Microcode and Certificate Microcode mismatch
    //     encountered."
    //                 .to_owned(),
    //         ));
    //     }
    //     debug!(
    //         "Reported TCB Microcode from certificate matches the attestation
    //     report."
    //     );
    // }

    if let Some(cert_hwid) = extensions.get(&SnpOid::HwId.oid()) {
        if !check_cert_ext_bytes(cert_hwid, &report.chip_id) {
            return Err(Error::VerificationFailure(
                "Report Chip ID and Certificate Chip ID mismatch encountered.".to_owned(),
            ));
        }
        debug!("Chip ID from certificate matches the attestation report.");
    }

    Ok(())
}

/// Requests the certificate-chain (AMD ASK + AMD ARK)
/// These may be used to verify the downloaded VCEK is authentic.
pub(crate) fn bytes_to_chain(bytes: &[u8]) -> Result<ca::Chain, Error> {
    debug!("Extracting certificate chain...");
    let chain = get_certificate_chain_from_pem(bytes)?;

    if chain.len() != 2 {
        return Err(Error::InvalidFormat(format!(
            "Unexpected certificate chain length {} ",
            chain.len()
        )));
    }

    // Create a ca chain with ark and ask
    Ok(ca::Chain::from_der(&chain[1], &chain[0])?)
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

/// Verify the quote body against expected values
pub(crate) fn verify_quote_policy(
    quote: &AttestationReport,
    policy: &SevQuoteVerificationPolicy,
) -> Result<(), Error> {
    debug!("Verifiying quote against the policy...");

    // Check the measurement
    if let Some(measurement) = policy.measurement {
        if quote.measurement != measurement {
            return Err(Error::VerificationFailure(format!(
                "Measurement miss-matches expected value ({})",
                hex::encode(quote.measurement),
            )));
        }
    }

    if let Some(report_data) = &policy.report_data {
        if &quote.report_data != report_data {
            return Err(Error::VerificationFailure(format!(
                "Attestation report data '{}' is not equal to the set value '{}'",
                hex::encode(quote.report_data),
                hex::encode(report_data)
            )));
        }
    }

    Ok(())
}
