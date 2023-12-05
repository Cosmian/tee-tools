use crate::error::Error;
use crate::policy::{TdxQuoteBodyVerificationPolicy, TdxQuoteHeaderVerificationPolicy};
use crate::quote::{
    EcdsaSigData, QuoteHeader, TdxReportBody, QUOTE_HEADER_SIZE, QUOTE_REPORT_BODY_SIZE,
};

use log::debug;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{AffinePoint, EncodedPoint};
use sha2::{Digest, Sha256};

use p256::elliptic_curve::sec1::FromEncodedPoint;

// If bit X is 1 in xfamFixed1, it must be 1 in any xfam.
const XFAM_FIXED1: u64 = 0x00000003;
// If bit X is 0 in xfamFixed0, it must be 0 in any xfam.
const XFAM_FIXED0: u64 = 0x0006DBE7;
// If bit X is 1 in tdAttributesFixed1, it must be 1 in any tdAttributes.
// const TD_ATTRIBUTES_FIXED1: u64 = 0x0;
const TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT: u64 = 1 << 28;
const TDX_ATTRIBUTES_PKS_SUPPORT: u64 = 1 << 30;
const TDX_ATTRIBUTES_PERFMON_SUPPORT: u64 = 1 << 63;
// Supported ATTRIBUTES bits depend on the supported features - bits 0 (DEBUG), 30 (PKS), 63 (PERFMON)
// and 28 (SEPT VE DISABLE)
// If bit X is 0 in tdAttributesFixed0, it must be 0 in any tdAttributes.
const TD_ATTRIBUTES_FIXED0: u64 = 0x1
    | TDX_ATTRIBUTES_SEPT_VE_DIS_SUPPORT
    | TDX_ATTRIBUTES_PKS_SUPPORT
    | TDX_ATTRIBUTES_PERFMON_SUPPORT;

/// - Verifying Header and TD Quote Body using attestation key and signature present in the quote
/// - Verifying QE Report Data
pub(crate) fn verify_quote_signature(
    raw_quote: &[u8],
    signature: &EcdsaSigData,
) -> Result<(), Error> {
    debug!("Verifying Header and TD Quote Body using attestation key and signature present in the quote");
    let pubkey = [vec![0x04], signature.attest_pub_key.to_vec()].concat();
    let pubkey = EncodedPoint::from_bytes(pubkey).map_err(|e| Error::CryptoError(e.to_string()))?;
    let point = Option::from(AffinePoint::from_encoded_point(&pubkey)).ok_or_else(|| {
        Error::CryptoError("Can't build an affine point from the provided public key".to_owned())
    })?;
    let mut message = Sha256::new();
    message.update(&raw_quote[..(QUOTE_HEADER_SIZE + QUOTE_REPORT_BODY_SIZE)]);
    let ecdsa_attestation_pk = VerifyingKey::from_affine(point)?;

    ecdsa_attestation_pk.verify_prehash(
        &message.finalize()[..],
        &Signature::from_slice(&signature.signature)?,
    )?;

    Ok(())
}

/// Verify the quote header against expected values
pub(crate) fn verify_quote_header_policy(
    header: &QuoteHeader,
    policy: &TdxQuoteHeaderVerificationPolicy,
) -> Result<(), Error> {
    debug!("Verifiying quote header against the policy...");

    if header.version != 4 {
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

    if header.tee_type != 0x00000081 {
        return Err(Error::VerificationFailure(format!(
            "Attestation tee type '{}' is not supported (should be TDX)",
            header.tee_type
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
    body: &TdxReportBody,
    policy: &TdxQuoteBodyVerificationPolicy,
) -> Result<(), Error> {
    debug!("Verifiying quote body against the policy...");

    if let Some(minimum_tee_tcb_svn) = policy.minimum_tee_tcb_svn {
        if body
            .tee_tcb_svn
            .iter()
            .zip(minimum_tee_tcb_svn.iter())
            .any(|(item1, item2)| item1 < item2)
        {
            return Err(Error::VerificationFailure(format!(
                "Attestation TEE security-version number '{}' is lower than the set value '{}'",
                hex::encode(body.tee_tcb_svn),
                hex::encode(minimum_tee_tcb_svn)
            )));
        }
    }

    if let Some(mr_seam) = policy.mr_seam {
        if body.mr_seam != mr_seam {
            return Err(Error::VerificationFailure(format!(
                "Attestation MR SEAM '{}' is not equal to the set value '{}'",
                hex::encode(body.mr_seam),
                hex::encode(mr_seam)
            )));
        }
    }

    if let Some(td_attributes) = policy.td_attributes {
        if body.td_attributes != td_attributes {
            return Err(Error::VerificationFailure(format!(
                "Attestation TD Attributes '{}' is not equal to the set value '{}'",
                hex::encode(body.td_attributes),
                hex::encode(td_attributes)
            )));
        }
    }

    let td_attributes = u64::from_le_bytes(body.td_attributes);

    // Commented code: X & 0 = 0 is quite obvious...
    // if td_attributes & TD_ATTRIBUTES_FIXED1 != TD_ATTRIBUTES_FIXED1 {
    //     return Err(Error::VerificationFailure(format!(
    //         "Unauthorized TD Attributes '{}' (TD_ATTRIBUTES_FIXED1 is not set)",
    //         td_attributes
    //     )));
    // }

    if td_attributes & (!TD_ATTRIBUTES_FIXED0) != 0 {
        return Err(Error::VerificationFailure(format!(
            "Unauthorized TD Attributes '{}' (TD_ATTRIBUTES_FIXED0 is not set)",
            td_attributes
        )));
    }

    if let Some(xfam) = policy.xfam {
        if body.xfam != xfam {
            return Err(Error::VerificationFailure(format!(
                "Attestation XFAM '{}' is not equal to the set value '{}'",
                body.xfam, xfam
            )));
        }
    }

    if body.xfam & XFAM_FIXED1 != XFAM_FIXED1 {
        return Err(Error::VerificationFailure(format!(
            "Unauthorized XFAM '{}' (XFAM_FIXED1 is not set)",
            body.xfam
        )));
    }

    if body.xfam & (!XFAM_FIXED0) != 0 {
        return Err(Error::VerificationFailure(format!(
            "Unauthorized XFAM '{}' (XFAM_FIXED0 is not set)",
            body.xfam
        )));
    }

    if let Some(mr_td) = policy.mr_td {
        if body.mr_td != mr_td {
            return Err(Error::VerificationFailure(format!(
                "Attestation MR TD '{}' is not equal to the set value '{}'",
                hex::encode(body.mr_td),
                hex::encode(mr_td)
            )));
        }
    }

    if let Some(mr_config_id) = policy.mr_config_id {
        if body.mr_config_id != mr_config_id {
            return Err(Error::VerificationFailure(format!(
                "Attestation MR Config ID '{}' is not equal to the set value '{}'",
                hex::encode(body.mr_config_id),
                hex::encode(mr_config_id)
            )));
        }
    }

    if let Some(mr_owner) = policy.mr_owner {
        if body.mr_owner != mr_owner {
            return Err(Error::VerificationFailure(format!(
                "Attestation MR Owner'{}' is not equal to the set value '{}'",
                hex::encode(body.mr_owner),
                hex::encode(mr_owner)
            )));
        }
    }

    if let Some(mr_owner_config) = policy.mr_owner_config {
        if body.mr_owner_config != mr_owner_config {
            return Err(Error::VerificationFailure(format!(
                "Attestation MR Owner Config '{}' is not equal to the set value '{}'",
                hex::encode(body.mr_owner_config),
                hex::encode(mr_owner_config)
            )));
        }
    }

    if let Some(report_data) = policy.report_data {
        if body.report_data != report_data {
            return Err(Error::VerificationFailure(format!(
                "Attestation report data '{}' is not equal to the set value '{}'",
                hex::encode(body.report_data),
                hex::encode(report_data)
            )));
        }
    }

    Ok(())
}
