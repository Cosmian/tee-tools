use crate::key::{get_key_from_persistent_handle, TPM_AK_NVINDEX};
use error::Error;
use policy::TpmPolicy;
use std::convert::TryInto;
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Attest, AttestInfo, PcrSelectionListBuilder, PcrSlot, Public, Signature},
    traits::{Marshall, UnMarshall},
    Context,
};
use verify::{verify_pcr_value, verify_quote_policy, verify_quote_signature};

pub mod command;
pub mod convert;
pub mod error;
pub mod key;
pub mod policy;
pub mod verify;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
pub enum PcrHashMethod {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl PcrHashMethod {
    #[must_use]
    pub fn size(&self) -> usize {
        match self {
            PcrHashMethod::Sha1 => 20,
            PcrHashMethod::Sha256 => 32,
            PcrHashMethod::Sha384 => 48,
            PcrHashMethod::Sha512 => 64,
        }
    }
}

/// TPM Quote of PCR slots in `pcr_list`.
///
/// Use a nonce to avoid replay attacks.
///
/// # Returns
///
/// Either (quote, signature, public_key): ([`Vec<u8>`], [`Vec<u8>`], [`Vec<u8>`]`) or [`Error`].
#[allow(clippy::type_complexity)]
pub fn get_quote(
    context: &mut Context,
    pcr_list: &[u8],
    nonce: Option<&[u8]>,
    method: PcrHashMethod,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let pcr_list = pcr_list
        .iter()
        .map(|n| (1 << u32::from(*n)).try_into())
        .collect::<Result<Vec<PcrSlot>, _>>()?;

    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(
            match method {
                PcrHashMethod::Sha1 => HashingAlgorithm::Sha1,
                PcrHashMethod::Sha256 => HashingAlgorithm::Sha256,
                PcrHashMethod::Sha384 => HashingAlgorithm::Sha384,
                PcrHashMethod::Sha512 => HashingAlgorithm::Sha512,
            },
            &pcr_list,
        )
        .build()?;

    let (ak_handle, ak_pub) = get_key_from_persistent_handle(context, TPM_AK_NVINDEX)?;

    let (attestation_data, signature) =
        command::attest_pcr(context, &ak_handle, pcr_selection_list, nonce)?;

    Ok((
        attestation_data.marshall()?,
        signature.marshall()?,
        ak_pub.marshall()?,
    ))
}

/// Extract the digest of PCRs in TPM `quote`.
///
/// # Returns
///
/// Either [`Vec<u8>`] or [`Error`].
pub fn get_pcr_digest_from_quote(quote: &[u8]) -> Result<Vec<u8>, Error> {
    let attestation_data = Attest::unmarshall(quote)?;
    let AttestInfo::Quote { info: quote_info } = attestation_data.attested() else {
        return Err(Error::QuoteError("unexpected attestion type".to_owned()));
    };

    Ok(quote_info.pcr_digest().to_owned().to_vec())
}

/// Verify signature of the `quote` with `public_key`` and `nonce`.
///
/// # Returns
///
/// Either [`()`] or [`Error`].
pub fn verify_quote(
    quote: &[u8],
    signature: &[u8],
    public_key: &[u8],
    nonce: Option<&[u8]>,
    pcr_value: &[u8],
    policy: &TpmPolicy,
) -> Result<(), Error> {
    let attestation_data = Attest::unmarshall(quote)?;
    let signature = Signature::unmarshall(signature)?;
    let public_key = Public::unmarshall(public_key)?;
    let expected_nonce = verify_quote_signature(&attestation_data, &signature, &public_key)?;

    match nonce {
        Some(nonce) => {
            if nonce != expected_nonce {
                return Err(Error::QuoteError("unexpected nonce in quote".to_owned()));
            }
        }
        None => {
            if expected_nonce != vec![0xff; 16] {
                return Err(Error::QuoteError("unexpected nonce in quote".to_owned()));
            }
        }
    }

    verify_quote_policy(&attestation_data, policy)?;

    let AttestInfo::Quote { info: quote_info } = attestation_data.attested() else {
        return Err(Error::QuoteError("unexpected attestion type".to_owned()));
    };

    verify_pcr_value(quote_info, pcr_value)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{get_quote, policy::TpmPolicy, verify_quote};
    use test_log::test;
    use tss_esapi::{tcti_ldr::TctiNameConf, Context};

    #[test]
    fn test_tpm_get_quote() {
        let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").unwrap();
        let context = Context::new(tcti);
        match context {
            Ok(mut context) => {
                assert!(
                    get_quote(&mut context, &[10u8], None, crate::PcrHashMethod::Sha256).is_ok()
                );
            }
            Err(_) => {
                println!("[WARNING] No TPM found, skipped `test_tpm_get_quote` test");
            }
        }
    }

    #[test]
    fn test_tpm_verify_quote() {
        let quote = include_bytes!("../data/pcr_quote.plain");
        let sig = include_bytes!("../data/pcr_quote.sig");
        let pk = include_bytes!("../data/ak.pub");

        assert!(verify_quote(
            quote,
            sig,
            pk,
            Some(&[]),
            &hex::decode("CF0BEEC1CEE65650DF8E89FF535A901E8C8F6180").unwrap(),
            &TpmPolicy {
                reset_count: Some(25),
                restart_count: Some(0)
            },
        )
        .is_ok());
    }
}
