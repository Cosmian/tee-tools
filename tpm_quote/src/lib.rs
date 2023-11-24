use crate::key::{get_key_from_persistent_handle, TPM_AK_NVINDEX};
use error::Error;
use std::convert::TryInto;
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{
        Attest, AttestInfo, PcrSelectionListBuilder, PcrSlot, Public, QuoteInfo, Signature,
    },
    traits::{Marshall, UnMarshall},
    Context,
};
use verify::verify_quote_signature;

pub mod command;
pub mod convert;
pub mod error;
pub mod key;
pub mod verify;

/// TPM Quote of PCR slots in `pcr_list`.
///
/// # Returns
///
/// Either (quote, signature, public_key): ([`Vec<u8>`], [`Vec<u8>`], [`Vec<u8>`]`) or [`Error`].
#[allow(clippy::type_complexity)]
pub fn get_quote(
    context: &mut Context,
    pcr_list: &[u8],
    nonce: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let pcr_list = pcr_list
        .iter()
        .map(|n| (1 << (*n as u32)).try_into())
        .collect::<Result<Vec<PcrSlot>, _>>()?;

    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha1, &pcr_list)
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

/// Verify signature of the `quote` with `public_key`` and `nonce`.
///
/// # Returns
///
/// Either [`QuoteInfo`] or [`Error`].
pub fn verify_quote(
    quote: &[u8],
    signature: &[u8],
    public_key: &[u8],
    nonce: Option<&[u8]>,
) -> Result<QuoteInfo, Error> {
    let attestation_data = Attest::unmarshall(quote)?;
    let signature = Signature::unmarshall(signature)?;
    let public_key = Public::unmarshall(public_key)?;

    let quote_info = match attestation_data.attested() {
        AttestInfo::Quote { info } => Ok(info),
        _ => Err(Error::QuoteError("unexpected nonce in quote".to_owned())),
    }?;
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

    Ok(quote_info.to_owned())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{get_quote, verify_quote};
    use log::info;
    use test_log::test;
    use tss_esapi::{tcti_ldr::TctiNameConf, Context};

    #[test]
    fn test_get_quote() {
        let tcti = TctiNameConf::from_str("device:/dev/tpmrm0").unwrap();
        let context = Context::new(tcti);
        match context {
            Ok(mut context) => {
                let (quote, signature, pk) = get_quote(&mut context, &[10u8], None).unwrap();
                verify_quote(&quote, &signature, &pk, None).unwrap();
            }
            Err(_) => {
                info!("No TPM found, skipped some tests");
            }
        }
    }

    #[test]
    fn test_verify_quote() {
        let quote = include_bytes!("../data/pcr_quote.plain");
        let sig = include_bytes!("../data/pcr_quote.sig");
        let pk = include_bytes!("../data/ak.pub");

        let nonce: [u8; 16] = [0xff; 16];

        verify_quote(quote, sig, pk, Some(&nonce)).unwrap();
    }
}