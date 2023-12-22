use crate::error::Error;

use tss_esapi::{
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
    structures::{Attest, Data, HashScheme, PcrSelectionList, Signature, SignatureScheme},
    Context,
};

use std::convert::TryFrom;

pub(crate) fn attest_pcr(
    context: &mut Context,
    key_handle: &KeyHandle,
    pcr_selection_list: PcrSelectionList,
    nonce: Option<&[u8]>,
) -> Result<(Attest, Signature), Error> {
    let nonce = if let Some(nonce) = nonce {
        nonce.to_vec()
    } else {
        vec![0xff; 16]
    };

    let qualifying_data =
        Data::try_from(nonce).map_err(|e| Error::AttestationError(format!("{e}")))?;

    let (attestation, signature) = context.execute_with_nullauth_session(|ctx| {
        ctx.quote(
            *key_handle,
            qualifying_data,
            SignatureScheme::EcDsa {
                hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
            },
            pcr_selection_list.clone(),
        )
    })?;

    Ok((attestation, signature))
}

#[allow(dead_code)]
pub(crate) fn certify_key_handle(
    context: &mut Context,
    sign_key_handle: &KeyHandle,
    key_handle: &KeyHandle,
    nonce: Option<&[u8]>,
) -> Result<(Attest, Signature), Error> {
    let nonce = if let Some(nonce) = nonce {
        nonce.to_vec()
    } else {
        vec![0xff; 16]
    };

    let qualifying_data = Data::try_from(nonce)?;

    let (attestation, signature) = context.execute_with_sessions(
        (
            Some(AuthSession::Password),
            Some(AuthSession::Password),
            None,
        ),
        |ctx| {
            ctx.certify(
                (*key_handle).into(),
                *sign_key_handle,
                qualifying_data,
                SignatureScheme::Null,
            )
        },
    )?;

    Ok((attestation, signature))
}
