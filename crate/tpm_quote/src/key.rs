use crate::error::Error;

use tss_esapi::{
    abstraction::nv,
    handles::{KeyHandle, NvIndexTpmHandle, PersistentTpmHandle, TpmHandle},
    interface_types::resource_handles::NvAuth,
    structures::Public,
    Context,
};

pub const TPM_EK_NVINDEX: u32 = 0x81000050;
pub const TPM_AK_NVINDEX: u32 = 0x81000051;

pub(crate) fn get_key_from_persistent_handle(
    context: &mut Context,
    index: u32,
) -> Result<(KeyHandle, Public), Error> {
    let tpm_handle = TpmHandle::Persistent(PersistentTpmHandle::new(index)?);
    let key_handle: KeyHandle = context.tr_from_tpm_public(tpm_handle)?.into();

    let (public, _, _) = context.read_public(key_handle)?;

    Ok((key_handle, public))
}

#[allow(dead_code)]
pub(crate) fn get_content_from_nv_handle(
    context: &mut Context,
    index: u32,
) -> Result<Vec<u8>, Error> {
    let nv_idx = NvIndexTpmHandle::new(index)?;
    let tpm_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(tpm_handle)
            .map(|v| NvAuth::NvIndex(v.into()))
    })?;

    Ok(context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))?)
}
