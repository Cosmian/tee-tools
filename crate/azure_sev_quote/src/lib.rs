use std::str::FromStr;

use tss_esapi::{
    abstraction::nv, handles::NvIndexTpmHandle, interface_types::resource_handles::NvAuth,
    tcti_ldr::TctiNameConf, Context,
};

use crate::error::Error;

pub mod error;

const AZURE_QUOTE_NVINDEX: u32 = 0x1400001;
const AZURE_QUOTE_START_OFFSET: usize = 32;
const SEV_QUOTE_SIZE: usize = 1184;

pub fn get_quote_from_tpm() -> Result<Vec<u8>, Error> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut context = Context::new(tcti)?;

    let nv_idx = NvIndexTpmHandle::new(AZURE_QUOTE_NVINDEX)?;
    let nv_auth_handle: NvAuth = NvAuth::Owner;

    let content =
        context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))?;

    let mut buf = [0u8; SEV_QUOTE_SIZE];
    buf.copy_from_slice(
        &content[AZURE_QUOTE_START_OFFSET..AZURE_QUOTE_START_OFFSET + SEV_QUOTE_SIZE],
    );

    Ok(buf.to_vec())
}
