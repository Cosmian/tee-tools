use std::str::FromStr;

use tss_esapi::{
    abstraction::nv, handles::NvIndexTpmHandle, interface_types::resource_handles::NvAuth,
    tcti_ldr::TctiNameConf, Context,
};

use crate::error::Error;

const HCL_REPORT_INDEX: u32 = 0x1400001;

pub fn get_hcl_report() -> Result<Vec<u8>, Error> {
    let tcti = TctiNameConf::from_str("device:/dev/tpmrm0")?;
    let mut context = Context::new(tcti)?;

    let nv_idx = NvIndexTpmHandle::new(HCL_REPORT_INDEX)?;
    let nv_auth_handle: NvAuth = NvAuth::Owner;

    let hcl_report =
        context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))?;

    Ok(hcl_report)
}
