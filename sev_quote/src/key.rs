use openssl::{md::Md, pkey::Id, pkey_ctx::PkeyCtx, rand::rand_bytes};
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

use crate::error::Error;

/// Generate a key derived from the start measurement
pub fn get_key(use_salt: bool) -> Result<Vec<u8>, Error> {
    let request = DerivedKey::new(false, GuestFieldSelect(4), 0, 0, 0);
    let mut fw = Firmware::open()?;
    let derived_key = fw.get_derived_key(None, request)?;

    let mut k = [0; 32];

    let mut pkey = PkeyCtx::new_id(Id::HKDF)?;
    pkey.derive_init()?;
    pkey.add_hkdf_info(b"sgx-enclave-sealing-key")?;

    if use_salt {
        let mut salt = [0; 16];
        rand_bytes(&mut salt)?;
        pkey.set_hkdf_salt(&salt)?;
    }

    pkey.set_hkdf_md(Md::sha256())?;
    pkey.set_hkdf_key(&derived_key)?;
    pkey.derive(Some(&mut k))?;

    Ok(k.to_vec())
}
