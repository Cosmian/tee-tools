use std::{fs, io::Read};

use openssl::{md::Md, pkey::Id, pkey_ctx::PkeyCtx, rand::rand_bytes};

use crate::error::Error;

/// Generate a key derived from the mr_enclave
pub fn get_key(use_salt: bool) -> Result<Vec<u8>, Error> {
    let mut file = fs::File::open("/dev/attestation/keys/_sgx_mrenclave")?;
    let mut buf = [0; 16];
    let n = file.read(&mut buf[..])?;

    if n != 16 {
        return Err(Error::InvalidFormat(
            "Can't read 16 bytes to build the MREnclave key".to_string(),
        ));
    }

    let mut k = [0; 32];

    let mut pkey = PkeyCtx::new_id(Id::HKDF)?;
    pkey.derive_init()?;
    pkey.add_hkdf_info(b"sev-vm-sealing-key")?;

    if use_salt {
        let mut salt = [0; 16];
        rand_bytes(&mut salt)?;
        pkey.set_hkdf_salt(&salt)?;
    }

    pkey.set_hkdf_md(Md::sha256())?;
    pkey.set_hkdf_key(&buf)?;
    pkey.derive(Some(&mut k))?;

    Ok(k.to_vec())
}
