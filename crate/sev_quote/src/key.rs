use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::Error;

/// Generate a key derived from the start measurement
pub fn get_key(salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let request = DerivedKey::new(false, GuestFieldSelect(4), 0, 0, 0, None);
    let mut fw = Firmware::open()?;
    let derived_key = fw.get_derived_key(None, request)?;

    let mut k = [0; 32];

    let hk = Hkdf::<Sha256>::new(salt, &derived_key);

    hk.expand(b"amd-sealing-key", &mut k)
        .map_err(|e| Error::CryptoError(format!("Invalid length for HKDF {e:?}")))?;

    Ok(k.to_vec())
}
