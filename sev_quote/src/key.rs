use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};

use hkdf::Hkdf;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

use crate::error::Error;

/// Generate a key derived from the start measurement
pub fn get_key(use_salt: bool) -> Result<Vec<u8>, Error> {
    let request = DerivedKey::new(false, GuestFieldSelect(4), 0, 0, 0);
    let mut fw = Firmware::open()?;
    let derived_key = fw.get_derived_key(None, request)?;

    let mut k = [0; 32];

    let hk = if use_salt {
        let mut salt = [0; 16];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);
        Hkdf::<Sha256>::new(Some(&salt[..]), &derived_key)
    } else {
        Hkdf::<Sha256>::new(None, &derived_key)
    };

    hk.expand(b"sev-vm-sealing-key", &mut k)
        .map_err(|e| Error::CryptoError(format!("Invalid length for HKDF {e:?}")))?;

    Ok(k.to_vec())
}
