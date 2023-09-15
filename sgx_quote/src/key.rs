use std::{fs, io::Read};

use crate::error::Error;
use hkdf::Hkdf;
use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

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

    let hk = if use_salt {
        let mut salt = [0; 16];
        let mut rng = ChaCha20Rng::from_entropy();
        rng.fill_bytes(&mut salt);
        Hkdf::<Sha256>::new(Some(&salt[..]), &buf)
    } else {
        Hkdf::<Sha256>::new(None, &buf)
    };

    hk.expand(b"intel-sealing-key", &mut k)
        .map_err(|e| Error::CryptoError(format!("Invalid length for HKDF {e:?}")))?;

    Ok(k.to_vec())
}
