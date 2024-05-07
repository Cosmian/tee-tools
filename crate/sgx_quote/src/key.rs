use std::{fs, io::Read};

use crate::error::Error;
use hkdf::Hkdf;

use sha2::Sha256;

/// Generate a key derived from the `mr_enclave`
pub fn get_key(salt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut file = fs::File::open("/dev/attestation/keys/_sgx_mrenclave")?;
    let mut buf = [0; 16];
    let n = file.read(&mut buf[..])?;

    if n != 16 {
        return Err(Error::InvalidFormat(
            "Can't read 16 bytes to build the MREnclave key".to_string(),
        ));
    }

    let mut k = [0; 32];

    let hk = Hkdf::<Sha256>::new(salt, &buf);

    hk.expand(b"intel-sealing-key", &mut k)
        .map_err(|e| Error::CryptoError(format!("Invalid length for HKDF {e:?}")))?;

    Ok(k.to_vec())
}
