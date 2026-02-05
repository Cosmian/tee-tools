use crate::{error::Error, MRSIGNER_SIZE};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;

/// Compute the `MR_SIGNER` from the public enclave certificate (PEM format)
pub fn compute_mr_signer(pem_public_enclave_cert: &str) -> Result<[u8; MRSIGNER_SIZE], Error> {
    // Parse PEM to get the DER-encoded data
    let pem_data = pem::parse(pem_public_enclave_cert)
        .map_err(|e| Error::CryptoError(format!("Failed to parse PEM: {}", e)))?;

    if pem_data.tag() != "PUBLIC KEY" {
        return Err(Error::CryptoError(format!(
            "Expected PUBLIC KEY, got {}",
            pem_data.tag()
        )));
    }

    // Parse the SubjectPublicKeyInfo
    let spki = SubjectPublicKeyInfoRef::try_from(pem_data.contents())
        .map_err(|e| Error::CryptoError(format!("Failed to parse SPKI: {}", e)))?;

    // Extract the modulus from the RSA public key
    // RSA public key in DER is SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let public_key_bytes = spki.subject_public_key.raw_bytes();

    // Parse the SEQUENCE to extract modulus
    // Skip the SEQUENCE tag (0x30) and length
    if public_key_bytes.is_empty() || public_key_bytes[0] != 0x30 {
        return Err(Error::CryptoError(
            "Invalid RSA public key format".to_owned(),
        ));
    }

    let mut idx = 1;
    // Parse length (can be short or long form)
    let _seq_len = if public_key_bytes[idx] & 0x80 == 0 {
        idx += 1;
        public_key_bytes[idx - 1] as usize
    } else {
        let len_bytes = (public_key_bytes[idx] & 0x7F) as usize;
        idx += 1;
        let mut len = 0usize;
        for _ in 0..len_bytes {
            len = (len << 8) | public_key_bytes[idx] as usize;
            idx += 1;
        }
        len
    };

    // Now we should be at the modulus INTEGER tag
    if public_key_bytes[idx] != 0x02 {
        return Err(Error::CryptoError(
            "Expected INTEGER tag for modulus".to_owned(),
        ));
    }
    idx += 1;

    // Parse modulus length
    let modulus_len = if public_key_bytes[idx] & 0x80 == 0 {
        let len = public_key_bytes[idx] as usize;
        idx += 1;
        len
    } else {
        let len_bytes = (public_key_bytes[idx] & 0x7F) as usize;
        idx += 1;
        let mut len = 0usize;
        for _ in 0..len_bytes {
            len = (len << 8) | public_key_bytes[idx] as usize;
            idx += 1;
        }
        len
    };

    // Skip leading zero byte if present (used for sign bit)
    let modulus_start = if public_key_bytes[idx] == 0x00 {
        idx + 1
    } else {
        idx
    };

    let modulus_end =
        modulus_start + modulus_len - (if public_key_bytes[idx] == 0x00 { 1 } else { 0 });
    let mut modulus_bytes = public_key_bytes[modulus_start..modulus_end].to_vec();
    modulus_bytes.reverse();

    let mut hash = Sha256::new();
    hash.update(&modulus_bytes);

    hash.finalize()[..]
        .try_into()
        .map_err(|_| Error::CryptoError("MR signer size is invalid!".to_owned()))
}

#[cfg(test)]
mod tests {
    use hex::{self, encode};

    use super::compute_mr_signer;

    #[test]
    pub(super) fn test_sgx_compute_mr_signer() {
        assert_eq!(
            encode(
                compute_mr_signer(
                    "-----BEGIN PUBLIC KEY-----
MIIBoDANBgkqhkiG9w0BAQEFAAOCAY0AMIIBiAKCAYEA2YzUlbbI7SY73icXh0vm
iIPBW6il9UVfYkTgN/FaMe5sFR2bWaQ9JhRaoXfF8ghx44z/WigkFjCQr/TacYPc
jUpNyDgOte3TbJGOIKR0riXesJAeXVHwoesZdB4QZ0ZMDoGshe5k2bl9+/4nzK0z
1BdgkpCTGFaXCTw/GlluxHoczBtTm2Gjo7feX+ETGymwiYvscje/dUERJ1NWSgT/
DxF2mRkf5nP+bKeeZ/pLtcSxZsZJMtKic5xlcEIavYm7i8fMtqAjYduPobIKwKyg
Z9vhBP2bFMzOBD0yAsifoSdZRnGDFs+KnKpCoIfB1Tjqj+OLj4l86XAC1A0rc/Xe
FqQQenlM8XhvNRjxbX59tjpXUXhTTxOtQlI7DnNxU8+RwcIIlJbm0iFnSIW3U6At
/T3feHCwPk417zjJAIMJYvjdCDfDLnw3ZM+Q1aYnzPLmScRiaUtbDnm4dJZPWed7
4+qnTOgBm+8QGug3ksh6C6hnsbZ0DtkRLOQ1u+DMexwXAgED
-----END PUBLIC KEY-----\n"
                )
                .unwrap()
            ),
            "2a6fbd91d09d26e5541a4060b0cc456827fd4d41e1928c98d89364557d40bff3"
        );
    }
}
