use crate::error::Error;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};

/// Compute the `MR_SIGNER` from the public enclave certificate (PEM format)
pub fn compute_mr_signer(pem_public_enclave_cert: &str) -> Result<Vec<u8>, Error> {
    let public_key = RsaPublicKey::from_public_key_pem(pem_public_enclave_cert)?;

    let modulus = public_key.n();
    let mut modulus_bytes = modulus.to_bytes_be();
    modulus_bytes.reverse();

    let mut hash = Sha256::new();
    hash.update(&modulus_bytes);
    Ok(hash.finalize()[..].to_vec())
}

#[cfg(test)]
mod tests {
    use hex::{self, encode};

    use super::compute_mr_signer;

    #[test]
    pub fn test_compute_mr_signer() {
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
