use crate::{MRSIGNER_SIZE, error::Error};
use sha2::{Digest, Sha256};
use x509_parser::{
    der_parser::asn1_rs::FromDer, pem::parse_x509_pem, public_key::PublicKey,
    x509::SubjectPublicKeyInfo,
};

/// Compute the `MR_SIGNER` from the public enclave certificate (PEM format)
pub fn compute_mr_signer(pem_public_enclave_cert: &str) -> Result<[u8; MRSIGNER_SIZE], Error> {
    // Parse PEM
    let (_, pem) = parse_x509_pem(pem_public_enclave_cert.as_bytes())
        .map_err(|_| Error::CryptoError("failed to parse PEM public key".to_owned()))?;
    // The PEM is a bare SubjectPublicKeyInfo, not a certificate
    let (_, spki) = SubjectPublicKeyInfo::from_der(&pem.contents)
        .map_err(|_| Error::CryptoError("failed to parse SubjectPublicKeyInfo".to_owned()))?;

    if let Ok(PublicKey::RSA(rsa)) = spki.parsed() {
        let modulus = rsa.modulus.strip_prefix(&[0x00]).unwrap_or(rsa.modulus);

        let rev_modulus: Vec<u8> = modulus.iter().rev().copied().collect();

        let mut hash = Sha256::new();
        hash.update(&rev_modulus);

        return hash.finalize()[..]
            .try_into()
            .map_err(|_| Error::CryptoError("MRSIGNER size is invalid!".to_owned()));
    }

    Err(Error::CryptoError(
        "Failed to parse RSA public key".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use hex::{self, encode};

    use super::compute_mr_signer;

    #[test]
    pub fn test_sgx_compute_mr_signer() {
        let pk = "-----BEGIN PUBLIC KEY-----
MIIBoDANBgkqhkiG9w0BAQEFAAOCAY0AMIIBiAKCAYEA2YzUlbbI7SY73icXh0vm
iIPBW6il9UVfYkTgN/FaMe5sFR2bWaQ9JhRaoXfF8ghx44z/WigkFjCQr/TacYPc
jUpNyDgOte3TbJGOIKR0riXesJAeXVHwoesZdB4QZ0ZMDoGshe5k2bl9+/4nzK0z
1BdgkpCTGFaXCTw/GlluxHoczBtTm2Gjo7feX+ETGymwiYvscje/dUERJ1NWSgT/
DxF2mRkf5nP+bKeeZ/pLtcSxZsZJMtKic5xlcEIavYm7i8fMtqAjYduPobIKwKyg
Z9vhBP2bFMzOBD0yAsifoSdZRnGDFs+KnKpCoIfB1Tjqj+OLj4l86XAC1A0rc/Xe
FqQQenlM8XhvNRjxbX59tjpXUXhTTxOtQlI7DnNxU8+RwcIIlJbm0iFnSIW3U6At
/T3feHCwPk417zjJAIMJYvjdCDfDLnw3ZM+Q1aYnzPLmScRiaUtbDnm4dJZPWed7
4+qnTOgBm+8QGug3ksh6C6hnsbZ0DtkRLOQ1u+DMexwXAgED
-----END PUBLIC KEY-----\n";

        assert_eq!(
            encode(compute_mr_signer(pk).unwrap()),
            "2a6fbd91d09d26e5541a4060b0cc456827fd4d41e1928c98d89364557d40bff3"
        );
    }
}
