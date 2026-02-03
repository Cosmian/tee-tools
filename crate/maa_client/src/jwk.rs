use crate::error::Error;

use base64::{engine::general_purpose, Engine as _};
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use x509_cert::{der::Decode, Certificate};

/// JSON Web Key type returned by MAA service API.
#[derive(Clone, Debug, Deserialize)]
pub struct MaaJwk {
    pub kid: String,
    pub kty: String,
    pub x5c: Vec<String>,
}

impl MaaJwk {
    /// Convert MaaJwk to jsonwebtoken DecodingKey
    pub fn to_decoding_key(&self) -> Result<DecodingKey, Error> {
        if self.kty != "RSA" {
            return Err(Error::MaaResponseError(
                "RSA key expected in JWK".to_owned(),
            ));
        }

        if self.x5c.is_empty() {
            return Err(Error::MaaResponseError(
                "no certificate in field x5c of JWK".to_owned(),
            ));
        }

        let cert = general_purpose::STANDARD
            .decode(self.x5c[0].as_bytes())
            .map_err(|_| Error::DecodeError("failed to decode base64 in JWK".to_owned()))?;

        let cert = Certificate::from_der(&cert)
            .map_err(|_| Error::DecodeError("failed to decode X.509 certificate".to_owned()))?;

        // For RSA keys, the `subject_public_key` BIT STRING contains a DER-encoded
        // `RSAPublicKey` (PKCS#1). `jsonwebtoken::DecodingKey::from_rsa_der` expects
        // that format, not the full SubjectPublicKeyInfo (SPKI) wrapper.
        let public_key_der = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| {
                Error::DecodeError(
                    "invalid certificate public key bitstring (non-octet-aligned)".to_owned(),
                )
            })?;

        Ok(DecodingKey::from_rsa_der(public_key_der))
    }
}

/// JSON Web Key Set type returned by MAA service API.
#[derive(Clone, Debug, Deserialize)]
pub struct MaaJwks {
    pub keys: Vec<MaaJwk>,
}

impl MaaJwks {
    /// Find kid in the JSON Web Key Set.
    ///
    /// # Returns
    ///
    /// [`Some(MaaJwk)`] if success, [`None`] otherwise.
    #[must_use]
    pub fn find(self, kid: &str) -> Option<MaaJwk> {
        self.keys.into_iter().find(|key| key.kid == kid)
    }
}
