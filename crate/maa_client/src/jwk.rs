use std::convert::TryFrom;

use crate::error::Error;

use base64::{engine::general_purpose, Engine as _};
use jose_jwk::{
    jose_b64::serde::Bytes,
    jose_jwa::{Algorithm, Signing},
    Jwk, JwkSet, Key, Parameters, Rsa, Thumbprint,
};
use jwt_simple::prelude::*;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::Deserialize;
use x509_cert::der::{Decode, Document};

/// JSON Web Key type returned by MAA service API.
#[derive(Clone, Debug, Deserialize)]
pub struct MaaJwk {
    pub kid: String,
    pub kty: String,
    pub x5c: Vec<String>,
}

/// Conversion from [`BadJwk`] to [`jose_jwk::Jwk`]`.
impl TryFrom<MaaJwk> for Jwk {
    type Error = Error;

    fn try_from(bad_jwk: MaaJwk) -> Result<Self, Self::Error> {
        if bad_jwk.kty != "RSA" {
            return Err(Error::MaaResponseError(
                "RSA key expected in JWK".to_owned(),
            ));
        }

        if bad_jwk.x5c.is_empty() {
            return Err(Error::MaaResponseError(
                "more than one certificate in JWK".to_owned(),
            ));
        }

        let cert = general_purpose::STANDARD
            .decode(bad_jwk.x5c[0].as_bytes())
            .map_err(|_| Error::DecodeError("failed to decode base64 in JWK".to_owned()))?;

        let cert = x509_cert::Certificate::from_der(&cert)
            .map_err(|_| Error::DecodeError("failed to decode X.509 certificate".to_owned()))?;

        let spki_der: Document = cert
            .tbs_certificate
            .subject_public_key_info
            .try_into()
            .map_err(|_| {
                Error::DecodeError(
                    "failed to decode certificate's Subject Public Key Info".to_owned(),
                )
            })?;

        let pk = RsaPublicKey::from_public_key_der(spki_der.as_bytes()).unwrap();

        let pk = Rsa {
            n: Bytes::from(pk.n().to_bytes_be()),
            e: Bytes::from(pk.e().to_bytes_be()),
            prv: None,
        };

        Ok(Jwk {
            key: Key::Rsa(pk),
            prm: Parameters {
                alg: Some(Algorithm::Signing(Signing::Rs256)),
                kid: Some(bad_jwk.kid),
                cls: None,
                ops: None,
                x5c: None,
                x5t: Thumbprint {
                    s1: None,
                    s256: None,
                },
            },
        })
    }
}

/// Conversion from [`MaaJwk`] to [`jwt_simple::algorithms::RS256PublicKey`].
impl TryFrom<MaaJwk> for RS256PublicKey {
    type Error = Error;

    fn try_from(bad_jwk: MaaJwk) -> Result<Self, Self::Error> {
        if bad_jwk.kty != "RSA" {
            return Err(Error::MaaResponseError(
                "RSA key expected in JWK".to_owned(),
            ));
        }

        if bad_jwk.x5c.is_empty() {
            return Err(Error::MaaResponseError(
                "no certificate in field x5c of JWK".to_owned(),
            ));
        }

        let cert = general_purpose::STANDARD
            .decode(bad_jwk.x5c[0].as_bytes())
            .map_err(|_| Error::DecodeError("failed to decode base64 in JWK".to_owned()))?;

        let cert = x509_cert::Certificate::from_der(&cert)
            .map_err(|_| Error::DecodeError("failed to decode X.509 certificate".to_owned()))?;

        let spki_der: Document = cert
            .tbs_certificate
            .subject_public_key_info
            .try_into()
            .map_err(|_| {
                Error::DecodeError(
                    "failed to decode certificate's Subject Public Key Info".to_owned(),
                )
            })?;

        Ok(RS256PublicKey::from_der(spki_der.as_bytes())
            .map_err(|_| Error::MaaResponseError("RSA public key not found".to_owned()))?
            .with_key_id(&bad_jwk.kid))
    }
}

/// JSON Web Key Set type returned by MAA service API.
#[derive(Clone, Debug, Deserialize)]
pub struct MaaJwks {
    pub keys: Vec<MaaJwk>,
}

/// Conversion from [`MaaJwks`] to [`jose_jwk::JwkSet`].
impl TryFrom<MaaJwks> for JwkSet {
    type Error = Error;

    fn try_from(bad_jwks: MaaJwks) -> Result<JwkSet, Error> {
        let keys = bad_jwks
            .keys
            .into_iter()
            .map(|key| key.try_into().expect("unexpected JWK conversion"))
            .collect::<Vec<Jwk>>();

        Ok(JwkSet { keys })
    }
}

impl MaaJwks {
    /// Find kid in the JSON Web Key Set.
    ///
    /// # Returns
    ///
    /// [`Some(MaaJwk)`] if success, [`None`] otherwise.
    pub fn find(self, kid: &str) -> Option<MaaJwk> {
        self.keys.into_iter().find(|key| key.kid == kid)
    }
}
