use std::convert::TryFrom;

use crate::error::Error;

use base64::{Engine as _, engine::general_purpose};
use jose_jwk::{
    Jwk, JwkSet, Key, Parameters, Rsa, Thumbprint,
    jose_b64::serde::Bytes,
    jose_jwa::{Algorithm, Signing},
};
use jwt_simple::prelude::*;
use serde::Deserialize;
use x509_cert::{
    der::asn1::UintRef,
    der::oid::ObjectIdentifier,
    der::{Decode, Document, Reader, SliceReader},
};

// rsaEncryption OID: 1.2.840.113549.1.1.1
const RSA_ENCRYPTION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

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

        let cert = x509_cert::Certificate::from_der(&cert)?;

        let spki = &cert.tbs_certificate.subject_public_key_info;

        if spki.algorithm.oid != RSA_ENCRYPTION_OID {
            return Err(Error::DecodeError(
                "No RSA public key found in certificate".to_owned(),
            ));
        }

        // Extract the public key from the certificate
        let pk = spki.subject_public_key.raw_bytes();

        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let mut reader = SliceReader::new(pk)?;

        let (modulus, exponent) = reader.sequence(|seq| {
            Ok((
                UintRef::decode(seq)?.as_bytes().to_vec(),
                UintRef::decode(seq)?.as_bytes().to_vec(),
            ))
        })?;

        let pk = Rsa {
            n: Bytes::from(modulus),
            e: Bytes::from(exponent),
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

        let cert = x509_cert::Certificate::from_der(&cert)?;

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
    #[must_use]
    pub fn find(self, kid: &str) -> Option<MaaJwk> {
        self.keys.into_iter().find(|key| key.kid == kid)
    }
}
