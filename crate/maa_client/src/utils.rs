pub mod base64url_serde {
    use base64::{engine::general_purpose, Engine as _};
    use serde::Serializer;
    use serde::{Deserialize as _, Deserializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = general_purpose::URL_SAFE_NO_PAD.encode(v);
        s.serialize_str(&base64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        general_purpose::URL_SAFE_NO_PAD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
