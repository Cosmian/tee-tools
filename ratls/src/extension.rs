use const_oid::AssociatedOid;
use x509_cert::{
    der::asn1::OctetString,
    ext::{AsExtension, Extension},
    impl_newtype,
    spki::ObjectIdentifier,
};

pub enum RatlsExtension {
    IntelSgxTee(IntelSgxRatlsExtension),
    IntelTdxTee(IntelTdxRatlsExtension),
    AMDSevTee(AMDSevRatlsExtension),
}

pub const INTEL_SGX_RATLS_EXTENSION_OID: &str = "1.2.840.113741.1337.6";
pub const AMD_SEV_RATLS_EXTENSION_OID: &str = "1.2.840.113741.1337.7";
pub const INTEL_TDX_RATLS_EXTENSION_OID: &str = "1.2.840.113741.1337.8";

pub struct IntelTdxRatlsExtension(OctetString);

impl AssociatedOid for IntelTdxRatlsExtension {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(INTEL_TDX_RATLS_EXTENSION_OID);
}

impl_newtype!(IntelTdxRatlsExtension, OctetString);

impl AsExtension for IntelTdxRatlsExtension {
    /// Should the extension be marked critical
    fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[Extension]) -> bool {
        false
    }

    /// Returns the Extension with the content encoded.
    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[Extension],
    ) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: self.0.clone(),
        })
    }
}

pub struct IntelSgxRatlsExtension(OctetString);

impl AssociatedOid for IntelSgxRatlsExtension {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(INTEL_SGX_RATLS_EXTENSION_OID);
}

impl_newtype!(IntelSgxRatlsExtension, OctetString);

impl AsExtension for IntelSgxRatlsExtension {
    /// Should the extension be marked critical
    fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[Extension]) -> bool {
        false
    }

    /// Returns the Extension with the content encoded.
    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[Extension],
    ) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: self.0.clone(),
        })
    }
}

pub struct AMDSevRatlsExtension(OctetString);

impl AssociatedOid for AMDSevRatlsExtension {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(AMD_SEV_RATLS_EXTENSION_OID);
}

impl_newtype!(AMDSevRatlsExtension, OctetString);

impl AsExtension for AMDSevRatlsExtension {
    /// Should the extension be marked critical
    fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[Extension]) -> bool {
        false
    }

    /// Returns the Extension with the content encoded.
    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[Extension],
    ) -> Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: self.0.clone(),
        })
    }
}
