use const_oid::AssociatedOid;
use x509_cert::{
    der::asn1::OctetString,
    ext::{AsExtension, Extension},
    impl_newtype,
    spki::ObjectIdentifier,
};

pub enum RatlsExtension {
    IntelTee(IntelRatlsExtension),
    AMDTee(AMDRatlsSExtension),
}

pub const INTEL_RATLS_EXTENSION_OID: &str = "1.2.840.113741.1337.6";
pub const AMD_RATLS_EXTENSION_OID: &str = "1.2.840.113741.1337.7";

pub struct IntelRatlsExtension(OctetString);

impl AssociatedOid for IntelRatlsExtension {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(INTEL_RATLS_EXTENSION_OID);
}

impl_newtype!(IntelRatlsExtension, OctetString);

impl AsExtension for IntelRatlsExtension {
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

pub struct AMDRatlsSExtension(OctetString);

impl AssociatedOid for AMDRatlsSExtension {
    const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap(AMD_RATLS_EXTENSION_OID);
}

impl_newtype!(AMDRatlsSExtension, OctetString);

impl AsExtension for AMDRatlsSExtension {
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
