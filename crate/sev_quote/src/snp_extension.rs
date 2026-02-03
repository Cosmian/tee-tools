use asn1_rs::{oid, Oid};
use x509_parser::prelude::X509Extension;

use crate::error::Error;

pub enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    #[allow(dead_code)]
    Ucode,
    HwId,
}

impl SnpOid {
    /// References: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
    pub fn oid(&self) -> Oid<'_> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1),
            SnpOid::Tee => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2),
            SnpOid::Snp => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3),
            SnpOid::Ucode => oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8),
            SnpOid::HwId => oid!(1.3.6 .1 .4 .1 .3704 .1 .4),
        }
    }
}

impl std::fmt::Display for SnpOid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.oid().to_id_string())
    }
}

pub(crate) fn check_cert_ext_byte(ext: &X509Extension, val: u8) -> Result<bool, Error> {
    if ext.value[0] != 0x2 {
        return Err(Error::InvalidFormat("Invalid type encountered!".to_owned()));
    }

    if ext.value[1] != 0x1 && ext.value[1] != 0x2 {
        return Err(Error::InvalidFormat(
            "Invalid octet length encountered".to_owned(),
        ));
    }

    if let Some(byte_value) = ext.value.last() {
        Ok(*byte_value == val)
    } else {
        Ok(false)
    }
}

pub(crate) fn check_cert_ext_bytes(ext: &X509Extension, val: &[u8]) -> bool {
    ext.value == val
}
