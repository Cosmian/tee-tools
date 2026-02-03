//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

use asn1::{oid, ObjectIdentifier, SequenceOf};
use asn1_rs::Oid;
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

use crate::error::SgxPckExtensionError;

pub const SGX_EXTENSIONS_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1);
pub const PPID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 1);

pub const TCB_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2);
pub const TCB_COMP01SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 1);
pub const TCB_COMP02SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 2);
pub const TCB_COMP03SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 3);
pub const TCB_COMP04SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 4);
pub const TCB_COMP05SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 5);
pub const TCB_COMP06SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 6);
pub const TCB_COMP07SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 7);
pub const TCB_COMP08SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 8);
pub const TCB_COMP09SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 9);
pub const TCB_COMP10SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 10);
pub const TCB_COMP11SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 11);
pub const TCB_COMP12SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 12);
pub const TCB_COMP13SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 13);
pub const TCB_COMP14SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 14);
pub const TCB_COMP15SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 15);
pub const TCB_COMP16SVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 16);
pub const TCB_PCESVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 17);
pub const TCB_CPUSVN_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 2, 18);

pub const PCE_ID_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 3);
pub const FMSPC_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 4);
pub const SGX_TYPE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 5);
pub const PLATFORM_INSTANCE_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 6);

pub const CONFIGURATION_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7);
pub const CONFIGURATION_DYNAMIC_PLATFORM_OID: ObjectIdentifier =
    oid!(1, 2, 840, 113741, 1, 13, 1, 7, 1);
pub const CONFIGURATION_CACHED_KEYS_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 2);
pub const CONFIGURATION_SMT_ENABLED_OID: ObjectIdentifier = oid!(1, 2, 840, 113741, 1, 13, 1, 7, 3);

const PPID_LEN: usize = 16;
const CPUSVN_LEN: usize = 16;
const PCEID_LEN: usize = 2;
const FMSPC_LEN: usize = 6;
const PLATFORM_INSTANCE_ID_LEN: usize = 16;
const COMPSVN_LEN: usize = 16;

#[derive(Debug)]
pub struct SgxPckExtension {
    // intel-dcap returns ppid, sgx_type, platform_instance_id,
    // configuration as supplemental data, but doesn't check any of them
    pub ppid: [u8; PPID_LEN],
    pub tcb: Tcb,
    pub pceid: [u8; PCEID_LEN],
    pub fmspc: [u8; FMSPC_LEN],
    pub sgx_type: SgxType,
    // Value of Platform Instance ID.
    // It is only relevant to PCK Certificates issued by PCK Platform CA.
    pub platform_instance_id: Option<[u8; PLATFORM_INSTANCE_ID_LEN]>,
    // Optional sequence of additional configuration settings.
    // It is only relevant to PCK Certificates issued by PCK Platform CA.
    pub configuration: Option<Configuration>,
}

impl SgxPckExtension {
    pub fn from_der(der: &[u8]) -> Result<SgxPckExtension, SgxPckExtensionError> {
        let mut ppid = None;
        let mut tcb = None;
        let mut pceid = None;
        let mut fmspc = None;
        let mut sgx_type = None;
        let mut platform_instance_id = None;
        let mut configuration = None;

        let extensions = asn1::parse_single::<asn1::SequenceOf<SgxExtension>>(der)
            .map_err(|_| SgxPckExtensionError::SgxPckExtensionNotFoundError)?;

        parse_extensions(
            extensions,
            HashMap::from([
                (
                    PPID_OID,
                    &mut ppid as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (TCB_OID, &mut tcb),
                (PCE_ID_OID, &mut pceid),
                (FMSPC_OID, &mut fmspc),
                (SGX_TYPE_OID, &mut sgx_type),
                (PLATFORM_INSTANCE_OID, &mut platform_instance_id),
                (CONFIGURATION_OID, &mut configuration),
            ]),
        )?;

        Ok(SgxPckExtension {
            ppid: ppid.unwrap(),
            tcb: tcb.unwrap(),
            pceid: pceid.unwrap(),
            fmspc: fmspc.unwrap(),
            sgx_type: sgx_type.unwrap(),
            platform_instance_id,
            configuration,
        })
    }

    pub fn from_pem_certificate(
        pem_certificate: &[u8],
    ) -> Result<SgxPckExtension, SgxPckExtensionError> {
        match parse_x509_pem(pem_certificate) {
            Ok((rem, pem)) if !rem.is_empty() || pem.label.as_str() != "CERTIFICATE" => {
                Err(SgxPckExtensionError::PEMParsingError)
            }
            Ok((_, pem)) => SgxPckExtension::from_der_certificate(&pem.contents),
            Err(_) => Err(SgxPckExtensionError::PEMParsingError),
        }
    }

    pub fn from_der_certificate(
        der_certificate: &[u8],
    ) -> Result<SgxPckExtension, SgxPckExtensionError> {
        let sgx_extension_oid =
            Oid::from_str(&SGX_EXTENSIONS_OID.to_string()).expect("Bad SGX extension OID");

        match parse_x509_certificate(der_certificate) {
            Ok((rem, _)) if !rem.is_empty() => Err(SgxPckExtensionError::X509ParsingError),
            Ok((_, x509)) => match x509.get_extension_unique(&sgx_extension_oid) {
                Ok(Some(sgx_extension)) => SgxPckExtension::from_der(sgx_extension.value)
                    .map_err(|_| SgxPckExtensionError::SgxPckParsingError),
                Ok(None) => Err(SgxPckExtensionError::SgxPckExtensionNotFoundError),
                Err(e) => {
                    panic!("Failed to get X509 extension: {e:?}")
                }
            },
            Err(_) => Err(SgxPckExtensionError::SgxPckParsingError),
        }
    }
}

#[allow(clippy::result_large_err)]
#[derive(asn1::Asn1Read)]
struct SgxExtension<'a> {
    pub sgx_extension_id: ObjectIdentifier,
    pub value: ExtensionValue<'a>,
}

#[allow(clippy::result_large_err)]
#[derive(asn1::Asn1Read)]
enum ExtensionValue<'a> {
    OctetString(&'a [u8]),
    Sequence(SequenceOf<'a, SgxExtension<'a>>),
    Integer(u64),
    Enumerated(asn1::Enumerated),
    Bool(bool),
}

impl<'a, const LEN: usize> TryFrom<ExtensionValue<'a>> for [u8; LEN] {
    type Error = SgxPckExtensionError;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::OctetString(v) = value {
            v.try_into()
                .map_err(|_| SgxPckExtensionError::SgxPckParsingError)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u8 {
    type Error = SgxPckExtensionError;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Integer(v) = value {
            v.try_into()
                .map_err(|_| SgxPckExtensionError::SgxPckParsingError)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

impl<'a> TryFrom<ExtensionValue<'a>> for u16 {
    type Error = SgxPckExtensionError;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Integer(v) = value {
            v.try_into()
                .map_err(|_| SgxPckExtensionError::SgxPckParsingError)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}
impl<'a> TryFrom<ExtensionValue<'a>> for bool {
    type Error = SgxPckExtensionError;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Bool(v) = value {
            Ok(v)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

fn parse_extensions<'a>(
    extensions: asn1::SequenceOf<'a, SgxExtension<'a>>,
    mut attributes: HashMap<ObjectIdentifier, &mut dyn OptionOfTryFromExtensionValue>,
) -> Result<(), SgxPckExtensionError> {
    for extension in extensions {
        let SgxExtension {
            sgx_extension_id,
            value,
        } = extension;
        if let Some(attr) = attributes.get_mut(&sgx_extension_id) {
            attr.parse_and_save(value)
                .map_err(|_| SgxPckExtensionError::SgxPckParsingError)?;
        } else {
            return Err(SgxPckExtensionError::SgxPckParsingError);
        }
    }
    Ok(())
}

/// Exists because `&mut Option<dyn TryFrom<…>>` isn't a thing in Rust.
///
/// (If you're wondering how it would work, read Gankra's
/// "[DSTs Are Just Polymorphically Compiled Generics][dsts]".)
///
/// [dsts]: https://gankra.github.io/blah/dsts-are-polymorphic-generics/
#[allow(dead_code)]
trait OptionOfTryFromExtensionValue {
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<(), SgxPckExtensionError>;
    #[allow(dead_code)]
    fn is_none(&self) -> bool;
}

impl<T> OptionOfTryFromExtensionValue for Option<T>
where
    T: for<'a> TryFrom<ExtensionValue<'a>, Error = SgxPckExtensionError>,
{
    fn parse_and_save(&mut self, value: ExtensionValue<'_>) -> Result<(), SgxPckExtensionError> {
        if self.is_some() {
            return Err(SgxPckExtensionError::SgxPckParsingError);
        }
        *self = Some(T::try_from(value)?);
        Ok(())
    }

    fn is_none(&self) -> bool {
        self.is_none()
    }
}

#[derive(Debug)]
pub struct Tcb {
    pub compsvn: [u8; COMPSVN_LEN],
    pub pcesvn: u16,
    pub cpusvn: [u8; CPUSVN_LEN],
}

impl<'a> TryFrom<ExtensionValue<'a>> for Tcb {
    type Error = SgxPckExtensionError;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Sequence(v) = value {
            Self::try_from(v)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Tcb {
    type Error = SgxPckExtensionError;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self, SgxPckExtensionError> {
        let mut compsvn = [None; COMPSVN_LEN];
        let mut pcesvn = None;
        let mut cpusvn = None;

        // rustfmt doesn't like this next line,
        // but it's the only way to get simultaneous mutable references to each element!
        let [compsvn01, compsvn02, compsvn03, compsvn04, compsvn05, compsvn06, compsvn07, compsvn08, compsvn09, compsvn10, compsvn11, compsvn12, compsvn13, compsvn14, compsvn15, compsvn16] =
            &mut compsvn;

        parse_extensions(
            value,
            HashMap::from([
                (
                    TCB_COMP01SVN_OID,
                    compsvn01 as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (TCB_COMP02SVN_OID, compsvn02),
                (TCB_COMP03SVN_OID, compsvn03),
                (TCB_COMP04SVN_OID, compsvn04),
                (TCB_COMP05SVN_OID, compsvn05),
                (TCB_COMP06SVN_OID, compsvn06),
                (TCB_COMP07SVN_OID, compsvn07),
                (TCB_COMP08SVN_OID, compsvn08),
                (TCB_COMP09SVN_OID, compsvn09),
                (TCB_COMP10SVN_OID, compsvn10),
                (TCB_COMP11SVN_OID, compsvn11),
                (TCB_COMP12SVN_OID, compsvn12),
                (TCB_COMP13SVN_OID, compsvn13),
                (TCB_COMP14SVN_OID, compsvn14),
                (TCB_COMP15SVN_OID, compsvn15),
                (TCB_COMP16SVN_OID, compsvn16),
                (TCB_PCESVN_OID, &mut pcesvn),
                (TCB_CPUSVN_OID, &mut cpusvn),
            ]),
        )?;

        Ok(Self {
            compsvn: compsvn.map(Option::unwrap),
            pcesvn: pcesvn.unwrap(),
            cpusvn: cpusvn.unwrap(),
        })
    }
}

#[derive(Debug)]
pub enum SgxType {
    Standard,
    Scalable,
}

impl<'a> TryFrom<ExtensionValue<'a>> for SgxType {
    type Error = SgxPckExtensionError;
    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Enumerated(v) = value {
            Self::try_from(v)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

impl TryFrom<asn1::Enumerated> for SgxType {
    type Error = SgxPckExtensionError;
    fn try_from(value: asn1::Enumerated) -> Result<Self, SgxPckExtensionError> {
        match value.value() {
            0 => Ok(SgxType::Standard),
            1 => Ok(SgxType::Scalable),
            _ => Err(SgxPckExtensionError::SgxPckParsingError),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Configuration {
    pub dynamic_platform: bool,
    pub cached_keys: bool,
    pub smt_enabled: bool,
}

impl<'a> TryFrom<ExtensionValue<'a>> for Configuration {
    type Error = SgxPckExtensionError;

    fn try_from(value: ExtensionValue<'a>) -> Result<Self, SgxPckExtensionError> {
        if let ExtensionValue::Sequence(v) = value {
            Self::try_from(v)
        } else {
            Err(SgxPckExtensionError::SgxPckParsingError)
        }
    }
}

impl<'a> TryFrom<SequenceOf<'a, SgxExtension<'a>>> for Configuration {
    type Error = SgxPckExtensionError;

    fn try_from(value: SequenceOf<'a, SgxExtension<'a>>) -> Result<Self, SgxPckExtensionError> {
        let mut dynamic_platform = None;
        let mut cached_keys = None;
        let mut smt_enabled = None;

        parse_extensions(
            value,
            HashMap::from([
                (
                    CONFIGURATION_DYNAMIC_PLATFORM_OID,
                    &mut dynamic_platform as &mut dyn OptionOfTryFromExtensionValue,
                ),
                (CONFIGURATION_CACHED_KEYS_OID, &mut cached_keys),
                (CONFIGURATION_SMT_ENABLED_OID, &mut smt_enabled),
            ]),
        )?;

        Ok(Self {
            dynamic_platform: dynamic_platform.unwrap(),
            cached_keys: cached_keys.unwrap(),
            smt_enabled: smt_enabled.unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pck_extension_from_pem() {
        let pck_cert_from_platform = include_bytes!("../data/pck_from_platform_ca.pem");
        let pck_cert_from_processor = include_bytes!("../data/pck_from_processor_ca.pem");

        assert!(SgxPckExtension::from_pem_certificate(pck_cert_from_platform).is_ok());
        assert!(SgxPckExtension::from_pem_certificate(pck_cert_from_processor).is_ok());
    }
}
