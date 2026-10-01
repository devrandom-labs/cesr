//! Pinned Draft 7 schema verification for V1 ACDC credentials.
//!
//! This standard-library adapter has no HTTP or file resolver. Schemas are
//! supplied by the host as exact bytes and checked against their `$id` SAID.

use alloc::{string::String, string::ToString};

use keri_events::Said;
use keri_events::acdc::{Acdc, AcdcField};
use serde_json::Value;

use crate::codec::field::Field;
use crate::codec::scanner::Scanner;
use crate::error::CodecError;
use crate::said::infer_digest_code;
use crate::{Deserialize, JsonLimits, SadCodes};

const MAX_SCHEMA_BYTES: usize = 1_048_576;
const MAX_CREDENTIAL_BYTES: usize = 1_048_576;
const MAX_JSON_DEPTH: usize = 128;

/// A schema whose canonical bytes, `$id` SAID and Draft 7 grammar have been
/// checked. Compilation has no network or filesystem resolver.
pub struct VerifiedSchema {
    said: Said<'static>,
    validator: jsonschema::Validator,
}

/// Why a supplied schema or credential failed the schema boundary.
#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    /// Canonical JSON or SAID validation failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The schema lacks a string `$id` SAID or a supported Draft 7 marker.
    #[error("schema requires a `$id` SAID and a Draft 7 `$schema` marker")]
    Header,
    /// Schema document is not valid Draft 7.
    #[error("invalid Draft 7 schema: {0}")]
    InvalidSchema(String),
    /// Credential's `s` does not name this verified schema.
    #[error("credential schema SAID does not match supplied schema")]
    SchemaMismatch,
    /// The selected profile needs an `s` SAID, not an inline schema block.
    #[error("inline credential schema block is outside the selected verification profile")]
    UnsupportedSchemaForm,
    /// Aggregate or externally referenced attributes need a disclosure proof.
    #[error("aggregate or referenced attributes are outside the selected verification profile")]
    UnsupportedDisclosure,
    /// Credential JSON violates the supplied Draft 7 schema.
    #[error("credential violates the supplied Draft 7 schema: {0}")]
    InvalidCredential(String),
    /// A selected hard bound was exceeded before schema compilation.
    #[error("schema or credential resource limit exceeded")]
    ResourceLimit,
    /// External or recursive schema resolution is outside this local profile.
    #[error("schema `$ref` is outside the selected local profile")]
    UnsupportedReference,
}

impl VerifiedSchema {
    /// Parse canonical schema bytes, verify `$id`, and compile Draft 7 locally.
    ///
    /// # Errors
    ///
    /// Returns a typed grammar, SAID, dialect, or schema compilation error.
    pub fn from_bytes(raw: &[u8], limits: JsonLimits) -> Result<Self, SchemaError> {
        if raw.len() > MAX_SCHEMA_BYTES || limits.max_depth > MAX_JSON_DEPTH {
            return Err(SchemaError::ResourceLimit);
        }
        let mut scan = Scanner::with_budget(raw, limits.into());
        scan.object_value_span()?;
        scan.finish().map_err(CodecError::from)?;
        let value: Value =
            serde_json::from_slice(raw).map_err(|e| SchemaError::InvalidSchema(e.to_string()))?;
        if has_reference(&value) {
            return Err(SchemaError::UnsupportedReference);
        }
        let said_text = value
            .get("$id")
            .and_then(Value::as_str)
            .ok_or(SchemaError::Header)?;
        let dialect = value
            .get("$schema")
            .and_then(Value::as_str)
            .ok_or(SchemaError::Header)?;
        if dialect != "http://json-schema.org/draft-07/schema#"
            && dialect != "https://json-schema.org/draft-07/schema#"
        {
            return Err(SchemaError::Header);
        }
        let code = infer_digest_code(said_text).map_err(CodecError::from)?;
        let config = SadCodes::from_pairs(&[("$id", code)])
            .map_err(|e| SchemaError::InvalidSchema(e.to_string()))?;
        config.verify(raw)?;
        let said = Field::new("$id", said_text)
            .decode::<Said>()
            .map_err(CodecError::from)?
            .into_static();
        let validator = jsonschema::draft7::new(&value)
            .map_err(|e| SchemaError::InvalidSchema(e.to_string()))?;
        Ok(Self { said, validator })
    }

    /// Schema SAID whose verified bytes and validator back this value.
    #[must_use]
    pub const fn said(&self) -> &Said<'static> {
        &self.said
    }

    /// Validate one exact V1 ACDC body under this schema. The returned ACDC
    /// was parsed from these same bytes, preserving field/body provenance.
    ///
    /// # Errors
    ///
    /// Rejects malformed ACDC, wrong schema reference, unsupported inline
    /// schema form or any Draft 7 instance violation.
    pub fn validate_credential(
        &self,
        raw: &[u8],
        limits: JsonLimits,
    ) -> Result<Acdc<'static>, SchemaError> {
        if raw.len() > MAX_CREDENTIAL_BYTES || limits.max_depth > MAX_JSON_DEPTH {
            return Err(SchemaError::ResourceLimit);
        }
        let credential = Acdc::deserialize(raw, limits)?;
        match credential.schema() {
            AcdcField::Said(said) if said == &self.said => {}
            AcdcField::Said(_) => return Err(SchemaError::SchemaMismatch),
            AcdcField::Block(_) => return Err(SchemaError::UnsupportedSchemaForm),
        }
        if credential.aggregate_attributes().is_some()
            || matches!(credential.attributes(), Some(AcdcField::Said(_)) | None)
        {
            return Err(SchemaError::UnsupportedDisclosure);
        }
        let value: Value = serde_json::from_slice(raw)
            .map_err(|e| SchemaError::InvalidCredential(e.to_string()))?;
        self.validator
            .validate(&value)
            .map_err(|e| SchemaError::InvalidCredential(e.to_string()))?;
        Ok(credential)
    }
}

fn has_reference(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.contains_key("$ref") || map.values().any(has_reference),
        Value::Array(items) => items.iter().any(has_reference),
        _ => false,
    }
}
