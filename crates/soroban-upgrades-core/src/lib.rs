//! Upgrade-safety primitives for Soroban contracts.
//!
//! The crate inspects the metadata and contract specification embedded in
//! Soroban WASM binaries. It never signs or submits a transaction.

use schemars::JsonSchema;
use semver::Version;
use serde::{
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Cursor,
};
use stellar_xdr::{
    Error as XdrError, Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry, ScMetaV0,
    ScSpecEntry, ScSpecTypeDef, ScSpecUdtUnionCaseV0,
};

const SPEC_XDR_DEPTH_LIMIT: u32 = 500;
pub const MAX_ARTIFACT_SIZE_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLIC_IMPACT_DEPTH: usize = 64;
const MAX_PUBLIC_IMPACT_PATHS: usize = 256;
const MAX_PUBLIC_IMPACT_STEPS: usize = 10_000;
const CAP_0086_PROTOCOL: u32 = 28;
const CAP_0086_SPARSE_WRITE_IMPORT: &str = "m.b";
const CAP_0086_SPARSE_READ_IMPORT: &str = "m.c";
const UPDATE_CURRENT_CONTRACT_WASM_IMPORT: &str = "l.6";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WASM artifact is {size_bytes} bytes. The parser limit is {limit_bytes} bytes")]
    ArtifactTooLarge {
        size_bytes: usize,
        limit_bytes: usize,
    },
    #[error("invalid Soroban contract specification: {0}")]
    Spec(#[from] soroban_spec::read::FromWasmError),
    #[error("expected exactly one contractspecv0 section, found {0}")]
    ContractSpecSectionCount(usize),
    #[error("expected exactly one contractenvmetav0 section, found {0}")]
    ContractEnvMetaSectionCount(usize),
    #[error("expected exactly one environment interface version, found {0}")]
    ContractEnvVersionCount(usize),
    #[error("contract specification contains duplicate {kind} name {name:?}")]
    DuplicateSpecName { kind: &'static str, name: String },
    #[error("contract specification {kind} {owner:?} contains duplicate member {name:?}")]
    DuplicateSpecMember {
        kind: &'static str,
        owner: String,
        name: String,
    },
    #[error("contract metadata contains duplicate key {0:?}")]
    DuplicateMetadataKey(String),
    #[error("invalid WASM binary: {0}")]
    Wasm(#[from] wasmparser::BinaryReaderError),
    #[error("incomplete WASM call-graph evidence: {0}")]
    CallGraph(String),
    #[error("invalid XDR metadata: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid contract ID {0:?}. Expected a checksummed Stellar C... strkey")]
    InvalidContractId(String),
    #[error("invalid upgrade plan: {0}")]
    Plan(String),
}

struct UniqueJson;

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJson>()?.is_some() {}
        Ok(UniqueJson)
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            object.next_value::<UniqueJson>()?;
        }
        Ok(UniqueJson)
    }
}

fn parse_json_strict<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    let mut duplicate_check = serde_json::Deserializer::from_slice(bytes);
    UniqueJson::deserialize(&mut duplicate_check)?;
    duplicate_check.end()?;
    Ok(serde_json::from_slice(bytes)?)
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceEntry {
    pub kind: String,
    pub name: String,
    pub canonical: serde_json::Value,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryPosition {
    Input,
    Output,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicTypeBoundary {
    pub function: String,
    pub position: BoundaryPosition,
    pub index: usize,
    pub label: Option<String>,
    pub root_type: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeReference {
    pub owner_type: String,
    pub member: String,
    pub target_type: String,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportCallEvidence {
    pub host_imports: BTreeSet<String>,
    pub dynamic_dispatch_reachable: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FunctionImport {
    pub function_index: u32,
    pub module: String,
    pub name: String,
}

impl FunctionImport {
    pub fn canonical_name(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub format_version: u32,
    pub sha256: String,
    pub size_bytes: usize,
    pub env_protocol_version: u32,
    pub env_pre_release: u32,
    pub metadata: BTreeMap<String, String>,
    pub host_imports: BTreeSet<String>,
    pub functions: BTreeMap<String, InterfaceEntry>,
    pub events: BTreeMap<String, InterfaceEntry>,
    pub user_types: BTreeMap<String, InterfaceEntry>,
    pub public_type_boundaries: Vec<PublicTypeBoundary>,
    pub type_references: Vec<TypeReference>,
    pub export_call_evidence: BTreeMap<String, ExportCallEvidence>,
}

impl Artifact {
    pub fn from_wasm(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ARTIFACT_SIZE_BYTES {
            return Err(Error::ArtifactTooLarge {
                size_bytes: bytes.len(),
                limit_bytes: MAX_ARTIFACT_SIZE_BYTES,
            });
        }
        wasmparser::Validator::new().validate_all(bytes)?;
        let sha256 = hex::encode(Sha256::digest(bytes));
        require_single_contract_spec_section(bytes)?;
        let (env_protocol_version, env_pre_release) = read_contract_env_metadata(bytes)?;
        let spec = soroban_spec::read::from_wasm(bytes)?;
        let metadata = read_contract_metadata(bytes)?;
        let host_imports = read_host_imports(bytes)?;
        let export_call_evidence = inspect_export_call_evidence(bytes)?;
        let mut functions = BTreeMap::new();
        let mut events = BTreeMap::new();
        let mut user_types = BTreeMap::new();
        let mut public_type_boundaries = BTreeSet::new();
        let mut type_references = BTreeSet::new();

        for entry in spec.iter() {
            let canonical = canonicalize_spec_entry(entry)?;
            match entry {
                ScSpecEntry::FunctionV0(function) => {
                    let name = function.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "function",
                        &name,
                        function
                            .inputs
                            .iter()
                            .map(|input| input.name.to_utf8_string_lossy()),
                    )?;
                    for (index, input) in function.inputs.iter().enumerate() {
                        let mut referenced = BTreeSet::new();
                        collect_udt_names(&input.type_, &mut referenced);
                        for root_type in referenced {
                            public_type_boundaries.insert(PublicTypeBoundary {
                                function: name.clone(),
                                position: BoundaryPosition::Input,
                                index,
                                label: Some(input.name.to_utf8_string_lossy()),
                                root_type,
                            });
                        }
                    }
                    for (index, output) in function.outputs.iter().enumerate() {
                        let mut referenced = BTreeSet::new();
                        collect_udt_names(output, &mut referenced);
                        for root_type in referenced {
                            public_type_boundaries.insert(PublicTypeBoundary {
                                function: name.clone(),
                                position: BoundaryPosition::Output,
                                index,
                                label: None,
                                root_type,
                            });
                        }
                    }
                    if functions
                        .insert(
                            name.clone(),
                            InterfaceEntry {
                                kind: "function".into(),
                                name: name.clone(),
                                canonical,
                            },
                        )
                        .is_some()
                    {
                        return Err(Error::DuplicateSpecName {
                            kind: "function",
                            name,
                        });
                    }
                }
                ScSpecEntry::UdtStructV0(value) => {
                    let owner_type = value.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "struct",
                        &owner_type,
                        value
                            .fields
                            .iter()
                            .map(|field| field.name.to_utf8_string_lossy()),
                    )?;
                    for field in value.fields.iter() {
                        let mut referenced = BTreeSet::new();
                        collect_udt_names(&field.type_, &mut referenced);
                        for target_type in referenced {
                            type_references.insert(TypeReference {
                                owner_type: owner_type.clone(),
                                member: field.name.to_utf8_string_lossy(),
                                target_type,
                            });
                        }
                    }
                    insert_user_type(&mut user_types, "struct", owner_type, canonical)?;
                }
                ScSpecEntry::UdtUnionV0(value) => {
                    let owner_type = value.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "union",
                        &owner_type,
                        value.cases.iter().map(|case| match case {
                            ScSpecUdtUnionCaseV0::VoidV0(case) => case.name.to_utf8_string_lossy(),
                            ScSpecUdtUnionCaseV0::TupleV0(case) => case.name.to_utf8_string_lossy(),
                        }),
                    )?;
                    for case in value.cases.iter() {
                        if let ScSpecUdtUnionCaseV0::TupleV0(tuple) = case {
                            let case_name = tuple.name.to_utf8_string_lossy();
                            for (index, value_type) in tuple.type_.iter().enumerate() {
                                let mut referenced = BTreeSet::new();
                                collect_udt_names(value_type, &mut referenced);
                                for target_type in referenced {
                                    type_references.insert(TypeReference {
                                        owner_type: owner_type.clone(),
                                        member: format!("{case_name}[{index}]"),
                                        target_type,
                                    });
                                }
                            }
                        }
                    }
                    insert_user_type(&mut user_types, "union", owner_type, canonical)?;
                }
                ScSpecEntry::UdtEnumV0(value) => {
                    let name = value.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "enum",
                        &name,
                        value
                            .cases
                            .iter()
                            .map(|case| case.name.to_utf8_string_lossy()),
                    )?;
                    insert_user_type(&mut user_types, "enum", name, canonical)?;
                }
                ScSpecEntry::UdtErrorEnumV0(value) => {
                    let name = value.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "error enum",
                        &name,
                        value
                            .cases
                            .iter()
                            .map(|case| case.name.to_utf8_string_lossy()),
                    )?;
                    insert_user_type(&mut user_types, "error_enum", name, canonical)?;
                }
                ScSpecEntry::EventV0(value) => {
                    let name = value.name.to_utf8_string_lossy();
                    ensure_unique_spec_members(
                        "event",
                        &name,
                        value
                            .params
                            .iter()
                            .map(|param| param.name.to_utf8_string_lossy()),
                    )?;
                    if events
                        .insert(
                            name.clone(),
                            InterfaceEntry {
                                kind: "event".into(),
                                name: name.clone(),
                                canonical,
                            },
                        )
                        .is_some()
                    {
                        return Err(Error::DuplicateSpecName {
                            kind: "event",
                            name,
                        });
                    }
                }
            }
        }

        Ok(Self {
            format_version: 1,
            sha256,
            size_bytes: bytes.len(),
            env_protocol_version,
            env_pre_release,
            metadata,
            host_imports,
            functions,
            events,
            user_types,
            public_type_boundaries: public_type_boundaries.into_iter().collect(),
            type_references: type_references.into_iter().collect(),
            export_call_evidence,
        })
    }

    pub fn version(&self) -> Option<&str> {
        self.metadata.get("binver").map(String::as_str)
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    pub fn uses_cap_0086_sparse_read(&self) -> bool {
        self.host_imports.contains(CAP_0086_SPARSE_READ_IMPORT)
    }

    pub fn uses_cap_0086_sparse_write(&self) -> bool {
        self.host_imports.contains(CAP_0086_SPARSE_WRITE_IMPORT)
    }
}

fn collect_udt_names(value_type: &ScSpecTypeDef, destination: &mut BTreeSet<String>) {
    match value_type {
        ScSpecTypeDef::Udt(value) => {
            destination.insert(value.name.to_utf8_string_lossy());
        }
        ScSpecTypeDef::Option(value) => collect_udt_names(&value.value_type, destination),
        ScSpecTypeDef::Result(value) => {
            collect_udt_names(&value.ok_type, destination);
            collect_udt_names(&value.error_type, destination);
        }
        ScSpecTypeDef::Vec(value) => collect_udt_names(&value.element_type, destination),
        ScSpecTypeDef::Map(value) => {
            collect_udt_names(&value.key_type, destination);
            collect_udt_names(&value.value_type, destination);
        }
        ScSpecTypeDef::Tuple(value) => {
            for member in value.value_types.iter() {
                collect_udt_names(member, destination);
            }
        }
        ScSpecTypeDef::Val
        | ScSpecTypeDef::Bool
        | ScSpecTypeDef::Void
        | ScSpecTypeDef::Error
        | ScSpecTypeDef::U32
        | ScSpecTypeDef::I32
        | ScSpecTypeDef::U64
        | ScSpecTypeDef::I64
        | ScSpecTypeDef::Timepoint
        | ScSpecTypeDef::Duration
        | ScSpecTypeDef::U128
        | ScSpecTypeDef::I128
        | ScSpecTypeDef::U256
        | ScSpecTypeDef::I256
        | ScSpecTypeDef::Bytes
        | ScSpecTypeDef::String
        | ScSpecTypeDef::Symbol
        | ScSpecTypeDef::Address
        | ScSpecTypeDef::MuxedAddress
        | ScSpecTypeDef::BytesN(_) => {}
    }
}

fn require_single_contract_spec_section(bytes: &[u8]) -> Result<(), Error> {
    let mut count = 0;
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CustomSection(section) = payload? {
            count += usize::from(section.name() == "contractspecv0");
        }
    }
    if count == 1 {
        Ok(())
    } else {
        Err(Error::ContractSpecSectionCount(count))
    }
}

fn canonicalize_spec_entry(entry: &ScSpecEntry) -> Result<serde_json::Value, serde_json::Error> {
    let mut value = serde_json::to_value(entry)?;
    strip_documentation(&mut value);
    Ok(value)
}

// Documentation changes do not alter the callable ABI. Keeping them in the
// comparison would turn harmless comment edits into release-blocking findings.
fn strip_documentation(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            object.remove("doc");
            for child in object.values_mut() {
                strip_documentation(child);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values {
                strip_documentation(child);
            }
        }
        _ => {}
    }
}

fn ensure_unique_spec_members(
    kind: &'static str,
    owner: &str,
    names: impl IntoIterator<Item = String>,
) -> Result<(), Error> {
    let mut unique = BTreeSet::new();
    for name in names {
        if !unique.insert(name.clone()) {
            return Err(Error::DuplicateSpecMember {
                kind,
                owner: owner.into(),
                name,
            });
        }
    }
    Ok(())
}

fn insert_user_type(
    destination: &mut BTreeMap<String, InterfaceEntry>,
    kind: &str,
    name: String,
    canonical: serde_json::Value,
) -> Result<(), Error> {
    if destination
        .insert(
            name.clone(),
            InterfaceEntry {
                kind: kind.into(),
                name: name.clone(),
                canonical,
            },
        )
        .is_some()
    {
        Err(Error::DuplicateSpecName {
            kind: "user-defined type",
            name,
        })
    } else {
        Ok(())
    }
}

fn read_contract_metadata(bytes: &[u8]) -> Result<BTreeMap<String, String>, Error> {
    let mut raw = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CustomSection(section) = payload? {
            if section.name() == "contractmetav0" {
                raw.extend_from_slice(section.data());
            }
        }
    }

    let cursor = Cursor::new(raw);
    let mut reader = Limited::new(cursor, Limits::depth(SPEC_XDR_DEPTH_LIMIT));
    let entries = ScMetaEntry::read_xdr_iter(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let mut metadata = BTreeMap::new();
    for entry in entries {
        let ScMetaEntry::ScMetaV0(ScMetaV0 { key, val }) = entry;
        let key = key.to_utf8_string_lossy();
        if metadata
            .insert(key.clone(), val.to_utf8_string_lossy())
            .is_some()
        {
            return Err(Error::DuplicateMetadataKey(key));
        }
    }
    Ok(metadata)
}

fn read_contract_env_metadata(bytes: &[u8]) -> Result<(u32, u32), Error> {
    let mut raw = Vec::new();
    let mut section_count = 0;
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::CustomSection(section) = payload? {
            if section.name() == "contractenvmetav0" {
                section_count += 1;
                raw.extend_from_slice(section.data());
            }
        }
    }
    if section_count != 1 {
        return Err(Error::ContractEnvMetaSectionCount(section_count));
    }

    let cursor = Cursor::new(raw);
    let mut reader = Limited::new(cursor, Limits::depth(SPEC_XDR_DEPTH_LIMIT));
    let entries = ScEnvMetaEntry::read_xdr_iter(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if entries.len() != 1 {
        return Err(Error::ContractEnvVersionCount(entries.len()));
    }
    let ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(version) = &entries[0];
    Ok((version.protocol, version.pre_release))
}

#[derive(Default)]
struct FunctionBodyCalls {
    direct_calls: Vec<u32>,
    has_dynamic_dispatch: bool,
}

fn read_host_imports(bytes: &[u8]) -> Result<BTreeSet<String>, Error> {
    Ok(inspect_function_imports(bytes)?
        .into_iter()
        .map(|import| import.canonical_name())
        .collect())
}

pub fn inspect_function_imports(bytes: &[u8]) -> Result<Vec<FunctionImport>, Error> {
    let mut imports = Vec::new();
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::ImportSection(section) = payload? {
            for import in section.into_imports() {
                let import = import?;
                if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                    let function_index = u32::try_from(imports.len()).map_err(|_| {
                        Error::CallGraph("too many function imports to inspect".into())
                    })?;
                    imports.push(FunctionImport {
                        function_index,
                        module: import.module.to_owned(),
                        name: import.name.to_owned(),
                    });
                }
            }
        }
    }
    Ok(imports)
}

pub fn inspect_export_call_evidence(
    bytes: &[u8],
) -> Result<BTreeMap<String, ExportCallEvidence>, Error> {
    let mut function_imports = Vec::new();
    let mut function_exports = BTreeMap::new();
    let mut function_bodies = Vec::new();

    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        match payload? {
            wasmparser::Payload::ImportSection(section) => {
                for import in section.into_imports() {
                    let import = import?;
                    if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                        function_imports.push(format!("{}.{}", import.module, import.name));
                    }
                }
            }
            wasmparser::Payload::ExportSection(section) => {
                for export in section {
                    let export = export?;
                    if export.kind == wasmparser::ExternalKind::Func {
                        function_exports.insert(export.name.to_owned(), export.index);
                    }
                }
            }
            wasmparser::Payload::CodeSectionEntry(body) => {
                let mut calls = FunctionBodyCalls::default();
                let mut operators = body.get_operators_reader()?;
                while !operators.eof() {
                    match operators.read()? {
                        wasmparser::Operator::Call { function_index }
                        | wasmparser::Operator::ReturnCall { function_index } => {
                            calls.direct_calls.push(function_index);
                        }
                        wasmparser::Operator::CallIndirect { .. }
                        | wasmparser::Operator::ReturnCallIndirect { .. }
                        | wasmparser::Operator::CallRef { .. }
                        | wasmparser::Operator::ReturnCallRef { .. } => {
                            calls.has_dynamic_dispatch = true;
                        }
                        _ => {}
                    }
                }
                function_bodies.push(calls);
            }
            _ => {}
        }
    }

    let imported_function_count = u32::try_from(function_imports.len())
        .map_err(|_| Error::CallGraph("too many function imports to inspect".into()))?;
    let mut result = BTreeMap::new();
    for (export, function_index) in function_exports {
        let mut visited = BTreeSet::new();
        let mut evidence = ExportCallEvidence::default();
        collect_export_call_evidence(
            function_index,
            imported_function_count,
            &function_imports,
            &function_bodies,
            &mut visited,
            &mut evidence,
        )?;
        result.insert(export, evidence);
    }
    Ok(result)
}

fn collect_export_call_evidence(
    function_index: u32,
    imported_function_count: u32,
    function_imports: &[String],
    function_bodies: &[FunctionBodyCalls],
    visited: &mut BTreeSet<u32>,
    evidence: &mut ExportCallEvidence,
) -> Result<(), Error> {
    let mut pending = vec![function_index];
    while let Some(current) = pending.pop() {
        if current < imported_function_count {
            let import = function_imports
                .get(current as usize)
                .ok_or_else(|| Error::CallGraph("function import index is out of range".into()))?;
            evidence.host_imports.insert(import.clone());
            continue;
        }
        if !visited.insert(current) {
            continue;
        }

        let body_index = usize::try_from(current - imported_function_count).map_err(|_| {
            Error::CallGraph("function body index does not fit this platform".into())
        })?;
        let body = function_bodies
            .get(body_index)
            .ok_or_else(|| Error::CallGraph("function body index is out of range".into()))?;
        evidence.dynamic_dispatch_reachable |= body.has_dynamic_dispatch;
        pending.extend(body.direct_calls.iter().rev().copied());
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSource {
    #[default]
    Unpinned,
    OfflineAssertion,
    StellarCliNetworkInfo,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationContext {
    pub target_protocol_version: Option<u32>,
    pub protocol_source: ProtocolSource,
    pub network_name: Option<String>,
    pub network_id: Option<String>,
    pub network_passphrase: Option<String>,
    pub rpc_version: Option<String>,
    pub captive_core_version: Option<String>,
    pub observed_at_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub format_version: u32,
    pub name: String,
    pub require_upgrade_function: bool,
    pub forbid_constructor: bool,
    pub require_semver_increase: bool,
    pub require_storage_schema: bool,
    pub require_schema_history: bool,
    pub deny_removed_functions: bool,
    pub deny_changed_functions: bool,
    pub deny_removed_events: bool,
    pub deny_changed_events: bool,
    pub deny_changed_user_types: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            format_version: 1,
            name: "soroban-upgrades-default".into(),
            require_upgrade_function: true,
            forbid_constructor: false,
            require_semver_increase: true,
            require_storage_schema: true,
            require_schema_history: true,
            deny_removed_functions: true,
            deny_changed_functions: true,
            deny_removed_events: true,
            deny_changed_events: true,
            deny_changed_user_types: true,
        }
    }
}

impl Policy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        parse_json_strict(bytes)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub strategy: String,
    pub entrypoint: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Instance,
    Persistent,
    Temporary,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub key: String,
    pub durability: Durability,
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default)]
    pub migration: Option<Migration>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageSchema {
    pub format_version: u32,
    pub complete: bool,
    pub schema_version: u32,
    pub contract_version: String,
    pub entries: Vec<StorageEntry>,
}

impl StorageSchema {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        parse_json_strict(bytes)
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoricalField {
    #[serde(rename = "type")]
    pub value_type: serde_json::Value,
    pub first_seen: String,
    #[serde(default)]
    pub retired_in: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeHistory {
    #[serde(default)]
    pub fields: BTreeMap<String, HistoricalField>,
    #[serde(default)]
    pub reserved_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaHistory {
    pub format_version: u32,
    pub complete: bool,
    pub types: BTreeMap<String, TypeHistory>,
    #[serde(default)]
    #[schemars(skip)]
    pub source_sha256: String,
}

impl SchemaHistory {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let mut history: Self = parse_json_strict(bytes)?;
        history.source_sha256 = hex::encode(Sha256::digest(bytes));
        Ok(history)
    }
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Fact,
    Inference,
    Unknown,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceItem {
    pub status: EvidenceStatus,
    pub claim: String,
    pub basis: String,
    pub limitation: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceCoverage {
    pub compiled_contract_spec: EvidenceItem,
    pub artifact_host_imports: EvidenceItem,
    pub target_network_protocol: EvidenceItem,
    pub declared_storage_schema: EvidenceItem,
    pub declared_schema_history: EvidenceItem,
    pub ledger_storage_coverage: EvidenceItem,
    pub deployed_caller_graph: EvidenceItem,
    pub cap0086_per_type_reader_binding: EvidenceItem,
    pub migration_completion: EvidenceItem,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImpactStep {
    pub owner_type: String,
    pub member: String,
    pub target_type: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicImpact {
    pub changed_type: String,
    pub boundary: PublicTypeBoundary,
    pub steps: Vec<ImpactStep>,
    pub structural_reachability: EvidenceStatus,
    pub runtime_compatibility: EvidenceStatus,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ValidationReport {
    pub format_version: u32,
    pub tool_version: String,
    pub safe: bool,
    pub policy: Policy,
    pub context: ValidationContext,
    pub source: Artifact,
    pub target: Artifact,
    pub findings: Vec<Finding>,
    pub public_impacts: Vec<PublicImpact>,
    pub evidence: EvidenceCoverage,
    pub storage_schema_checked: bool,
    pub schema_history_checked: bool,
    pub policy_sha256: String,
    pub source_schema_sha256: Option<String>,
    pub target_schema_sha256: Option<String>,
    pub schema_history_sha256: Option<String>,
    pub source_schema: Option<StorageSchema>,
    pub target_schema: Option<StorageSchema>,
    pub schema_history: Option<SchemaHistory>,
}

pub fn validate(
    source: &Artifact,
    target: &Artifact,
    source_schema: Option<&StorageSchema>,
    target_schema: Option<&StorageSchema>,
    policy: &Policy,
) -> ValidationReport {
    validate_with_history(
        source,
        target,
        source_schema,
        target_schema,
        policy,
        &ValidationContext::default(),
        None,
    )
}

pub fn validate_with_context(
    source: &Artifact,
    target: &Artifact,
    source_schema: Option<&StorageSchema>,
    target_schema: Option<&StorageSchema>,
    policy: &Policy,
    context: &ValidationContext,
) -> ValidationReport {
    validate_with_history(
        source,
        target,
        source_schema,
        target_schema,
        policy,
        context,
        None,
    )
}

pub fn validate_with_history(
    source: &Artifact,
    target: &Artifact,
    source_schema: Option<&StorageSchema>,
    target_schema: Option<&StorageSchema>,
    policy: &Policy,
    context: &ValidationContext,
    schema_history: Option<&SchemaHistory>,
) -> ValidationReport {
    let mut findings = Vec::new();

    check_policy(policy, &mut findings);
    check_protocol_context(context, &mut findings);
    check_environment_compatibility(target, context, &mut findings);
    check_cap_0086(target, context, &mut findings);

    if policy.require_upgrade_function && !target.has_function("upgrade") {
        findings.push(error(
            "UPG001",
            "Target removes the upgrade entrypoint",
            "The target contract specification has no `upgrade` function. A successful deployment makes subsequent upgrades unavailable without another authorized host update.",
            "Retain an authorized `upgrade` entrypoint or explicitly approve immutability as a terminal release.",
        ));
    }
    if policy.require_upgrade_function {
        check_upgrade_host_capability(source, "source", "UPG003", &mut findings);
        check_upgrade_host_capability(target, "target", "UPG004", &mut findings);
    }

    if target.has_function("__constructor") {
        let constructor = if policy.forbid_constructor {
            error(
                "UPG002",
                "Target contains a constructor",
                "Soroban does not invoke `__constructor` when WASM is replaced. Any state initialization placed there will be skipped during this upgrade.",
                "Move upgrade-time initialization to an idempotent migration entrypoint and test it against the pre-upgrade state.",
            )
        } else {
            warning(
                "UPG002",
                "Target constructor will not run during upgrade",
                "The target can validly retain a constructor for fresh deployments, but Soroban will not invoke it when replacing WASM.",
                "Confirm that upgrade-time initialization is handled by an idempotent migration and that no upgrade invariant depends on the constructor.",
            )
        };
        findings.push(constructor);
    }

    check_versions(source, target, policy, &mut findings);
    compare_interfaces(source, target, policy, context, &mut findings);

    if let Some(history) = schema_history {
        validate_schema_history(source, target, history, &mut findings);
    } else {
        let finding = if policy.require_schema_history {
            error(
                "HIS000",
                "Historical field lifecycle was not checked",
                "A two-artifact comparison cannot detect reuse of a field name from an older release.",
                "Commit a complete schema-history manifest and pass `--schema-history`.",
            )
        } else {
            warning(
            "HIS000",
            "Historical field lifecycle was not checked",
            "A two-artifact comparison cannot detect reuse of a field name that existed in an older release or prove that archived state no longer contains retired layouts.",
            "Commit a complete schema-history manifest and pass `--schema-history`.",
            )
        };
        findings.push(finding);
    }

    match (source_schema, target_schema) {
        (Some(from), Some(to)) => {
            validate_schema_manifests(source, target, from, to, &mut findings);
            compare_storage_schemas(from, to, &mut findings);
        }
        (None, None) => {
            let finding = if policy.require_storage_schema {
                error(
                    "STO000",
                    "Storage compatibility was not checked",
                    "Soroban WASM does not contain a complete description of all storage keys and value layouts.",
                    "Commit complete source and target storage schemas and pass both files.",
                )
            } else {
                warning(
                    "STO000",
                    "Storage compatibility was not checked",
                    "Soroban WASM does not contain a complete description of all storage keys and value layouts.",
                    "Commit complete source and target storage schemas and pass both files.",
                )
            };
            findings.push(finding);
        }
        _ => findings.push(error(
            "STO004",
            "Storage schema pair is incomplete",
            "Only one side of the upgrade supplied a storage schema, so compatibility cannot be evaluated.",
            "Supply both `--from-schema` and `--to-schema`.",
        )),
    }

    let (public_impacts, impact_limit_exceeded) = trace_public_impacts(source, target);
    if impact_limit_exceeded {
        findings.push(error(
            "RES001",
            "Public type-impact analysis exceeded its limit",
            "The type graph produced too many paths or too much traversal work for a complete result.",
            "Reduce the public type graph or split the contract interface before approval.",
        ));
    }
    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.code.cmp(&b.code)));
    let safe = !findings.iter().any(|f| f.severity == Severity::Error);
    let evidence = build_evidence_coverage(
        context,
        source_schema.is_some() && target_schema.is_some(),
        schema_history.is_some(),
    );
    ValidationReport {
        format_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        safe,
        policy: policy.clone(),
        context: context.clone(),
        source: source.clone(),
        target: target.clone(),
        findings,
        public_impacts,
        evidence,
        storage_schema_checked: source_schema.is_some() && target_schema.is_some(),
        schema_history_checked: schema_history.is_some(),
        policy_sha256: canonical_sha256(policy),
        source_schema_sha256: source_schema.map(canonical_sha256),
        target_schema_sha256: target_schema.map(canonical_sha256),
        schema_history_sha256: schema_history.map(|history| history.source_sha256.clone()),
        source_schema: source_schema.cloned(),
        target_schema: target_schema.cloned(),
        schema_history: schema_history.cloned(),
    }
}

fn check_upgrade_host_capability(
    artifact: &Artifact,
    side: &str,
    code: &str,
    findings: &mut Vec<Finding>,
) {
    if !artifact.has_function("upgrade") {
        if side == "source" {
            findings.push(error(
                code,
                "Source has no executable upgrade path",
                "The source Contract Spec has no `upgrade` function for the planned replacement.",
                "Deploy through an existing authorized replacement path before you use the standard planner.",
            ));
        }
        return;
    }
    let reaches_update = artifact
        .export_call_evidence
        .get("upgrade")
        .is_some_and(|evidence| {
            evidence
                .host_imports
                .contains(UPDATE_CURRENT_CONTRACT_WASM_IMPORT)
        });
    if !reaches_update {
        findings.push(error(
            code,
            &format!("{side} upgrade function cannot replace WASM"),
            &format!(
                "The {side} `upgrade` export does not reach Stellar host import `{UPDATE_CURRENT_CONTRACT_WASM_IMPORT}`."
            ),
            "Call `update_current_contract_wasm` from the authorized upgrade path and rebuild the exact candidate.",
        ));
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> String {
    serde_json::to_vec(value)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .unwrap_or_default()
}

fn evidence_item(
    status: EvidenceStatus,
    claim: &str,
    basis: &str,
    limitation: Option<&str>,
) -> EvidenceItem {
    EvidenceItem {
        status,
        claim: claim.into(),
        basis: basis.into(),
        limitation: limitation.map(str::to_owned),
    }
}

fn build_evidence_coverage(
    context: &ValidationContext,
    storage_schema_checked: bool,
    schema_history_checked: bool,
) -> EvidenceCoverage {
    let target_network_protocol = match context.protocol_source {
        ProtocolSource::StellarCliNetworkInfo
            if context.target_protocol_version.is_some()
                && context.network_name.is_some()
                && context.network_id.is_some()
                && context.observed_at_unix_seconds.is_some() =>
        {
            evidence_item(
                EvidenceStatus::Fact,
                "The named network reported the recorded target protocol at the observation time.",
                "Live Stellar CLI network-info evidence is embedded in the report.",
                Some("Network state can change. Resolve it again immediately before execution."),
            )
        }
        ProtocolSource::OfflineAssertion => evidence_item(
            EvidenceStatus::Inference,
            "The selected protocol is an offline release assumption.",
            "The operator supplied a protocol number without live network evidence.",
            Some("This does not prove that any named network has activated the protocol."),
        ),
        _ => evidence_item(
            EvidenceStatus::Unknown,
            "The target network protocol is not established.",
            "No complete live network evidence is present.",
            Some("Resolve a named network before producing an executable release plan."),
        ),
    };

    EvidenceCoverage {
        compiled_contract_spec: evidence_item(
            EvidenceStatus::Fact,
            "The report compares the exact compiled Contract Spec entries in both artifacts.",
            "The validator parsed one unambiguous contractspecv0 section from each hashed WASM.",
            Some("Contract Spec is not a complete deployed-caller or storage inventory."),
        ),
        artifact_host_imports: evidence_item(
            EvidenceStatus::Fact,
            "The report records artifact-wide host imports and direct per-export reachability.",
            "The validator inspected the WASM import, export, and code sections.",
            Some("Dynamic dispatch makes static reachability incomplete."),
        ),
        target_network_protocol,
        declared_storage_schema: if storage_schema_checked {
            evidence_item(
                EvidenceStatus::Fact,
                "The source-controlled source and target storage declarations were compared.",
                "A complete manifest pair was supplied and bound to the validation report.",
                Some("A declaration does not prove that it covers every ledger entry."),
            )
        } else {
            evidence_item(
                EvidenceStatus::Unknown,
                "The declared storage change is not established.",
                "No complete source/target manifest pair was supplied.",
                Some("Contract Spec alone cannot recover a complete storage inventory."),
            )
        },
        declared_schema_history: if schema_history_checked {
            evidence_item(
                EvidenceStatus::Fact,
                "A cumulative source-controlled field history was checked.",
                "The history bytes are hashed into the validation and release plan.",
                Some("The history is a reviewed declaration, not proof of ledger-wide migration."),
            )
        } else {
            evidence_item(
                EvidenceStatus::Unknown,
                "Historical field-name lifecycle is not established.",
                "No cumulative schema-history manifest was supplied.",
                Some("A two-release diff cannot detect older retired-name reuse."),
            )
        },
        ledger_storage_coverage: evidence_item(
            EvidenceStatus::Unknown,
            "Complete live and archived ledger storage coverage is not proven.",
            "Artifact validation does not sample or enumerate deployed ledger state.",
            Some("Use an application-specific snapshot rehearsal before a production migration."),
        ),
        deployed_caller_graph: evidence_item(
            EvidenceStatus::Unknown,
            "The complete deployed caller graph and rollout order are not proven.",
            "Public impact paths are structural paths inside the two compiled Contract Specs.",
            Some("External contracts and off-chain clients can exist outside both artifacts."),
        ),
        cap0086_per_type_reader_binding: evidence_item(
            EvidenceStatus::Unknown,
            "A global sparse-reader import is not bound to the changed type.",
            "Per-export direct-call reachability narrows the evidence but generated type-level binding is absent.",
            Some("Approve schema evolution only after type-specific runtime and rollout evidence."),
        ),
        migration_completion: evidence_item(
            EvidenceStatus::Unknown,
            "Ledger-wide migration completion and invariant preservation are not proven.",
            "The validator checks declarations but does not execute application migrations.",
            Some("Record application-specific rehearsal, completion, and invariant evidence."),
        ),
    }
}

fn trace_public_impacts(source: &Artifact, target: &Artifact) -> (Vec<PublicImpact>, bool) {
    let changed_types = source
        .user_types
        .iter()
        .filter_map(|(name, before)| {
            target
                .user_types
                .get(name)
                .filter(|after| after.canonical != before.canonical)
                .map(|_| name.clone())
        })
        .collect::<BTreeSet<_>>();

    let source_boundaries = source
        .public_type_boundaries
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let target_boundaries = target
        .public_type_boundaries
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let retained_boundaries = source_boundaries
        .intersection(&target_boundaries)
        .filter(|boundary| {
            source
                .functions
                .get(&boundary.function)
                .map(|entry| &entry.canonical)
                == target
                    .functions
                    .get(&boundary.function)
                    .map(|entry| &entry.canonical)
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut impacts = BTreeSet::new();
    let mut limit_exceeded = false;
    for boundary in retained_boundaries {
        for changed_type in &changed_types {
            let (source_routes, source_limited) =
                routes_to_type(source, &boundary.root_type, changed_type);
            let (target_routes, target_limited) =
                routes_to_type(target, &boundary.root_type, changed_type);
            limit_exceeded |= source_limited || target_limited;
            for steps in source_routes.intersection(&target_routes) {
                impacts.insert(PublicImpact {
                    changed_type: changed_type.clone(),
                    boundary: boundary.clone(),
                    steps: steps.clone(),
                    structural_reachability: EvidenceStatus::Fact,
                    runtime_compatibility: EvidenceStatus::Unknown,
                });
            }
        }
    }
    (impacts.into_iter().collect(), limit_exceeded)
}

fn routes_to_type(
    artifact: &Artifact,
    root_type: &str,
    target_type: &str,
) -> (BTreeSet<Vec<ImpactStep>>, bool) {
    let mut result = BTreeSet::new();
    let mut visited_steps = 0;
    let mut limit_exceeded = false;
    let mut pending = Vec::new();
    if artifact.user_types.contains_key(root_type) {
        pending.push((root_type.to_owned(), Vec::new(), BTreeSet::new()));
    }

    while let Some((current, steps, mut active_types)) = pending.pop() {
        visited_steps += 1;
        if visited_steps > MAX_PUBLIC_IMPACT_STEPS
            || steps.len() > MAX_PUBLIC_IMPACT_DEPTH
            || result.len() >= MAX_PUBLIC_IMPACT_PATHS
        {
            limit_exceeded = true;
            break;
        }
        if current == target_type {
            result.insert(steps);
            continue;
        }
        if !active_types.insert(current.clone()) {
            continue;
        }
        for edge in artifact
            .type_references
            .iter()
            .rev()
            .filter(|edge| edge.owner_type == current)
        {
            if pending.len() + visited_steps >= MAX_PUBLIC_IMPACT_STEPS {
                limit_exceeded = true;
                break;
            }
            let mut next_steps = steps.clone();
            next_steps.push(ImpactStep {
                owner_type: edge.owner_type.clone(),
                member: edge.member.clone(),
                target_type: edge.target_type.clone(),
            });
            pending.push((edge.target_type.clone(), next_steps, active_types.clone()));
        }
        if limit_exceeded {
            break;
        }
    }
    (result, limit_exceeded)
}

fn check_policy(policy: &Policy, findings: &mut Vec<Finding>) {
    if policy.format_version != 1 {
        findings.push(error(
            "POL001",
            "Unsupported policy format",
            &format!(
                "Policy `{}` uses format version {}. This build supports version 1.",
                policy.name, policy.format_version
            ),
            "Regenerate the policy with a supported format or upgrade the validator before relying on its result.",
        ));
    }

    let disabled = [
        (
            !policy.require_upgrade_function,
            "retained upgrade entrypoint",
        ),
        (!policy.require_semver_increase, "increasing `binver`"),
        (!policy.require_storage_schema, "complete storage schemas"),
        (!policy.require_schema_history, "complete schema history"),
        (!policy.deny_removed_functions, "removed public functions"),
        (
            !policy.deny_changed_functions,
            "changed function signatures",
        ),
        (!policy.deny_removed_events, "removed contract events"),
        (!policy.deny_changed_events, "changed contract events"),
        (
            !policy.deny_changed_user_types,
            "changed or removed user-defined types",
        ),
    ]
    .into_iter()
    .filter_map(|(is_disabled, label)| is_disabled.then_some(label))
    .collect::<Vec<_>>();

    if !disabled.is_empty() {
        findings.push(warning(
            "POL002",
            "Policy disables compatibility protections",
            &format!(
                "Policy `{}` disables checks for: {}.",
                policy.name,
                disabled.join(", ")
            ),
            "Use the conservative default or ensure every exception is reviewed and preserved in the plan digest.",
        ));
    }
}

fn check_environment_compatibility(
    target: &Artifact,
    context: &ValidationContext,
    findings: &mut Vec<Finding>,
) {
    if target.env_pre_release != 0 {
        findings.push(error(
            "ENV001",
            "Candidate uses a prerelease host interface",
            &format!(
                "The candidate declares environment protocol {} with prerelease value {}.",
                target.env_protocol_version, target.env_pre_release
            ),
            "Build the candidate with a stable Soroban SDK before release.",
        ));
    }

    if context
        .target_protocol_version
        .is_some_and(|protocol| protocol < target.env_protocol_version)
    {
        findings.push(error(
            "ENV002",
            "Candidate requires a newer network protocol",
            &format!(
                "The candidate requires protocol {}, but the selected network evidence reports protocol {}.",
                target.env_protocol_version,
                context.target_protocol_version.unwrap_or_default()
            ),
            "Use a compatible SDK or wait for the network protocol upgrade.",
        ));
    }
}

fn check_protocol_context(context: &ValidationContext, findings: &mut Vec<Finding>) {
    match context.protocol_source {
        ProtocolSource::Unpinned if context.target_protocol_version.is_none() => {
            findings.push(warning(
                "NET001",
                "Target protocol was not pinned",
                "Protocol-dependent host capabilities cannot be approved without the target network's active protocol version.",
                "Pass `--network` for a live Stellar CLI network read or `--protocol-version` for an explicitly recorded offline assertion.",
            ));
        }
        ProtocolSource::Unpinned => findings.push(error(
            "NET002",
            "Protocol version has no evidence source",
            "The validation context contains a protocol version but does not state whether it came from a live network read or an offline assertion.",
            "Construct the context through the CLI resolver so provenance is recorded and plan-bound.",
        )),
        ProtocolSource::OfflineAssertion if context.target_protocol_version.is_some() => {
            findings.push(warning(
                "NET003",
                "Target protocol is an offline assertion",
                "The protocol version was supplied by the operator and was not read from live network state during this validation.",
                "Re-run with `--network` immediately before release, or preserve independent protocol evidence with the reviewed plan.",
            ));
        }
        ProtocolSource::OfflineAssertion => findings.push(error(
            "NET004",
            "Offline protocol assertion is empty",
            "The context marks its protocol as an offline assertion but contains no protocol version.",
            "Supply an explicit protocol version or use a live network read.",
        )),
        ProtocolSource::StellarCliNetworkInfo
            if context.target_protocol_version.is_some()
                && context.network_name.is_some()
                && context.network_id.is_some()
                && context.network_passphrase.is_some()
                && context.rpc_version.is_some()
                && context.observed_at_unix_seconds.is_some() =>
        {
            findings.push(info(
                "NET005",
                "Target protocol resolved from live network state",
                &format!(
                    "Stellar CLI read protocol {} for network `{}` (network ID {}).",
                    context.target_protocol_version.unwrap_or_default(),
                    context.network_name.as_deref().unwrap_or("unknown"),
                    context.network_id.as_deref().unwrap_or("unknown")
                ),
                "Keep this evidence in the content-addressed plan and resolve it again immediately before submission.",
            ));
        }
        ProtocolSource::StellarCliNetworkInfo => findings.push(error(
            "NET006",
            "Live network evidence is incomplete",
            "The context claims a Stellar CLI network read but is missing protocol, network identity, passphrase, RPC version, or observation time.",
            "Discard the incomplete context and repeat the live network query.",
        )),
    }
}

fn check_cap_0086(target: &Artifact, context: &ValidationContext, findings: &mut Vec<Finding>) {
    let sparse_read = target.uses_cap_0086_sparse_read();
    let sparse_write = target.uses_cap_0086_sparse_write();

    match context.target_protocol_version {
        None => {}
        Some(protocol) if (sparse_read || sparse_write) && protocol < CAP_0086_PROTOCOL => {
            findings.push(error(
                "CAP001",
                "Candidate requires CAP-0086 before network activation",
                &format!(
                    "The target imports CAP-0086 sparse-map host functions, which require protocol {CAP_0086_PROTOCOL}, but the selected target protocol is {protocol}."
                ),
                "Deploy a protocol-27-compatible build or wait until the target network activates protocol 28 and re-run validation.",
            ));
        }
        Some(protocol) if protocol >= CAP_0086_PROTOCOL && sparse_read => {
            findings.push(info(
                "CAP002",
                "Candidate imports CAP-0086 sparse decoding",
                &format!(
                    "The candidate imports `sparse_map_unpack_to_linear_memory` and the selected protocol {protocol} supports it. This artifact-level fact does not prove which contract type uses the sparse reader."
                ),
                "Require type-specific reader evidence plus field-history and cross-contract rollout checks before approving schema evolution.",
            ));
        }
        Some(protocol) if protocol >= CAP_0086_PROTOCOL => findings.push(warning(
            "CAP003",
            "Protocol supports CAP-0086 but the candidate does not use sparse decoding",
            &format!(
                "Protocol {protocol} exposes CAP-0086, but this WASM does not import `sparse_map_unpack_to_linear_memory`. Its contract-type decoding remains strict."
            ),
            "Use an SDK or explicit implementation that opts into CAP-0086 before treating missing or additional fields as compatible.",
        )),
        Some(_) => {}
    }

    if sparse_write && !sparse_read {
        findings.push(warning(
            "CAP004",
            "Sparse writer is enabled without sparse reader",
            "Omitting `Void` fields can break older strict readers in cross-contract calls when contracts are upgraded independently.",
            "Prefer sparse reads first, keep sparse writes explicitly opt-in, and validate a staged dependency-aware rollout.",
        ));
    }

    let sparse_read_exports = target
        .export_call_evidence
        .iter()
        .filter_map(|(export, evidence)| {
            evidence
                .host_imports
                .contains(CAP_0086_SPARSE_READ_IMPORT)
                .then_some(export.as_str())
        })
        .collect::<Vec<_>>();
    let sparse_write_exports = target
        .export_call_evidence
        .iter()
        .filter_map(|(export, evidence)| {
            evidence
                .host_imports
                .contains(CAP_0086_SPARSE_WRITE_IMPORT)
                .then_some(export.as_str())
        })
        .collect::<Vec<_>>();
    let dynamic_exports = target
        .export_call_evidence
        .iter()
        .filter_map(|(export, evidence)| {
            evidence
                .dynamic_dispatch_reachable
                .then_some(export.as_str())
        })
        .collect::<Vec<_>>();

    if sparse_read && sparse_read_exports.is_empty() {
        findings.push(error(
            "CAP007",
            "Sparse-reader import is not directly reachable from an exported function",
            "The candidate imports `m.c`, but the direct-call graph does not connect that import to any exported function. An unused or dynamically reached import is not evidence that a contract entrypoint decodes sparsely.",
            "Provide an artifact whose relevant exported entrypoint directly reaches the sparse reader, and retain the call evidence with the report.",
        ));
    }
    if sparse_write && sparse_write_exports.is_empty() {
        findings.push(error(
            "CAP009",
            "Sparse-writer import is not directly reachable from an exported function",
            "The candidate imports `m.b`, but the direct-call graph does not connect that import to any exported function. An unused or dynamically reached import is not evidence that a contract entrypoint writes sparsely.",
            "Provide an artifact whose relevant exported entrypoint directly reaches the sparse writer, and retain the call evidence with the report.",
        ));
    }
    if (sparse_read || sparse_write) && !dynamic_exports.is_empty() {
        findings.push(warning(
            "CAP008",
            "Dynamic dispatch limits CAP-0086 call-graph evidence",
            &format!(
                "Exported function(s) {} reach indirect or reference calls, so static host-import reachability is incomplete even where direct CAP-0086 paths are present.",
                dynamic_exports.join(", ")
            ),
            "Remove dynamic dispatch from the compatibility-critical path or provide a separately verified complete call-target set.",
        ));
    }
}

fn validate_schema_manifests(
    source: &Artifact,
    target: &Artifact,
    source_schema: &StorageSchema,
    target_schema: &StorageSchema,
    findings: &mut Vec<Finding>,
) {
    for (side, artifact, schema) in [
        ("source", source, source_schema),
        ("target", target, target_schema),
    ] {
        if schema.format_version != 1 {
            findings.push(error(
                "STO006",
                "Unsupported storage manifest format",
                &format!(
                    "The {side} manifest uses format version {}. This build supports version 1.",
                    schema.format_version
                ),
                "Regenerate the manifest with a supported tool version or upgrade the validator before relying on its result.",
            ));
        }

        if !schema.complete {
            findings.push(error(
                "STO010",
                "Storage schema is not marked complete",
                &format!(
                    "The {side} storage schema does not declare complete coverage of its known storage keys."
                ),
                "Set `complete` to true only after you include every known storage key and value type.",
            ));
        }

        if schema.schema_version == 0 {
            findings.push(error(
                "STO011",
                "Storage schema version is zero",
                &format!("The {side} storage schema must use a positive schema version."),
                "Set `schemaVersion` to the version that the contract stores or enforces.",
            ));
        }

        if Version::parse(&schema.contract_version).is_err() {
            findings.push(error(
                "STO012",
                "Storage schema contract version is invalid",
                &format!(
                    "The {side} storage schema uses `{}` as its contract version.",
                    schema.contract_version
                ),
                "Use the exact semantic version from the artifact `binver` metadata.",
            ));
        }

        if let Some(artifact_version) = artifact.version() {
            if artifact_version != schema.contract_version {
                findings.push(error(
                    "STO007",
                    "Storage manifest version does not match WASM",
                    &format!(
                        "The {side} manifest declares contract version `{}`, but its WASM `binver` is `{artifact_version}`.",
                        schema.contract_version
                    ),
                    "Generate and commit the storage manifest from the same source revision and build as the reviewed WASM.",
                ));
            }
        }

        let mut counts = BTreeMap::new();
        for entry in &schema.entries {
            *counts.entry(&entry.key).or_insert(0_u32) += 1;
        }
        for (key, count) in counts {
            if count > 1 {
                findings.push(error(
                    "STO008",
                    "Storage manifest contains duplicate keys",
                    &format!(
                        "The {side} manifest declares storage key `{key}` {count} times, making comparison ambiguous."
                    ),
                    "Keep exactly one declaration for each logical storage key.",
                ));
            }
        }
    }

    for entry in &target_schema.entries {
        let Some(migration) = &entry.migration else {
            continue;
        };
        if migration.strategy.trim().is_empty()
            || migration.strategy.len() > 128
            || migration.strategy.chars().any(char::is_control)
        {
            findings.push(error(
                "STO013",
                "Migration strategy is invalid",
                &format!(
                    "Storage key `{}` has an empty, oversized, or invalid migration strategy.",
                    entry.key
                ),
                "Use a short reviewed strategy name without control characters.",
            ));
        }
        let Some(entrypoint) = &migration.entrypoint else {
            findings.push(error(
                "STO014",
                "Migration entrypoint is not declared",
                &format!(
                    "Storage key `{}` has migration data without an entrypoint.",
                    entry.key
                ),
                "Name the exported idempotent migration function in the storage declaration.",
            ));
            continue;
        };
        if !target.has_function(entrypoint) {
            findings.push(error(
                "STO009",
                "Declared migration entrypoint is missing",
                &format!(
                    "Storage key `{}` declares migration entrypoint `{entrypoint}`, but the target WASM specification does not export it.",
                    entry.key
                ),
                "Export the declared migration function or correct the manifest and rehearse the selected strategy.",
            ));
        }
    }
}

fn validate_schema_history(
    source: &Artifact,
    target: &Artifact,
    history: &SchemaHistory,
    findings: &mut Vec<Finding>,
) {
    if history.format_version != 1 {
        findings.push(error(
            "HIS001",
            "Unsupported schema-history format",
            &format!(
                "The history manifest uses format version {}. This build supports version 1.",
                history.format_version
            ),
            "Regenerate the history manifest with a supported format before relying on it.",
        ));
        return;
    }
    if !history.complete {
        findings.push(error(
            "HIS012",
            "Schema history is not marked complete",
            "The history does not declare complete coverage of all known releases and fields.",
            "Set `complete` to true only after you reconstruct and review the full release history.",
        ));
    }

    for (type_name, type_history) in &history.types {
        for (field_name, record) in &type_history.fields {
            let first_seen = Version::parse(&record.first_seen);
            let retired_in = record.retired_in.as_deref().map(Version::parse).transpose();
            if first_seen.is_err() || retired_in.is_err() {
                findings.push(error(
                    "HIS013",
                    "History contains an invalid semantic version",
                    &format!(
                        "History for `{type_name}.{field_name}` has an invalid `firstSeen` or `retiredIn` value."
                    ),
                    "Use exact semantic versions from released `binver` metadata.",
                ));
                continue;
            }
            if let (Ok(first_seen), Ok(Some(retired_in))) = (first_seen, retired_in) {
                if retired_in < first_seen {
                    findings.push(error(
                        "HIS014",
                        "Field retirement precedes its first release",
                        &format!(
                            "History retires `{type_name}.{field_name}` in {retired_in}, before its first release {first_seen}."
                        ),
                        "Correct the release versions from attested historical artifacts.",
                    ));
                }
                if !type_history.reserved_fields.contains(field_name) {
                    findings.push(error(
                        "HIS015",
                        "Retired field name is not reserved",
                        &format!(
                            "History retires `{type_name}.{field_name}` but does not reserve the field name."
                        ),
                        "Add every retired field name to `reservedFields` and never reuse it.",
                    ));
                }
            }
        }
        for field_name in &type_history.reserved_fields {
            if type_history
                .fields
                .get(field_name)
                .is_none_or(|record| record.retired_in.is_none())
            {
                findings.push(error(
                    "HIS016",
                    "Reserved field has no retirement record",
                    &format!(
                        "History reserves `{type_name}.{field_name}` without a matching retired field record."
                    ),
                    "Record the historical type and retirement release for each reserved field name.",
                ));
            }
        }
    }

    let source_version = source.version().unwrap_or("unknown");
    let target_version = target.version().unwrap_or("unknown");
    let source_types = artifact_struct_fields(source);
    let target_types = artifact_struct_fields(target);

    for (type_name, fields) in &source_types {
        for (field_name, field_type) in fields {
            let Some(record) = history
                .types
                .get(type_name)
                .and_then(|type_history| type_history.fields.get(field_name))
            else {
                findings.push(error(
                    "HIS002",
                    "Historical baseline is incomplete",
                    &format!(
                        "Source {source_version} contains `{type_name}.{field_name}`, but the cumulative history has no record of it."
                    ),
                    "Bootstrap the manifest from all known releases and preserve every historical field before approving an upgrade.",
                ));
                continue;
            };
            if record.value_type != *field_type {
                findings.push(error(
                    "HIS003",
                    "Historical field type does not match the source artifact",
                    &format!(
                        "History records `{type_name}.{field_name}` as {}, but source {source_version} contains {}.",
                        display_json(&record.value_type),
                        display_json(field_type)
                    ),
                    "Correct the history from attested release artifacts. Do not rewrite history to fit the candidate.",
                ));
            }
        }
    }

    for (type_name, fields) in &target_types {
        let Some(type_history) = history.types.get(type_name) else {
            findings.push(error(
                "HIS004",
                "Candidate type is missing from schema history",
                &format!(
                    "Target {target_version} contains struct `{type_name}`, but the cumulative history has no record for the type."
                ),
                "Add the type and every field with accurate `firstSeen` values in the same reviewed release change.",
            ));
            continue;
        };

        for (field_name, field_type) in fields {
            if type_history.reserved_fields.contains(field_name) {
                findings.push(error(
                    "HIS005",
                    "Reserved field name was reused",
                    &format!(
                        "Target {target_version} reintroduces reserved field `{type_name}.{field_name}`, creating a historical type-confusion risk."
                    ),
                    "Choose a new field name and keep the historical name permanently reserved.",
                ));
            }

            let Some(record) = type_history.fields.get(field_name) else {
                findings.push(error(
                    "HIS006",
                    "Candidate field is missing from schema history",
                    &format!(
                        "Target {target_version} contains `{type_name}.{field_name}`, but the cumulative history was not updated."
                    ),
                    "Record the field type and set `firstSeen` to the candidate contract version.",
                ));
                continue;
            };
            if record.retired_in.is_some() {
                findings.push(error(
                    "HIS007",
                    "Retired field was reintroduced",
                    &format!(
                        "Target {target_version} contains `{type_name}.{field_name}`, which history marks retired in {}.",
                        record.retired_in.as_deref().unwrap_or("an earlier release")
                    ),
                    "Use a new field name. Never reinterpret a retired key across stored or cross-contract maps.",
                ));
            }
            if record.value_type != *field_type {
                findings.push(error(
                    "HIS008",
                    "Historical field type changed",
                    &format!(
                        "History fixes `{type_name}.{field_name}` as {}, but target {target_version} contains {}.",
                        display_json(&record.value_type),
                        display_json(field_type)
                    ),
                    "Add a new field and explicit migration rather than changing the meaning or representation of a historical field name.",
                ));
            }
            if !source_types
                .get(type_name)
                .is_some_and(|source_fields| source_fields.contains_key(field_name))
                && record.first_seen != target_version
            {
                findings.push(error(
                    "HIS009",
                    "New field has an incorrect first-seen release",
                    &format!(
                        "`{type_name}.{field_name}` first appears in target {target_version}, but history declares `{}`.",
                        record.first_seen
                    ),
                    "Set `firstSeen` to the exact candidate `binver` and review the history change with the WASM.",
                ));
            }
        }
    }

    for (type_name, source_fields) in &source_types {
        let target_fields = target_types.get(type_name);
        for field_name in source_fields.keys() {
            if target_fields.is_some_and(|fields| fields.contains_key(field_name)) {
                continue;
            }
            let record = history
                .types
                .get(type_name)
                .and_then(|type_history| type_history.fields.get(field_name));
            let reserved = history
                .types
                .get(type_name)
                .is_some_and(|type_history| type_history.reserved_fields.contains(field_name));
            if record.is_none_or(|record| record.retired_in.as_deref() != Some(target_version))
                || !reserved
            {
                findings.push(error(
                    "HIS010",
                    "Removed field is not retired and reserved",
                    &format!(
                        "Target {target_version} removes `{type_name}.{field_name}` without recording retirement in this release and permanently reserving the name."
                    ),
                    "Keep the field, or record `retiredIn` and add it to `reservedFields`. Prove all migration and reader compatibility assumptions separately.",
                ));
            } else {
                findings.push(warning(
                    "HIS011",
                    "Field removal is explicitly retired but remains migration-sensitive",
                    &format!(
                        "`{type_name}.{field_name}` is retired and reserved in {target_version}. Archived records or older contracts can still carry it."
                    ),
                    "Rehearse archived-state reads and dependency rollout, and never reuse the field name.",
                ));
            }
        }
    }
}

fn artifact_struct_fields(
    artifact: &Artifact,
) -> BTreeMap<String, BTreeMap<String, serde_json::Value>> {
    artifact
        .user_types
        .iter()
        .filter_map(|(name, entry)| struct_fields(entry).map(|fields| (name.clone(), fields)))
        .collect()
}

fn display_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<invalid type>".into())
}

fn check_versions(
    source: &Artifact,
    target: &Artifact,
    policy: &Policy,
    findings: &mut Vec<Finding>,
) {
    if !policy.require_semver_increase {
        return;
    }
    let (Some(from), Some(to)) = (source.version(), target.version()) else {
        findings.push(error(
            "VER001",
            "Missing SEP-49 `binver` metadata",
            "Both source and target WASM must embed a semantic version under the `binver` contract metadata key.",
            "Build with `stellar contract build --meta binver=<semver>` for both artifacts.",
        ));
        return;
    };
    match (Version::parse(from), Version::parse(to)) {
        (Ok(from), Ok(to)) if to > from => {}
        (Ok(from), Ok(to)) => findings.push(error(
            "VER002",
            "Target version does not increase",
            &format!("Target `binver` {to} must be greater than source `binver` {from}."),
            "Use a higher semantic version matching the compatibility impact of the release.",
        )),
        _ => findings.push(error(
            "VER003",
            "Invalid semantic version metadata",
            &format!("Could not compare source `{from}` with target `{to}` as semantic versions."),
            "Use valid SemVer values such as `1.2.0`.",
        )),
    }
}

fn compare_interfaces(
    source: &Artifact,
    target: &Artifact,
    policy: &Policy,
    context: &ValidationContext,
    findings: &mut Vec<Finding>,
) {
    for (name, old) in &source.functions {
        match target.functions.get(name) {
            None if policy.deny_removed_functions => findings.push(error(
                "ABI001",
                "Public function removed",
                &format!("The target contract removes `{name}` from the public specification."),
                "Preserve the function, introduce a compatibility shim, or document and explicitly approve the breaking change.",
            )),
            Some(new) if policy.deny_changed_functions && old.canonical != new.canonical => {
                findings.push(error(
                    "ABI002",
                    "Public function signature changed",
                    &format!("The inputs, output, or specification of `{name}` changed."),
                    "Add a new entrypoint and keep the old signature until downstream clients have migrated.",
                ));
            }
            _ => {}
        }
    }

    for (name, old) in &source.events {
        match target.events.get(name) {
            None if policy.deny_removed_events => findings.push(error(
                "EVT001",
                "Contract event was removed",
                &format!("The target contract removes event `{name}` from the public specification."),
                "Keep the event schema or complete a reviewed indexer migration before the release.",
            )),
            Some(new) if policy.deny_changed_events && old.canonical != new.canonical => {
                findings.push(error(
                    "EVT002",
                    "Contract event schema changed",
                    &format!("The topics, parameters, types, or data format of event `{name}` changed."),
                    "Add a new event name and keep the old schema for existing consumers.",
                ));
            }
            _ => {}
        }
    }

    for (name, old) in &source.user_types {
        match target.user_types.get(name) {
            None if policy.deny_changed_user_types => findings.push(error(
                "ABI003",
                "Contract Spec type removed",
                &format!(
                    "The target contract removes the `{name}` {} definition. Contract Spec alone does not identify every public, stored, or cross-contract use of this type.",
                    old.kind
                ),
                "Preserve the type or prove every relevant public, storage, and cross-contract migration path before approving removal.",
            )),
            Some(new) if policy.deny_changed_user_types && old.canonical != new.canonical => {
                match optional_struct_fields_added(old, new) {
                    Some(added)
                        if context.target_protocol_version.unwrap_or_default()
                            >= CAP_0086_PROTOCOL
                            && target.uses_cap_0086_sparse_read() =>
                    {
                        findings.push(error(
                            "CAP005",
                            "CAP-0086 reader binding is not proven for the changed type",
                            &format!(
                                "The `{name}` struct adds only optional field(s): {}. Protocol support and a global sparse-read import are present, but the artifact does not prove that this specific type is decoded through that reader.",
                                added.join(", ")
                            ),
                            "Provide generated type-to-reader evidence and test old/new reader-writer directions against historical state before approving the change.",
                        ));
                    }
                    Some(added) => findings.push(error(
                        "CAP006",
                        "Optional field addition is not supported by the selected artifact and protocol",
                        &format!(
                            "The `{name}` struct adds optional field(s) {}, but compatibility requires both protocol 28+ and a candidate that imports CAP-0086 sparse decoding.",
                            added.join(", ")
                        ),
                        "Use explicit versioned migration today, or rebuild with CAP-0086 support after activation and re-run validation against the target protocol.",
                    )),
                    None => findings.push(error(
                        "ABI004",
                        "Contract Spec type changed",
                        &format!(
                            "The `{name}` {} definition changed in a way this policy does not classify as compatible. Contract Spec alone does not prove the type's runtime role.",
                            old.kind
                        ),
                        "Introduce a versioned type and migration path instead of mutating the existing definition in place.",
                    )),
                }
            }
            _ => {}
        }
    }
}

fn optional_struct_fields_added(old: &InterfaceEntry, new: &InterfaceEntry) -> Option<Vec<String>> {
    if old.kind != "struct" || new.kind != "struct" {
        return None;
    }
    let old_fields = struct_fields(old)?;
    let new_fields = struct_fields(new)?;
    if new_fields.len() <= old_fields.len()
        || old_fields
            .iter()
            .any(|(name, old_type)| new_fields.get(name) != Some(old_type))
    {
        return None;
    }

    let added = new_fields
        .iter()
        .filter(|(name, _)| !old_fields.contains_key(*name))
        .map(|(name, field_type)| is_option_type(field_type).then_some(name.clone()))
        .collect::<Option<Vec<_>>>()?;
    (!added.is_empty()).then_some(added)
}

fn struct_fields(entry: &InterfaceEntry) -> Option<BTreeMap<String, serde_json::Value>> {
    entry
        .canonical
        .pointer("/udt_struct_v0/fields")?
        .as_array()?
        .iter()
        .map(|field| {
            Some((
                field.get("name")?.as_str()?.to_owned(),
                field.get("type_")?.clone(),
            ))
        })
        .collect()
}

fn is_option_type(value: &serde_json::Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("option"))
}

fn compare_storage_schemas(
    source: &StorageSchema,
    target: &StorageSchema,
    findings: &mut Vec<Finding>,
) {
    let old: BTreeMap<_, _> = source.entries.iter().map(|e| (&e.key, e)).collect();
    let new: BTreeMap<_, _> = target.entries.iter().map(|e| (&e.key, e)).collect();
    let mut layout_changed = false;

    for (key, old_entry) in old {
        match new.get(key) {
            None => {
                layout_changed = true;
                findings.push(error(
                    "STO001",
                    "Storage key removed without a retirement plan",
                    &format!("Storage key `{key}` is absent from the target schema."),
                    "Keep the key readable through the migration window or declare and test a versioned retirement strategy.",
                ));
            }
            Some(new_entry)
                if old_entry.durability != new_entry.durability
                    || old_entry.value_type != new_entry.value_type =>
            {
                layout_changed = true;
                if let Some(migration) = &new_entry.migration {
                    findings.push(warning(
                        "STO002",
                        "Storage layout change requires migration",
                        &format!(
                            "Storage key `{key}` changes from `{:?}/{}` to `{:?}/{}` and declares `{}` migration.",
                            old_entry.durability,
                            old_entry.value_type,
                            new_entry.durability,
                            new_entry.value_type,
                            migration.strategy
                        ),
                        "Exercise the migration against a representative pre-upgrade ledger snapshot and verify idempotency.",
                    ));
                } else {
                    findings.push(error(
                        "STO003",
                        "Storage layout changes without migration",
                        &format!(
                            "Storage key `{key}` changes from `{:?}/{}` to `{:?}/{}` with no migration declaration.",
                            old_entry.durability,
                            old_entry.value_type,
                            new_entry.durability,
                            new_entry.value_type
                        ),
                        "Declare an eager, lazy, or versioned migration and test it before generating a signer review plan.",
                    ));
                }
            }
            _ => {}
        }
    }

    if layout_changed && target.schema_version <= source.schema_version {
        findings.push(error(
            "STO005",
            "Schema version was not incremented",
            &format!(
                "Storage changed but target schema version {} is not greater than source schema version {}.",
                target.schema_version, source.schema_version
            ),
            "Increment `schemaVersion` and guard migration execution with the on-chain schema version.",
        ));
    }
}

fn error(code: &str, title: &str, detail: &str, remediation: &str) -> Finding {
    Finding {
        code: code.into(),
        severity: Severity::Error,
        title: title.into(),
        detail: detail.into(),
        remediation: remediation.into(),
    }
}

fn warning(code: &str, title: &str, detail: &str, remediation: &str) -> Finding {
    Finding {
        code: code.into(),
        severity: Severity::Warning,
        title: title.into(),
        detail: detail.into(),
        remediation: remediation.into(),
    }
}

fn info(code: &str, title: &str, detail: &str, remediation: &str) -> Finding {
    Finding {
        code: code.into(),
        severity: Severity::Info,
        title: title.into(),
        detail: detail.into(),
        remediation: remediation.into(),
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStepKind {
    VerifyCurrentExecutable,
    UploadTargetWasm,
    SimulateUpgrade,
    ExecuteUpgrade,
    ExecuteMigration,
    VerifyExecutable,
    VerifyInvariants,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStatus {
    OfflineDraft,
    ReviewReady,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub position: u32,
    pub kind: PlanStepKind,
    pub program: String,
    pub arguments: Vec<String>,
    pub command: String,
    pub expected: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MigrationCall {
    pub entrypoint: String,
    pub arguments: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InvariantCheck {
    pub program: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanOperations {
    pub migration: Option<MigrationCall>,
    pub invariant_check: InvariantCheck,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanInputPaths {
    pub source_wasm: String,
    pub target_wasm: String,
    pub source_schema: String,
    pub target_schema: String,
    pub schema_history: String,
    pub policy: Option<String>,
}

impl PlanStep {
    fn new(
        position: u32,
        kind: PlanStepKind,
        program: &str,
        arguments: Vec<String>,
        expected: String,
    ) -> Self {
        let command = render_command(program, &arguments);
        Self {
            position,
            kind,
            program: program.into(),
            arguments,
            command,
            expected,
        }
    }
}

fn render_command(program: &str, arguments: &[String]) -> String {
    std::iter::once(program)
        .chain(arguments.iter().map(String::as_str))
        .map(shell_quote)
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_+-./:=@".contains(character))
    {
        value.into()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpgradePlan {
    pub format_version: u32,
    pub plan_sha256: String,
    pub status: PlanStatus,
    pub network: String,
    pub contract_id: String,
    pub source_identity: String,
    pub inputs: PlanInputPaths,
    pub source_wasm_sha256: String,
    pub target_wasm_sha256: String,
    pub rollback_wasm_sha256: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub migration: Option<MigrationCall>,
    pub invariant_check: InvariantCheck,
    pub validation: ValidationReport,
    pub steps: Vec<PlanStep>,
}

impl UpgradePlan {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        parse_json_strict(bytes)
    }
}

pub fn create_plan(
    report: ValidationReport,
    network: &str,
    contract_id: &str,
    source_identity: &str,
    target_wasm_path: &str,
    migration_entrypoint: Option<&str>,
) -> Result<UpgradePlan, Error> {
    let migration = migration_entrypoint.map(|entrypoint| MigrationCall {
        entrypoint: entrypoint.into(),
        arguments: BTreeMap::from([("operator".into(), source_identity.into())]),
    });
    create_plan_with_paths(
        report,
        network,
        contract_id,
        source_identity,
        PlanInputPaths {
            source_wasm: "source.wasm".into(),
            target_wasm: target_wasm_path.into(),
            source_schema: "source.schema.json".into(),
            target_schema: "target.schema.json".into(),
            schema_history: "schema-history.json".into(),
            policy: None,
        },
        PlanOperations {
            migration,
            invariant_check: InvariantCheck {
                program: "cargo".into(),
                arguments: strings(&["test", "--workspace"]),
            },
        },
    )
}

pub fn create_plan_with_paths(
    report: ValidationReport,
    network: &str,
    contract_id: &str,
    source_identity: &str,
    inputs: PlanInputPaths,
    operations: PlanOperations,
) -> Result<UpgradePlan, Error> {
    let PlanOperations {
        migration,
        invariant_check,
    } = operations;
    validate_plan_input_paths(&inputs)?;
    validate_plan_string("network", network, 256)?;
    if stellar_strkey::Contract::from_string(contract_id).is_err() {
        return Err(Error::InvalidContractId(contract_id.into()));
    }

    if !report.safe
        || report
            .findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    {
        return Err(Error::Plan(
            "validation report contains release-blocking findings".into(),
        ));
    }

    if report.context.target_protocol_version.is_none()
        || report.context.protocol_source == ProtocolSource::Unpinned
    {
        return Err(Error::Plan(
            "target protocol and its evidence source are not pinned in the validation report"
                .into(),
        ));
    }
    match report.context.network_name.as_deref() {
        Some(evidence_network) if evidence_network == network => {}
        Some(evidence_network) => {
            return Err(Error::Plan(format!(
                "plan network `{network}` does not match protocol evidence for `{evidence_network}`"
            )));
        }
        None => {
            return Err(Error::Plan(
                "protocol evidence is not bound to the plan network".into(),
            ));
        }
    }
    if !report.storage_schema_checked {
        return Err(Error::Plan(
            "storage schemas were not checked in the validation report".into(),
        ));
    }
    if !report.schema_history_checked || report.schema_history_sha256.is_none() {
        return Err(Error::Plan(
            "cumulative schema history was not checked in the validation report".into(),
        ));
    }

    validate_source_identity(source_identity)?;

    let storage_migration_required = report
        .findings
        .iter()
        .any(|finding| finding.code == "STO002");
    if storage_migration_required && migration.is_none() {
        return Err(Error::Plan(
            "storage layout changed but no migration entrypoint was selected".into(),
        ));
    }
    if storage_migration_required {
        let declared = report
            .target_schema
            .as_ref()
            .into_iter()
            .flat_map(|schema| &schema.entries)
            .filter_map(|entry| entry.migration.as_ref()?.entrypoint.as_ref())
            .cloned()
            .collect::<BTreeSet<_>>();
        let selected = migration
            .as_ref()
            .map(|call| BTreeSet::from([call.entrypoint.clone()]))
            .unwrap_or_default();
        if declared != selected {
            return Err(Error::Plan(format!(
                "selected migration [{}] does not match declared entrypoints [{}]",
                selected.into_iter().collect::<Vec<_>>().join(", "),
                declared.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
    }

    validate_standard_upgrade_entrypoint(&report.source)?;
    validate_standard_upgrade_entrypoint(&report.target)?;

    if let Some(migration) = &migration {
        validate_call_arguments(
            &report.target,
            &migration.entrypoint,
            &migration.arguments,
            "migration",
        )?;
    }
    validate_invariant_check(&invariant_check)?;

    let source_hash = report.source.sha256.clone();
    let target_hash = report.target.sha256.clone();
    let mut steps = vec![
        PlanStep::new(
            1,
            PlanStepKind::VerifyCurrentExecutable,
            "stellar",
            strings(&[
                "contract",
                "fetch",
                "--id",
                contract_id,
                "--network",
                network,
                "--out-file",
                "current.wasm",
            ]),
            format!("Fetched WASM SHA-256 equals {source_hash}"),
        ),
        PlanStep::new(
            2,
            PlanStepKind::UploadTargetWasm,
            "stellar",
            strings(&[
                "contract",
                "upload",
                "--wasm",
                &inputs.target_wasm,
                "--optimize=false",
                "--source-account",
                source_identity,
                "--network",
                network,
            ]),
            format!("WASM hash {target_hash}"),
        ),
        PlanStep::new(
            3,
            PlanStepKind::SimulateUpgrade,
            "stellar",
            strings(&[
                "contract",
                "invoke",
                "--id",
                contract_id,
                "--source-account",
                source_identity,
                "--network",
                network,
                "--send",
                "no",
                "--",
                "upgrade",
                "--new_wasm_hash",
                &target_hash,
                "--operator",
                source_identity,
            ]),
            "Successful simulation with expected authorization and resource footprint".into(),
        ),
        PlanStep::new(
            4,
            PlanStepKind::ExecuteUpgrade,
            "stellar",
            strings(&[
                "contract",
                "invoke",
                "--id",
                contract_id,
                "--source-account",
                source_identity,
                "--network",
                network,
                "--",
                "upgrade",
                "--new_wasm_hash",
                &target_hash,
                "--operator",
                source_identity,
            ]),
            "Successful executable_update system event".into(),
        ),
    ];

    if let Some(migration) = &migration {
        let mut migration_arguments = strings(&[
            "contract",
            "invoke",
            "--id",
            contract_id,
            "--source-account",
            source_identity,
            "--network",
            network,
            "--",
            &migration.entrypoint,
        ]);
        for (name, value) in &migration.arguments {
            migration_arguments.push(format!("--{name}"));
            migration_arguments.push(value.clone());
        }
        steps.push(PlanStep::new(
            5,
            PlanStepKind::ExecuteMigration,
            "stellar",
            migration_arguments,
            "Migration succeeds once and records the new schema version".into(),
        ));
    }
    let next = steps.len() as u32 + 1;
    steps.push(PlanStep::new(
        next,
        PlanStepKind::VerifyExecutable,
        "stellar",
        strings(&[
            "contract",
            "fetch",
            "--id",
            contract_id,
            "--network",
            network,
            "--out-file",
            "deployed.wasm",
        ]),
        format!("Fetched WASM SHA-256 equals {target_hash}"),
    ));
    steps.push(PlanStep::new(
        next + 1,
        PlanStepKind::VerifyInvariants,
        &invariant_check.program,
        invariant_check.arguments.clone(),
        "The application-specific post-upgrade invariants pass".into(),
    ));

    let mut plan = UpgradePlan {
        format_version: 3,
        plan_sha256: String::new(),
        status: if report.context.protocol_source == ProtocolSource::StellarCliNetworkInfo {
            PlanStatus::ReviewReady
        } else {
            PlanStatus::OfflineDraft
        },
        network: network.into(),
        contract_id: contract_id.into(),
        source_identity: source_identity.into(),
        inputs,
        source_wasm_sha256: report.source.sha256.clone(),
        target_wasm_sha256: report.target.sha256.clone(),
        rollback_wasm_sha256: report.source.sha256.clone(),
        from_version: report.source.version().map(str::to_owned),
        to_version: report.target.version().map(str::to_owned),
        migration,
        invariant_check,
        validation: report,
        steps,
    };
    let encoded = serde_json::to_string(&plan)?;
    if contains_stellar_private_key(&encoded) {
        return Err(Error::Plan(
            "plan evidence must not contain a Stellar private key".into(),
        ));
    }
    plan.plan_sha256 = calculate_plan_sha256(&plan)?;
    Ok(plan)
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn calculate_plan_sha256(plan: &UpgradePlan) -> Result<String, Error> {
    let mut canonical = serde_json::to_value(plan)?;
    let Some(object) = canonical.as_object_mut() else {
        return Err(Error::Plan("serialized plan is not a JSON object".into()));
    };
    object.remove("planSha256");
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn verify_plan_digest(plan: &UpgradePlan) -> Result<bool, Error> {
    validate_plan_structure(plan)?;
    Ok(plan.plan_sha256 == calculate_plan_sha256(plan)?)
}

fn validate_plan_structure(plan: &UpgradePlan) -> Result<(), Error> {
    if plan.format_version != 3 {
        return Err(Error::Plan(format!(
            "unsupported plan format version {}. This build supports version 3",
            plan.format_version
        )));
    }

    let revalidated = validate_with_history(
        &plan.validation.source,
        &plan.validation.target,
        plan.validation.source_schema.as_ref(),
        plan.validation.target_schema.as_ref(),
        &plan.validation.policy,
        &plan.validation.context,
        plan.validation.schema_history.as_ref(),
    );
    if revalidated != plan.validation {
        return Err(Error::Plan(
            "embedded validation report does not match a fresh validation of its evidence".into(),
        ));
    }

    let upload_steps = plan
        .steps
        .iter()
        .filter(|step| step.kind == PlanStepKind::UploadTargetWasm)
        .collect::<Vec<_>>();
    if upload_steps.len() != 1 {
        return Err(Error::Plan(
            "plan must contain exactly one target-WASM upload step".into(),
        ));
    }
    let target_wasm_path = argument_after(&upload_steps[0].arguments, "--wasm")
        .ok_or_else(|| Error::Plan("upload step has no `--wasm` argument".into()))?;
    if target_wasm_path != plan.inputs.target_wasm {
        return Err(Error::Plan(
            "upload step target does not match the plan input path".into(),
        ));
    }

    let migration_steps = plan
        .steps
        .iter()
        .filter(|step| step.kind == PlanStepKind::ExecuteMigration)
        .collect::<Vec<_>>();
    if migration_steps.len() > 1 {
        return Err(Error::Plan(
            "plan contains more than one migration step".into(),
        ));
    }
    if migration_steps.len() != usize::from(plan.migration.is_some()) {
        return Err(Error::Plan(
            "migration metadata and migration steps do not match".into(),
        ));
    }

    let mut expected = create_plan_with_paths(
        plan.validation.clone(),
        &plan.network,
        &plan.contract_id,
        &plan.source_identity,
        plan.inputs.clone(),
        PlanOperations {
            migration: plan.migration.clone(),
            invariant_check: plan.invariant_check.clone(),
        },
    )?;
    let mut observed = plan.clone();
    expected.plan_sha256.clear();
    observed.plan_sha256.clear();
    if observed != expected {
        return Err(Error::Plan(
            "plan fields or commands do not match the canonical validation-derived plan".into(),
        ));
    }
    Ok(())
}

fn validate_invariant_check(check: &InvariantCheck) -> Result<(), Error> {
    if check.program.is_empty()
        || check.program.len() > 256
        || check
            .program
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::Plan(
            "invariant program must be a non-empty command name without whitespace".into(),
        ));
    }
    if contains_stellar_private_key(&check.program) {
        return Err(Error::Plan(
            "invariant program must not contain a private key".into(),
        ));
    }
    for argument in &check.arguments {
        if argument.len() > 4_096 || argument.chars().any(char::is_control) {
            return Err(Error::Plan(
                "invariant arguments must not contain control characters or exceed 4096 bytes"
                    .into(),
            ));
        }
        if contains_stellar_private_key(argument) {
            return Err(Error::Plan(
                "invariant arguments must not contain private keys".into(),
            ));
        }
    }
    Ok(())
}

fn validate_plan_input_paths(paths: &PlanInputPaths) -> Result<(), Error> {
    let required = [
        ("source WASM", paths.source_wasm.as_str()),
        ("target WASM", paths.target_wasm.as_str()),
        ("source schema", paths.source_schema.as_str()),
        ("target schema", paths.target_schema.as_str()),
        ("schema history", paths.schema_history.as_str()),
    ];
    for (label, path) in required {
        validate_plan_string(&format!("{label} path"), path, 4_096)?;
    }
    if let Some(path) = &paths.policy {
        validate_plan_string("policy path", path, 4_096)?;
    }
    Ok(())
}

fn validate_plan_string(label: &str, value: &str, maximum_bytes: usize) -> Result<(), Error> {
    if value.is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control) {
        return Err(Error::Plan(format!(
            "{label} must be non-empty, contain no control characters, and stay within {maximum_bytes} bytes"
        )));
    }
    if contains_stellar_private_key(value) {
        return Err(Error::Plan(format!(
            "{label} must not contain a Stellar private key"
        )));
    }
    Ok(())
}

const STELLAR_SECRET_SEED_LENGTH: usize = 56;

fn contains_stellar_private_key(value: &str) -> bool {
    value
        .as_bytes()
        .windows(STELLAR_SECRET_SEED_LENGTH)
        .filter(|candidate| candidate[0] == b'S' && candidate.is_ascii())
        .filter_map(|candidate| std::str::from_utf8(candidate).ok())
        .any(|candidate| {
            matches!(
                stellar_strkey::Strkey::from_string(candidate),
                Ok(stellar_strkey::Strkey::PrivateKeyEd25519(_))
            )
        })
}

fn validate_standard_upgrade_entrypoint(target: &Artifact) -> Result<(), Error> {
    let arguments = BTreeMap::from([
        ("new_wasm_hash".into(), String::new()),
        ("operator".into(), String::new()),
    ]);
    validate_call_arguments(
        target,
        "upgrade",
        &arguments,
        "OpenZeppelin-compatible upgrade",
    )?;
    let inputs = target
        .functions
        .get("upgrade")
        .and_then(|function| function.canonical.pointer("/function_v0/inputs"))
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Plan("cannot read arguments for `upgrade`".into()))?;
    let types = inputs
        .iter()
        .filter_map(|input| Some((input.get("name")?.as_str()?, input.get("type_")?.clone())))
        .collect::<BTreeMap<_, _>>();
    if types.get("new_wasm_hash") != Some(&serde_json::json!({"bytes_n": {"n": 32}}))
        || types.get("operator") != Some(&serde_json::json!("address"))
    {
        return Err(Error::Plan(
            "the `upgrade` entrypoint must use `new_wasm_hash: BytesN<32>` and `operator: Address`"
                .into(),
        ));
    }
    let reaches_update = target
        .export_call_evidence
        .get("upgrade")
        .is_some_and(|evidence| {
            evidence
                .host_imports
                .contains(UPDATE_CURRENT_CONTRACT_WASM_IMPORT)
        });
    if !reaches_update {
        return Err(Error::Plan(
            "the `upgrade` entrypoint must reach Stellar `update_current_contract_wasm`".into(),
        ));
    }
    Ok(())
}

fn validate_call_arguments(
    target: &Artifact,
    entrypoint: &str,
    arguments: &BTreeMap<String, String>,
    call_kind: &str,
) -> Result<(), Error> {
    let function = target.functions.get(entrypoint).ok_or_else(|| {
        Error::Plan(format!(
            "{call_kind} entrypoint `{entrypoint}` is not exported by the target WASM"
        ))
    })?;
    let inputs = function
        .canonical
        .pointer("/function_v0/inputs")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| Error::Plan(format!("cannot read arguments for `{entrypoint}`")))?;
    let expected = inputs
        .iter()
        .map(|input| {
            input
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::Plan(format!("cannot read an argument for `{entrypoint}`")))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let supplied = arguments.keys().cloned().collect::<BTreeSet<_>>();
    if expected != supplied {
        return Err(Error::Plan(format!(
            "{call_kind} entrypoint `{entrypoint}` requires arguments [{}], but the plan supplies [{}]",
            expected.into_iter().collect::<Vec<_>>().join(", "),
            supplied.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    for value in arguments.values() {
        if contains_stellar_private_key(value) {
            return Err(Error::Plan(
                "plan arguments must not contain private keys".into(),
            ));
        }
    }
    Ok(())
}

fn validate_source_identity(source_identity: &str) -> Result<(), Error> {
    if source_identity.is_empty()
        || source_identity.len() > 128
        || source_identity
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(Error::Plan(
            "source identity must be a non-empty Stellar CLI alias or public account without whitespace"
                .into(),
        ));
    }
    if contains_stellar_private_key(source_identity) {
        return Err(Error::Plan(
            "source identity must not contain a private key. Use a Stellar CLI alias or public account"
                .into(),
        ));
    }
    Ok(())
}

fn argument_after<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    let position = arguments.iter().position(|argument| argument == flag)?;
    arguments.get(position + 1).map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONTRACT_ID: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";

    fn artifact(version: &str, functions: &[&str]) -> Artifact {
        Artifact {
            format_version: 1,
            sha256: "00".repeat(32),
            size_bytes: 1,
            env_protocol_version: 27,
            env_pre_release: 0,
            metadata: BTreeMap::from([("binver".into(), version.into())]),
            host_imports: BTreeSet::new(),
            functions: functions
                .iter()
                .map(|name| {
                    (
                        (*name).into(),
                        InterfaceEntry {
                            kind: "function".into(),
                            name: (*name).into(),
                            canonical: match *name {
                                "upgrade" => serde_json::json!({
                                    "function_v0": {
                                        "name": "upgrade",
                                        "inputs": [
                                            {"name": "new_wasm_hash", "type_": {"bytes_n": {"n": 32}}},
                                            {"name": "operator", "type_": "address"}
                                        ],
                                        "outputs": []
                                    }
                                }),
                                "migrate" => serde_json::json!({
                                    "function_v0": {
                                        "name": "migrate",
                                        "inputs": [{"name": "operator", "type_": "address"}],
                                        "outputs": []
                                    }
                                }),
                                _ => serde_json::json!({}),
                            },
                        },
                    )
                })
                .collect(),
            events: BTreeMap::new(),
            user_types: BTreeMap::new(),
            public_type_boundaries: Vec::new(),
            type_references: Vec::new(),
            export_call_evidence: functions
                .iter()
                .map(|name| {
                    let host_imports = if *name == "upgrade" {
                        BTreeSet::from([UPDATE_CURRENT_CONTRACT_WASM_IMPORT.into()])
                    } else {
                        BTreeSet::new()
                    };
                    (
                        (*name).into(),
                        ExportCallEvidence {
                            host_imports,
                            dynamic_dispatch_reachable: false,
                        },
                    )
                })
                .collect(),
        }
    }

    fn schema(version: u32, value_type: &str, migration: Option<Migration>) -> StorageSchema {
        StorageSchema {
            format_version: 1,
            complete: true,
            schema_version: version,
            contract_version: format!("{version}.0.0"),
            entries: vec![StorageEntry {
                key: "Config".into(),
                durability: Durability::Instance,
                value_type: value_type.into(),
                migration,
            }],
        }
    }

    fn safe_report() -> ValidationReport {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::OfflineAssertion,
            network_name: Some("testnet".into()),
            ..ValidationContext::default()
        };
        let history = SchemaHistory {
            format_version: 1,
            complete: true,
            types: BTreeMap::new(),
            source_sha256: "11".repeat(32),
        };
        validate_with_history(
            &artifact("1.0.0", &["upgrade"]),
            &artifact("2.0.0", &["upgrade", "migrate"]),
            Some(&schema(1, "u32", None)),
            Some(&schema(2, "u32", None)),
            &Policy::default(),
            &context,
            Some(&history),
        )
    }

    fn struct_entry(name: &str, fields: &[(&str, serde_json::Value)]) -> InterfaceEntry {
        InterfaceEntry {
            kind: "struct".into(),
            name: name.into(),
            canonical: serde_json::json!({
                "udt_struct_v0": {
                    "name": name,
                    "lib": "",
                    "fields": fields
                        .iter()
                        .map(|(field_name, field_type)| serde_json::json!({
                            "name": field_name,
                            "type_": field_type,
                        }))
                        .collect::<Vec<_>>()
                }
            }),
        }
    }

    #[test]
    fn storage_change_without_migration_is_an_error() {
        let mut findings = Vec::new();
        compare_storage_schemas(
            &schema(1, "ConfigV1", None),
            &schema(2, "ConfigV2", None),
            &mut findings,
        );
        assert!(findings.iter().any(|f| f.code == "STO003"));
    }

    #[test]
    fn acknowledged_storage_change_is_a_warning() {
        let migration = Migration {
            strategy: "eager".into(),
            entrypoint: Some("migrate".into()),
            notes: None,
        };
        let mut findings = Vec::new();
        compare_storage_schemas(
            &schema(1, "ConfigV1", None),
            &schema(2, "ConfigV2", Some(migration)),
            &mut findings,
        );
        assert!(findings.iter().any(|f| f.code == "STO002"));
        assert!(!findings.iter().any(|f| f.severity == Severity::Error));
    }

    #[test]
    fn documentation_is_not_part_of_the_abi_comparison() {
        let mut value = serde_json::json!({
            "function_v0": {
                "doc": "function docs",
                "inputs": [{"doc": "argument docs", "name": "value", "type_": "u32"}]
            }
        });
        strip_documentation(&mut value);
        assert_eq!(
            value,
            serde_json::json!({
                "function_v0": {
                    "inputs": [{"name": "value", "type_": "u32"}]
                }
            })
        );
    }

    #[test]
    fn manifest_must_match_wasm_and_export_migration() {
        let source = artifact("1.0.0", &["upgrade"]);
        let target = artifact("2.0.0", &["upgrade"]);
        let mut target_schema = schema(
            2,
            "ConfigV2",
            Some(Migration {
                strategy: "eager".into(),
                entrypoint: Some("migrate".into()),
                notes: None,
            }),
        );
        target_schema.contract_version = "2.0.1".into();
        let mut findings = Vec::new();
        validate_schema_manifests(
            &source,
            &target,
            &schema(1, "ConfigV1", None),
            &target_schema,
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "STO007"));
        assert!(findings.iter().any(|finding| finding.code == "STO009"));
    }

    #[test]
    fn migration_declaration_requires_a_strategy_and_entrypoint() {
        let source = artifact("1.0.0", &["upgrade"]);
        let target = artifact("2.0.0", &["upgrade"]);
        let target_schema = schema(
            2,
            "ConfigV2",
            Some(Migration {
                strategy: " ".into(),
                entrypoint: None,
                notes: None,
            }),
        );
        let mut findings = Vec::new();
        validate_schema_manifests(
            &source,
            &target,
            &schema(1, "ConfigV1", None),
            &target_schema,
            &mut findings,
        );

        assert!(findings.iter().any(|finding| finding.code == "STO013"));
        assert!(findings.iter().any(|finding| finding.code == "STO014"));
    }

    #[test]
    fn history_versions_and_reservations_are_consistent() {
        let history = SchemaHistory {
            format_version: 1,
            complete: true,
            types: BTreeMap::from([(
                "OldType".into(),
                TypeHistory {
                    fields: BTreeMap::from([
                        (
                            "invalid".into(),
                            HistoricalField {
                                value_type: serde_json::json!("u32"),
                                first_seen: "not-semver".into(),
                                retired_in: None,
                            },
                        ),
                        (
                            "late".into(),
                            HistoricalField {
                                value_type: serde_json::json!("u32"),
                                first_seen: "2.0.0".into(),
                                retired_in: Some("1.0.0".into()),
                            },
                        ),
                    ]),
                    reserved_fields: BTreeSet::from(["unknown".into()]),
                },
            )]),
            source_sha256: "00".repeat(32),
        };
        let mut findings = Vec::new();
        validate_schema_history(
            &artifact("1.0.0", &["upgrade"]),
            &artifact("2.0.0", &["upgrade"]),
            &history,
            &mut findings,
        );

        for code in ["HIS013", "HIS014", "HIS015", "HIS016"] {
            assert!(findings.iter().any(|finding| finding.code == code));
        }
    }

    #[test]
    fn event_removal_and_schema_change_are_blocked() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        source.events.insert(
            "transfer".into(),
            InterfaceEntry {
                kind: "event".into(),
                name: "transfer".into(),
                canonical: serde_json::json!({"params": ["from", "to"]}),
            },
        );
        let mut changed = artifact("2.0.0", &["upgrade"]);
        changed.events.insert(
            "transfer".into(),
            InterfaceEntry {
                kind: "event".into(),
                name: "transfer".into(),
                canonical: serde_json::json!({"params": ["from", "to", "amount"]}),
            },
        );
        let mut findings = Vec::new();
        compare_interfaces(
            &source,
            &changed,
            &Policy::default(),
            &ValidationContext::default(),
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "EVT002"));

        findings.clear();
        compare_interfaces(
            &source,
            &artifact("2.0.0", &["upgrade"]),
            &Policy::default(),
            &ValidationContext::default(),
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "EVT001"));
    }

    #[test]
    fn duplicate_spec_members_are_rejected() {
        assert!(matches!(
            ensure_unique_spec_members("function", "transfer", ["to".to_owned(), "to".to_owned()],),
            Err(Error::DuplicateSpecMember { .. })
        ));
    }

    #[test]
    fn plan_digest_detects_any_mutation() {
        let mut plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        assert!(verify_plan_digest(&plan).unwrap());

        plan.plan_sha256 = "ff".repeat(32);
        assert!(!verify_plan_digest(&plan).unwrap());
    }

    #[test]
    fn plan_verification_rejects_recomputed_digest_for_noncanonical_command() {
        let mut plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        plan.steps[0].command = "stellar contract upload --wasm substituted.wasm".into();
        plan.plan_sha256 = calculate_plan_sha256(&plan).unwrap();

        assert!(matches!(
            verify_plan_digest(&plan),
            Err(Error::Plan(message)) if message.contains("canonical")
        ));
    }

    #[test]
    fn plan_verification_rejects_recomputed_digest_for_hash_mismatch() {
        let mut plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        plan.target_wasm_sha256 = "ff".repeat(32);
        plan.plan_sha256 = calculate_plan_sha256(&plan).unwrap();

        assert!(matches!(verify_plan_digest(&plan), Err(Error::Plan(_))));
    }

    #[test]
    fn plan_verification_rejects_a_forged_embedded_report() {
        let mut plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        plan.validation.safe = false;
        plan.plan_sha256 = calculate_plan_sha256(&plan).unwrap();

        assert!(matches!(
            verify_plan_digest(&plan),
            Err(Error::Plan(message)) if message.contains("fresh validation")
        ));
    }

    #[test]
    fn plan_rejects_invalid_contract_id() {
        assert!(matches!(
            create_plan(
                safe_report(),
                "testnet",
                "C-not-a-contract",
                "deployer",
                "target.wasm",
                None,
            ),
            Err(Error::InvalidContractId(_))
        ));
    }

    #[test]
    fn plan_rejects_private_source_identity() {
        let secret = stellar_strkey::ed25519::PrivateKey([7; 32]).to_string();
        assert!(matches!(
            create_plan(
                safe_report(),
                "testnet",
                TEST_CONTRACT_ID,
                &secret,
                "target.wasm",
                None,
            ),
            Err(Error::Plan(message)) if message.contains("private key")
        ));
    }

    #[test]
    fn private_key_scanner_rejects_a_seed_at_every_byte_offset() {
        let secret = stellar_strkey::ed25519::PrivateKey([8; 32]).to_string();
        for offset in 0..128 {
            let value = format!(
                "{}{}{}",
                "x".repeat(offset),
                secret,
                "y".repeat(128 - offset)
            );
            assert!(
                contains_stellar_private_key(&value),
                "missed offset {offset}"
            );
        }
    }

    #[test]
    fn private_key_scanner_handles_unicode_and_near_matches() {
        let secret = stellar_strkey::ed25519::PrivateKey([10; 32]).to_string();
        assert!(contains_stellar_private_key(&format!(
            "blue=🔒{secret}:end"
        )));

        let mut invalid_checksum = secret.into_bytes();
        let last = invalid_checksum.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let invalid_checksum = String::from_utf8(invalid_checksum).unwrap();
        assert!(!contains_stellar_private_key(&invalid_checksum));
        assert!(!contains_stellar_private_key(&"S".repeat(56)));
    }

    #[test]
    fn policy_json_rejects_unknown_fields() {
        let json = br#"{
            "formatVersion": 1,
            "name": "strict",
            "requireUpgradeFuncton": false
        }"#;

        assert!(matches!(Policy::from_json(json), Err(Error::Json(_))));
    }

    #[test]
    fn policy_json_rejects_duplicate_fields() {
        let json = br#"{
            "formatVersion": 1,
            "formatVersion": 1
        }"#;

        assert!(matches!(Policy::from_json(json), Err(Error::Json(_))));
    }

    #[test]
    fn plan_json_rejects_unbound_unknown_fields() {
        let plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        let mut value = serde_json::to_value(plan).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unsignedInstruction".into(), serde_json::json!("approve"));

        assert!(matches!(
            UpgradePlan::from_json(&serde_json::to_vec(&value).unwrap()),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn plan_json_rejects_duplicate_digest_fields() {
        let plan = create_plan(
            safe_report(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .unwrap();
        let encoded = serde_json::to_string(&plan).unwrap();
        let duplicate = format!(
            "{{\"planSha256\":\"{}\",{}",
            plan.plan_sha256,
            &encoded[1..]
        );

        assert!(matches!(
            UpgradePlan::from_json(duplicate.as_bytes()),
            Err(Error::Json(_))
        ));
    }

    #[test]
    fn plan_commands_quote_untrusted_arguments_and_preserve_structure() {
        let mut report = safe_report();
        report.context.network_name = Some("testnet; echo compromised".into());
        let plan = create_plan(
            report,
            "testnet; echo compromised",
            TEST_CONTRACT_ID,
            "operator",
            "target file.wasm",
            None,
        )
        .unwrap();
        let upload = plan
            .steps
            .iter()
            .find(|step| step.kind == PlanStepKind::UploadTargetWasm)
            .unwrap();
        assert_eq!(upload.program, "stellar");
        assert_eq!(upload.arguments[3], "target file.wasm");
        assert!(upload
            .arguments
            .iter()
            .any(|argument| argument == "--optimize=false"));
        assert!(upload.command.contains("'target file.wasm'"));
        assert!(upload.command.contains("'testnet; echo compromised'"));
    }

    #[test]
    fn plan_rejects_private_key_in_invariant_arguments() {
        let secret = stellar_strkey::ed25519::PrivateKey([9; 32]).to_string();
        assert!(matches!(
            create_plan_with_paths(
                safe_report(),
                "testnet",
                TEST_CONTRACT_ID,
                "deployer",
                PlanInputPaths {
                    source_wasm: "source.wasm".into(),
                    target_wasm: "target.wasm".into(),
                    source_schema: "source.schema.json".into(),
                    target_schema: "target.schema.json".into(),
                    schema_history: "schema-history.json".into(),
                    policy: None,
                },
                PlanOperations {
                    migration: None,
                    invariant_check: InvariantCheck {
                        program: "verify-upgrade".into(),
                        arguments: vec![secret],
                    },
                },
            ),
            Err(Error::Plan(message)) if message.contains("private key")
        ));
    }

    #[test]
    fn plan_rejects_private_keys_embedded_in_structured_arguments_and_paths() {
        let secret = stellar_strkey::ed25519::PrivateKey([11; 32]).to_string();
        let report = safe_report();
        assert!(matches!(
            create_plan_with_paths(
                report.clone(),
                "testnet",
                TEST_CONTRACT_ID,
                "deployer",
                PlanInputPaths {
                    source_wasm: "source.wasm".into(),
                    target_wasm: format!("artifacts/{secret}/target.wasm"),
                    source_schema: "source.schema.json".into(),
                    target_schema: "target.schema.json".into(),
                    schema_history: "schema-history.json".into(),
                    policy: None,
                },
                PlanOperations {
                    migration: None,
                    invariant_check: InvariantCheck {
                        program: "verify-upgrade".into(),
                        arguments: vec!["testnet".into()],
                    },
                },
            ),
            Err(Error::Plan(message)) if message.contains("private key")
        ));

        assert!(matches!(
            create_plan_with_paths(
                report,
                "testnet",
                TEST_CONTRACT_ID,
                "deployer",
                PlanInputPaths {
                    source_wasm: "source.wasm".into(),
                    target_wasm: "target.wasm".into(),
                    source_schema: "source.schema.json".into(),
                    target_schema: "target.schema.json".into(),
                    schema_history: "schema-history.json".into(),
                    policy: None,
                },
                PlanOperations {
                    migration: None,
                    invariant_check: InvariantCheck {
                        program: "verify-upgrade".into(),
                        arguments: vec![format!(r#"{{"secret":"{secret}"}}"#)],
                    },
                },
            ),
            Err(Error::Plan(message)) if message.contains("private key")
        ));
    }

    #[test]
    fn plan_rejects_private_keys_embedded_in_artifact_evidence() {
        let secret = stellar_strkey::ed25519::PrivateKey([12; 32]).to_string();
        let mut report = safe_report();
        report
            .target
            .metadata
            .insert("operator_hint".into(), format!("ref:{secret}"));

        assert!(matches!(
            create_plan(
                report,
                "testnet",
                TEST_CONTRACT_ID,
                "deployer",
                "target.wasm",
                None,
            ),
            Err(Error::Plan(message)) if message.contains("private key")
        ));
    }

    #[test]
    fn public_impact_traversal_stops_at_the_depth_limit() {
        let mut artifact = artifact("1.0.0", &["read"]);
        for index in 0..=MAX_PUBLIC_IMPACT_DEPTH + 1 {
            let name = format!("Type{index}");
            artifact.user_types.insert(
                name.clone(),
                InterfaceEntry {
                    kind: "struct".into(),
                    name,
                    canonical: serde_json::json!({}),
                },
            );
            if index <= MAX_PUBLIC_IMPACT_DEPTH {
                artifact.type_references.push(TypeReference {
                    owner_type: format!("Type{index}"),
                    member: "next".into(),
                    target_type: format!("Type{}", index + 1),
                });
            }
        }

        let (routes, limited) = routes_to_type(
            &artifact,
            "Type0",
            &format!("Type{}", MAX_PUBLIC_IMPACT_DEPTH + 1),
        );
        assert!(routes.is_empty());
        assert!(limited);
    }

    #[test]
    fn named_upgrade_without_host_update_is_blocked() {
        let mut candidate = artifact("2.0.0", &["upgrade"]);
        candidate
            .export_call_evidence
            .get_mut("upgrade")
            .unwrap()
            .host_imports
            .clear();
        let mut findings = Vec::new();
        check_upgrade_host_capability(&candidate, "target", "UPG004", &mut findings);

        assert!(findings
            .iter()
            .any(|finding| { finding.code == "UPG004" && finding.severity == Severity::Error }));
    }

    #[test]
    fn plan_rejects_network_evidence_mismatch() {
        assert!(create_plan(
            safe_report(),
            "mainnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .is_err());
    }

    #[test]
    fn plan_refuses_unsafe_report() {
        let mut report = safe_report();
        report
            .findings
            .push(error("ABI001", "removed", "removed function", "restore it"));
        assert!(report.safe, "fixture exercises a forged safe flag");
        assert!(create_plan(
            report,
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None
        )
        .is_err());
    }

    #[test]
    fn plan_requires_declared_storage_migration() {
        let mut report = safe_report();
        report.target_schema.as_mut().unwrap().entries[0].migration = Some(Migration {
            strategy: "eager".into(),
            entrypoint: Some("migrate".into()),
            notes: None,
        });
        report.findings.push(warning(
            "STO002",
            "migration required",
            "storage changed",
            "run migrate",
        ));
        assert!(create_plan(
            report.clone(),
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .is_err());
        assert!(create_plan(
            report,
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            Some("migrate"),
        )
        .is_ok());
    }

    #[test]
    fn plan_requires_protocol_storage_and_history_evidence() {
        let mut missing_protocol = safe_report();
        missing_protocol.context.target_protocol_version = None;
        assert!(create_plan(
            missing_protocol,
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .is_err());

        let mut missing_storage = safe_report();
        missing_storage.storage_schema_checked = false;
        assert!(create_plan(
            missing_storage,
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .is_err());

        let mut missing_history = safe_report();
        missing_history.schema_history_checked = false;
        missing_history.schema_history_sha256 = None;
        assert!(create_plan(
            missing_history,
            "testnet",
            TEST_CONTRACT_ID,
            "deployer",
            "target.wasm",
            None,
        )
        .is_err());
    }

    #[test]
    fn wasm_import_reader_detects_cap_0086_functions() {
        let wasm = wat::parse_str(
            r#"(module
                (type (func (param i64 i64 i64 i64) (result i64)))
                (import "m" "b" (func (type 0)))
                (import "m" "c" (func (type 0))))"#,
        )
        .unwrap();
        let imports = read_host_imports(&wasm).unwrap();
        assert!(imports.contains(CAP_0086_SPARSE_WRITE_IMPORT));
        assert!(imports.contains(CAP_0086_SPARSE_READ_IMPORT));
    }

    #[test]
    fn artifact_rejects_duplicate_contract_spec_sections() {
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        for _ in 0..2 {
            wasm.extend_from_slice(&[0, 15, 14]);
            wasm.extend_from_slice(b"contractspecv0");
        }

        let error = Artifact::from_wasm(&wasm).unwrap_err();
        assert!(matches!(error, Error::ContractSpecSectionCount(2)));
    }

    #[test]
    fn artifact_rejects_input_above_the_parser_limit() {
        let oversized = vec![0; MAX_ARTIFACT_SIZE_BYTES + 1];

        let error = Artifact::from_wasm(&oversized).unwrap_err();
        assert!(matches!(error, Error::ArtifactTooLarge { .. }));
    }

    #[test]
    fn artifact_rejects_duplicate_user_type_names() {
        let mut types = BTreeMap::new();
        insert_user_type(&mut types, "struct", "State".into(), serde_json::json!({})).unwrap();
        let error = insert_user_type(&mut types, "enum", "State".into(), serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(error, Error::DuplicateSpecName { .. }));
    }

    #[test]
    fn offline_protocol_assertion_is_explicitly_warned() {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::OfflineAssertion,
            network_name: Some("testnet".into()),
            ..ValidationContext::default()
        };
        let mut findings = Vec::new();
        check_protocol_context(&context, &mut findings);

        assert!(findings.iter().any(|finding| finding.code == "NET003"));
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Error));
    }

    #[test]
    fn complete_live_protocol_evidence_is_accepted() {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::StellarCliNetworkInfo,
            network_name: Some("testnet".into()),
            network_id: Some("network-id".into()),
            network_passphrase: Some("Test SDF Network ; September 2015".into()),
            rpc_version: Some("27.1.1".into()),
            captive_core_version: Some("stellar-core 27.1.0".into()),
            observed_at_unix_seconds: Some(1_786_000_000),
        };
        let mut findings = Vec::new();
        check_protocol_context(&context, &mut findings);

        assert!(findings.iter().any(|finding| finding.code == "NET005"));
        assert!(!findings
            .iter()
            .any(|finding| finding.severity == Severity::Error));
    }

    #[test]
    fn incomplete_live_protocol_evidence_is_rejected() {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::StellarCliNetworkInfo,
            network_name: Some("testnet".into()),
            ..ValidationContext::default()
        };
        let mut findings = Vec::new();
        check_protocol_context(&context, &mut findings);

        assert!(findings.iter().any(|finding| finding.code == "NET006"));
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::Error));
    }

    #[test]
    fn default_policy_blocks_missing_storage_evidence() {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::OfflineAssertion,
            network_name: Some("testnet".into()),
            ..ValidationContext::default()
        };
        let report = validate_with_history(
            &artifact("1.0.0", &["upgrade"]),
            &artifact("2.0.0", &["upgrade"]),
            None,
            None,
            &Policy::default(),
            &context,
            None,
        );

        assert!(!report.safe);
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "STO000" && finding.severity == Severity::Error }));
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "HIS000" && finding.severity == Severity::Error }));
    }

    #[test]
    fn environment_protocol_and_prerelease_are_release_gates() {
        let mut target = artifact("2.0.0", &["upgrade"]);
        target.env_protocol_version = 28;
        target.env_pre_release = 1;
        let context = ValidationContext {
            target_protocol_version: Some(27),
            protocol_source: ProtocolSource::OfflineAssertion,
            network_name: Some("testnet".into()),
            ..ValidationContext::default()
        };
        let mut findings = Vec::new();
        check_environment_compatibility(&target, &context, &mut findings);

        assert!(findings.iter().any(|finding| finding.code == "ENV001"));
        assert!(findings.iter().any(|finding| finding.code == "ENV002"));
    }

    #[test]
    fn protocol_without_provenance_is_rejected() {
        let context = ValidationContext {
            target_protocol_version: Some(27),
            ..ValidationContext::default()
        };
        let mut findings = Vec::new();
        check_protocol_context(&context, &mut findings);

        assert!(findings.iter().any(|finding| finding.code == "NET002"));
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::Error));
    }

    #[test]
    fn optional_field_addition_requires_per_type_cap_0086_evidence() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        source.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Account".into(),
            struct_entry(
                "Account",
                &[
                    ("balance", serde_json::json!("i128")),
                    (
                        "status",
                        serde_json::json!({"option": {"value_type": "u32"}}),
                    ),
                ],
            ),
        );
        target
            .host_imports
            .insert(CAP_0086_SPARSE_READ_IMPORT.into());

        let mut findings = Vec::new();
        compare_interfaces(
            &source,
            &target,
            &Policy::default(),
            &ValidationContext {
                target_protocol_version: Some(28),
                ..ValidationContext::default()
            },
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "CAP005"));
        assert!(findings
            .iter()
            .any(|finding| finding.severity == Severity::Error));
    }

    #[test]
    fn optional_field_addition_is_blocked_without_both_cap_requirements() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        source.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Account".into(),
            struct_entry(
                "Account",
                &[
                    ("balance", serde_json::json!("i128")),
                    (
                        "status",
                        serde_json::json!({"option": {"value_type": "u32"}}),
                    ),
                ],
            ),
        );

        for context in [
            ValidationContext {
                target_protocol_version: Some(27),
                ..ValidationContext::default()
            },
            ValidationContext {
                target_protocol_version: Some(28),
                ..ValidationContext::default()
            },
        ] {
            let mut findings = Vec::new();
            compare_interfaces(
                &source,
                &target,
                &Policy::default(),
                &context,
                &mut findings,
            );
            assert!(findings.iter().any(|finding| finding.code == "CAP006"));
        }
    }

    #[test]
    fn cap_0086_never_approves_field_rename_or_type_change() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        source.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("amount", serde_json::json!("u64"))]),
        );
        target
            .host_imports
            .insert(CAP_0086_SPARSE_READ_IMPORT.into());
        let mut findings = Vec::new();
        compare_interfaces(
            &source,
            &target,
            &Policy::default(),
            &ValidationContext {
                target_protocol_version: Some(28),
                ..ValidationContext::default()
            },
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "ABI004"));
    }

    #[test]
    fn cap_0086_import_is_blocked_before_protocol_28() {
        let mut target = artifact("2.0.0", &["upgrade"]);
        target
            .host_imports
            .insert(CAP_0086_SPARSE_READ_IMPORT.into());
        let mut findings = Vec::new();
        check_cap_0086(
            &target,
            &ValidationContext {
                target_protocol_version: Some(27),
                ..ValidationContext::default()
            },
            &mut findings,
        );
        assert!(findings.iter().any(|finding| finding.code == "CAP001"));
    }

    #[test]
    fn cap_0086_requires_export_reachability_and_flags_dynamic_dispatch() {
        let mut target = artifact("2.0.0", &["account", "upgrade"]);
        target
            .host_imports
            .insert(CAP_0086_SPARSE_READ_IMPORT.into());
        let context = ValidationContext {
            target_protocol_version: Some(28),
            ..ValidationContext::default()
        };

        let mut findings = Vec::new();
        check_cap_0086(&target, &context, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "CAP007"));

        target.export_call_evidence.insert(
            "account".into(),
            ExportCallEvidence {
                host_imports: BTreeSet::from([CAP_0086_SPARSE_READ_IMPORT.into()]),
                dynamic_dispatch_reachable: true,
            },
        );
        findings.clear();
        check_cap_0086(&target, &context, &mut findings);
        assert!(!findings.iter().any(|finding| finding.code == "CAP007"));
        assert!(findings.iter().any(|finding| finding.code == "CAP008"));
    }

    #[test]
    fn schema_history_accepts_an_exact_cumulative_record() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        source.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Account".into(),
            struct_entry(
                "Account",
                &[
                    ("balance", serde_json::json!("i128")),
                    (
                        "status",
                        serde_json::json!({"option": {"value_type": "u32"}}),
                    ),
                ],
            ),
        );
        let history = SchemaHistory {
            format_version: 1,
            complete: true,
            types: BTreeMap::from([(
                "Account".into(),
                TypeHistory {
                    fields: BTreeMap::from([
                        (
                            "balance".into(),
                            HistoricalField {
                                value_type: serde_json::json!("i128"),
                                first_seen: "1.0.0".into(),
                                retired_in: None,
                            },
                        ),
                        (
                            "status".into(),
                            HistoricalField {
                                value_type: serde_json::json!({"option": {"value_type": "u32"}}),
                                first_seen: "2.0.0".into(),
                                retired_in: None,
                            },
                        ),
                    ]),
                    reserved_fields: BTreeSet::new(),
                },
            )]),
            source_sha256: "22".repeat(32),
        };
        let mut findings = Vec::new();
        validate_schema_history(&source, &target, &history, &mut findings);
        assert!(findings.is_empty());
    }

    #[test]
    fn schema_history_blocks_retired_field_reuse() {
        let source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        target.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("u64"))]),
        );
        let history = SchemaHistory {
            format_version: 1,
            complete: true,
            types: BTreeMap::from([(
                "Account".into(),
                TypeHistory {
                    fields: BTreeMap::from([(
                        "balance".into(),
                        HistoricalField {
                            value_type: serde_json::json!("i128"),
                            first_seen: "0.5.0".into(),
                            retired_in: Some("1.0.0".into()),
                        },
                    )]),
                    reserved_fields: BTreeSet::from(["balance".into()]),
                },
            )]),
            source_sha256: "33".repeat(32),
        };
        let mut findings = Vec::new();
        validate_schema_history(&source, &target, &history, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "HIS005"));
        assert!(findings.iter().any(|finding| finding.code == "HIS007"));
        assert!(findings.iter().any(|finding| finding.code == "HIS008"));
    }

    #[test]
    fn removed_field_must_be_retired_and_reserved() {
        let mut source = artifact("1.0.0", &["upgrade"]);
        let mut target = artifact("2.0.0", &["upgrade"]);
        source.user_types.insert(
            "Account".into(),
            struct_entry("Account", &[("balance", serde_json::json!("i128"))]),
        );
        target
            .user_types
            .insert("Account".into(), struct_entry("Account", &[]));
        let history = SchemaHistory {
            format_version: 1,
            complete: true,
            types: BTreeMap::from([(
                "Account".into(),
                TypeHistory {
                    fields: BTreeMap::from([(
                        "balance".into(),
                        HistoricalField {
                            value_type: serde_json::json!("i128"),
                            first_seen: "1.0.0".into(),
                            retired_in: None,
                        },
                    )]),
                    reserved_fields: BTreeSet::new(),
                },
            )]),
            source_sha256: "44".repeat(32),
        };
        let mut findings = Vec::new();
        validate_schema_history(&source, &target, &history, &mut findings);
        assert!(findings.iter().any(|finding| finding.code == "HIS010"));
    }

    #[test]
    fn export_call_evidence_separates_directly_reachable_host_functions() {
        let wasm = wat::parse_str(
            r#"(module
                (import "m" "c" (func $sparse))
                (import "m" "a" (func $dense))
                (func $sparse_wrapper call $sparse)
                (func (export "read_sparse") call $sparse_wrapper)
                (func (export "read_dense") call $dense)
            )"#,
        )
        .unwrap();

        let evidence = inspect_export_call_evidence(&wasm).unwrap();
        assert_eq!(
            evidence["read_sparse"].host_imports,
            BTreeSet::from(["m.c".into()])
        );
        assert_eq!(
            evidence["read_dense"].host_imports,
            BTreeSet::from(["m.a".into()])
        );
        assert!(!evidence["read_sparse"].dynamic_dispatch_reachable);
    }

    #[test]
    fn function_import_inspection_preserves_order_and_duplicates() {
        let wasm = wat::parse_str(
            r#"(module
                (import "m" "c" (func $first))
                (import "m" "a" (func $dense))
                (import "m" "c" (func $second))
            )"#,
        )
        .unwrap();

        let imports = inspect_function_imports(&wasm).unwrap();
        assert_eq!(
            imports
                .iter()
                .map(FunctionImport::canonical_name)
                .collect::<Vec<_>>(),
            ["m.c", "m.a", "m.c"]
        );
        assert_eq!(
            imports
                .iter()
                .map(|import| import.function_index)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
    }

    #[test]
    fn export_call_evidence_flags_dynamic_dispatch() {
        let wasm = wat::parse_str(
            r#"(module
                (type $callback (func))
                (func $target)
                (table 1 funcref)
                (elem (i32.const 0) $target)
                (func (export "dispatch")
                    i32.const 0
                    call_indirect (type $callback))
            )"#,
        )
        .unwrap();

        let evidence = inspect_export_call_evidence(&wasm).unwrap();
        assert!(evidence["dispatch"].dynamic_dispatch_reachable);
        assert!(evidence["dispatch"].host_imports.is_empty());
    }

    #[test]
    fn changed_nested_type_traces_to_a_retained_public_boundary() {
        let mut source = artifact("1.0.0", &["portfolio", "upgrade"]);
        let mut target = artifact("2.0.0", &["portfolio", "upgrade"]);
        source.user_types.insert(
            "Balance".into(),
            struct_entry("Balance", &[("amount", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Balance".into(),
            struct_entry("Balance", &[("amount", serde_json::json!("u64"))]),
        );
        for artifact in [&mut source, &mut target] {
            artifact.public_type_boundaries.push(PublicTypeBoundary {
                function: "portfolio".into(),
                position: BoundaryPosition::Output,
                index: 0,
                label: None,
                root_type: "Portfolio".into(),
            });
            artifact.type_references.extend([
                TypeReference {
                    owner_type: "Portfolio".into(),
                    member: "position".into(),
                    target_type: "Position".into(),
                },
                TypeReference {
                    owner_type: "Position".into(),
                    member: "balance".into(),
                    target_type: "Balance".into(),
                },
            ]);
            artifact.user_types.insert(
                "Portfolio".into(),
                struct_entry("Portfolio", &[("position", serde_json::json!("Position"))]),
            );
            artifact.user_types.insert(
                "Position".into(),
                struct_entry("Position", &[("balance", serde_json::json!("Balance"))]),
            );
        }

        let (impacts, limited) = trace_public_impacts(&source, &target);
        assert!(!limited);
        assert_eq!(impacts.len(), 1);
        assert_eq!(impacts[0].changed_type, "Balance");
        assert_eq!(
            impacts[0]
                .steps
                .iter()
                .map(|step| step.member.as_str())
                .collect::<Vec<_>>(),
            ["position", "balance"]
        );
        assert_eq!(impacts[0].structural_reachability, EvidenceStatus::Fact);
        assert_eq!(impacts[0].runtime_compatibility, EvidenceStatus::Unknown);
    }

    #[test]
    fn public_impact_keeps_distinct_fields_that_reach_the_same_type() {
        let mut source = artifact("1.0.0", &["portfolio", "upgrade"]);
        let mut target = artifact("2.0.0", &["portfolio", "upgrade"]);
        source.user_types.insert(
            "Balance".into(),
            struct_entry("Balance", &[("amount", serde_json::json!("i128"))]),
        );
        target.user_types.insert(
            "Balance".into(),
            struct_entry("Balance", &[("amount", serde_json::json!("u64"))]),
        );
        for artifact in [&mut source, &mut target] {
            artifact.public_type_boundaries.push(PublicTypeBoundary {
                function: "portfolio".into(),
                position: BoundaryPosition::Output,
                index: 0,
                label: None,
                root_type: "Portfolio".into(),
            });
            artifact.type_references.extend([
                TypeReference {
                    owner_type: "Portfolio".into(),
                    member: "left".into(),
                    target_type: "Balance".into(),
                },
                TypeReference {
                    owner_type: "Portfolio".into(),
                    member: "right".into(),
                    target_type: "Balance".into(),
                },
            ]);
            artifact.user_types.insert(
                "Portfolio".into(),
                struct_entry(
                    "Portfolio",
                    &[
                        ("left", serde_json::json!("Balance")),
                        ("right", serde_json::json!("Balance")),
                    ],
                ),
            );
        }

        let (impacts, limited) = trace_public_impacts(&source, &target);
        assert!(!limited);
        assert_eq!(impacts.len(), 2);
        assert_eq!(impacts[0].steps[0].member, "left");
        assert_eq!(impacts[1].steps[0].member, "right");
    }

    #[test]
    fn evidence_coverage_distinguishes_live_fact_from_offline_inference() {
        let live = build_evidence_coverage(
            &ValidationContext {
                target_protocol_version: Some(28),
                protocol_source: ProtocolSource::StellarCliNetworkInfo,
                network_name: Some("testnet".into()),
                network_id: Some("network-id".into()),
                observed_at_unix_seconds: Some(1),
                ..ValidationContext::default()
            },
            true,
            true,
        );
        assert_eq!(live.target_network_protocol.status, EvidenceStatus::Fact);
        assert_eq!(live.ledger_storage_coverage.status, EvidenceStatus::Unknown);

        let offline = build_evidence_coverage(
            &ValidationContext {
                target_protocol_version: Some(28),
                protocol_source: ProtocolSource::OfflineAssertion,
                ..ValidationContext::default()
            },
            false,
            false,
        );
        assert_eq!(
            offline.target_network_protocol.status,
            EvidenceStatus::Inference
        );
        assert_eq!(
            offline.declared_storage_schema.status,
            EvidenceStatus::Unknown
        );
    }
}
