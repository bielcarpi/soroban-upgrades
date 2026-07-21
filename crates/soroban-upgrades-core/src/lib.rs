//! Upgrade-safety primitives for Soroban contracts.
//!
//! The crate inspects the metadata and contract specification embedded in
//! Soroban WASM binaries. It never signs or submits a transaction.

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
    Error as XdrError, Limited, Limits, ReadXdr, ScMetaEntry, ScMetaV0, ScSpecEntry,
};

const SPEC_XDR_DEPTH_LIMIT: u32 = 500;
pub const MAX_ARTIFACT_SIZE_BYTES: usize = 16 * 1024 * 1024;
const CAP_0086_PROTOCOL: u32 = 28;
const CAP_0086_SPARSE_WRITE_IMPORT: &str = "m.b";
const CAP_0086_SPARSE_READ_IMPORT: &str = "m.c";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("WASM artifact is {size_bytes} bytes; the parser limit is {limit_bytes} bytes")]
    ArtifactTooLarge {
        size_bytes: usize,
        limit_bytes: usize,
    },
    #[error("invalid Soroban contract specification: {0}")]
    Spec(#[from] soroban_spec::read::FromWasmError),
    #[error("expected exactly one contractspecv0 section, found {0}")]
    ContractSpecSectionCount(usize),
    #[error("contract specification contains duplicate {kind} name {name:?}")]
    DuplicateSpecName { kind: &'static str, name: String },
    #[error("contract metadata contains duplicate key {0:?}")]
    DuplicateMetadataKey(String),
    #[error("invalid WASM binary: {0}")]
    Wasm(#[from] wasmparser::BinaryReaderError),
    #[error("invalid XDR metadata: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid contract ID {0:?}; expected a checksummed Stellar C... strkey")]
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

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceEntry {
    pub kind: String,
    pub name: String,
    pub canonical: serde_json::Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
    pub size_bytes: usize,
    pub metadata: BTreeMap<String, String>,
    pub host_imports: BTreeSet<String>,
    pub functions: BTreeMap<String, InterfaceEntry>,
    pub user_types: BTreeMap<String, InterfaceEntry>,
}

impl Artifact {
    pub fn from_wasm(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_ARTIFACT_SIZE_BYTES {
            return Err(Error::ArtifactTooLarge {
                size_bytes: bytes.len(),
                limit_bytes: MAX_ARTIFACT_SIZE_BYTES,
            });
        }
        let sha256 = hex::encode(Sha256::digest(bytes));
        require_single_contract_spec_section(bytes)?;
        let spec = soroban_spec::read::from_wasm(bytes)?;
        let metadata = read_contract_metadata(bytes)?;
        let host_imports = read_host_imports(bytes)?;
        let mut functions = BTreeMap::new();
        let mut user_types = BTreeMap::new();

        for entry in spec.iter() {
            let canonical = canonicalize_spec_entry(entry)?;
            match entry {
                ScSpecEntry::FunctionV0(function) => {
                    let name = function.name.to_utf8_string_lossy();
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
                ScSpecEntry::UdtStructV0(value) => insert_user_type(
                    &mut user_types,
                    "struct",
                    value.name.to_utf8_string_lossy(),
                    canonical,
                )?,
                ScSpecEntry::UdtUnionV0(value) => insert_user_type(
                    &mut user_types,
                    "union",
                    value.name.to_utf8_string_lossy(),
                    canonical,
                )?,
                ScSpecEntry::UdtEnumV0(value) => insert_user_type(
                    &mut user_types,
                    "enum",
                    value.name.to_utf8_string_lossy(),
                    canonical,
                )?,
                ScSpecEntry::UdtErrorEnumV0(value) => insert_user_type(
                    &mut user_types,
                    "error_enum",
                    value.name.to_utf8_string_lossy(),
                    canonical,
                )?,
                ScSpecEntry::EventV0(_) => {}
            }
        }

        Ok(Self {
            sha256,
            size_bytes: bytes.len(),
            metadata,
            host_imports,
            functions,
            user_types,
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

fn read_host_imports(bytes: &[u8]) -> Result<BTreeSet<String>, Error> {
    let mut imports = BTreeSet::new();
    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        if let wasmparser::Payload::ImportSection(section) = payload? {
            for import in section.into_imports() {
                let import = import?;
                imports.insert(format!("{}.{}", import.module, import.name));
            }
        }
    }
    Ok(imports)
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolSource {
    #[default]
    Unpinned,
    OfflineAssertion,
    StellarCliNetworkInfo,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub format_version: u32,
    pub name: String,
    pub require_upgrade_function: bool,
    pub forbid_constructor: bool,
    pub require_semver_increase: bool,
    pub deny_removed_functions: bool,
    pub deny_changed_functions: bool,
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
            deny_removed_functions: true,
            deny_changed_functions: true,
            deny_changed_user_types: true,
        }
    }
}

impl Policy {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        parse_json_strict(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    pub strategy: String,
    pub entrypoint: Option<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Durability {
    Instance,
    Persistent,
    Temporary,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageEntry {
    pub key: String,
    pub durability: Durability,
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default)]
    pub migration: Option<Migration>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageSchema {
    pub format_version: u32,
    pub schema_version: u32,
    pub contract_version: String,
    pub entries: Vec<StorageEntry>,
}

impl StorageSchema {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        parse_json_strict(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoricalField {
    #[serde(rename = "type")]
    pub value_type: serde_json::Value,
    pub first_seen: String,
    #[serde(default)]
    pub retired_in: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypeHistory {
    #[serde(default)]
    pub fields: BTreeMap<String, HistoricalField>,
    #[serde(default)]
    pub reserved_fields: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SchemaHistory {
    pub format_version: u32,
    pub types: BTreeMap<String, TypeHistory>,
    #[serde(default, skip_deserializing)]
    pub source_sha256: String,
}

impl SchemaHistory {
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        let mut history: Self = parse_json_strict(bytes)?;
        history.source_sha256 = hex::encode(Sha256::digest(bytes));
        Ok(history)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub safe: bool,
    pub policy: Policy,
    pub context: ValidationContext,
    pub source: Artifact,
    pub target: Artifact,
    pub findings: Vec<Finding>,
    pub storage_schema_checked: bool,
    pub schema_history_checked: bool,
    pub schema_history_sha256: Option<String>,
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
    check_cap_0086(target, context, &mut findings);

    if policy.require_upgrade_function && !target.has_function("upgrade") {
        findings.push(error(
            "UPG001",
            "Target removes the upgrade entrypoint",
            "The target contract specification has no `upgrade` function. A successful deployment would make subsequent upgrades unavailable unless another authorized entrypoint performs the host update.",
            "Retain an authorized `upgrade` entrypoint or explicitly approve immutability as a terminal release.",
        ));
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
        findings.push(warning(
            "HIS000",
            "Historical field lifecycle was not checked",
            "A two-artifact comparison cannot detect reuse of a field name that existed in an older release or prove that archived state no longer contains retired layouts.",
            "Commit a cumulative schema-history manifest and pass `--schema-history` for production review.",
        ));
    }

    match (source_schema, target_schema) {
        (Some(from), Some(to)) => {
            validate_schema_manifests(source, target, from, to, &mut findings);
            compare_storage_schemas(from, to, &mut findings);
        }
        (None, None) => findings.push(warning(
            "STO000",
            "Storage compatibility was not checked",
            "Soroban WASM exposes the contract interface but does not provide a complete, standardized description of every storage key and value layout.",
            "Commit source and target storage schema manifests and pass them to validation before approving production upgrades.",
        )),
        _ => findings.push(error(
            "STO004",
            "Storage schema pair is incomplete",
            "Only one side of the upgrade supplied a storage schema, so compatibility cannot be evaluated.",
            "Supply both `--from-schema` and `--to-schema`.",
        )),
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.code.cmp(&b.code)));
    let safe = !findings.iter().any(|f| f.severity == Severity::Error);
    ValidationReport {
        safe,
        policy: policy.clone(),
        context: context.clone(),
        source: source.clone(),
        target: target.clone(),
        findings,
        storage_schema_checked: source_schema.is_some() && target_schema.is_some(),
        schema_history_checked: schema_history.is_some(),
        schema_history_sha256: schema_history.map(|history| history.source_sha256.clone()),
    }
}

fn check_policy(policy: &Policy, findings: &mut Vec<Finding>) {
    if policy.format_version != 1 {
        findings.push(error(
            "POL001",
            "Unsupported policy format",
            &format!(
                "Policy `{}` uses format version {}; this build supports version 1.",
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
        (!policy.deny_removed_functions, "removed public functions"),
        (
            !policy.deny_changed_functions,
            "changed function signatures",
        ),
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
                "Protocol {protocol} exposes CAP-0086, but this WASM does not import `sparse_map_unpack_to_linear_memory`; its contract-type decoding remains strict."
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
                    "The {side} manifest uses format version {}; this build supports version 1.",
                    schema.format_version
                ),
                "Regenerate the manifest with a supported tool version or upgrade the validator before relying on its result.",
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
        if let Some(entrypoint) = &migration.entrypoint {
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
                "The history manifest uses format version {}; this build supports version 1.",
                history.format_version
            ),
            "Regenerate the history manifest with a supported format before relying on it.",
        ));
        return;
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
                    "Correct the history from signed release artifacts; do not rewrite history to fit the candidate.",
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
                    "Use a new field name; never reinterpret a retired key across stored or cross-contract maps.",
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
                    "Keep the field, or record `retiredIn` and add it to `reservedFields`; separately prove all migration and reader compatibility assumptions.",
                ));
            } else {
                findings.push(warning(
                    "HIS011",
                    "Field removal is explicitly retired but remains migration-sensitive",
                    &format!(
                        "`{type_name}.{field_name}` is retired and reserved in {target_version}; archived records or older contracts may still carry it."
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
            "Both source and target WASM should embed a semantic version under the `binver` contract metadata key.",
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
                        "Declare an eager, lazy, or versioned migration and test it before generating an execution plan.",
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanStepKind {
    UploadTargetWasm,
    SimulateUpgrade,
    ExecuteUpgrade,
    ExecuteMigration,
    VerifyExecutable,
    VerifyInvariants,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStep {
    pub position: u32,
    pub kind: PlanStepKind,
    pub program: String,
    pub arguments: Vec<String>,
    pub command: String,
    pub expected: String,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpgradePlan {
    pub format_version: u32,
    pub plan_sha256: String,
    pub network: String,
    pub contract_id: String,
    pub source_identity: String,
    pub source_wasm_sha256: String,
    pub target_wasm_sha256: String,
    pub rollback_wasm_sha256: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
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

    if report
        .findings
        .iter()
        .any(|finding| finding.code == "STO002")
        && migration_entrypoint.is_none()
    {
        return Err(Error::Plan(
            "storage layout changed but no migration entrypoint was selected".into(),
        ));
    }

    if let Some(entrypoint) = migration_entrypoint {
        if !report.target.has_function(entrypoint) {
            return Err(Error::Plan(format!(
                "migration entrypoint `{entrypoint}` is not exported by the target WASM"
            )));
        }
    }

    let target_hash = report.target.sha256.clone();
    let mut steps = vec![
        PlanStep::new(
            1,
            PlanStepKind::UploadTargetWasm,
            "stellar",
            strings(&[
                "contract",
                "upload",
                "--wasm",
                target_wasm_path,
                "--source-account",
                source_identity,
                "--network",
                network,
            ]),
            format!("WASM hash {target_hash}"),
        ),
        PlanStep::new(
            2,
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
            3,
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

    if let Some(entrypoint) = migration_entrypoint {
        steps.push(PlanStep::new(
            4,
            PlanStepKind::ExecuteMigration,
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
                entrypoint,
                "--operator",
                source_identity,
            ]),
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
        "cargo",
        strings(&["test", "--workspace"]),
        "All upgrade-chain, migration, authorization, and rollback invariants pass".into(),
    ));

    let mut plan = UpgradePlan {
        format_version: 2,
        plan_sha256: String::new(),
        network: network.into(),
        contract_id: contract_id.into(),
        source_identity: source_identity.into(),
        source_wasm_sha256: report.source.sha256.clone(),
        target_wasm_sha256: report.target.sha256.clone(),
        rollback_wasm_sha256: report.source.sha256.clone(),
        from_version: report.source.version().map(str::to_owned),
        to_version: report.target.version().map(str::to_owned),
        validation: report,
        steps,
    };
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
    if plan.format_version != 2 {
        return Err(Error::Plan(format!(
            "unsupported plan format version {}; this build supports version 2",
            plan.format_version
        )));
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
    let migration_entrypoint = migration_steps
        .first()
        .map(|step| {
            let separator = step
                .arguments
                .iter()
                .position(|argument| argument == "--")
                .ok_or_else(|| Error::Plan("migration step has no `--` separator".into()))?;
            step.arguments
                .get(separator + 1)
                .map(String::as_str)
                .ok_or_else(|| Error::Plan("migration step has no entrypoint".into()))
        })
        .transpose()?;

    let mut expected = create_plan(
        plan.validation.clone(),
        &plan.network,
        &plan.contract_id,
        &plan.source_identity,
        target_wasm_path,
        migration_entrypoint,
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
            sha256: "00".repeat(32),
            size_bytes: 1,
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
                            canonical: serde_json::json!({}),
                        },
                    )
                })
                .collect(),
            user_types: BTreeMap::new(),
        }
    }

    fn schema(version: u32, value_type: &str, migration: Option<Migration>) -> StorageSchema {
        StorageSchema {
            format_version: 1,
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
        ValidationReport {
            safe: true,
            policy: Policy::default(),
            context: ValidationContext {
                target_protocol_version: Some(27),
                protocol_source: ProtocolSource::OfflineAssertion,
                network_name: Some("testnet".into()),
                ..ValidationContext::default()
            },
            source: artifact("1.0.0", &["upgrade"]),
            target: artifact("2.0.0", &["upgrade", "migrate"]),
            findings: Vec::new(),
            storage_schema_checked: true,
            schema_history_checked: true,
            schema_history_sha256: Some("11".repeat(32)),
        }
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
            "operator name",
            "target file.wasm",
            None,
        )
        .unwrap();
        let upload = &plan.steps[0];
        assert_eq!(upload.program, "stellar");
        assert_eq!(upload.arguments[3], "target file.wasm");
        assert!(upload.command.contains("'target file.wasm'"));
        assert!(upload.command.contains("'testnet; echo compromised'"));
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
}
