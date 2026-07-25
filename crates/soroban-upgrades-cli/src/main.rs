use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use soroban_upgrades_core::{
    create_plan, validate_with_history, verify_plan_digest, Artifact, BoundaryPosition,
    EvidenceItem, EvidenceStatus, Policy, ProtocolSource, PublicImpact, SchemaHistory, Severity,
    StorageSchema, UpgradePlan, ValidationContext, ValidationReport, MAX_ARTIFACT_SIZE_BYTES,
};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_JSON_INPUT_SIZE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "soroban-upgrades",
    version,
    about = "Validate and plan safe Soroban contract upgrades"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect the interface, metadata, version, and hash embedded in a WASM file.
    Inspect {
        #[arg(long)]
        wasm: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compare source and target WASM files and fail on unsafe changes.
    Validate {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long, requires = "to_schema")]
        from_schema: Option<PathBuf>,
        #[arg(long, requires = "from_schema")]
        to_schema: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Print a demo- and CI-friendly verdict instead of the full finding details.
        #[arg(long, conflicts_with = "json")]
        compact: bool,
        /// Optional version-controlled compatibility policy. Defaults fail closed.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Network to query live with `stellar network info`.
        #[arg(long)]
        network: Option<String>,
        /// Offline protocol assertion; skips the live network query.
        #[arg(long)]
        protocol_version: Option<u32>,
        /// Cumulative field lifecycle and reserved-name manifest.
        #[arg(long)]
        schema_history: Option<PathBuf>,
    },
    /// Emit a deterministic, reviewable execution plan. Refuses unsafe upgrades.
    Plan {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long, requires = "to_schema")]
        from_schema: Option<PathBuf>,
        #[arg(long, requires = "from_schema")]
        to_schema: Option<PathBuf>,
        #[arg(long)]
        network: String,
        #[arg(long)]
        contract_id: String,
        #[arg(long, default_value = "deployer")]
        source_identity: String,
        #[arg(long)]
        migration_entrypoint: Option<String>,
        /// Optional version-controlled compatibility policy. Defaults fail closed.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Offline protocol assertion; omit to query the selected network live.
        #[arg(long)]
        protocol_version: Option<u32>,
        /// Cumulative field lifecycle and reserved-name manifest.
        #[arg(long)]
        schema_history: PathBuf,
        /// Write the plan to a file instead of standard output.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify that a saved plan still matches its content-addressed digest.
    VerifyPlan {
        #[arg(long)]
        plan: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Inspect { wasm, json } => {
            let artifact = load_artifact(&wasm)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&artifact)?);
            } else {
                print_artifact(&wasm, &artifact);
            }
        }
        Command::Validate {
            from,
            to,
            from_schema,
            to_schema,
            json,
            compact,
            policy,
            network,
            protocol_version,
            schema_history,
        } => {
            let context = resolve_validation_context(network.as_deref(), protocol_version)?;
            let report = load_report(
                &from,
                &to,
                from_schema.as_deref(),
                to_schema.as_deref(),
                policy.as_deref(),
                &context,
                schema_history.as_deref(),
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if compact {
                print_compact_report(&report);
            } else {
                print_report(&report);
            }
            if !report.safe {
                bail!("upgrade validation failed");
            }
        }
        Command::Plan {
            from,
            to,
            from_schema,
            to_schema,
            network,
            contract_id,
            source_identity,
            migration_entrypoint,
            policy,
            protocol_version,
            schema_history,
            out,
        } => {
            let context = resolve_validation_context(Some(&network), protocol_version)?;
            let report = load_report(
                &from,
                &to,
                from_schema.as_deref(),
                to_schema.as_deref(),
                policy.as_deref(),
                &context,
                Some(&schema_history),
            )?;
            if !report.safe {
                print_report(&report);
                bail!("refusing to create a plan for an unsafe upgrade");
            }
            let plan = create_plan(
                report,
                &network,
                &contract_id,
                &source_identity,
                &to.to_string_lossy(),
                migration_entrypoint.as_deref(),
            )?;
            let mut json = serde_json::to_vec_pretty(&plan)?;
            json.push(b'\n');
            if let Some(out) = out {
                fs::write(&out, json).with_context(|| format!("writing {}", out.display()))?;
                println!("Plan written: {}", out.display());
                println!("Plan SHA-256: {}", plan.plan_sha256);
            } else {
                println!("{}", String::from_utf8(json)?);
            }
        }
        Command::VerifyPlan { plan } => {
            let bytes = read_bounded(&plan, MAX_JSON_INPUT_SIZE_BYTES, "JSON plan")?;
            let plan = UpgradePlan::from_json(&bytes)
                .with_context(|| format!("parsing {}", plan.display()))?;
            if !verify_plan_digest(&plan)? {
                bail!("upgrade plan digest mismatch");
            }
            println!("Plan digest verified: {}", plan.plan_sha256);
        }
    }
    Ok(())
}

fn load_artifact(path: &Path) -> Result<Artifact> {
    let bytes = read_bounded(path, MAX_ARTIFACT_SIZE_BYTES, "WASM artifact")?;
    Artifact::from_wasm(&bytes).with_context(|| format!("inspecting {}", path.display()))
}

fn load_schema(path: &Path) -> Result<StorageSchema> {
    let bytes = read_bounded(path, MAX_JSON_INPUT_SIZE_BYTES, "JSON storage schema")?;
    StorageSchema::from_json(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn load_policy(path: Option<&Path>) -> Result<Policy> {
    path.map(|path| {
        let bytes = read_bounded(path, MAX_JSON_INPUT_SIZE_BYTES, "JSON policy")?;
        Policy::from_json(&bytes).with_context(|| format!("parsing {}", path.display()))
    })
    .transpose()
    .map(|policy| policy.unwrap_or_default())
}

fn load_schema_history(path: Option<&Path>) -> Result<Option<SchemaHistory>> {
    path.map(|path| {
        let bytes = read_bounded(path, MAX_JSON_INPUT_SIZE_BYTES, "JSON schema history")?;
        SchemaHistory::from_json(&bytes).with_context(|| format!("parsing {}", path.display()))
    })
    .transpose()
}

fn read_bounded(path: &Path, limit: usize, kind: &str) -> Result<Vec<u8>> {
    let file = File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > limit {
        bail!(
            "{kind} {} exceeds the {} byte input limit",
            path.display(),
            limit
        );
    }
    Ok(bytes)
}

fn load_report(
    from: &Path,
    to: &Path,
    from_schema: Option<&Path>,
    to_schema: Option<&Path>,
    policy: Option<&Path>,
    context: &ValidationContext,
    schema_history: Option<&Path>,
) -> Result<ValidationReport> {
    let source = load_artifact(from)?;
    let target = load_artifact(to)?;
    let old_schema = from_schema.map(load_schema).transpose()?;
    let new_schema = to_schema.map(load_schema).transpose()?;
    let policy = load_policy(policy)?;
    let schema_history = load_schema_history(schema_history)?;
    Ok(validate_with_history(
        &source,
        &target,
        old_schema.as_ref(),
        new_schema.as_ref(),
        &policy,
        context,
        schema_history.as_ref(),
    ))
}

#[derive(Debug, Deserialize)]
struct NetworkInfo {
    id: String,
    version: String,
    captive_core_version: Option<String>,
    protocol_version: u32,
    passphrase: String,
}

fn resolve_validation_context(
    network: Option<&str>,
    protocol_version: Option<u32>,
) -> Result<ValidationContext> {
    match (network, protocol_version) {
        (Some(network), None) => resolve_live_network(network),
        (network, Some(protocol_version)) => Ok(ValidationContext {
            target_protocol_version: Some(protocol_version),
            protocol_source: ProtocolSource::OfflineAssertion,
            network_name: network.map(str::to_owned),
            ..ValidationContext::default()
        }),
        (None, None) => Ok(ValidationContext::default()),
    }
}

fn resolve_live_network(network: &str) -> Result<ValidationContext> {
    let output = ProcessCommand::new("stellar")
        .args(["network", "info", "--network", network, "--output", "json"])
        .output()
        .with_context(|| {
            "running `stellar network info`; install Stellar CLI or use --protocol-version for an explicit offline assertion"
        })?;

    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!(
            "live network query for `{network}` failed: {}. Configure that Stellar CLI network or use --protocol-version for an explicit offline assertion",
            if detail.is_empty() {
                format!("stellar exited with {}", output.status)
            } else {
                detail
            }
        );
    }

    let observed_at_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    context_from_network_info(network, &output.stdout, observed_at_unix_seconds)
}

fn context_from_network_info(
    network: &str,
    json: &[u8],
    observed_at_unix_seconds: u64,
) -> Result<ValidationContext> {
    let info: NetworkInfo = serde_json::from_slice(json)
        .with_context(|| format!("parsing Stellar CLI network info for `{network}`"))?;
    Ok(ValidationContext {
        target_protocol_version: Some(info.protocol_version),
        protocol_source: ProtocolSource::StellarCliNetworkInfo,
        network_name: Some(network.into()),
        network_id: Some(info.id),
        network_passphrase: Some(info.passphrase),
        rpc_version: Some(info.version),
        captive_core_version: info.captive_core_version,
        observed_at_unix_seconds: Some(observed_at_unix_seconds),
    })
}

fn print_artifact(path: &Path, artifact: &Artifact) {
    println!("Artifact: {}", path.display());
    println!("SHA-256: {}", artifact.sha256);
    println!("Size: {} bytes", artifact.size_bytes);
    println!("Version: {}", artifact.version().unwrap_or("missing"));
    println!("Upgrade entrypoint: {}", artifact.has_function("upgrade"));
    println!("Constructor: {}", artifact.has_function("__constructor"));
    println!(
        "Functions: {}",
        artifact
            .functions
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "User types: {}",
        artifact
            .user_types
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Entrypoint host-import reachability:");
    for (entrypoint, evidence) in &artifact.export_call_evidence {
        let imports = if evidence.host_imports.is_empty() {
            "none".to_owned()
        } else {
            evidence
                .host_imports
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "  {entrypoint}: {imports}; dynamic dispatch reachable: {}",
            evidence.dynamic_dispatch_reachable
        );
    }
}

fn print_report(report: &ValidationReport) {
    println!("Upgrade safe: {}", report.safe);
    println!(
        "Version: {} -> {}",
        report.source.version().unwrap_or("missing"),
        report.target.version().unwrap_or("missing")
    );
    println!("Source SHA-256: {}", report.source.sha256);
    println!("Target SHA-256: {}", report.target.sha256);
    println!("Storage schema checked: {}", report.storage_schema_checked);
    println!("Schema history checked: {}", report.schema_history_checked);
    println!(
        "Target protocol: {}",
        report
            .context
            .target_protocol_version
            .map_or_else(|| "unpinned".into(), |version| version.to_string())
    );
    println!(
        "Protocol evidence: {}",
        match report.context.protocol_source {
            ProtocolSource::Unpinned => "unpinned",
            ProtocolSource::OfflineAssertion => "offline assertion",
            ProtocolSource::StellarCliNetworkInfo => "live Stellar CLI network info",
        }
    );
    if let Some(network) = &report.context.network_name {
        println!("Target network: {network}");
    }
    if let Some(network_id) = &report.context.network_id {
        println!("Network ID: {network_id}");
    }
    if let Some(observed_at) = report.context.observed_at_unix_seconds {
        println!("Network observed at (Unix): {observed_at}");
    }
    println!(
        "CAP-0086 sparse read/write: {}/{}",
        report.target.uses_cap_0086_sparse_read(),
        report.target.uses_cap_0086_sparse_write()
    );
    println!("Evidence coverage (FACT / INFERENCE / UNKNOWN):");
    for (name, item) in evidence_items(report) {
        print_evidence_item(name, item);
    }
    if !report.public_impacts.is_empty() {
        println!("Retained public impact paths:");
        for impact in &report.public_impacts {
            println!("  {}", format_public_impact(impact));
            println!(
                "    structural reachability: {}; runtime compatibility: {}",
                evidence_status_label(&impact.structural_reachability),
                evidence_status_label(&impact.runtime_compatibility)
            );
        }
    }
    for finding in &report.findings {
        let label = match finding.severity {
            Severity::Info => "INFO",
            Severity::Warning => "WARN",
            Severity::Error => "ERROR",
        };
        println!("[{label}] {}: {}", finding.code, finding.title);
        println!("  {}", finding.detail);
        println!("  Fix: {}", finding.remediation);
    }
}

fn evidence_items(report: &ValidationReport) -> [(&'static str, &EvidenceItem); 9] {
    [
        (
            "compiled Contract Spec",
            &report.evidence.compiled_contract_spec,
        ),
        (
            "artifact host imports",
            &report.evidence.artifact_host_imports,
        ),
        (
            "target network protocol",
            &report.evidence.target_network_protocol,
        ),
        (
            "declared storage schema",
            &report.evidence.declared_storage_schema,
        ),
        (
            "declared schema history",
            &report.evidence.declared_schema_history,
        ),
        (
            "ledger storage coverage",
            &report.evidence.ledger_storage_coverage,
        ),
        (
            "deployed caller graph",
            &report.evidence.deployed_caller_graph,
        ),
        (
            "CAP-0086 per-type reader binding",
            &report.evidence.cap0086_per_type_reader_binding,
        ),
        (
            "migration completion",
            &report.evidence.migration_completion,
        ),
    ]
}

fn evidence_status_label(status: &EvidenceStatus) -> &'static str {
    match status {
        EvidenceStatus::Fact => "FACT",
        EvidenceStatus::Inference => "INFERENCE",
        EvidenceStatus::Unknown => "UNKNOWN",
    }
}

fn print_evidence_item(name: &str, item: &EvidenceItem) {
    println!(
        "  [{}] {name}: {}",
        evidence_status_label(&item.status),
        item.claim
    );
    println!("    Basis: {}", item.basis);
    if let Some(limitation) = &item.limitation {
        println!("    Limit: {limitation}");
    }
}

fn format_public_impact(impact: &PublicImpact) -> String {
    let position = match impact.boundary.position {
        BoundaryPosition::Input => "input",
        BoundaryPosition::Output => "output",
    };
    let label = impact
        .boundary
        .label
        .as_deref()
        .map_or_else(String::new, |label| format!(" `{label}`"));
    let mut path = format!(
        "{}() {position}[{}]{label} -> {}",
        impact.boundary.function, impact.boundary.index, impact.boundary.root_type
    );
    for step in &impact.steps {
        path.push_str(&format!(".{} -> {}", step.member, step.target_type));
    }
    path.push_str(&format!(" (changed {})", impact.changed_type));
    path
}

fn print_compact_report(report: &ValidationReport) {
    let errors = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .collect::<Vec<_>>();
    let warnings = report
        .findings
        .iter()
        .filter(|finding| finding.severity == Severity::Warning)
        .collect::<Vec<_>>();
    let protocol = report
        .context
        .target_protocol_version
        .map_or_else(|| "unpinned".into(), |version| version.to_string());
    let evidence = match report.context.protocol_source {
        ProtocolSource::Unpinned => "no network evidence",
        ProtocolSource::OfflineAssertion => "offline assertion",
        ProtocolSource::StellarCliNetworkInfo => "live network evidence",
    };

    println!(
        "{} {} -> {} | protocol {} ({}) | {} error(s), {} warning(s)",
        if report.safe { "PASS" } else { "BLOCKED" },
        report.source.version().unwrap_or("missing"),
        report.target.version().unwrap_or("missing"),
        protocol,
        evidence,
        errors.len(),
        warnings.len()
    );
    if !errors.is_empty() {
        println!(
            "  errors: {}",
            errors
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !warnings.is_empty() {
        println!(
            "  warnings: {}",
            warnings
                .iter()
                .map(|finding| finding.code.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "  artifact: {} -> {}",
        short_hash(&report.source.sha256),
        short_hash(&report.target.sha256)
    );
    println!(
        "  CAP-0086 sparse read/write: {}/{}",
        report.target.uses_cap_0086_sparse_read(),
        report.target.uses_cap_0086_sparse_write()
    );
    for impact in report.public_impacts.iter().take(3) {
        println!("  public impact: {}", format_public_impact(impact));
    }
    if report.public_impacts.len() > 3 {
        println!(
            "  public impact: {} additional path(s) in the full JSON report",
            report.public_impacts.len() - 3
        );
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TESTNET_INFO: &[u8] = br#"{
        "id": "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472",
        "version": "27.1.1-7e71d70",
        "captive_core_version": "stellar-core 27.1.0",
        "protocol_version": 27,
        "passphrase": "Test SDF Network ; September 2015"
    }"#;

    #[test]
    fn parses_live_network_info_into_complete_evidence() {
        let context = context_from_network_info("testnet", TESTNET_INFO, 123).unwrap();

        assert_eq!(context.target_protocol_version, Some(27));
        assert_eq!(
            context.protocol_source,
            ProtocolSource::StellarCliNetworkInfo
        );
        assert_eq!(context.network_name.as_deref(), Some("testnet"));
        assert_eq!(context.observed_at_unix_seconds, Some(123));
        assert!(context.network_id.is_some());
        assert!(context.network_passphrase.is_some());
        assert!(context.rpc_version.is_some());
    }

    #[test]
    fn protocol_flag_creates_an_offline_assertion() {
        let context = resolve_validation_context(Some("testnet"), Some(28)).unwrap();

        assert_eq!(context.target_protocol_version, Some(28));
        assert_eq!(context.protocol_source, ProtocolSource::OfflineAssertion);
        assert_eq!(context.network_name.as_deref(), Some("testnet"));
        assert!(context.network_id.is_none());
    }

    #[test]
    fn short_hash_is_stable_for_full_and_short_inputs() {
        assert_eq!(short_hash("1234567890abcdef"), "1234567890ab");
        assert_eq!(short_hash("short"), "short");
    }
}
