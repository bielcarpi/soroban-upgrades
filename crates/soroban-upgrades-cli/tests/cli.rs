use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrades"))
}

#[test]
fn help_exposes_the_complete_read_only_workflow() {
    let output = cli().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in ["inspect", "schema", "validate", "plan", "verify-plan"] {
        assert!(stdout.contains(command), "help omitted {command}");
    }
    assert!(stdout.contains("Check compiled Soroban contract upgrades before signer review"));
}

#[test]
fn schema_command_emits_machine_readable_contracts() {
    for kind in ["artifact", "policy", "storage", "history", "report", "plan"] {
        let output = cli().args(["schema", kind]).output().unwrap();
        assert!(output.status.success(), "schema command failed for {kind}");
        let schema: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(schema.get("$schema").is_some());
        assert!(schema.get("title").is_some());
    }
}

#[test]
fn inspect_reports_a_contextual_missing_artifact_error() {
    let output = cli()
        .args(["inspect", "--wasm", "definitely-missing-contract.wasm"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("reading definitely-missing-contract.wasm"));
}

#[test]
fn validate_requires_storage_manifests_as_a_pair() {
    let output = cli()
        .args([
            "validate",
            "--from",
            "baseline.wasm",
            "--to",
            "candidate.wasm",
            "--from-schema",
            "baseline.schema.json",
            "--protocol-version",
            "27",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--to-schema"));
}

#[test]
fn plan_requires_an_application_invariant_program() {
    let output = cli()
        .args([
            "plan",
            "--from",
            "baseline.wasm",
            "--to",
            "candidate.wasm",
            "--from-schema",
            "baseline.schema.json",
            "--to-schema",
            "candidate.schema.json",
            "--schema-history",
            "schema-history.json",
            "--protocol-version",
            "27",
            "--network",
            "testnet",
            "--contract-id",
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--invariant-program"));
}
