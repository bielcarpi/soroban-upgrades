use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_soroban-upgrades"))
}

#[test]
fn help_exposes_the_complete_read_only_workflow() {
    let output = cli().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in ["inspect", "validate", "plan", "verify-plan"] {
        assert!(stdout.contains(command), "help omitted {command}");
    }
    assert!(stdout.contains("Validate and plan safe Soroban contract upgrades"));
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
