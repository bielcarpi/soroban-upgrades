use serde_json::json;
use soroban_env_host::{
    budget::Budget,
    storage::Storage,
    testutils::{generate_account_id, generate_bytes_array, MockSnapshotSource},
    Env, EnvBase, Host, HostError, LedgerInfo, Symbol, TryFromVal, U32Val, Val, VecObject,
};
use soroban_upgrades_core::{inspect_export_call_evidence, inspect_function_imports};
use std::{env, fs, path::Path, rc::Rc};

const PROTOCOL_28: u32 = 28;
const EXPECTED_FUNCTION_IMPORTS: [&str; 5] = ["m.9", "m.b", "v.g", "m.a", "m.c"];

fn host_for_protocol(protocol_version: u32) -> Result<Host, HostError> {
    let snapshot = Rc::new(MockSnapshotSource::new());
    let storage = Storage::with_recording_footprint(snapshot);
    let host = Host::with_storage_and_budget(storage, Budget::default());
    host.set_ledger_info(LedgerInfo {
        protocol_version,
        sequence_number: 1,
        timestamp: 0,
        network_id: [0; 32],
        base_reserve: 0,
        min_persistent_entry_ttl: 4096,
        min_temp_entry_ttl: 16,
        max_entry_ttl: 6_312_000,
    })?;
    host.set_test_prng();
    host.with_budget(|budget| {
        budget.reset_unlimited()?;
        Ok(())
    })?;
    Ok(host)
}

fn invoke(wasm: &[u8], export: &str, protocol: u32) -> Result<(Host, Val), HostError> {
    let host = host_for_protocol(protocol)?;
    let account = generate_account_id(&host);
    let salt = generate_bytes_array(&host);
    let contract = host.register_test_contract_wasm_from_source_account(wasm, account, salt)?;
    let function = Symbol::try_from_val(&host, &export)?;
    let arguments = host.vec_new_from_slice(&[])?;
    let result = host.call(contract, function, arguments)?;
    Ok((host, result))
}

fn vector_values(host: &Host, value: Val) -> Result<Vec<Option<u32>>, HostError> {
    let vector = VecObject::try_from_val(host, &value)?;
    let length: u32 = host.vec_len(vector)?.into();
    (0..length)
        .map(|index| {
            let value = host.vec_get(vector, U32Val::from(index))?;
            if value.is_void() {
                Ok(None)
            } else {
                let value: u32 = U32Val::try_from_val(host, &value)?.into();
                Ok(Some(value))
            }
        })
        .collect()
}

fn expect_values(wasm: &[u8], export: &str, expected: &[Option<u32>]) -> Result<(), String> {
    let (host, value) = invoke(wasm, export, PROTOCOL_28)
        .map_err(|error| format!("{export} should execute under protocol 28: {error}"))?;
    let observed = vector_values(&host, value)
        .map_err(|error| format!("{export} should return a u32/Void vector: {error}"))?;
    if observed != expected {
        return Err(format!(
            "{export} returned {observed:?}; expected {expected:?}"
        ));
    }
    Ok(())
}

fn expect_trap(wasm: &[u8], export: &str, protocol: u32) -> Result<String, String> {
    match invoke(wasm, export, protocol) {
        Ok(_) => Err(format!(
            "{export} unexpectedly executed under protocol {protocol}"
        )),
        Err(error) => Ok(error.to_string()),
    }
}

fn require_reachable_imports(wasm: &[u8]) -> Result<(), String> {
    let imports = inspect_function_imports(wasm)
        .map_err(|error| format!("function-import inspection failed: {error}"))?;
    let observed_imports = imports
        .iter()
        .map(|import| import.canonical_name())
        .collect::<Vec<_>>();
    if observed_imports != EXPECTED_FUNCTION_IMPORTS {
        return Err(format!(
            "function-import contract is {observed_imports:?}; expected {EXPECTED_FUNCTION_IMPORTS:?}"
        ));
    }

    let evidence = inspect_export_call_evidence(wasm)
        .map_err(|error| format!("call-graph inspection failed: {error}"))?;
    let expectations = [
        ("old_to_new_sparse", ["m.9", "m.c", "v.g"].as_slice()),
        ("old_to_new_dense", ["m.9", "m.a", "v.g"].as_slice()),
        ("new_none_to_old_dense", ["m.a", "m.b", "v.g"].as_slice()),
        ("new_some_to_old_dense", ["m.a", "m.b", "v.g"].as_slice()),
        ("new_some_to_new_sparse", ["m.b", "m.c", "v.g"].as_slice()),
    ];
    for (export, expected) in expectations {
        let observed = evidence
            .get(export)
            .ok_or_else(|| format!("required export {export} is absent"))?;
        if observed.dynamic_dispatch_reachable {
            return Err(format!(
                "{export} reaches dynamic dispatch, so its host-call graph is incomplete"
            ));
        }
        let expected = expected.iter().map(|value| (*value).to_owned()).collect();
        if observed.host_imports != expected {
            return Err(format!(
                "{export} reaches {:?}; expected {expected:?}",
                observed.host_imports
            ));
        }
    }
    Ok(())
}

fn run(wasm_path: &Path) -> Result<serde_json::Value, String> {
    let wasm = fs::read(wasm_path)
        .map_err(|error| format!("cannot read {}: {error}", wasm_path.display()))?;
    require_reachable_imports(&wasm)?;

    expect_values(&wasm, "old_to_new_sparse", &[None, Some(10), Some(20)])?;
    let dense_old_to_new = expect_trap(&wasm, "old_to_new_dense", PROTOCOL_28)?;
    expect_values(&wasm, "new_none_to_old_dense", &[Some(10), Some(20)])?;
    let present_to_old = expect_trap(&wasm, "new_some_to_old_dense", PROTOCOL_28)?;
    expect_values(
        &wasm,
        "new_some_to_new_sparse",
        &[Some(30), Some(10), Some(20)],
    )?;
    let protocol_27 = expect_trap(&wasm, "old_to_new_sparse", 27)?;

    Ok(json!({
        "status": "PASS",
        "hostVersion": "28.0.1",
        "protocol": 28,
        "facts": {
            "denseOldToSparseNew": [null, 10, 20],
            "denseOldToDenseNew": "TRAP",
            "sparseNewNoneToDenseOld": [10, 20],
            "sparseNewSomeToDenseOld": "TRAP",
            "sparseNewSomeToSparseNew": [30, 10, 20],
            "protocol27RejectsProtocol28Guest": true
        },
        "trapEvidence": {
            "denseOldToDenseNew": dense_old_to_new,
            "sparseNewSomeToDenseOld": present_to_old,
            "protocol27": protocol_27
        },
        "inference": "Optional-field rollout can preserve an old dense reader only while the sparse writer omits the new field.",
        "unknown": [
            "SDK-generated per-type sparse reader binding",
            "persisted ledger-state migration",
            "complete deployed caller graph",
            "public-network protocol activation"
        ]
    }))
}

fn main() {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: cap0086-runtime-runner <guest.wasm>");
        std::process::exit(2);
    };
    match run(Path::new(&path)) {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(error) => {
            eprintln!("CAP-0086 runtime witness failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::require_reachable_imports;

    const IMPORTS: &str = r#"
        (import "m" "9" (func $dense_write))
        (import "m" "b" (func $sparse_write))
        (import "v" "g" (func $vec_new))
        (import "m" "a" (func $dense_read))
        (import "m" "c" (func $sparse_read))
    "#;

    const EXPORTS: &str = r#"
        (func (export "old_to_new_sparse")
            call $dense_write call $sparse_read call $vec_new)
        (func (export "old_to_new_dense")
            call $dense_write call $dense_read call $vec_new)
        (func (export "new_none_to_old_dense")
            call $sparse_write call $dense_read call $vec_new)
        (func (export "new_some_to_old_dense")
            call $sparse_write call $dense_read call $vec_new)
        (func (export "new_some_to_new_sparse")
            call $sparse_write call $sparse_read call $vec_new)
    "#;

    fn module(imports: &str, exports: &str) -> Vec<u8> {
        wat::parse_str(format!("(module {imports} {exports})")).unwrap()
    }

    fn rejection(imports: &str, exports: &str) -> String {
        require_reachable_imports(&module(imports, exports)).unwrap_err()
    }

    #[test]
    fn canonical_witness_contract_passes() {
        require_reachable_imports(&module(IMPORTS, EXPORTS)).unwrap();
    }

    #[test]
    fn extra_manual_lookup_import_fails_closed() {
        let imports = format!("{IMPORTS} (import \"m\" \"manual_lookup\" (func $manual))");
        assert!(rejection(&imports, EXPORTS).contains("function-import contract"));
    }

    #[test]
    fn missing_sparse_reader_import_fails_closed() {
        let imports = IMPORTS.replace("(import \"m\" \"c\" (func $sparse_read))", "");
        let exports = format!("(func $sparse_read) {EXPORTS}");
        assert!(rejection(&imports, &exports).contains("function-import contract"));
    }

    #[test]
    fn duplicate_import_fails_closed() {
        let imports = format!("{IMPORTS} (import \"m\" \"c\" (func $sparse_read_decoy))");
        assert!(rejection(&imports, EXPORTS).contains("function-import contract"));
    }

    #[test]
    fn reordered_imports_fail_closed() {
        let imports = r#"
            (import "m" "b" (func $sparse_write))
            (import "m" "9" (func $dense_write))
            (import "v" "g" (func $vec_new))
            (import "m" "a" (func $dense_read))
            (import "m" "c" (func $sparse_read))
        "#;
        assert!(rejection(imports, EXPORTS).contains("function-import contract"));
    }

    #[test]
    fn swapped_sparse_selector_in_call_graph_fails_closed() {
        let exports = EXPORTS.replacen(
            "call $dense_write call $sparse_read call $vec_new",
            "call $dense_write call $dense_read call $vec_new",
            1,
        );
        assert!(rejection(IMPORTS, &exports).contains("old_to_new_sparse reaches"));
    }

    #[test]
    fn dynamic_dispatch_fails_closed() {
        let exports = EXPORTS.replacen(
            "call $dense_write call $sparse_read call $vec_new",
            "i32.const 0 call_indirect (type $callback)",
            1,
        );
        let prelude = r#"
            (type $callback (func))
            (func $target)
            (table 1 funcref)
            (elem (i32.const 0) $target)
        "#;
        let wasm = module(IMPORTS, &format!("{prelude} {exports}"));
        assert!(require_reachable_imports(&wasm)
            .unwrap_err()
            .contains("reaches dynamic dispatch"));
    }

    #[test]
    fn hardcoded_result_cannot_substitute_for_host_calls() {
        let exports = EXPORTS.replacen(
            "call $dense_write call $sparse_read call $vec_new",
            "call $vec_new",
            1,
        );
        assert!(rejection(IMPORTS, &exports).contains("old_to_new_sparse reaches"));
    }
}
