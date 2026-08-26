#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_upgrades_core::{Artifact, Policy, SchemaHistory, StorageSchema, UpgradePlan};

fuzz_target!(|data: &[u8]| {
    let _ = Artifact::from_wasm(data);
    let _ = Policy::from_json(data);
    let _ = StorageSchema::from_json(data);
    let _ = SchemaHistory::from_json(data);
    let _ = UpgradePlan::from_json(data);
});
