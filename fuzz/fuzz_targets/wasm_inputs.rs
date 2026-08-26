#![no_main]

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use soroban_upgrades_core::Artifact;
use wasm_smith::{Config, Module};

fuzz_target!(|data: &[u8]| {
    let _ = Artifact::from_wasm(data);

    let mut input = Unstructured::new(data);
    if let Ok(module) = Module::new(Config::default(), &mut input) {
        let _ = Artifact::from_wasm(&module.to_bytes());
    }
});
