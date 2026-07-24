#![no_std]

use soroban_sdk::{contract, contractimpl, contractmeta, contracttype, Address, Env};

// Deliberately not greater than v1.
contractmeta!(key = "binver", val = "1.0.0");

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Count,
}

#[contract]
pub struct UnsafeCounter;

#[contractimpl]
impl UnsafeCounter {
    // Constructors are not invoked on Soroban WASM replacement.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Count, &0_u64);
    }

    // The return type changes and the upgrade entrypoint is removed.
    pub fn count(env: Env) -> u64 {
        env.storage().instance().get(&DataKey::Count).unwrap_or(0)
    }
}
