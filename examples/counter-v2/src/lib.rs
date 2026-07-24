#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, panic_with_error, Address,
    BytesN, Env,
};

contractmeta!(key = "binver", val = "2.0.0");

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Config,
    SchemaVersion,
}

// Retaining the exact v1 type is what makes host-level decoding of legacy state safe.
#[contracttype]
#[derive(Clone)]
pub struct ConfigV1 {
    pub count: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct ConfigV2 {
    pub count: u32,
    pub paused: bool,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    Unauthorized = 1,
    Paused = 2,
}

#[contract]
pub struct Counter;

#[contractimpl]
impl Counter {
    // Fresh deployments still need initialization. Soroban skips this function
    // when replacing WASM, so existing deployments use `migrate`/`load_v2`.
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(
            &DataKey::Config,
            &ConfigV2 {
                count: 0,
                paused: false,
            },
        );
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &2_u32);
    }

    pub fn count(env: Env) -> u32 {
        load_v2(&env).count
    }

    pub fn increment(env: Env) -> u32 {
        let mut config = load_v2(&env);
        if config.paused {
            panic_with_error!(&env, ContractError::Paused);
        }
        config.count += 1;
        env.storage().instance().set(&DataKey::Config, &config);
        config.count
    }

    pub fn paused(env: Env) -> bool {
        load_v2(&env).paused
    }

    pub fn set_paused(env: Env, operator: Address, paused: bool) {
        require_admin(&env, &operator);
        let mut config = load_v2(&env);
        config.paused = paused;
        env.storage().instance().set(&DataKey::Config, &config);
    }

    // Idempotent eager migration is available to upgrade orchestrators. The same
    // conversion also runs lazily on first use, eliminating a dangerous window.
    pub fn migrate(env: Env, operator: Address) {
        require_admin(&env, &operator);
        let _ = load_v2(&env);
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, operator: Address) {
        require_admin(&env, &operator);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

fn require_admin(env: &Env, operator: &Address) {
    operator.require_auth();
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    if admin != *operator {
        panic_with_error!(env, ContractError::Unauthorized);
    }
}

fn load_v2(env: &Env) -> ConfigV2 {
    let schema_version = env
        .storage()
        .instance()
        .get::<_, u32>(&DataKey::SchemaVersion)
        .unwrap_or(0);
    if schema_version < 2 {
        let old: ConfigV1 = env.storage().instance().get(&DataKey::Config).unwrap();
        let new = ConfigV2 {
            count: old.count,
            paused: false,
        };
        env.storage().instance().set(&DataKey::Config, &new);
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &2_u32);
        new
    } else {
        env.storage().instance().get(&DataKey::Config).unwrap()
    }
}
