#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, panic_with_error, Address,
    BytesN, Env,
};

contractmeta!(key = "binver", val = "1.0.0");

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Config,
    SchemaVersion,
}

#[contracttype]
#[derive(Clone)]
pub struct ConfigV1 {
    pub count: u32,
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
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::Config, &ConfigV1 { count: 0 });
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &1_u32);
    }

    pub fn count(env: Env) -> u32 {
        let config: ConfigV1 = env.storage().instance().get(&DataKey::Config).unwrap();
        config.count
    }

    pub fn increment(env: Env) -> u32 {
        let mut config: ConfigV1 = env.storage().instance().get(&DataKey::Config).unwrap();
        config.count += 1;
        env.storage().instance().set(&DataKey::Config, &config);
        config.count
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, operator: Address) {
        operator.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if admin != operator {
            panic_with_error!(&env, ContractError::Unauthorized);
        }
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
