#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, panic_with_error, Address,
    BytesN, Env,
};

contractmeta!(key = "binver", val = "3.0.0");

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Account,
}

// Deliberately unsafe even after CAP-0086: rename, signedness/width change,
// and optional-to-required transition are semantic migrations, not sparse-map fixes.
#[contracttype]
#[derive(Clone)]
pub struct Account {
    pub owner: Address,
    pub amount: u64,
    pub status: u32,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    Unauthorized = 1,
}

#[contract]
pub struct Cap86Account;

#[contractimpl]
impl Cap86Account {
    pub fn __constructor(env: Env, owner: Address) {
        env.storage().persistent().set(
            &DataKey::Account,
            &Account {
                owner,
                amount: 0,
                status: 0,
            },
        );
    }

    pub fn balance(env: Env) -> i128 {
        let account: Account = env.storage().persistent().get(&DataKey::Account).unwrap();
        account.amount as i128
    }

    pub fn account(env: Env) -> Account {
        env.storage().persistent().get(&DataKey::Account).unwrap()
    }

    pub fn deposit(env: Env, amount: i128) -> i128 {
        let mut account: Account = env.storage().persistent().get(&DataKey::Account).unwrap();
        account.amount = account.amount.saturating_add(amount.max(0) as u64);
        env.storage().persistent().set(&DataKey::Account, &account);
        account.amount as i128
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>, operator: Address) {
        operator.require_auth();
        let account: Account = env.storage().persistent().get(&DataKey::Account).unwrap();
        if account.owner != operator {
            panic_with_error!(&env, ContractError::Unauthorized);
        }
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
