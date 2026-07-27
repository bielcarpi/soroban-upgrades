#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contractmeta, contracttype, panic_with_error, Address,
    BytesN, Env,
};

contractmeta!(key = "binver", val = "1.0.0");

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Account,
}

#[contracttype]
#[derive(Clone)]
pub struct Account {
    pub owner: Address,
    pub balance: i128,
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
        env.storage()
            .persistent()
            .set(&DataKey::Account, &Account { owner, balance: 0 });
    }

    pub fn balance(env: Env) -> i128 {
        let account: Account = env.storage().persistent().get(&DataKey::Account).unwrap();
        account.balance
    }

    pub fn account(env: Env) -> Account {
        env.storage().persistent().get(&DataKey::Account).unwrap()
    }

    pub fn deposit(env: Env, amount: i128) -> i128 {
        let mut account: Account = env.storage().persistent().get(&DataKey::Account).unwrap();
        account.balance += amount;
        env.storage().persistent().set(&DataKey::Account, &account);
        account.balance
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
