//! Mock token contract for testing the ignored-return vulnerability.
//!
//! `MockToken` is a minimal ERC-20-style token that can be configured to
//! silently no-op on `transfer()` (i.e. do nothing and return without
//! panicking). This simulates a token contract that "fails" without
//! propagating an error — exactly the scenario the vulnerability exploits.

#![allow(dead_code)]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum MockKey {
    /// If `true`, `transfer()` is a silent no-op.
    ShouldFail,
    /// Token balances keyed by address.
    Balance(Address),
}

#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    /// Mint `amount` tokens to `to`.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current: i128 = env
            .storage()
            .persistent()
            .get(&MockKey::Balance(to.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(current + amount));
    }

    /// Configure whether `transfer()` should silently fail.
    pub fn set_fail(env: Env, fail: bool) {
        env.storage()
            .persistent()
            .set(&MockKey::ShouldFail, &fail);
    }

    /// Transfer `amount` from `from` to `to`.
    ///
    /// When `ShouldFail` is `true` this is a silent no-op — it returns
    /// without moving any tokens and without panicking. This is the
    /// condition that the vulnerable escrow fails to detect.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let should_fail: bool = env
            .storage()
            .persistent()
            .get(&MockKey::ShouldFail)
            .unwrap_or(false);

        if should_fail {
            // Silent no-op — no tokens move, no panic.
            return;
        }

        let from_bal: i128 = env
            .storage()
            .persistent()
            .get(&MockKey::Balance(from.clone()))
            .unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");

        let to_bal: i128 = env
            .storage()
            .persistent()
            .get(&MockKey::Balance(to.clone()))
            .unwrap_or(0);

        env.storage()
            .persistent()
            .set(&MockKey::Balance(from), &(from_bal - amount));
        env.storage()
            .persistent()
            .set(&MockKey::Balance(to), &(to_bal + amount));
    }

    /// Return the balance of `account`.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&MockKey::Balance(account))
            .unwrap_or(0)
    }
}
