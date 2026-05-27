//! SECURE: Escrow with Propagated Sub-Call Result
//!
//! This is the fixed mirror of `VulnerableEscrow`.
//!
//! FIX APPLIED:
//! `release()` calls `token_interface::TokenClient::transfer()` directly,
//! without wrapping it in `let _ = ...`. In Soroban, a panicking sub-call
//! rolls back the entire transaction. Because we no longer discard the
//! result, any failure in the token contract propagates upward and the
//! `Released` flag is never set to `true` unless the transfer actually
//! succeeded.

use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, token_interface};

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
    /// Initialise the escrow with a token, recipient, and locked amount.
    ///
    /// # Panics
    /// Panics if the escrow has already been initialised.
    pub fn initialize(
        env: Env,
        owner: Address,
        token_id: Address,
        recipient: Address,
        amount: i128,
    ) {
        owner.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Released),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Owner, &owner);
        env.storage().persistent().set(&DataKey::TokenId, &token_id);
        env.storage().persistent().set(&DataKey::Recipient, &recipient);
        env.storage().persistent().set(&DataKey::Amount, &amount);
        env.storage().persistent().set(&DataKey::Released, &false);
    }

    /// Release escrowed funds to the recipient.
    ///
    /// ✅ SECURE: `transfer()` is called directly — no `let _ = ...`.
    ///    If the token contract panics the Soroban host rolls back the
    ///    entire transaction, so `Released` is never set to `true` unless
    ///    the transfer actually succeeded.
    pub fn release(env: Env) {
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner)
            .unwrap();
        owner.require_auth();

        let released: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false);
        assert!(!released, "already released");

        let token_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::TokenId)
            .unwrap();
        let recipient: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Recipient)
            .unwrap();
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Amount)
            .unwrap();

        // ✅ FIX: call transfer directly — result is NOT discarded.
        //    A panicking token contract rolls back the whole transaction,
        //    so Released is never set to true unless the transfer succeeds.
        token_interface::TokenClient::new(&env, &token_id)
            .transfer(&env.current_contract_address(), &recipient, &amount);

        env.storage()
            .persistent()
            .set(&DataKey::Released, &true);
    }

    /// Returns `true` if the escrow has been released.
    pub fn is_released(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};
    use crate::token::{MockToken, MockTokenClient};

    fn setup(env: &Env, should_fail: bool) -> (
        SecureEscrowClient,
        Address, // owner
        Address, // recipient
        Address, // escrow contract id
    ) {
        let token_id = env.register_contract(None, MockToken);
        let token_client = MockTokenClient::new(env, &token_id);
        token_client.set_fail(&should_fail);

        let escrow_id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(env, &escrow_id);

        let owner = Address::generate(env);
        let recipient = Address::generate(env);

        // Mint tokens to the escrow contract so it has funds to release.
        token_client.mint(&escrow_id, &500);

        client.initialize(&owner, &token_id, &recipient, &500);

        (client, owner, recipient, escrow_id)
    }

    /// Normal release: token transfer succeeds and escrow is marked released.
    #[test]
    fn test_secure_normal_release_works() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, _owner, _recipient, _escrow_id) = setup(&env, false);

        assert!(!client.is_released());
        client.release();
        assert!(client.is_released());
    }

    /// Secure version: when the token contract panics (e.g. insufficient
    /// balance), the panic propagates through the direct call and rolls back
    /// the entire transaction — the escrow is NOT marked as released.
    ///
    /// This test uses a token with zero balance for the escrow, so the
    /// `assert!(from_bal >= amount)` inside `MockToken::transfer` panics.
    /// Because `SecureEscrow::release` calls `transfer()` directly (no
    /// `let _ = ...`), the panic propagates and the transaction is rolled
    /// back — `Released` is never set to `true`.
    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn test_secure_rejects_failed_sub_call() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, MockToken);
        // No set_fail, no mint — escrow balance is 0.
        let _token_client = MockTokenClient::new(&env, &token_id);

        let escrow_id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(&env, &escrow_id);

        let owner = Address::generate(&env);
        let recipient = Address::generate(&env);

        // Intentionally do NOT mint tokens to the escrow — balance is 0.
        // When release() calls transfer(escrow, recipient, 500), the token
        // contract will panic with "insufficient balance".
        client.initialize(&owner, &token_id, &recipient, &500);

        // ✅ SECURE: the panic from the token contract propagates here,
        //    rolling back the transaction. Released is never set to true.
        client.release();
    }
}
