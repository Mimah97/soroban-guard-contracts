//! VULNERABLE: Scanner Metadata Stored Without Size Limit
//!
//! A scanner registry contract where `register_scanner` persists arbitrary
//! caller-supplied metadata strings with no length cap. An attacker can submit
//! very large metadata payloads, bloating persistent storage and increasing
//! ledger rent costs for every reader of that entry.
//!
//! VULNERABILITY: Caller-supplied `metadata` is written to persistent storage
//! without any length validation — missing `assert!(metadata.len() <= MAX_METADATA_LEN)`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

pub mod secure;

/// Maximum allowed byte length for scanner metadata in the secure implementation.
pub const MAX_METADATA_LEN: u32 = 256;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Metadata(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ScannerRegistry;

#[contractimpl]
impl ScannerRegistry {
    /// VULNERABLE: stores caller-supplied `metadata` for `scanner` with no size cap.
    ///
    /// # Vulnerability
    /// Missing `assert!(metadata.len() <= MAX_METADATA_LEN)`.
    /// Impact: unbounded storage growth — attackers can persist arbitrarily large
    /// strings, inflating ledger rent and exceeding practical read limits.
    pub fn register_scanner(env: Env, scanner: Address, metadata: String) {
        scanner.require_auth();
        // ❌ Missing: assert!(metadata.len() <= MAX_METADATA_LEN, "metadata too large");
        env.storage()
            .persistent()
            .set(&DataKey::Metadata(scanner), &metadata);
    }

    /// Returns the stored metadata for `scanner`, or an empty string if not registered.
    pub fn get_metadata(env: Env, scanner: Address) -> String {
        env.storage()
            .persistent()
            .get(&DataKey::Metadata(scanner))
            .unwrap_or(String::from_str(&env, ""))
    }

    /// Fixture entry matching the issue's vulnerable pattern signature.
    ///
    /// # Vulnerability
    /// `actor` and `amount` are accepted but unused; the real unsafe path is
    /// that any metadata string — regardless of size — is persisted.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        // BUG: caller supplied metadata is persisted without length cap.
        // The fixture should make this unsafe path reachable and easy to scan.
        let _ = (env, actor, amount);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureScannerRegistryClient;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ScannerRegistry);
        (env, id)
    }

    /// Demonstrates the vulnerability: huge metadata is accepted and stored.
    #[test]
    fn test_vulnerable_stores_huge_metadata() {
        let (env, id) = setup();
        let client = ScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        // Build a metadata string well beyond any reasonable limit.
        let huge: String = String::from_str(&env, &"A".repeat(10_000));

        // ❌ Vulnerable path: no rejection — oversized metadata is persisted.
        client.register_scanner(&scanner, &huge);

        let stored = client.get_metadata(&scanner);
        assert_eq!(stored.len(), 10_000);
    }

    /// Boundary condition: a string of exactly MAX_METADATA_LEN + 1 should be
    /// rejected by the secure implementation but is accepted by the vulnerable one.
    #[test]
    fn test_vulnerable_accepts_boundary_violation() {
        let (env, id) = setup();
        let client = ScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        let over_limit: String =
            String::from_str(&env, &"X".repeat((MAX_METADATA_LEN + 1) as usize));

        // Vulnerable contract stores it without complaint.
        client.register_scanner(&scanner, &over_limit);
        assert_eq!(client.get_metadata(&scanner).len(), MAX_METADATA_LEN + 1);
    }

    /// Secure implementation rejects metadata that exceeds MAX_METADATA_LEN.
    #[test]
    #[should_panic]
    fn test_secure_rejects_oversized_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        let over_limit: String =
            String::from_str(&env, &"X".repeat((MAX_METADATA_LEN + 1) as usize));

        // ✅ Secure path: panics because metadata exceeds the cap.
        client.register_scanner(&scanner, &over_limit);
    }

    /// Secure implementation accepts metadata within the allowed length.
    #[test]
    fn test_secure_accepts_valid_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        let valid: String = String::from_str(&env, "scanner-v1.0.0");
        client.register_scanner(&scanner, &valid);
        assert_eq!(client.get_metadata(&scanner).len(), 14);
    }

    /// Secure implementation rejects empty metadata.
    #[test]
    #[should_panic]
    fn test_secure_rejects_empty_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        // ✅ Secure path: panics because metadata is empty.
        client.register_scanner(&scanner, &String::from_str(&env, ""));
    }
}
