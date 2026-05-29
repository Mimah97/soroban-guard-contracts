use super::{AuditRecord, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAuditRegistry;

#[contractimpl]
impl SecureAuditRegistry {
    pub fn submit_audit(
        env: Env,
        auditor: Address,
        contract_id: u64,
        expiry_ledger: u32,
    ) {
        auditor.require_auth();
        let record = AuditRecord {
            auditor,
            expiry_ledger,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Audit(contract_id), &record);
    }

    /// ✅ SECURE: returns `None` when the audit has expired.
    pub fn get_active_audit(env: Env, contract_id: u64) -> Option<AuditRecord> {
        let record: AuditRecord = env
            .storage()
            .persistent()
            .get(&DataKey::Audit(contract_id))?;

        // ✅ Expiry check: treat past-expiry records as absent.
        if env.ledger().sequence() > record.expiry_ledger {
            return None;
        }

        Some(record)
    }

    pub fn is_active(env: Env, contract_id: u64) -> bool {
        SecureAuditRegistry::get_active_audit(env, contract_id).is_some()
    }
}
