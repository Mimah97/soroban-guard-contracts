use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureReportRegistry;

#[contractimpl]
impl SecureReportRegistry {
    /// ✅ Rejects a zero threshold at configuration time.
    pub fn set_threshold(env: Env, admin: Address, threshold: u32) {
        admin.require_auth();
        if threshold == 0 {
            panic!("threshold must be > 0");
        }
        env.storage().persistent().set(&DataKey::Threshold, &threshold);
    }

    pub fn approve(env: Env, verifier: Address, report_id: u64) {
        verifier.require_auth();
        let key = DataKey::Approvals(report_id);
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
    }

    /// ✅ SECURE: requires `approvals >= threshold`.
    pub fn finalize_report(env: Env, report_id: u64) {
        let threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Threshold)
            .expect("threshold not set");

        let approvals: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Approvals(report_id))
            .unwrap_or(0);

        // ✅ Full quorum check.
        if approvals < threshold {
            panic!("threshold not met");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Finalized(report_id), &true);
    }

    pub fn is_finalized(env: Env, report_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Finalized(report_id))
            .unwrap_or(false)
    }

    pub fn approval_count(env: Env, report_id: u64) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Approvals(report_id))
            .unwrap_or(0)
    }
}
