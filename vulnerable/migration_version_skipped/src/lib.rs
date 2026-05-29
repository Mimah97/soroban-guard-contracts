#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

#[contracttype]
pub enum DataKey {
    Balances,
    SchemaVersion,
    Admin,
}

#[contract]
pub struct MigrationVersionSkipped;

#[contractimpl]
impl MigrationVersionSkipped {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::SchemaVersion, &0u32);
        let mut balances: Map<Address, i128> = Map::new(&env);
        balances.set(admin.clone(), 1_000_000i128);
        env.storage().instance().set(&DataKey::Balances, &balances);
    }

    /// BUG: migration rewrites layout without an expected-version guard.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = (actor, amount);
        let balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        let mut new_balances: Map<Address, i128> = Map::new(&env);
        for (addr, balance) in balances.iter() {
            new_balances.set(addr, balance * 2);
        }
        env.storage().instance().set(&DataKey::Balances, &new_balances);
    }

    pub fn migrate_vulnerable(env: Env, caller: Address) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }

        let balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        let mut new_balances: Map<Address, i128> = Map::new(&env);
        for (addr, balance) in balances.iter() {
            new_balances.set(addr, balance * 10);
        }
        env.storage().instance().set(&DataKey::Balances, &new_balances);
    }

    pub fn migrate_secure(env: Env, caller: Address, expected_version: u32) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }

        let current_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(0);
        if current_version != expected_version {
            panic!("version mismatch");
        }

        let balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        let mut new_balances: Map<Address, i128> = Map::new(&env);
        for (addr, balance) in balances.iter() {
            new_balances.set(addr, balance * 10);
        }
        env.storage().instance().set(&DataKey::Balances, &new_balances);
        env.storage()
            .instance()
            .set(&DataKey::SchemaVersion, &(current_version + 1));
    }

    pub fn get_balance(env: Env, addr: Address) -> i128 {
        let balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        balances.get(addr).unwrap_or(0)
    }

    pub fn get_schema_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::SchemaVersion)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (Address, Address) {
        let contract_id = env.register_contract(None, MigrationVersionSkipped);
        let client = MigrationVersionSkippedClient::new(env, &contract_id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.init(&admin);
        (contract_id, admin)
    }

    #[test]
    fn test_vulnerable_double_migration_corrupts_balances() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = MigrationVersionSkippedClient::new(&env, &contract_id);

        assert_eq!(client.get_balance(&admin), 1_000_000);
        client.migrate_vulnerable(&admin);
        assert_eq!(client.get_balance(&admin), 10_000_000);
        client.migrate_vulnerable(&admin);
        assert_eq!(client.get_balance(&admin), 100_000_000);
    }

    #[test]
    fn test_secure_first_migration_succeeds() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = MigrationVersionSkippedClient::new(&env, &contract_id);

        client.migrate_secure(&admin, &0u32);
        assert_eq!(client.get_balance(&admin), 10_000_000);
        assert_eq!(client.get_schema_version(), 1);
    }

    #[test]
    #[should_panic(expected = "version mismatch")]
    fn test_secure_rejects_second_migration_run() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = MigrationVersionSkippedClient::new(&env, &contract_id);

        client.migrate_secure(&admin, &0u32);
        client.migrate_secure(&admin, &0u32);
    }

    #[test]
    fn test_boundary_wrong_expected_version_rejected() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = MigrationVersionSkippedClient::new(&env, &contract_id);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.migrate_secure(&admin, &99u32);
        }));
        assert!(result.is_err(), "wrong version should panic");
    }
}
