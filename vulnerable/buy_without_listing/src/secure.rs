use super::{DataKey, Listing};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureMarketplace;

#[contractimpl]
impl SecureMarketplace {
    pub fn mint(env: Env, owner: Address, token_id: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &owner);
    }

    pub fn fund(env: Env, buyer: Address, amount: i128) {
        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(buyer.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(buyer), &(bal + amount));
    }

    /// ✅ Seller creates an explicit listing stored on-chain.
    pub fn list(env: Env, seller: Address, token_id: u64, price: i128) {
        seller.require_auth();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(token_id))
            .expect("token not found");
        if owner != seller {
            panic!("not owner");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Listing(token_id), &Listing { seller, price });
    }

    /// ✅ SECURE: requires a stored listing before transferring the NFT.
    pub fn buy(env: Env, buyer: Address, token_id: u64, max_price: i128) {
        buyer.require_auth();

        // ✅ Listing must exist.
        let listing: Listing = env
            .storage()
            .persistent()
            .get(&DataKey::Listing(token_id))
            .expect("no active listing");

        if max_price < listing.price {
            panic!("price too low");
        }

        // Deduct payment from buyer.
        let buyer_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(buyer.clone()))
            .unwrap_or(0);
        if buyer_bal < listing.price {
            panic!("insufficient funds");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Balance(buyer.clone()), &(buyer_bal - listing.price));

        // Credit seller.
        let seller_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(listing.seller.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(listing.seller.clone()), &(seller_bal + listing.price));

        // Transfer NFT and remove listing.
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &buyer);
        env.storage()
            .persistent()
            .remove(&DataKey::Listing(token_id));
    }

    pub fn owner_of(env: Env, token_id: u64) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Owner(token_id))
    }

    pub fn balance_of(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}
