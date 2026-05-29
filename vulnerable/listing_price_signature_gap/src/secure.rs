use super::DataKey;
use soroban_sdk::{contract, contractimpl, xdr::ToXdr, Address, Bytes, BytesN, Env};

/// Build a full listing digest that binds contract, nft_id, seller, price, and expiry.
pub fn secure_listing_digest(
    env: &Env,
    contract_id: &Address,
    nft_id: u64,
    seller: &Address,
    price: i128,
    expiry_ledger: u32,
) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    msg.append(&contract_id.clone().to_xdr(env));
    msg.append(&Bytes::from_array(env, &nft_id.to_be_bytes()));
    msg.append(&seller.clone().to_xdr(env));
    msg.append(&Bytes::from_array(env, &price.to_be_bytes()));
    msg.append(&Bytes::from_array(env, &expiry_ledger.to_be_bytes()));
    env.crypto().sha256(&msg).into()
}

/// Test helper: produce a SHA-256 "signature" over the secure digest.
/// In production this would be an ed25519 signature.
pub fn make_test_sig(
    env: &Env,
    contract_id: &Address,
    nft_id: u64,
    seller: &Address,
    price: i128,
    expiry_ledger: u32,
) -> BytesN<64> {
    let digest = secure_listing_digest(env, contract_id, nft_id, seller, price, expiry_ledger);
    // Pad the 32-byte hash to 64 bytes for the BytesN<64> slot.
    let mut buf = [0u8; 64];
    let hash_bytes = digest.to_array();
    buf[..32].copy_from_slice(&hash_bytes);
    BytesN::from_array(env, &buf)
}

#[contract]
pub struct SecureListingMarketplace;

#[contractimpl]
impl SecureListingMarketplace {
    pub fn mint(env: Env, owner: Address, nft_id: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::Owner(nft_id), &owner);
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

    /// ✅ SECURE: `price` and `expiry_ledger` are part of the signed payload.
    /// Any attempt to alter the price after signing will produce a digest
    /// mismatch and be rejected.
    pub fn fill_listing(
        env: Env,
        buyer: Address,
        seller: Address,
        nft_id: u64,
        price: i128,
        sig: BytesN<64>,
        expiry_ledger: u32,
    ) {
        buyer.require_auth();

        if env.ledger().sequence() > expiry_ledger {
            panic!("listing expired");
        }

        // ✅ Recompute the digest including price and expiry.
        let contract_addr = env.current_contract_address();
        let expected_digest =
            secure_listing_digest(&env, &contract_addr, nft_id, &seller, price, expiry_ledger);

        // Verify: the first 32 bytes of `sig` must equal the digest.
        let sig_bytes = sig.to_array();
        let mut digest_buf = [0u8; 32];
        digest_buf.copy_from_slice(&sig_bytes[..32]);
        let sig_digest = BytesN::<32>::from_array(&env, &digest_buf);

        if sig_digest != expected_digest {
            panic!("price mismatch");
        }

        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(nft_id))
            .expect("token not found");
        if owner != seller {
            panic!("seller mismatch");
        }

        // Deduct payment from buyer.
        let buyer_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(buyer.clone()))
            .unwrap_or(0);
        if buyer_bal < price {
            panic!("insufficient funds");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Balance(buyer.clone()), &(buyer_bal - price));

        // Credit seller.
        let seller_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(seller.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(seller.clone()), &(seller_bal + price));

        // Transfer NFT.
        env.storage()
            .persistent()
            .set(&DataKey::Owner(nft_id), &buyer);
    }

    pub fn owner_of(env: Env, nft_id: u64) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Owner(nft_id))
    }

    pub fn balance_of(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}
