# feat: Vulnerable escrow with ignored sub-call return value

Implements the ignored return value vulnerability described in the issue.

An escrow contract that calls an external token contract's `transfer()` and
discards the result with `let _ = ...`. State is updated unconditionally,
so a failed (or no-op) token transfer still marks the escrow as released.

## Vulnerable pattern

```rust
pub fn release(env: Env) {
    // ...
    // ❌ Return value ignored — if token transfer fails, escrow still marks as released
    let _ = token_interface::TokenClient::new(&env, &token_id)
        .transfer(&env.current_contract_address(), &recipient, &amount);

    // State updated unconditionally — funds may never have moved.
    env.storage().persistent().set(&DataKey::Released, &true);
}
```

## Secure fix

```rust
pub fn release(env: Env) {
    // ...
    // ✅ Call transfer directly — no `let _ = ...`.
    //    A panicking token contract rolls back the entire transaction,
    //    so Released is never set to true unless the transfer succeeds.
    token_interface::TokenClient::new(&env, &token_id)
        .transfer(&env.current_contract_address(), &recipient, &amount);

    env.storage().persistent().set(&DataKey::Released, &true);
}
```

## What's added

- `VulnerableEscrow` — escrow contract whose `release()` discards the token
  transfer result with `let _ = ...`, updating state regardless of outcome
- `MockToken` — test token that can be configured to silently no-op on
  `transfer()`, simulating a token that fails without panicking
- `secure::SecureEscrow` — identical escrow but calls `transfer()` directly;
  a panicking token contract rolls back the whole transaction

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_normal_release_works` | Vulnerable | passes — token transfer succeeds, escrow released |
| `test_failed_sub_call_still_marks_escrow_released` | Vulnerable | passes — demonstrates the bug: escrow released even though no tokens moved |
| `test_secure_normal_release_works` | Secure | passes — token transfer succeeds, escrow released |
| `test_secure_rejects_failed_sub_call` | Secure | panics — failed transfer rolls back the transaction |

**Severity:** High

