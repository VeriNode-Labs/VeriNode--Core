# Landlord-Tenant Susu Escrow Integration (#105)

Inter-contract hook that lets a tenant who wins their Susu pot authorise
SoroSusu to redirect the payout directly to a LeaseInstance contract as
an automated rent-drip.

## Why

- Tenants are never late on rent during their winning month.
- Landlords get verifiable on-chain proof of the tenant's participation
  in a disciplined savings circle (the `lease_payout` event ties the pot
  amount to the tenant and the lease contract).
- Lower security-deposit requirements become defensible because
  landlords can reference an immutable, on-chain payment history.

## Contract surface (added)

```rust
fn register_lease_payout(env: Env, tenant: Address, circle_id: u64, lease_contract: Address);
fn cancel_lease_payout(env: Env, tenant: Address, circle_id: u64);
fn get_lease_payout(env: Env, tenant: Address, circle_id: u64) -> Option<LeasePayoutConfig>;
```

`LeasePayoutConfig` is keyed by `(tenant, circle_id)` so each circle's
payout destination is independent — a tenant in two circles can rent-drip
one and self-receive the other.

## Behaviour change in `claim_pot`

When the tenant is the round's pot recipient:

| Condition                                    | Recipient of `token::transfer` |
| -------------------------------------------- | ------------------------------ |
| No `LeasePayoutConfig` registered (default)  | Tenant's own address           |
| `LeasePayoutConfig` registered               | `lease_contract` from config   |

When the redirect path is taken, the contract emits:

```
("LEASE_PAY", tenant) -> (circle_id, lease_contract, pot_amount)
```

Registration and cancellation emit `LEASE_REG` / `LEASE_CAN` for
landlord-side off-chain indexing.

## What this PR does NOT change

- The LeaseInstance contract API is intentionally not assumed. The
  redirect uses a plain `token::transfer` so any compatible Soroban
  contract can receive funds; LeaseInstance can index incoming
  payments by watching the token contract for transfers to its
  address.
- Rebroadcasting the pot when the LeaseInstance refuses funds is out
  of scope. The transfer is final on a successful `claim_pot`.

## Test coverage

See `tests/landlord_tenant_test.rs`:

- Default path: pot lands in tenant's address.
- Redirect path: registered tenant's pot lands in `lease_contract`.
- Cancel restores the default.
- Duplicate `register_lease_payout` and unregistered `cancel_lease_payout` panic.
- `get_lease_payout` returns `None` when nothing is registered.
