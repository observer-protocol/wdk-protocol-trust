# @observer-protocol/wdk-protocol-trust

> WDK protocol module: agent identity, bilateral trust handshake, AIP v0.8 spending-mandate verification, and ERC-8004-anchored settlement attestation via Observer Protocol.

**Note**: This package is currently in beta (`0.2.0-beta.1`). The earlier handshake methods (`register`, `verify(alias)`, `bilateralVerify`, `attestPayment`) ship alongside the AIP v0.8 mandate surface (`verifyMandate`, `withinScope`, `attest`, `PolicyGate`) added in this release. The underlying protocol (AIP v0.8 draft-1) is itself pre-1.0. Test thoroughly in development before production use.

> [!IMPORTANT]
> **Reference use & security.** This module is the reusable trust layer composed by the [`at-reference-wallet`](../at-reference-wallet) reference implementation. It is self-custodial by design — it verifies and attests, it never holds keys or moves funds. It is **not audited for production**; audit before any mainnet use with real funds. Enforcement is delegated to WDK (PR #55) via `WdkEnforcementGate`; OP attests the outcome and never re-decides policy per trade.

---

## Why this exists

WDK gives agents wallets. It doesn't give agents **identity**. Two agents with WDK wallets can pay each other, but neither knows who the other is. The recipient sees a wallet address. The sender sees a wallet address. Both are operating on assumptions — which is fine for friend-to-friend transfers and not fine for autonomous machine commerce, where the question "is the wallet on the other side controlled by an agent I should be transacting with?" is the difference between revenue and fraud.

This module fills that gap. It binds a WDK wallet account to a W3C `did:web` agent identity registered on Observer Protocol. Before a payment, both parties' identities are cryptographically verified through a bilateral handshake. After settlement, the payment is attested to a permanent registry — including, optionally, ERC-8004 chain anchoring. The full path from "I have a WDK wallet" to "I have a verifiable agent operating in machine commerce" is four method calls.

Observer Protocol provides the open identity, attestation, and revocation infrastructure ([technical paper](https://observerprotocol.org/papers/technical-paper), [AIP v0.6 draft spec](https://github.com/observer-protocol/aip/blob/main/aip-v0.6-draft-1.md)). This module is the WDK-shaped surface to it.

---

## Where this fits in WDK's architecture

WDK currently recognizes four protocol categories, each with an abstract base class in `@tetherto/wdk-wallet/protocols`:

- `BridgeProtocol` — cross-chain asset movement (e.g. `wdk-protocol-bridge-usdt0-evm`)
- `SwapProtocol` — DEX swaps
- `FiatProtocol` — fiat onramps / offramps
- `LendingProtocol` — yield / borrow primitives

**Trust is a fifth category that does not yet exist in WDK.**

This package proposes `TrustProtocol` as that fifth category, structured identically to the four existing ones — abstract base class with an interface contract, concrete implementation per identity backend. The base class lives in this package's `src/trust-protocol.js` so consumers can install it today; we'd be glad to upstream the abstract base into `@tetherto/wdk-wallet/protocols` if Tether sees value in formalizing the category.

The strategic claim: trust is **architecturally orthogonal** to bridge / swap / fiat / lending. None of the existing four cover "is this counterparty who they claim to be, and what's their settlement history". As autonomous agent commerce moves from human-in-the-loop transactions to fully autonomous, that orthogonal axis becomes load-bearing — chargeback prevention, KYA compliance for institutional flows, reputation portability across rails. It earns its own protocol category.

We're shipping this independently because we have something to ship now, not because we want to fork. If the architecture lands cleanly under Tether's ownership long-term, that's the right outcome.

---

## AIP v0.8 mandate surface (new in 0.2.0)

The mandate surface lets a WDK agent **verify** a delegation credential issued under [AIP v0.8](https://github.com/observer-protocol/aip), **gate** a proposed spend against the verified mandate, and **attest** the settlement — all without OP touching funds. Four method calls, no new dependencies:

```javascript
import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'

const op = new ObserverTrustProtocol(wallet, {
  trustedIssuers: ['did:web:observerprotocol.org'],
  attestationKey,   // DISTINCT from the WDK wallet key
  // gate: optional — defaults to AdvisoryGate (client-side gating)
})

const mandate  = await op.verifyMandate(agentCredential)        // did:web + Ed25519Signature2026 + schema-allowlist + validity
const decision = await op.withinScope(proposedAction, mandate)  // per-tx ceiling + rail + category + authz-level rules
if (!decision.allow) throw new Error('mandate violation: ' + JSON.stringify(decision.reasons))

const tx = await wallet.send(/* … */)                           // WDK executes; OP never touches funds
await op.attest({ credential: agentCredential, action: proposedAction, settlement: { rail: 'usdt_tron', ref: tx.id } })
```

A runnable end-to-end example with a self-issued demo credential and stub wallet: [`examples/mandate-flow.mjs`](./examples/mandate-flow.mjs). Run it with `npm run example`.

### Design invariants

These are load-bearing — they shape the API and they shape what this adapter will and won't do:

- **OP attests authorization; it never settles or moves funds.** WDK / the rail is the source of truth for the transaction fact. Every surface, label, and return field reflects this.
- **`withinScope` is I/O-free.** No FX, no oracles, no HTTP, no chain RPCs, no database calls. Input is `(proposedAction, mandate)`; output is `{allow, reasons, advisories}`. Importing settlement truth into the evaluator would cross the verify-don't-settle line.
- **Same-currency amount checks only.** A currency mismatch is a deny with reason, never a conversion. Per-rail ceilings follow naturally — each rail's natural unit differs.
- **Per-transaction ceiling is the only binding amount check.** `cumulative_budget` is **advisory only** in v0.8: declared in the credential, surfaced in the verifier result, never grounds a deny. Same for `allowed_counterparty_types` and `geographic_restriction` — reserved with constrained shapes and explicit advisory normative status, until the substrate source-of-truth for each is defined.
- **Schema allowlist, not arbitrary fetch.** This adapter recognises `credentialSchema.id = https://observerprotocol.org/schemas/delegation/v2.1.json`. Unknown URLs are rejected; the adapter does not fetch arbitrary schema URLs. The earlier `v2.json` URL (frozen at AIP v0.7-era content for the maxi-0001 demo) is **deliberately excluded** — its older `cumulative_ceiling` / `period` vocabulary does not match this adapter's logic. See `SCHEMA_POLICY.md` in `observer-protocol/aip` for the schema immutability policy.
- **OP attests, WDK enforces.** Where Tether WDK's native transaction-policy engine (PR #55) is present, `WdkEnforcementGate` installs it via [`@observer-protocol/wdk-op-policy`](https://www.npmjs.com/package/@observer-protocol/wdk-op-policy) — an ALLOW + DENY rule pair WDK evaluates inside its own signing path, fail-closed, before the key signs. OP does **not** re-decide policy per trade; it verifies the signed delegation credential and attests the outcome (a signed `PolicyEvaluationCredential`). The `AdvisoryGate` (`withinScope` client-side, gated by the developer's `throw`) remains a fallback for rails with no native WDK engine.

### `verifyMandate(credential, opts?)`

Does:

1. Shape validation (required fields present).
2. `credentialSchema.id` in `SCHEMA_ALLOWLIST` (default: `['https://observerprotocol.org/schemas/delegation/v2.1.json']`). Pass `opts.schemaAllowlist` or `config.schemaAllowlist` to extend.
3. Issuer in `trustedIssuers`.
4. `validFrom ≤ now ≤ validUntil`.
5. `did:web` resolution of the issuer.
6. `Ed25519Signature2026` proof verification bound to an `assertionMethod` key in the issuer DID document.

Returns a typed `Mandate` (`{credentialId, issuer, subjectDid, validFrom, validUntil, authorizationLevel, authorizationConfig, actionScope, credentialSchemaId, raw}`). Throws `VerificationError` with a machine-readable `code` on any failure.

Status-list (revocation) checking is intentionally NOT performed in v1; layer it on top if you need it.

### `withinScope(action, mandate)`

Pure evaluator. Binding deny rules:

- `proposed.rail ∈ actionScope.allowed_rails`
- `proposed.amount.currency === per_transaction_ceiling.currency` AND `proposed.amount.amount ≤ ceiling.amount` (decimal-string compare, no float)
- `proposed.category ∈ actionScope.allowed_transaction_categories` (when the list is present)
- `authorizationLevel`-gated rules from `authorizationConfig` (`one-time` / `recurring` / `policy`)

Advisory surfacing (returned in `decision.advisories`, never `decision.reasons`):

- `cumulative_budget` declared
- `allowed_counterparty_types` declared
- `geographic_restriction` declared
- `recurring.period` declared (stateful — no in-adapter state)
- `policy.time_windows` / `escalation_threshold` / `fallback_rules` declared

### `attest({credential, action, settlement})`

Builds and signs an `ObserverSettlementAttestation` binding the delegation (by SHA-256 of its JCS-canonical bytes, plus the issuer's `proofValue`), the action, the settlement reference, this adapter as evaluator, and a timestamp. Signed by the agent's `attestationKey` using `Ed25519Signature2026`.

Optional ERC-8004 anchoring is gated by `config.erc8004` (a stub-compatible anchorer with an `anchor()` method). Pass `args.anchor: true` to invoke; the anchor reference lands inside `credentialSubject.settlement.anchored` before signing, so the binding is part of the signed envelope.

`attestationKey` MUST be distinct from the WDK wallet key in production — pass it via `config.attestationKey`. The wallet-derived fallback is for early development only.

---

## Installation

```bash
npm install @observer-protocol/wdk-protocol-trust
```

Peer dependencies (declare in your application):

```bash
npm install @tetherto/wdk-wallet @tetherto/wdk-wallet-evm
```

Native dependencies are minimal: `@noble/curves` and `@noble/hashes` for Ed25519 operations and key derivation. No native bindings, no build step required.

Runtime: Node.js 18+ (uses native `fetch`) or Bare runtime (via the `bare` exports condition).

---

## Quick start

### Direct usage

The primary integration pattern today: instantiate the protocol with a WDK wallet account, call the four methods directly.

```javascript
import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'
import { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'

const seedPhrase = 'your bip-39 mnemonic here twelve or twenty four words'

// 1. Construct the wallet account (standard WDK pattern)
const account = new WalletAccountEvm(seedPhrase, "0'/0/0", {
  provider: 'https://ethereum-rpc.publicnode.com'
})

// 2. Bind the trust protocol to the account
const trust = new ObserverTrustProtocol(account, {
  apiBase: 'https://api.observerprotocol.org', // default
  apiKey: process.env.OP_INTEGRATOR_KEY        // required only for attestPayment
})

// 3. Register the agent identity (idempotent per wallet seed)
const { agentId, did } = await trust.register({
  alias: 'my-agent',
  metadata: {
    framework: 'wdk',
    chains: ['evm']
  }
})

// 4. Verify a counterparty before paying them
const counterparty = await trust.verify('seller-agent-7')
if (counterparty.trustScore?.trust_score < 50) {
  throw new Error('Counterparty trust score below threshold')
}

// 5. Run the bilateral handshake immediately before payment
const handshake = await trust.bilateralVerify('seller-agent-7')
if (!handshake.ok) throw new Error(handshake.reason)

// 6. Execute the payment via the wallet (your existing WDK code)
const txHash = await account.transfer({ /* ... */ })

// 7. Attest the settled payment to the trust registry
const receipt = await trust.attestPayment({
  txHash,
  recipient: 'seller-agent-7',
  chain: 'evm',
  amount: '1000000',
  token: 'USDT',
  pinErc8004: true   // optional: also pin to ERC-8004 NFT registry (Level 3 anchoring)
})
console.log('Audit event:', receipt.eventId)
console.log('Receipt VC URL:', receipt.receiptUrl)
console.log('ERC-8004 token ID:', receipt.erc8004?.tokenId)
```

### Forward-looking: WDK Core integration

If `TrustProtocol` lands as a recognized WDK category, integration would follow the established `wdk.registerProtocol(...)` pattern:

```javascript
import WDK from '@tetherto/wdk'
import WalletManagerEvm from '@tetherto/wdk-wallet-evm'
import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'

const wdk = new WDK(seedPhrase)
  .registerWallet('ethereum', WalletManagerEvm, { provider: 'https://...' })
  .registerProtocol('ethereum', 'observer-trust', ObserverTrustProtocol, {
    apiBase: 'https://api.observerprotocol.org',
    apiKey: process.env.OP_INTEGRATOR_KEY
  })

const account = await wdk.getAccount('ethereum', 0)
const trust = account.getTrustProtocol('observer-trust')   // ← requires WDK Core to recognize the category
await trust.register({ alias: 'my-agent' })
```

The `account.getTrustProtocol(...)` accessor doesn't exist in WDK Core today; the category recognition is the upstream piece. Direct usage above is the pattern that works without core changes.

---

## Method reference

### `new ObserverTrustProtocol(account, config)`

Construct the protocol bound to a WDK wallet account.

| Parameter | Type | Description |
|---|---|---|
| `account` | `WalletAccountEvm` (or compatible) | Bound wallet account. Read-only or signing. |
| `config.apiBase` | `string` | Default `https://api.observerprotocol.org`. |
| `config.apiKey` | `string` | Integrator API key (required only for `attestPayment`). Sent as `Authorization: Bearer <key>`. Other methods use public OP endpoints. |
| `config.requestTimeoutMs` | `number` | Per-request timeout, default 15000. |
| `config.didDerivationPath` | `string` | Domain-separated key derivation path, default `m/7000'/0'/0'/0/0`. |
| `config.defaultMetadata` | `object` | Metadata merged into every `register()` call. |

### `await trust.register({ alias, metadata? })`

Issue an agent identity bound to this wallet account. Derives an Ed25519 signing keypair deterministically from the wallet seed (under the configured derivation path), then registers the public key with Observer Protocol.

Returns:

```typescript
{
  agentId: string         // 32-char hex agent identifier (assigned by OP)
  did: string             // did:web:observerprotocol.org:agents:{agentId}
  didDocument: object     // W3C DID document with verificationMethod[0].type = Ed25519VerificationKey2020
}
```

Idempotent within a wallet: re-registering the same wallet with the same alias returns the same identity. The API may resolve alias collisions per its own policy.

### `await trust.verify(alias)`

Resolve a counterparty's identity package. Reads from `api.observerprotocol.org` only (no signing required; the call is public).

Returns:

```typescript
{
  did: string              // did:web:... of the resolved counterparty
  didDocument: object      // W3C DID document
  vac: object              // Verifiable Attestation Certificate (VAC) summary
  trustScore?: object      // Composite reputation / trust score (if available)
}
```

Accepts an alias, an agent_id (32 hex chars), or a full did string — all three resolve identically.

### `await trust.bilateralVerify(recipientAlias)`

Run the pre-payment trust handshake. Internally:

1. Requests a fresh challenge nonce from Observer Protocol for this account.
2. Signs the nonce with the agent's Ed25519 private key.
3. Submits the signature for verification (proves "I control the private key behind the registered DID").
4. Resolves the recipient's full identity package (`verify(recipient)`).
5. Returns both proofs.

Returns:

```typescript
{
  ok: boolean                    // true if both sides verified
  senderProof?: {
    did: string
    signature: string            // hex-encoded Ed25519 over the nonce
    nonce: string
  }
  recipient?: VerifyResult       // see verify() above
  reason?: string                // failure reason if ok=false
}
```

Use case: the recipient stores `senderProof` as cryptographic evidence of pre-payment authorization. In a chargeback dispute, the recipient presents the signed nonce + the agent's public-key DID document (resolvable independently via `did:web`) as deterministic proof that the sender authorized the transaction. No "we don't know who paid us" ambiguity.

### `await trust.attestPayment({ txHash, recipient, chain, amount?, token?, pinErc8004?, metadata? })`

Write a signed audit event for a settled payment. **Requires `config.apiKey`** (integrator-tier credential).

```typescript
{
  txHash: string                 // settlement transaction hash
  recipient: string              // recipient alias or DID
  chain: 'evm' | 'lightning' | 'tron' | 'x402' | 'solana'
  amount?: string | bigint | number
  token?: string                 // 'USDT', 'USDC', 'BTC', etc
  pinErc8004?: boolean           // also pin agent registration to ERC-8004 NFT registry
  metadata?: { category?: string; [k: string]: unknown }
}
```

Returns:

```typescript
{
  eventId: string                // OP audit event identifier
  receiptUrl?: string            // signed W3C VC verification receipt
  dashboardUrl?: string          // AT Enterprise dashboard view
  erc8004?: {
    tokenId: string              // NFT token id on chain
    txHash: string               // pin transaction hash
    status: string               // 'pinned' | 'pending' | etc
  }
}
```

The audit event is the canonical "this payment was made by this agent to this counterparty on this rail" record. The receipt VC is a portable artifact that the recipient (or any verifier) can independently validate against the agent's published DID document.

---

## DID and signature model

Each agent's identity is anchored by an Ed25519 keypair derived deterministically from the WDK wallet seed:

```
wallet seed → HMAC-SHA512(seed, "m/7000'/0'/0'/0/0") → first 32 bytes → Ed25519 secret key
```

This produces:

- **Agent DID** of the form `did:web:observerprotocol.org:agents:{agent_id}`. Resolvable by any W3C-compliant resolver (`dev.uniresolver.io`, `gossipsub-did-resolver`, etc).
- **DID document** containing the agent's public key in multibase base58btc format (`z6Mk...` per `Ed25519VerificationKey2020`).
- **Signature suite**: Ed25519Signature2026 (AIP v0.6 default; dual-accepted alongside the legacy `Ed25519Signature2020` label during the migration window).

The derivation is domain-separated under purpose `7000` to avoid collision with BIP-44 paths. **One wallet, one stable agent identity** — resetting state and re-deriving produces the same DID.

EVM signing keys (secp256k1) and the agent identity key (Ed25519) coexist on the same wallet seed without interference; they're derived under independent paths.

---

## Configuration via environment

The example in `examples/full-flow.mjs` honors:

| Variable | Purpose |
|---|---|
| `OP_API_BASE` | Override `apiBase` (e.g. point at a sandbox) |
| `OP_INTEGRATOR_KEY` | Bearer token for `attestPayment` |
| `OP_TEST_SEED_HEX` | 32-byte hex seed for the example's stub wallet (otherwise deterministic) |
| `OP_COUNTERPARTY` | Counterparty alias / agent_id to verify (default: well-known demo agent) |

```bash
OP_INTEGRATOR_KEY=$YOUR_KEY npm run example
```

---

## Roadmap

| Item | Status |
|---|---|
| EVM wallet binding (`@tetherto/wdk-wallet-evm`) | **v0.1 — shipped** |
| W3C `did:web` agent identity, deterministic Ed25519 derivation | **v0.1 — shipped** |
| Bilateral pre-payment handshake (challenge / signed-nonce / verify) | **v0.1 — shipped** |
| ERC-8004 chain-anchored attestation | **v0.1 — shipped** |
| TRON wallet binding (`@tetherto/wdk-wallet-tron`) | v0.2 — planned |
| Solana wallet binding | v0.2 — planned |
| Bare-runtime native fetch optimization | v0.2 — planned |
| `TrustProtocol` upstream into `@tetherto/wdk-wallet/protocols` | proposal — pending Tether discussion |
| Lightning preimage verification | shipped separately as [`@observer-protocol/wdk-lightning-verifier`](#composition) |

### Composition

Lightning preimage verification — including reputation contribution back to OP — lives in a separate package, [`@observer-protocol/wdk-lightning-verifier`](https://github.com/observer-protocol/wdk-lightning-verifier). The split is deliberate: that verifier is wallet-agnostic by design and serves any Lightning wallet, including but not limited to WDK. Use the two together for the full Lightning trust stack:

```javascript
import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'
import { verifyPreimage } from '@observer-protocol/wdk-lightning-verifier'
```

---

## Links

- **Observer Protocol:** [observerprotocol.org](https://observerprotocol.org)
- **AIP v0.6 draft specification:** [github.com/observer-protocol/aip](https://github.com/observer-protocol/aip/blob/main/aip-v0.6-draft-1.md)
- **OP API documentation:** [api.observerprotocol.org/docs](https://api.observerprotocol.org/docs)
- **Lightning verifier (companion package):** `@observer-protocol/wdk-lightning-verifier`
- **WDK ecosystem:** [docs.wallet.tether.io](https://docs.wallet.tether.io)
- **Issues / discussion:** GitHub issues on this repository

---

## Related WDK modules

This is one of several Observer Protocol modules for the Tether [WDK](https://github.com/tetherto/wdk) ecosystem:

- **[@observer-protocol/wdk-policy](https://github.com/observer-protocol/wdk-policy)** — delegation-scoped policy enforcement (per AIP v0.8).
- **[@observer-protocol/wdk-protocol-trust](https://github.com/observer-protocol/wdk-protocol-trust)** — agent identity + bilateral trust handshake. *(this module)*
- **[@observer-protocol/wdk-lightning-verifier](https://github.com/observer-protocol/wdk-lightning-verifier)** — verifiable Lightning payments + reputation attribution.

See [observer-protocol/wdk-modules](https://github.com/observer-protocol/wdk-modules) for the full index.

---

## License

Apache-2.0 © 2026 Observer Protocol, Inc.
