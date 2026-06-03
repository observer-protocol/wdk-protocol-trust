// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Mandate-flow example — the "ten lines" from the WDK implementation brief.
//
// Demonstrates the AIP v0.8 spending-mandate surface end-to-end:
//   verifyMandate → withinScope → (settle) → attest
//
// The wallet here is a stub (`FakeWalletAccount`) so the example runs without
// a real EVM provider or live network. Substitute `WalletAccountEvm` from
// `@tetherto/wdk-wallet-evm` in production.
//
// Run: node examples/mandate-flow.mjs

import { ed25519 } from '@noble/curves/ed25519'

import ObserverTrustProtocol, {
  canonicalizeForSigning,
  publicKeyMultibase
} from '../index.js'

// ── Stub: a delegation credential we'd normally receive via the upstream
// issuance flow. We freshly mint and sign one here so the example is
// self-contained. The issuer key, DID document, and credential bytes match
// what verifyMandate expects.

const issuer = 'did:web:observerprotocol.org'
const issuerPriv = ed25519.utils.randomPrivateKey()
const issuerPub = ed25519.getPublicKey(issuerPriv)
const vmId = issuer + '#key-2'

const delegationCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:demo-delegation-' + Date.now(),
  type: ['VerifiableCredential', 'ObserverDelegationCredential'],
  issuer,
  validFrom: new Date(Date.now() - 60_000).toISOString(),
  validUntil: new Date(Date.now() + 86_400_000).toISOString(),
  credentialSubject: {
    id: 'did:web:observerprotocol.org:agents:demo-agent',
    authorizationLevel: 'recurring',
    authorizationConfig: {
      recurring: {
        counterparty_did: 'did:web:vendor.example:agents:inference-store',
        ceiling_amount: '500',
        ceiling_currency: 'USDT',
        period: 'monthly',
        per_transaction_max: '25'
      }
    },
    actionScope: {
      allowed_rails: ['usdt_tron'],
      per_transaction_ceiling: { amount: '25', currency: 'USDT' },
      allowed_transaction_categories: ['ai_inference_credits'],
      cumulative_budget: { amount: '500', currency: 'USDT', window: 'credential_validity' }
    },
    delegationScope: { may_delegate_further: false },
    enforcementMode: 'pre_transaction_check'
  },
  credentialSchema: { id: 'https://observerprotocol.org/schemas/delegation/v2.1.json', type: 'JsonSchema' }
}

const canonical = canonicalizeForSigning(delegationCredential)
const sig = ed25519.sign(new TextEncoder().encode(canonical), issuerPriv)
delegationCredential.proof = {
  type: 'Ed25519Signature2026',
  created: new Date().toISOString(),
  verificationMethod: vmId,
  proofPurpose: 'assertionMethod',
  proofValue: 'z' + base58btcEncode(sig)
}

const issuerDidDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: issuer,
  verificationMethod: [
    { id: vmId, type: 'Ed25519VerificationKey2020', controller: issuer, publicKeyMultibase: publicKeyMultibase(issuerPub) }
  ],
  assertionMethod: [vmId]
}

// ── Stub: a wallet account.
class FakeWalletAccount {
  constructor () {
    this._seedBytes = new Uint8Array(64).fill(7) // demo only
    this.address = '0xdemo'
  }
  async send () {
    // Pretend we settled on-chain.
    return { id: '0x' + Math.random().toString(16).slice(2, 18) }
  }
}

// ── The "ten lines" ──────────────────────────────────────────────────────

const wallet = new FakeWalletAccount()
const op = new ObserverTrustProtocol(wallet, {
  // Override default trusted-issuer DID to demonstrate config; in production
  // the default ['did:web:observerprotocol.org'] is what you want.
  trustedIssuers: [issuer]
  // gate: omitted — defaults to AdvisoryGate; client-side gating.
  // attestationKey: omitted — falls back to wallet-derived key for the demo.
})

const mandate = await op.verifyMandate(delegationCredential, {
  resolveDid: async () => issuerDidDocument // local mock instead of fetching
})

const proposedAction = {
  rail: 'usdt_tron',
  amount: { amount: '10', currency: 'USDT' },
  category: 'ai_inference_credits',
  counterparty_did: 'did:web:vendor.example:agents:inference-store'
}

const decision = await op.withinScope(proposedAction, mandate)
if (!decision.allow) {
  console.error('mandate violation:', decision.reasons)
  process.exit(1)
}

const tx = await wallet.send(/* … */) // WDK executes; OP never touches funds

const attestation = await op.attest({
  credential: delegationCredential,
  action: proposedAction,
  settlement: { rail: 'usdt_tron', ref: tx.id }
})

console.log('decision:', JSON.stringify(decision, null, 2))
console.log('attestation:', JSON.stringify(attestation, null, 2))

// ── Helper (matches did-utils.js base58btc encode, redeclared for example
//    self-containment so the file runs without internal imports).

function base58btcEncode (bytes) {
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  const digits = [0]
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8
      digits[j] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  let out = ''
  for (let i = 0; i < zeros; i++) out += '1'
  for (let i = digits.length - 1; i >= 0; i--) out += A[digits[i]]
  return out
}
