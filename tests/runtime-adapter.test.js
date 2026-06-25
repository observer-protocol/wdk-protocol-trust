// Copyright 2026 Observer Protocol, Inc. SPDX-License-Identifier: Apache-2.0
// Tests for runRuntimeAdapter — BIND→LINK→AUTHORIZE community gate.

'use strict'

import { writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import {
  createDidKeyAgent,
  signDocument,
  DELEGATION_SCHEMA_V2_1,
  runRuntimeAdapter
} from '../index.js'

// ── Test helpers ──────────────────────────────────────────────────────────

function hex (b) { return Buffer.from(b).toString('hex') }
function toISO (d) { return d.toISOString().replace(/\.\d+Z$/, 'Z') }

function makePrincipal () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/principal/0/0/0")
}
function makeAgent () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/agent/0/0/0")
}
function makeWallet () {
  return createDidKeyAgent(randomBytes(32), "m/observer-protocol'/wallet/0/0/0")
}

function makeMandate (principal, agent, overrides = {}) {
  const now = new Date()
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    id: `urn:uuid:test-mandate-${hex(randomBytes(8))}`,
    issuer: principal.did,
    validFrom: toISO(now),
    validUntil: toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)),
    credentialSchema: { id: DELEGATION_SCHEMA_V2_1, type: 'JsonSchema' },
    credentialSubject: {
      id: agent.did,
      authorizationLevel: 'recurring',
      authorizationConfig: {
        recurring: { ceiling_amount: '100', ceiling_currency: 'USDT' }
      },
      actionScope: {
        allowed_rails: ['ethereum-mainnet'],
        per_transaction_ceiling: { amount: '100', currency: 'USDT' },
        allowed_transaction_categories: ['payment']
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    },
    ...overrides
  }
}

function makeWbc (principal, wallet, overrides = {}) {
  const now = new Date()
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:test-wbc-${hex(randomBytes(8))}`,
    type: ['VerifiableCredential', 'WalletBindingCredential'],
    issuer: principal.did,
    validFrom: toISO(now),
    validUntil: toISO(new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000)),
    credentialSubject: {
      id: principal.did,
      walletAddress: wallet.did,
      rail: 'ethereum-mainnet',
      issuanceMode: 'dev'
    },
    ...overrides
  }
}

function writeTmp (obj) {
  const path = join(tmpdir(), `ra-test-${hex(randomBytes(4))}.json`)
  writeFileSync(path, JSON.stringify(obj, null, 2))
  return path
}

function makeConfig (mandatePath, agentDid, opts = {}) {
  return { mandatePath, agentDid, ...opts }
}

// ── pe-042: no-WBC caller (enterprise passthrough) ────────────────────────
//
// When walletBindingCredentialPath is absent, BIND+LINK are skipped and the
// gate goes straight to AUTHORIZE (withinScope). This is the deliberate
// enterprise opt-out path; it is NOT the community default (the community
// bootstrap always generates a WBC).

test('pe-042: no-WBC config — gate skips BIND+LINK, evaluates withinScope', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '50', currency: 'USDT', category: 'payment' },
    makeConfig(mandatePath, agent.did, { trustedIssuers: [principal.did] })
  )
  expect(result.allow).toBe(true)
  expect(result.reasons).toHaveLength(0)
})

// ── Happy path with WBC ───────────────────────────────────────────────────

test('full BIND→LINK→AUTHORIZE: valid mandate + WBC + matching wallet_id → allow', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()

  const signed = signDocument(makeMandate(principal, agent), principal)
  const wbc = signDocument(makeWbc(principal, wallet), principal)
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '50', currency: 'USDT', category: 'payment', wallet_id: wallet.did },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(true)
  expect(result.notes.some(n => n.includes('issuer-linkage/dev'))).toBe(true)
})

test('no wallet_id — BIND address check skipped, LINK still enforces, allow', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()

  const signed = signDocument(makeMandate(principal, agent), principal)
  const wbc = signDocument(makeWbc(principal, wallet), principal)
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '30', currency: 'USDT', category: 'payment' },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(true)
})

// ── BIND failure: wallet_id mismatch ─────────────────────────────────────

test('BIND: wallet_id mismatch → deny', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()
  const wrongWallet = makeWallet()

  const signed = signDocument(makeMandate(principal, agent), principal)
  const wbc = signDocument(makeWbc(principal, wallet), principal)
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT', wallet_id: wrongWallet.did },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'wbc_address_mismatch')).toBe(true)
})

// ── LINK failure: cross-principal pairing ────────────────────────────────

test('LINK: wbc.issuer !== mandate.issuer → deny (cross-principal pairing attack)', async () => {
  const principalA = makePrincipal()
  const principalB = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()

  // Mandate issued by principalA; WBC issued by different principalB
  const signed = signDocument(makeMandate(principalA, agent), principalA)
  const wbc = signDocument(makeWbc(principalB, wallet), principalB)
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT', wallet_id: wallet.did },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principalA.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'link_issuer_mismatch')).toBe(true)
})

// ── WBC proof tampered ────────────────────────────────────────────────────

test('BIND: tampered WBC body → deny with wbc_proof_invalid', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()

  const signed = signDocument(makeMandate(principal, agent), principal)
  const wbc = signDocument(makeWbc(principal, wallet), principal)
  wbc.credentialSubject.walletAddress = makeWallet().did  // tamper after signing
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT', wallet_id: wallet.did },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'wbc_proof_invalid')).toBe(true)
})

// ── WBC expired ───────────────────────────────────────────────────────────

test('BIND: expired WBC → deny with wbc_expired', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const wallet = makeWallet()

  const signed = signDocument(makeMandate(principal, agent), principal)
  const past = new Date(Date.now() - 2 * 86400 * 1000)
  const wbc = signDocument(makeWbc(principal, wallet, {
    validFrom: toISO(new Date(past.getTime() - 365 * 86400 * 1000)),
    validUntil: toISO(past)
  }), principal)
  const mandatePath = writeTmp(signed)
  const wbcPath = writeTmp(wbc)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT', wallet_id: wallet.did },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: wbcPath
    })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'wbc_expired')).toBe(true)
})

// ── WBC file missing ──────────────────────────────────────────────────────

test('BIND: missing WBC file → deny with wbc_read', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' },
    makeConfig(mandatePath, agent.did, {
      trustedIssuers: [principal.did],
      walletBindingCredentialPath: '/nonexistent/path/wbc.json'
    })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'wbc_read')).toBe(true)
})

// ── Signer-boundary checks ────────────────────────────────────────────────

test('self-signed mandate → deny with self_signed_mandate', async () => {
  const agent = makeAgent()
  const signed = signDocument(makeMandate(agent, agent), agent)
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' },
    makeConfig(mandatePath, agent.did, { trustedIssuers: [agent.did] })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'self_signed_mandate')).toBe(true)
})

test('subject mismatch → deny with subject_mismatch', async () => {
  const principal = makePrincipal()
  const agentA = makeAgent()
  const agentB = makeAgent()

  const signed = signDocument(makeMandate(principal, agentA), principal)
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' },
    makeConfig(mandatePath, agentB.did, { trustedIssuers: [principal.did] })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'subject_mismatch')).toBe(true)
})

// ── AUTHORIZE-layer checks ────────────────────────────────────────────────

test('spend over ceiling → deny from withinScope', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '150', currency: 'USDT', category: 'payment' },
    makeConfig(mandatePath, agent.did, { trustedIssuers: [principal.did] })
  )
  expect(result.allow).toBe(false)
  expect(
    result.reasons.some(r => r.ruleField === 'per_transaction_ceiling' || r.ruleType === 'amountLimits')
  ).toBe(true)
})

test('tampered mandate → deny with mandate_invalid', async () => {
  const principal = makePrincipal()
  const agent = makeAgent()
  const signed = signDocument(makeMandate(principal, agent), principal)
  signed.credentialSubject.actionScope.per_transaction_ceiling.amount = '9999'
  const mandatePath = writeTmp(signed)

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '50', currency: 'USDT' },
    makeConfig(mandatePath, agent.did, { trustedIssuers: [principal.did] })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'mandate_invalid')).toBe(true)
})

test('missing mandate file → deny with mandate_read', async () => {
  const agent = makeAgent()

  const result = await runRuntimeAdapter(
    { rail: 'ethereum-mainnet', amount: '10', currency: 'USDT' },
    makeConfig('/nonexistent/path/mandate.json', agent.did, { trustedIssuers: ['did:key:ztest'] })
  )
  expect(result.allow).toBe(false)
  expect(result.reasons.some(r => r.ruleField === 'mandate_read')).toBe(true)
})
