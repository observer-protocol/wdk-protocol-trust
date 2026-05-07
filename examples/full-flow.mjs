// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Full-flow example for @observer-protocol/wdk-protocol-trust.
//
// This example runs against the live Observer Protocol mainnet API
// (https://api.observerprotocol.org). It executes the four trust operations:
//
//   1. register(alias)            — creates the agent identity if not already present
//   2. verify(counterparty)        — resolves a known counterparty's identity
//   3. bilateralVerify(counterparty) — runs the pre-payment trust handshake
//   4. attestPayment({...})        — writes a signed audit event after a simulated payment
//
// The example uses a FAKE wallet account with a deterministic seed so it can run
// without an EVM RPC provider and without broadcasting a real on-chain payment.
// In a real WDK integration you'd construct a WalletAccountEvm bound to a real
// provider; the trust module's API surface is identical either way.
//
// Override the API target with OP_API_BASE if you want to point at a sandbox.

import {
  ObserverTrustProtocol,
  deriveEd25519Keypair,
  DEFAULT_API_BASE,
  DEFAULT_DID_DERIVATION_PATH
} from '../index.js'

const API_BASE = process.env.OP_API_BASE || DEFAULT_API_BASE
const COUNTERPARTY = process.env.OP_COUNTERPARTY || '00a292ac00d4c671dd5a29c22b29f548' // ows-service-agent (well-known demo agent)
const ALIAS_PREFIX = 'wdk-trust-example'

// ── synthetic wallet account ────────────────────────────────────────────────
//
// In a real integration:
//
//   import { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'
//   const account = new WalletAccountEvm(seedPhrase, "0'/0/0", { provider: '...' })
//
// For this example we use a stub so the example runs without an EVM RPC. The
// trust module reads the wallet seed via _seedBytes, so any object exposing
// that property satisfies the contract.

function makeStubAccount () {
  // Deterministic 32-byte seed → deterministic agent identity per run.
  // Override with OP_TEST_SEED_HEX (32 bytes hex) for a different identity.
  const seed = process.env.OP_TEST_SEED_HEX
    ? hexToBytes(process.env.OP_TEST_SEED_HEX)
    : new Uint8Array(32).map((_, i) => (i * 13 + 42) & 0xff)
  return {
    _seedBytes: seed,
    address: '0x' + Buffer.from(seed).toString('hex').slice(0, 40)
  }
}

function hexToBytes (hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  return out
}

function header (n, label) {
  console.log('')
  console.log(`── ${n}. ${label} ${'─'.repeat(Math.max(0, 70 - label.length - 6))}`)
}

// ── main flow ───────────────────────────────────────────────────────────────

async function main () {
  console.log('@observer-protocol/wdk-protocol-trust — full-flow example')
  console.log('API base:        ', API_BASE)
  console.log('Counterparty:    ', COUNTERPARTY)

  const account = makeStubAccount()
  const trust = new ObserverTrustProtocol(account, { apiBase: API_BASE })

  // Show the deterministic identity that will be derived
  const { publicKey } = deriveEd25519Keypair(account._seedBytes, DEFAULT_DID_DERIVATION_PATH)
  const fingerprint = Buffer.from(publicKey).toString('hex').slice(0, 8)
  const alias = `${ALIAS_PREFIX}-${fingerprint}`
  console.log('Agent alias:     ', alias)
  console.log('EVM address:     ', account.address)

  header(1, 'register(alias) — issue identity')
  let registration
  try {
    registration = await trust.register({
      alias,
      metadata: {
        rails: ['evm', 'lightning'],
        runtime: 'node',
        example: '@observer-protocol/wdk-protocol-trust full-flow'
      }
    })
    console.log('  agent_id:', registration.agentId)
    console.log('  did:     ', registration.did)
    console.log('  did doc verificationMethod[0].type:',
      registration.didDocument.verificationMethod[0].type)
  } catch (err) {
    console.log('  register failed:', err.message)
    if (err.body) console.log('  details:', JSON.stringify(err.body))
    console.log('  (continuing — verify/bilateralVerify still demonstrable)')
  }

  header(2, `verify('${COUNTERPARTY}') — resolve counterparty`)
  try {
    const counterparty = await trust.verify(COUNTERPARTY)
    console.log('  counterparty did:', counterparty.did)
    console.log('  has VAC:        ', !!counterparty.vac)
    console.log('  has trust score:', !!counterparty.trustScore)
    if (counterparty.trustScore) {
      console.log('  trust score (excerpt):',
        JSON.stringify(counterparty.trustScore).slice(0, 120) + '…')
    }
  } catch (err) {
    console.log('  verify failed:', err.message)
  }

  header(3, `bilateralVerify('${COUNTERPARTY}') — pre-payment handshake`)
  try {
    const handshake = await trust.bilateralVerify(COUNTERPARTY)
    console.log('  ok:                       ', handshake.ok)
    if (handshake.ok) {
      console.log('  sender did:               ', handshake.senderProof.did)
      console.log('  sender signature length:  ', handshake.senderProof.signature.length)
      console.log('  recipient did:            ', handshake.recipient.did)
    } else {
      console.log('  reason:', handshake.reason)
    }
  } catch (err) {
    console.log('  bilateralVerify failed:', err.message)
  }

  header(4, 'attestPayment({...}) — post-settlement audit (simulated tx)')
  try {
    // Use a deterministic fake tx hash so re-runs produce the same audit record.
    const txHash = '0x' + Buffer.from(publicKey).toString('hex').slice(0, 64)
    const attest = await trust.attestPayment({
      txHash,
      recipient: COUNTERPARTY,
      chain: 'evm',
      amount: '1000000', // 1 USDT (6 decimals)
      token: 'USDT',
      metadata: { example: 'wdk-trust full-flow', simulated: true }
    })
    console.log('  event_id:    ', attest.eventId)
    if (attest.receiptUrl) console.log('  receipt URL: ', attest.receiptUrl)
    if (attest.dashboardUrl) console.log('  dashboard:   ', attest.dashboardUrl)
  } catch (err) {
    console.log('  attestPayment failed:', err.message)
    if (err.body) console.log('  details:', JSON.stringify(err.body))
  }

  console.log('')
  console.log('done.')
}

main().catch(err => {
  console.error('example failed:', err)
  process.exit(1)
})
