// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import {
  ObserverTrustProtocol,
  TrustProtocol,
  ITrustProtocol,
  NotImplementedError,
  OpClient,
  deriveEd25519Keypair,
  deriveAgentId,
  buildDid,
  buildDidDocument,
  publicKeyMultibase,
  signChallenge,
  verifySignature,
  DEFAULT_API_BASE,
  DEFAULT_DID_DERIVATION_PATH,
  DID_PREFIX,
  VERIFICATION_METHOD_TYPE
} from '../index.js'

// Minimum viable wallet account stub matching the seed-extraction protocol
// expected by ObserverTrustProtocol. Tests run without a real EVM provider.
class FakeWalletAccount {
  constructor (seedBytes, address) {
    this._seedBytes = seedBytes
    this.address = address
  }
}

describe('@observer-protocol/wdk-protocol-trust — surface', () => {
  test('public exports are present', () => {
    expect(typeof ObserverTrustProtocol).toBe('function')
    expect(typeof TrustProtocol).toBe('function')
    expect(typeof ITrustProtocol).toBe('function')
    expect(typeof OpClient).toBe('function')
    expect(typeof deriveEd25519Keypair).toBe('function')
    expect(typeof deriveAgentId).toBe('function')
    expect(typeof buildDid).toBe('function')
    expect(typeof buildDidDocument).toBe('function')
    expect(typeof publicKeyMultibase).toBe('function')
    expect(typeof signChallenge).toBe('function')
    expect(typeof verifySignature).toBe('function')
    expect(NotImplementedError.prototype).toBeInstanceOf(Error)
  })

  test('default export is ObserverTrustProtocol', async () => {
    const mod = await import('../index.js')
    expect(mod.default).toBe(ObserverTrustProtocol)
  })

  test('config constants are correctly typed', () => {
    expect(typeof DEFAULT_API_BASE).toBe('string')
    expect(DEFAULT_API_BASE.startsWith('https://')).toBe(true)
    expect(DEFAULT_DID_DERIVATION_PATH).toBe("m/7000'/0'/0'/0/0")
    expect(DID_PREFIX).toBe('did:web:observerprotocol.org:agents:')
    expect(VERIFICATION_METHOD_TYPE).toBe('Ed25519VerificationKey2020')
  })
})

describe('TrustProtocol — abstract base', () => {
  test('constructor rejects null account', () => {
    expect(() => new TrustProtocol(null)).toThrow(/wallet account/)
  })

  test('all four abstract methods throw NotImplementedError', async () => {
    const account = new FakeWalletAccount(new Uint8Array(32).fill(1), '0x0')
    const proto = new TrustProtocol(account)
    await expect(proto.register({ alias: 'x' })).rejects.toThrow(NotImplementedError)
    await expect(proto.verify('x')).rejects.toThrow(NotImplementedError)
    await expect(proto.bilateralVerify('x')).rejects.toThrow(NotImplementedError)
    await expect(proto.attestPayment({ txHash: '0x', recipient: 'x', chain: 'evm' })).rejects.toThrow(NotImplementedError)
  })

  test('account + config are exposed read-only', () => {
    const account = new FakeWalletAccount(new Uint8Array(32).fill(1), '0xabc')
    const cfg = { apiBase: 'https://test' }
    const proto = new TrustProtocol(account, cfg)
    expect(proto.account).toBe(account)
    expect(proto.config).toBe(cfg)
  })
})

describe('did-utils — deterministic Ed25519 derivation', () => {
  test('same seed + same path → same keypair', () => {
    const seed = new Uint8Array(32).fill(42)
    const a = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    const b = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    expect(Buffer.from(a.privateKey)).toEqual(Buffer.from(b.privateKey))
    expect(Buffer.from(a.publicKey)).toEqual(Buffer.from(b.publicKey))
  })

  test('different paths → different keypairs', () => {
    const seed = new Uint8Array(32).fill(42)
    const a = deriveEd25519Keypair(seed, "m/7000'/0'/0'/0/0")
    const b = deriveEd25519Keypair(seed, "m/7000'/0'/0'/0/1")
    expect(Buffer.from(a.publicKey).equals(Buffer.from(b.publicKey))).toBe(false)
  })

  test('agentId is 32-char hex', () => {
    const seed = new Uint8Array(32).fill(7)
    const { publicKey } = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    const id = deriveAgentId(publicKey)
    expect(id).toMatch(/^[0-9a-f]{32}$/)
  })

  test('publicKeyMultibase starts with z6Mk (Ed25519 prefix)', () => {
    const seed = new Uint8Array(32).fill(7)
    const { publicKey } = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    expect(publicKeyMultibase(publicKey)).toMatch(/^z6Mk[1-9A-HJ-NP-Za-km-z]+$/)
  })

  test('buildDidDocument is W3C-shape', () => {
    const seed = new Uint8Array(32).fill(7)
    const { publicKey } = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    const id = deriveAgentId(publicKey)
    const doc = buildDidDocument(id, publicKey)
    expect(doc['@context']).toEqual([
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ])
    expect(doc.id).toBe(buildDid(id))
    expect(doc.verificationMethod).toHaveLength(1)
    expect(doc.verificationMethod[0].type).toBe(VERIFICATION_METHOD_TYPE)
    expect(doc.verificationMethod[0].publicKeyMultibase).toMatch(/^z6Mk/)
    expect(doc.authentication).toContain(`${doc.id}#key-1`)
    expect(doc.assertionMethod).toContain(`${doc.id}#key-1`)
  })

  test('signature round-trip', () => {
    const seed = new Uint8Array(32).fill(7)
    const { privateKey, publicKey } = deriveEd25519Keypair(seed, DEFAULT_DID_DERIVATION_PATH)
    const msg = 'wdk-trust-handshake-nonce'
    const sig = signChallenge(msg, privateKey)
    expect(sig).toMatch(/^[0-9a-f]{128}$/)
    expect(verifySignature(sig, msg, publicKey)).toBe(true)
    expect(verifySignature(sig, 'tampered', publicKey)).toBe(false)
  })
})

describe('ObserverTrustProtocol — instantiation + identity derivation', () => {
  test('constructs cleanly with a wallet-shaped account', () => {
    const account = new FakeWalletAccount(new Uint8Array(32).fill(1), '0xabc')
    const trust = new ObserverTrustProtocol(account, { apiBase: 'https://test.example' })
    expect(trust).toBeInstanceOf(ObserverTrustProtocol)
    expect(trust).toBeInstanceOf(TrustProtocol)
    expect(trust.account).toBe(account)
  })

  test('register() rejects empty alias', async () => {
    const account = new FakeWalletAccount(new Uint8Array(32).fill(1), '0xabc')
    const trust = new ObserverTrustProtocol(account, { apiBase: 'https://test.example' })
    await expect(trust.register({})).rejects.toThrow(/alias/)
    await expect(trust.register({ alias: '' })).rejects.toThrow(/alias/)
  })

  test('verify() rejects empty alias', async () => {
    const account = new FakeWalletAccount(new Uint8Array(32).fill(1), '0xabc')
    const trust = new ObserverTrustProtocol(account, { apiBase: 'https://test.example' })
    await expect(trust.verify('')).rejects.toThrow(/alias/)
  })
})

describe('OpClient — request shaping', () => {
  test('builds correct URLs and methods using injected fetch', async () => {
    const calls = []
    const fakeFetch = async (url, init) => {
      calls.push({ url, method: init.method, body: init.body })
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify({ event_id: 'ev-123' })
      }
    }
    const client = new OpClient({ apiBase: 'https://api.example.test', fetchImpl: fakeFetch })
    const r = await client.writeVerifiedEvent({ agent_did: 'did:test', tx_hash: '0xabc', chain: 'evm' })
    expect(r.event_id).toBe('ev-123')
    expect(calls[0].url).toBe('https://api.example.test/v1/audit/verified-event')
    expect(calls[0].method).toBe('POST')
    expect(JSON.parse(calls[0].body).chain).toBe('evm')
  })

  test('non-2xx throws with status + body attached', async () => {
    const fakeFetch = async () => ({
      ok: false,
      status: 404,
      text: async () => JSON.stringify({ detail: 'not found' })
    })
    const client = new OpClient({ apiBase: 'https://api.example.test', fetchImpl: fakeFetch })
    await expect(client.getVac('zzz')).rejects.toMatchObject({ status: 404 })
  })
})
