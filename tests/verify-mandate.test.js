// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { ed25519 } from '@noble/curves/ed25519'

import {
  verifyMandate,
  canonicalizeForSigning,
  publicKeyMultibase,
  SCHEMA_ALLOWLIST,
  VerificationError
} from '../index.js'

// Build a credential signed by a freshly-generated key pair, and a matching
// DID document. The DID document is returned by a mocked resolveDid so the
// test is fully self-contained — no network.
function buildSignedCredential ({ schemaId, validFrom, validUntil } = {}) {
  const privateKey = ed25519.utils.randomPrivateKey()
  const publicKey = ed25519.getPublicKey(privateKey)
  const issuer = 'did:web:test.example'
  const vmId = issuer + '#key-1'

  const credential = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:verify-test-1',
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer,
    validFrom: validFrom || '2026-01-01T00:00:00Z',
    validUntil: validUntil || '2027-01-01T00:00:00Z',
    credentialSubject: {
      id: issuer + ':agents:test-agent',
      authorizationLevel: 'recurring',
      authorizationConfig: {
        recurring: {
          counterparty_did: 'did:web:example.com:agents:vendor',
          ceiling_amount: '1000',
          ceiling_currency: 'USDT',
          period: 'monthly'
        }
      },
      actionScope: {
        allowed_rails: ['usdt_tron'],
        per_transaction_ceiling: { amount: '100', currency: 'USDT' },
        allowed_transaction_categories: ['ai_inference_credits']
      },
      delegationScope: { may_delegate_further: false },
      enforcementMode: 'pre_transaction_check'
    },
    credentialSchema: {
      id: schemaId || SCHEMA_ALLOWLIST[0],
      type: 'JsonSchema'
    }
  }

  const canonical = canonicalizeForSigning(credential)
  const sig = ed25519.sign(new TextEncoder().encode(canonical), privateKey)
  credential.proof = {
    type: 'Ed25519Signature2026',
    created: '2026-01-01T00:00:00Z',
    verificationMethod: vmId,
    proofPurpose: 'assertionMethod',
    proofValue: 'z' + base58btcEncode(sig)
  }

  const didDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: issuer,
    verificationMethod: [
      { id: vmId, type: 'Ed25519VerificationKey2020', controller: issuer, publicKeyMultibase: publicKeyMultibase(publicKey) }
    ],
    assertionMethod: [vmId]
  }

  return { credential, didDocument, issuer }
}

// Minimal base58btc encoder. Mirrors did-utils.js for test self-containment.
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58btcEncode (bytes) {
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
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]]
  return out
}

describe('verifyMandate — allowlist gating', () => {
  test('accepts a credential pinned to v2.1.json', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential()
    const mandate = await verifyMandate(credential, {
      trustedIssuers: [issuer],
      resolveDid: async () => didDocument
    })
    expect(mandate.credentialSchemaId).toBe('https://observerprotocol.org/schemas/delegation/v2.1.json')
    expect(mandate.authorizationLevel).toBe('recurring')
  })

  test('rejects a credential pinned to v2.json (frozen, not in adapter allowlist)', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential({
      schemaId: 'https://observerprotocol.org/schemas/delegation/v2.json'
    })
    await expect(
      verifyMandate(credential, { trustedIssuers: [issuer], resolveDid: async () => didDocument })
    ).rejects.toMatchObject({ name: 'VerificationError', code: 'schema_not_recognised' })
  })

  test('rejects unknown schema URL', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential({
      schemaId: 'https://example.evil/schemas/whatever.json'
    })
    await expect(
      verifyMandate(credential, { trustedIssuers: [issuer], resolveDid: async () => didDocument })
    ).rejects.toMatchObject({ code: 'schema_not_recognised' })
  })

  test('honours a caller-supplied allowlist extension', async () => {
    const customSchema = 'https://observerprotocol.org/schemas/delegation/v2.1.json'
    const { credential, didDocument, issuer } = buildSignedCredential({ schemaId: customSchema })
    const m = await verifyMandate(credential, {
      trustedIssuers: [issuer],
      schemaAllowlist: [customSchema],
      resolveDid: async () => didDocument
    })
    expect(m.credentialSchemaId).toBe(customSchema)
  })
})

describe('verifyMandate — validity window', () => {
  test('rejects expired credential', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential({
      validFrom: '2024-01-01T00:00:00Z',
      validUntil: '2024-12-31T00:00:00Z'
    })
    await expect(
      verifyMandate(credential, {
        trustedIssuers: [issuer],
        resolveDid: async () => didDocument,
        nowMs: Date.parse('2026-06-01T00:00:00Z')
      })
    ).rejects.toMatchObject({ code: 'expired' })
  })

  test('rejects not-yet-valid credential', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential({
      validFrom: '2030-01-01T00:00:00Z',
      validUntil: '2030-12-31T00:00:00Z'
    })
    await expect(
      verifyMandate(credential, {
        trustedIssuers: [issuer],
        resolveDid: async () => didDocument,
        nowMs: Date.parse('2026-06-01T00:00:00Z')
      })
    ).rejects.toMatchObject({ code: 'not_yet_valid' })
  })
})

describe('verifyMandate — signature binding', () => {
  test('rejects a credential whose proof was tampered with', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential()
    // Mutate a field after signing — should fail signature verification.
    credential.credentialSubject.actionScope.per_transaction_ceiling.amount = '999999'
    await expect(
      verifyMandate(credential, { trustedIssuers: [issuer], resolveDid: async () => didDocument })
    ).rejects.toMatchObject({ code: 'signature_invalid' })
  })

  test('rejects a credential signed by a key not in assertionMethod', async () => {
    const { credential, didDocument, issuer } = buildSignedCredential()
    // Move the verification method out of assertionMethod.
    didDocument.assertionMethod = []
    await expect(
      verifyMandate(credential, { trustedIssuers: [issuer], resolveDid: async () => didDocument })
    ).rejects.toMatchObject({ code: 'verification_method_not_in_assertion' })
  })
})

describe('verifyMandate — issuer trust', () => {
  test('rejects untrusted issuer', async () => {
    const { credential, didDocument } = buildSignedCredential()
    await expect(
      verifyMandate(credential, { trustedIssuers: ['did:web:other.example'], resolveDid: async () => didDocument })
    ).rejects.toMatchObject({ code: 'issuer_untrusted' })
  })
})

describe('VerificationError', () => {
  test('carries a machine-readable code', () => {
    const err = new VerificationError('test_code', 'test message')
    expect(err.code).toBe('test_code')
    expect(err.message).toBe('test message')
    expect(err.name).toBe('VerificationError')
  })
})
