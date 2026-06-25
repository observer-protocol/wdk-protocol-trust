// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha256'

import {
  buildSettlementAttestation,
  jcsCanonicalize,
  decodePublicKeyMultibase,
  decodeSignatureMultibase,
  publicKeyMultibase,
  PROOF_SUITE_TYPE,
  PROOF_SUITE_CRYPTOSUITE
} from '../index.js'

function fixture () {
  const credential = {
    id: 'urn:uuid:test-delegation',
    type: ['VerifiableCredential', 'ObserverDelegationCredential'],
    issuer: 'did:web:observerprotocol.org',
    credentialSubject: {
      id: 'did:web:observerprotocol.org:agents:test-agent',
      actionScope: {
        allowed_rails: ['usdt_tron'],
        per_transaction_ceiling: { amount: '100', currency: 'USDT' }
      }
    },
    credentialSchema: { id: 'https://observerprotocol.org/schemas/delegation/v2.1.json', type: 'JsonSchema' },
    proof: {
      type: 'Ed25519Signature2026',
      verificationMethod: 'did:web:observerprotocol.org#key-2',
      proofPurpose: 'assertionMethod',
      proofValue: 'z3yY...'
    }
  }
  const action = {
    rail: 'usdt_tron',
    amount: { amount: '50', currency: 'USDT' },
    category: 'ai_inference_credits',
    counterparty_did: 'did:web:vendor.example:agents:store'
  }
  const settlement = { rail: 'usdt_tron', ref: '0xabcdef' }
  const attestationKey = ed25519.utils.randomPrivateKey()
  const publicKey = ed25519.getPublicKey(attestationKey)
  return { credential, action, settlement, attestationKey, publicKey }
}

// Recompute the eddsa-jcs-2022 hashData from a signed attestation so tests
// can manually verify the signature without re-implementing buildSettlementAttestation.
function attHashData (att) {
  const proofConfig = {}
  for (const [k, v] of Object.entries(att.proof)) {
    if (k !== 'proofValue') proofConfig[k] = v
  }
  const docNoProof = {}
  for (const [k, v] of Object.entries(att)) {
    if (k !== 'proof') docNoProof[k] = v
  }
  const enc = new TextEncoder()
  const hashData = new Uint8Array(64)
  hashData.set(sha256(enc.encode(jcsCanonicalize(proofConfig))), 0)
  hashData.set(sha256(enc.encode(jcsCanonicalize(docNoProof))), 32)
  return hashData
}

describe('buildSettlementAttestation', () => {
  test('produces a signed envelope with the required shape', () => {
    const { credential, action, settlement, attestationKey } = fixture()
    const att = buildSettlementAttestation({
      credential,
      action,
      settlement,
      attestationKey,
      verificationMethod: 'did:web:agent.example#key-1',
      issuerDid: 'did:web:agent.example'
    })
    expect(att.type).toEqual(['VerifiableCredential', 'ObserverSettlementAttestation'])
    expect(att.issuer).toBe('did:web:agent.example')
    expect(att.credentialSubject.delegation.credentialId).toBe(credential.id)
    expect(att.credentialSubject.delegation.credentialSchemaId).toBe(credential.credentialSchema.id)
    expect(att.credentialSubject.delegation.credentialHash).toMatch(/^[0-9a-f]{64}$/)
    expect(att.credentialSubject.action.rail).toBe('usdt_tron')
    expect(att.credentialSubject.action.amount).toEqual({ amount: '50', currency: 'USDT' })
    expect(att.credentialSubject.settlement).toEqual({ rail: 'usdt_tron', ref: '0xabcdef' })
    expect(att.proof.type).toBe(PROOF_SUITE_TYPE)
    expect(att.proof.cryptosuite).toBe(PROOF_SUITE_CRYPTOSUITE)
    expect(att.proof.proofValue.startsWith('z')).toBe(true)
  })

  test('round-trip: signature verifies against attestation key', () => {
    const { credential, action, settlement, attestationKey, publicKey } = fixture()
    const att = buildSettlementAttestation({
      credential,
      action,
      settlement,
      attestationKey,
      verificationMethod: 'did:web:agent.example#key-1',
      issuerDid: 'did:web:agent.example'
    })

    const sig = decodeSignatureMultibase(att.proof.proofValue)
    const ok = ed25519.verify(sig, attHashData(att), publicKey)
    expect(ok).toBe(true)
  })

  test('tampering with the action after signing breaks verification', () => {
    const { credential, action, settlement, attestationKey, publicKey } = fixture()
    const att = buildSettlementAttestation({
      credential,
      action,
      settlement,
      attestationKey,
      verificationMethod: 'did:web:agent.example#key-1',
      issuerDid: 'did:web:agent.example'
    })

    const origHashData = attHashData(att)
    att.credentialSubject.action.amount.amount = '9999'
    const sig = decodeSignatureMultibase(att.proof.proofValue)
    // Verify against the ORIGINAL hash (pre-tamper) to confirm signature bound to original content.
    // The tampered hash would differ, so we check the original still verifies and tampered does not.
    const okOriginal = ed25519.verify(sig, origHashData, publicKey)
    const okTampered = ed25519.verify(sig, attHashData(att), publicKey)
    expect(okOriginal).toBe(true)
    expect(okTampered).toBe(false)
  })

  test('string settlement is normalised to {rail, ref}', () => {
    const { credential, action, attestationKey } = fixture()
    const att = buildSettlementAttestation({
      credential,
      action,
      settlement: '0xdeadbeef',
      attestationKey,
      verificationMethod: 'did:web:agent.example#key-1',
      issuerDid: 'did:web:agent.example'
    })
    expect(att.credentialSubject.settlement).toEqual({ rail: 'usdt_tron', ref: '0xdeadbeef' })
  })

  test('anchored reference survives canonicalization', () => {
    const { credential, action, attestationKey, publicKey } = fixture()
    const att = buildSettlementAttestation({
      credential,
      action,
      settlement: { rail: 'usdt_tron', ref: '0xabc', anchored: { erc8004: '0xanchortxhash' } },
      attestationKey,
      verificationMethod: 'did:web:agent.example#key-1',
      issuerDid: 'did:web:agent.example'
    })
    expect(att.credentialSubject.settlement.anchored).toEqual({ erc8004: '0xanchortxhash' })
    // And the signature still verifies (anchored was inside the signed body).
    const sig = decodeSignatureMultibase(att.proof.proofValue)
    expect(ed25519.verify(sig, attHashData(att), publicKey)).toBe(true)
  })
})

describe('multibase decoders — round-trip', () => {
  test('decodePublicKeyMultibase reverses publicKeyMultibase', () => {
    const sk = ed25519.utils.randomPrivateKey()
    const pk = ed25519.getPublicKey(sk)
    const mb = publicKeyMultibase(pk)
    const decoded = decodePublicKeyMultibase(mb)
    expect(decoded).toEqual(pk)
  })
})
