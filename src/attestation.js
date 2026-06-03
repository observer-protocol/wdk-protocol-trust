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

import { canonicalizeForSigning } from './credential-verify.js'

const PKG_VERSION = '0.2.0-beta.1'

/**
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 * @typedef {import('./mandate-types.js').ProposedAction} ProposedAction
 */

/**
 * Build and sign a `ObserverSettlementAttestation`. Binds:
 *   - the delegation credential (by id, schema URL, and SHA-256 of its
 *     JCS-canonical bytes — the proof block included, so the binding is
 *     to the exact signed bytes the issuer produced)
 *   - the proposed action (rail, amount, category, counterparty, optional
 *     pre-sign proposal hash)
 *   - the settlement (rail and rail-native reference)
 *   - this adapter as evaluator (id + version)
 *   - a timestamp
 *
 * The whole envelope is signed by the agent's attestation key using
 * Ed25519Signature2026 over canonicalized bytes (same sort-keys + compact
 * JSON algorithm used for delegation signing).
 *
 * This is the centerpiece surface from the WDK implementation brief: a
 * portable, anchored attestation binding *this* agent to *this* scoped
 * mandate at *this* settlement, signed independently of any payment rail.
 *
 * @param {{
 *   credential: object,
 *   action: ProposedAction,
 *   settlement: { rail: string, ref: string } | string,
 *   attestationKey: Uint8Array,
 *   verificationMethod: string,
 *   issuerDid: string,
 *   subjectDid?: string,
 *   nowMs?: number,
 *   id?: string
 * }} args
 * @returns {object} The signed attestation.
 */
export function buildSettlementAttestation (args) {
  if (!args || typeof args !== 'object') {
    throw new TypeError('buildSettlementAttestation: args required')
  }
  const { credential, action, attestationKey, verificationMethod, issuerDid } = args
  if (!credential || typeof credential !== 'object') {
    throw new TypeError('buildSettlementAttestation: credential required')
  }
  if (!action || typeof action !== 'object' || typeof action.rail !== 'string') {
    throw new TypeError('buildSettlementAttestation: action with rail required')
  }
  if (!(attestationKey instanceof Uint8Array) || attestationKey.length !== 32) {
    throw new TypeError('buildSettlementAttestation: attestationKey must be a 32-byte Uint8Array')
  }
  if (typeof verificationMethod !== 'string' || !verificationMethod.length) {
    throw new TypeError('buildSettlementAttestation: verificationMethod required')
  }
  if (typeof issuerDid !== 'string' || !issuerDid.length) {
    throw new TypeError('buildSettlementAttestation: issuerDid required')
  }

  const settlement = _normaliseSettlement(args.settlement, action.rail)
  const nowMs = args.nowMs ?? Date.now()
  const nowIso = new Date(nowMs).toISOString()
  const id = args.id || ('urn:uuid:' + _randomUuid())

  const delegationCanonical = canonicalizeForSigning(credential)
  const delegationHash = _bytesToHex(sha256(new TextEncoder().encode(delegationCanonical)))
  // Re-derive proof hash separately so verifiers can re-check signed bytes
  // independent of whether they trust this adapter's canonicalization.
  const delegationProofValue = credential.proof && typeof credential.proof.proofValue === 'string'
    ? credential.proof.proofValue
    : null

  const envelope = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id,
    type: ['VerifiableCredential', 'ObserverSettlementAttestation'],
    issuer: issuerDid,
    validFrom: nowIso,
    credentialSubject: {
      id: args.subjectDid || issuerDid,
      delegation: {
        credentialId: typeof credential.id === 'string' ? credential.id : '',
        credentialSchemaId: credential.credentialSchema && credential.credentialSchema.id,
        credentialHash: delegationHash,
        issuerProofValue: delegationProofValue
      },
      action: _normaliseAction(action),
      settlement,
      evaluator: {
        id: 'urn:observer-protocol:adapter:wdk-protocol-trust',
        version: PKG_VERSION
      }
    }
  }

  const canonical = canonicalizeForSigning(envelope)
  const sigBytes = ed25519.sign(new TextEncoder().encode(canonical), attestationKey)
  envelope.proof = {
    type: 'Ed25519Signature2026',
    created: nowIso,
    verificationMethod,
    proofPurpose: 'assertionMethod',
    proofValue: 'z' + _base58Encode(sigBytes)
  }
  return envelope
}

/**
 * @private
 * @param {ProposedAction} a
 */
function _normaliseAction (a) {
  /** @type {Record<string, unknown>} */
  const out = { rail: a.rail }
  if (a.amount && typeof a.amount === 'object') {
    out.amount = { amount: a.amount.amount, currency: a.amount.currency }
  }
  if (typeof a.category === 'string') out.category = a.category
  if (typeof a.counterparty_did === 'string') out.counterparty_did = a.counterparty_did
  if (typeof a.proposalHash === 'string') out.proposalHash = a.proposalHash
  return out
}

/**
 * @private
 * @param {{rail: string, ref: string} | string | undefined} s
 * @param {string} actionRail
 */
function _normaliseSettlement (s, actionRail) {
  if (!s) {
    throw new TypeError('buildSettlementAttestation: settlement required (object with rail+ref or string ref)')
  }
  if (typeof s === 'string') return { rail: actionRail, ref: s }
  if (typeof s.rail !== 'string' || typeof s.ref !== 'string') {
    throw new TypeError('buildSettlementAttestation: settlement.rail and settlement.ref required')
  }
  /** @type {Record<string, unknown>} */
  const out = { rail: s.rail, ref: s.ref }
  if (s.anchored && typeof s.anchored === 'object') out.anchored = s.anchored
  return out
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * @private
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function _base58Encode (bytes) {
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  /** @type {number[]} */
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
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]]
  return out
}

/**
 * @private
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function _bytesToHex (bytes) {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

/**
 * RFC 4122-style v4 UUID using globalThis.crypto when available.
 *
 * @private
 * @returns {string}
 */
function _randomUuid () {
  if (globalThis.crypto && typeof globalThis.crypto.randomUUID === 'function') {
    return globalThis.crypto.randomUUID()
  }
  const buf = new Uint8Array(16)
  if (globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(buf)
  } else {
    for (let i = 0; i < 16; i++) buf[i] = Math.floor(Math.random() * 256)
  }
  buf[6] = (buf[6] & 0x0f) | 0x40
  buf[8] = (buf[8] & 0x3f) | 0x80
  const hex = _bytesToHex(buf)
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}
