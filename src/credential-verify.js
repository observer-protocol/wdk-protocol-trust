// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { ed25519 } from '@noble/curves/ed25519'

import { DEFAULT_TRUSTED_ISSUERS, DEFAULT_REQUEST_TIMEOUT_MS } from './config.js'
import { SCHEMA_ALLOWLIST, isAllowedSchema } from './schema-allowlist.js'

/**
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_MAP = new Map()
for (let i = 0; i < BASE58_ALPHABET.length; i++) BASE58_MAP.set(BASE58_ALPHABET[i], i)

/**
 * VerificationError carries a machine-readable `code` so callers can branch
 * on failure mode without parsing messages.
 */
export class VerificationError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor (code, message) {
    super(message)
    this.name = 'VerificationError'
    this.code = code
  }
}

/**
 * Canonicalize a credential for signing/verifying. Matches the Sovereign
 * issuer's canonicalization exactly: exclude the `proof` field, recursively
 * sort object keys lexicographically, JSON.stringify with no whitespace.
 *
 * Note: this is not full RFC 8785 JCS — it is the sort-keys-and-compact
 * subset, which matches the Python `json.dumps(..., sort_keys=True,
 * separators=(',', ':'))` used in the reference issuer. The two MUST stay
 * byte-identical; if the issuer ever switches to full RFC 8785, this
 * function moves with it via a new schema URL (per the schema immutability
 * policy).
 *
 * @param {object} credential
 * @returns {string}
 */
export function canonicalizeForSigning (credential) {
  if (credential === null || typeof credential !== 'object') {
    throw new TypeError('canonicalizeForSigning: credential must be an object')
  }
  const withoutProof = {}
  for (const [k, v] of Object.entries(credential)) {
    if (k !== 'proof') withoutProof[k] = v
  }
  return JSON.stringify(_sortKeysRecursive(withoutProof))
}

/**
 * @private
 * @param {*} value
 * @returns {*}
 */
function _sortKeysRecursive (value) {
  if (Array.isArray(value)) return value.map(_sortKeysRecursive)
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort()
    const out = {}
    for (const k of keys) out[k] = _sortKeysRecursive(value[k])
    return out
  }
  return value
}

/**
 * Decode a Bitcoin-alphabet base58 string to raw bytes.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function base58Decode (str) {
  if (typeof str !== 'string') throw new TypeError('base58Decode: input must be a string')
  if (str.length === 0) return new Uint8Array(0)

  let leading = 0
  while (leading < str.length && str[leading] === '1') leading++

  /** @type {number[]} */
  const bytes = []
  for (let i = leading; i < str.length; i++) {
    const c = str[i]
    const v = BASE58_MAP.get(c)
    if (v === undefined) throw new VerificationError('base58_invalid', 'invalid base58 character: ' + c)
    let carry = v
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58
      bytes[j] = carry & 0xff
      carry >>>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>>= 8
    }
  }

  const out = new Uint8Array(leading + bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    out[leading + bytes.length - 1 - i] = bytes[i]
  }
  return out
}

/**
 * Decode a multibase base58btc Ed25519 public key (z-prefixed, with the
 * 0xed 0x01 multicodec header). Returns the raw 32-byte public key.
 *
 * @param {string} mb
 * @returns {Uint8Array}
 */
export function decodePublicKeyMultibase (mb) {
  if (typeof mb !== 'string' || mb.length === 0 || mb[0] !== 'z') {
    throw new VerificationError('multibase_invalid', 'publicKeyMultibase must be a z-prefixed base58btc string')
  }
  const bytes = base58Decode(mb.slice(1))
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new VerificationError('multibase_invalid', 'publicKeyMultibase must carry the Ed25519 multicodec prefix 0xed 0x01')
  }
  return bytes.slice(2)
}

/**
 * Decode a multibase base58btc signature value (z-prefixed). Returns the
 * raw 64-byte signature.
 *
 * @param {string} mb
 * @returns {Uint8Array}
 */
export function decodeSignatureMultibase (mb) {
  if (typeof mb !== 'string' || mb.length === 0 || mb[0] !== 'z') {
    throw new VerificationError('multibase_invalid', 'proofValue must be a z-prefixed base58btc string')
  }
  const bytes = base58Decode(mb.slice(1))
  if (bytes.length !== 64) {
    throw new VerificationError('signature_length', 'Ed25519 signature must be 64 bytes; got ' + bytes.length)
  }
  return bytes
}

/**
 * Resolve a `did:web:...` DID to its DID document URL and fetch it.
 *
 * Mapping (per the did:web spec):
 *   did:web:example.org              → https://example.org/.well-known/did.json
 *   did:web:example.org:user:alice   → https://example.org/user/alice/did.json
 *
 * @param {string} did
 * @param {{fetchImpl?: typeof fetch, timeoutMs?: number}} [opts]
 * @returns {Promise<object>} The DID document.
 */
export async function resolveDidWeb (did, opts = {}) {
  if (typeof did !== 'string' || !did.startsWith('did:web:')) {
    throw new VerificationError('did_method_unsupported', 'verifyMandate supports did:web issuers only; got: ' + did)
  }
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch
  if (typeof fetchImpl !== 'function') {
    throw new VerificationError('fetch_unavailable', 'no global fetch available; pass fetchImpl in options')
  }
  const parts = did.slice('did:web:'.length).split(':').map(decodeURIComponent)
  const host = parts.shift()
  if (!host) throw new VerificationError('did_malformed', 'did:web has no host: ' + did)
  const url = parts.length === 0
    ? `https://${host}/.well-known/did.json`
    : `https://${host}/${parts.join('/')}/did.json`

  const ctrl = new AbortController()
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS)
  let res
  try {
    res = await fetchImpl(url, { signal: ctrl.signal })
  } finally {
    clearTimeout(t)
  }
  if (!res.ok) {
    throw new VerificationError('did_fetch_failed', `did:web fetch failed (${res.status}): ${url}`)
  }
  return res.json()
}

/**
 * Locate a verification method in a DID document by its full id
 * (e.g. `did:web:observerprotocol.org#key-2`). Returns the verification
 * method object, or throws.
 *
 * Verifies the method is referenced in `assertionMethod` so that keys
 * present only in `verificationMethod` (e.g. retained-for-history v0.6
 * `#key-1`) cannot be used to verify newly-issued credentials. Mirrors the
 * normative check in AIP v0.8 §3.4 / §4.
 *
 * @param {object} didDocument
 * @param {string} verificationMethodId
 * @returns {object}
 */
export function findAssertionMethod (didDocument, verificationMethodId) {
  if (!didDocument || typeof didDocument !== 'object') {
    throw new VerificationError('did_doc_malformed', 'DID document is not an object')
  }
  const vms = Array.isArray(didDocument.verificationMethod) ? didDocument.verificationMethod : []
  const am = Array.isArray(didDocument.assertionMethod) ? didDocument.assertionMethod : []

  const assertionIds = new Set()
  for (const entry of am) {
    if (typeof entry === 'string') assertionIds.add(entry)
    else if (entry && typeof entry.id === 'string') assertionIds.add(entry.id)
  }
  if (!assertionIds.has(verificationMethodId)) {
    throw new VerificationError(
      'verification_method_not_in_assertion',
      `verificationMethod ${verificationMethodId} is not listed in assertionMethod`
    )
  }

  for (const vm of vms) {
    if (vm && vm.id === verificationMethodId) return vm
  }
  // Fallback: assertionMethod entry may be the full object.
  for (const entry of am) {
    if (entry && typeof entry === 'object' && entry.id === verificationMethodId) return entry
  }
  throw new VerificationError('verification_method_missing', `verificationMethod ${verificationMethodId} not found in DID document`)
}

/**
 * Verify the W3C VC proof on a credential. Returns true on success; throws
 * `VerificationError` with a machine-readable code on failure.
 *
 * @param {object} credential
 * @param {object} didDocument
 * @returns {boolean}
 */
export function verifyCredentialProof (credential, didDocument) {
  if (!credential || typeof credential !== 'object') {
    throw new VerificationError('credential_malformed', 'credential must be an object')
  }
  const proof = credential.proof
  if (!proof || typeof proof !== 'object') {
    throw new VerificationError('proof_missing', 'credential.proof missing or malformed')
  }
  if (proof.type !== 'Ed25519Signature2026' && proof.type !== 'Ed25519Signature2020') {
    throw new VerificationError('proof_type_unsupported', 'unsupported proof.type: ' + proof.type)
  }
  if (proof.proofPurpose !== 'assertionMethod') {
    throw new VerificationError('proof_purpose_invalid', 'proof.proofPurpose must be assertionMethod')
  }
  if (typeof proof.verificationMethod !== 'string') {
    throw new VerificationError('proof_vm_missing', 'proof.verificationMethod missing')
  }
  if (typeof proof.proofValue !== 'string') {
    throw new VerificationError('proof_value_missing', 'proof.proofValue missing')
  }

  const vm = findAssertionMethod(didDocument, proof.verificationMethod)
  if (typeof vm.publicKeyMultibase !== 'string') {
    throw new VerificationError('vm_pubkey_missing', 'verificationMethod has no publicKeyMultibase')
  }
  const publicKey = decodePublicKeyMultibase(vm.publicKeyMultibase)
  const signature = decodeSignatureMultibase(proof.proofValue)
  const canonical = canonicalizeForSigning(credential)
  const msgBytes = new TextEncoder().encode(canonical)

  if (!ed25519.verify(signature, msgBytes, publicKey)) {
    throw new VerificationError('signature_invalid', 'Ed25519 signature verification failed')
  }
  return true
}

/**
 * Verify an `ObserverDelegationCredential` against the AIP v0.8 mandate
 * surface. Performs:
 *
 *   1. Shape validation (required fields present).
 *   2. credentialSchema.id is in the recognised allowlist (default:
 *      v2.1.json). Unknown URLs are rejected — the adapter does NOT fetch
 *      arbitrary schema URLs.
 *   3. issuer is in the trusted-issuer set.
 *   4. validFrom ≤ now ≤ validUntil.
 *   5. did:web resolution of the issuer.
 *   6. assertionMethod-bound Ed25519 signature verification over the
 *      canonical credential bytes.
 *
 * The status-list check (per AIP v0.6 §7) is NOT performed here in v1 —
 * it requires fetching the BitstringStatusListCredential, which is a
 * separate trust surface. Callers that require revocation checking
 * SHOULD layer it on top of this method, or use the OP API directly.
 *
 * @param {object} credential
 * @param {{
 *   trustedIssuers?: ReadonlyArray<string>,
 *   schemaAllowlist?: ReadonlyArray<string>,
 *   resolveDid?: (did: string) => Promise<object>,
 *   nowMs?: number
 * }} [options]
 * @returns {Promise<Mandate>}
 */
export async function verifyMandate (credential, options = {}) {
  if (credential === null || typeof credential !== 'object') {
    throw new VerificationError('credential_malformed', 'credential must be an object')
  }
  const trustedIssuers = options.trustedIssuers ?? DEFAULT_TRUSTED_ISSUERS
  const allowlist = options.schemaAllowlist ?? SCHEMA_ALLOWLIST
  const nowMs = options.nowMs ?? Date.now()

  const types = Array.isArray(credential.type) ? credential.type : []
  if (!types.includes('VerifiableCredential') || !types.includes('ObserverDelegationCredential')) {
    throw new VerificationError('credential_type_invalid', 'credential.type must include VerifiableCredential and ObserverDelegationCredential')
  }
  const schemaId = credential.credentialSchema && credential.credentialSchema.id
  if (!isAllowedSchema(schemaId, allowlist)) {
    throw new VerificationError(
      'schema_not_recognised',
      `credentialSchema.id (${schemaId}) is not in the adapter allowlist; this adapter implements AIP v0.8 semantics. ` +
      'Recognised set: ' + JSON.stringify(allowlist)
    )
  }
  if (typeof credential.issuer !== 'string' || !trustedIssuers.includes(credential.issuer)) {
    throw new VerificationError('issuer_untrusted', `issuer ${credential.issuer} is not in trustedIssuers ${JSON.stringify(trustedIssuers)}`)
  }
  if (typeof credential.validFrom !== 'string' || typeof credential.validUntil !== 'string') {
    throw new VerificationError('validity_missing', 'credential.validFrom and credential.validUntil are required')
  }
  const vf = Date.parse(credential.validFrom)
  const vu = Date.parse(credential.validUntil)
  if (Number.isNaN(vf) || Number.isNaN(vu)) {
    throw new VerificationError('validity_malformed', 'validFrom / validUntil must be ISO 8601 timestamps')
  }
  if (nowMs < vf) {
    throw new VerificationError('not_yet_valid', `credential not yet valid (validFrom=${credential.validFrom}, now=${new Date(nowMs).toISOString()})`)
  }
  if (nowMs > vu) {
    throw new VerificationError('expired', `credential expired (validUntil=${credential.validUntil}, now=${new Date(nowMs).toISOString()})`)
  }
  const subject = credential.credentialSubject
  if (!subject || typeof subject !== 'object' || typeof subject.id !== 'string') {
    throw new VerificationError('subject_malformed', 'credentialSubject.id must be a string DID')
  }
  if (!subject.actionScope || typeof subject.actionScope !== 'object') {
    throw new VerificationError('actionscope_missing', 'credentialSubject.actionScope is required for the spending mandate surface')
  }
  if (subject.authorizationLevel !== 'one-time' && subject.authorizationLevel !== 'recurring' && subject.authorizationLevel !== 'policy') {
    throw new VerificationError('authz_level_invalid', 'credentialSubject.authorizationLevel must be one-time | recurring | policy')
  }

  const resolveDid = options.resolveDid ?? resolveDidWeb
  const didDoc = await resolveDid(credential.issuer)
  verifyCredentialProof(credential, didDoc)

  return /** @type {Mandate} */ ({
    credentialId: typeof credential.id === 'string' ? credential.id : '',
    issuer: credential.issuer,
    subjectDid: subject.id,
    validFrom: credential.validFrom,
    validUntil: credential.validUntil,
    authorizationLevel: subject.authorizationLevel,
    authorizationConfig: subject.authorizationConfig ?? {},
    actionScope: subject.actionScope,
    credentialSchemaId: schemaId,
    raw: credential
  })
}
