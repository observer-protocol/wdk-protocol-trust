// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { canonicalizeForSigning, verifyCredentialProof } from './credential-verify.js'

/**
 * @file Proof helpers for the OP shared trust core.
 *
 * Signs and verifies JSON documents using the same proof convention as the
 * umbrella's settlement attestation, so they round-trip with `verifyCredentialProof`:
 *
 *   - canonicalize with `canonicalizeForSigning` (sorted-key JCS),
 *   - Ed25519-sign the canonical bytes with the agent's `did:key`,
 *   - attach a `proof` block: type `Ed25519Signature2026`,
 *     `proofValue = 'z' + base58btc(signature)`, `verificationMethod = agent.keyId`.
 */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function hexToBytes (hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function base58btcEncode (bytes) {
  if (bytes.length === 0) return ''
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  let n = 0n
  for (const b of bytes) n = (n << 8n) | BigInt(b)
  let out = ''
  while (n > 0n) {
    const r = n % 58n
    n = n / 58n
    out = BASE58_ALPHABET[Number(r)] + out
  }
  return '1'.repeat(zeros) + out
}

/**
 * Sign a JSON document, returning a copy with a `proof` block attached.
 *
 * @param {Record<string, unknown>} doc - The unsigned document.
 * @param {{ sign: (msg: string) => string, keyId: string }} agent - A `did:key`
 *   agent (see `createDidKeyAgent`).
 * @returns {Record<string, unknown>} The signed document.
 */
export function signDocument (doc, agent) {
  const canonical = canonicalizeForSigning(doc)
  const sigHex = agent.sign(canonical)
  const proofValue = 'z' + base58btcEncode(hexToBytes(sigHex))
  return {
    ...doc,
    proof: {
      type: 'Ed25519Signature2026',
      created: doc.issuanceDate || doc.created || undefined,
      verificationMethod: agent.keyId,
      proofPurpose: 'assertionMethod',
      proofValue
    }
  }
}

/**
 * Verify a signed document against a DID document, via `verifyCredentialProof`.
 *
 * @param {Record<string, unknown>} signedDoc
 * @param {Record<string, unknown>} didDocument
 * @returns {boolean}
 */
export function verifyDocument (signedDoc, didDocument) {
  try {
    return verifyCredentialProof(signedDoc, didDocument) === true
  } catch {
    return false
  }
}
