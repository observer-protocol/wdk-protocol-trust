// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { sha256 } from '@noble/hashes/sha256'
import { jcsCanonicalize, verifyCredentialProof } from './credential-verify.js'

/**
 * Canonical proof suite identifiers for Observer Protocol.
 * Import these wherever a proof type or cryptosuite string is needed —
 * never hardcode the literals.
 */
export const PROOF_SUITE_TYPE = 'DataIntegrityProof'
export const PROOF_SUITE_CRYPTOSUITE = 'eddsa-jcs-2022'

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
 * Sign a JSON document using DataIntegrityProof / eddsa-jcs-2022.
 *
 * Hash construction (W3C VC Data Integrity EdDSA Cryptosuites §3.3):
 *   hashData = SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(unsecuredDocument))
 *   signature = ed25519.sign(hashData, privateKey)
 *
 * @param {Record<string, unknown>} doc - The unsigned document.
 * @param {{ sign: (msg: Uint8Array | string) => string, keyId: string }} agent
 *   A `did:key` agent (see `createDidKeyAgent`). `sign` must accept a Uint8Array.
 * @returns {Record<string, unknown>} The signed document.
 */
export function signDocument (doc, agent) {
  const created = new Date().toISOString().replace(/\.\d+Z$/, 'Z')

  const proofConfig = {
    type: PROOF_SUITE_TYPE,
    cryptosuite: PROOF_SUITE_CRYPTOSUITE,
    created,
    verificationMethod: agent.keyId,
    proofPurpose: 'assertionMethod'
  }

  const docWithoutProof = {}
  for (const [k, v] of Object.entries(doc)) {
    if (k !== 'proof') docWithoutProof[k] = v
  }

  const enc = new TextEncoder()
  const hashProofConfig = sha256(enc.encode(jcsCanonicalize(proofConfig)))
  const hashDoc = sha256(enc.encode(jcsCanonicalize(docWithoutProof)))
  const hashData = new Uint8Array(64)
  hashData.set(hashProofConfig, 0)
  hashData.set(hashDoc, 32)

  const sigHex = agent.sign(hashData)
  const proofValue = 'z' + base58btcEncode(hexToBytes(sigHex))

  return {
    ...doc,
    proof: {
      ...proofConfig,
      proofValue
    }
  }
}

/**
 * Verify a signed document against a DID document.
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
