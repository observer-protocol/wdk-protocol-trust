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
import { hmac } from '@noble/hashes/hmac'
import { sha512 } from '@noble/hashes/sha512'

import { DID_PREFIX, VERIFICATION_METHOD_TYPE } from './config.js'

/**
 * Derive a deterministic Ed25519 keypair from a wallet account's seed material
 * and a derivation path string. The path is hashed with HMAC-SHA512 over the
 * raw seed bytes; the first 32 bytes of the result become the Ed25519 secret
 * key. This is NOT BIP-32 derivation (Ed25519 has its own SLIP-0010 spec); it
 * is a domain-separated KDF chosen for simplicity and determinism within this
 * module's scope.
 *
 * The result is stable across calls: same seed + same path → same keypair.
 *
 * @param {Uint8Array | string} seed - Raw seed bytes or hex-encoded seed.
 * @param {string} derivationPath - Domain-separation path (e.g. "m/7000'/0'/0'/0/0").
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}} The derived keypair.
 */
export function deriveEd25519Keypair (seed, derivationPath) {
  const seedBytes = typeof seed === 'string' ? hexToBytes(seed) : seed
  if (!(seedBytes instanceof Uint8Array)) {
    throw new TypeError('seed must be Uint8Array or hex string')
  }
  if (typeof derivationPath !== 'string' || !derivationPath.length) {
    throw new TypeError('derivationPath must be a non-empty string')
  }

  // HMAC-SHA512(key=seedBytes, msg=derivationPath) → 64 bytes; first 32 are sk
  const pathBytes = new TextEncoder().encode(derivationPath)
  const mac = hmac(sha512, seedBytes, pathBytes)
  const privateKey = mac.slice(0, 32)
  const publicKey = ed25519.getPublicKey(privateKey)
  return { privateKey, publicKey }
}

/**
 * Encode a 32-byte Ed25519 public key as multibase base58btc with the
 * `z` prefix and the Ed25519 multicodec header (0xed, 0x01), per W3C
 * `Ed25519VerificationKey2020`.
 *
 * @param {Uint8Array} publicKey - 32-byte raw Ed25519 public key.
 * @returns {string} Multibase string (e.g. "z6Mk...").
 */
export function publicKeyMultibase (publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new TypeError('publicKey must be a 32-byte Uint8Array')
  }
  // Multicodec prefix for ed25519-pub: varint 0xed, 0x01
  const prefixed = new Uint8Array(34)
  prefixed[0] = 0xed
  prefixed[1] = 0x01
  prefixed.set(publicKey, 2)
  return 'z' + base58btcEncode(prefixed)
}

/**
 * Compute the agent_id (per OP convention: SHA-256 of the multibase pubkey, hex-encoded
 * first 32 chars). This is deterministic given the public key.
 *
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key.
 * @returns {string} 32-char lowercase hex agent_id.
 */
export function deriveAgentId (publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new TypeError('publicKey must be a 32-byte Uint8Array')
  }
  const digest = sha256(publicKey)
  return bytesToHex(digest).slice(0, 32)
}

/**
 * Construct the full agent DID for a given agent_id.
 *
 * @param {string} agentId - 32-char hex agent identifier.
 * @returns {string} The DID (e.g. "did:web:observerprotocol.org:agents:abc...").
 */
export function buildDid (agentId) {
  return DID_PREFIX + agentId
}

/**
 * Build a W3C-conformant DID document for the given agent.
 *
 * @param {string} agentId - The agent identifier.
 * @param {Uint8Array} publicKey - The agent's 32-byte Ed25519 public key.
 * @returns {Record<string, unknown>} DID document object.
 */
export function buildDidDocument (agentId, publicKey) {
  const did = buildDid(agentId)
  const keyId = `${did}#key-1`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: VERIFICATION_METHOD_TYPE,
        controller: did,
        publicKeyMultibase: publicKeyMultibase(publicKey)
      }
    ],
    authentication: [keyId],
    assertionMethod: [keyId]
  }
}

/**
 * Sign a challenge with the agent's Ed25519 private key.
 *
 * @param {Uint8Array | string} message - Message bytes or UTF-8 string.
 * @param {Uint8Array} privateKey - 32-byte Ed25519 private key.
 * @returns {string} Hex-encoded signature.
 */
export function signChallenge (message, privateKey) {
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new TypeError('privateKey must be a 32-byte Uint8Array')
  }
  const sig = ed25519.sign(msgBytes, privateKey)
  return bytesToHex(sig)
}

/**
 * Verify an Ed25519 signature.
 *
 * @param {string} signatureHex - Hex-encoded signature.
 * @param {Uint8Array | string} message - Original message.
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key.
 * @returns {boolean} True if signature is valid.
 */
export function verifySignature (signatureHex, message, publicKey) {
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message
  const sigBytes = hexToBytes(signatureHex)
  return ed25519.verify(sigBytes, msgBytes, publicKey)
}

// ── helpers ────────────────────────────────────────────────────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * Encode bytes as base58btc (no checksum).
 *
 * @param {Uint8Array} bytes - Bytes to encode.
 * @returns {string} Base58btc string.
 * @private
 */
function base58btcEncode (bytes) {
  if (bytes.length === 0) return ''
  // Count leading zeros
  let zeros = 0
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++
  // BigInt accumulator
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
 * Decode a hex string into a byte array.
 *
 * @param {string} hex - Hex string, optionally prefixed with "0x".
 * @returns {Uint8Array} Decoded bytes.
 * @private
 */
function hexToBytes (hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  if (clean.length % 2 !== 0) throw new Error('invalid hex string length')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

/**
 * Encode a byte array as a lowercase hex string (no "0x" prefix).
 *
 * @param {Uint8Array} bytes - Bytes to encode.
 * @returns {string} Hex string.
 * @private
 */
function bytesToHex (bytes) {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}
