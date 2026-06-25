// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import {
  deriveEd25519Keypair,
  publicKeyMultibase,
  signChallenge,
  verifySignature
} from './did-utils.js'

/**
 * @file Ed25519 `did:key` agent creation for the OP shared trust core.
 *
 * `did:key` for Ed25519 is `did:key:` + the multibase-base58btc encoding of the
 * `0xed01` multicodec-prefixed public key. `publicKeyMultibase` from did-utils
 * emits that exact prefixed encoding, so the fragment is correct by construction
 * (avoids the missing-multicodec-prefix class of DID-doc bug).
 */

const DID_KEY_PREFIX = 'did:key:'

/**
 * Mint a fresh Ed25519 `did:key` agent from seed material.
 *
 * @param {Uint8Array | string} seed - Raw seed bytes or hex seed.
 * @param {string} [derivationPath] - Domain-separation path for the KDF.
 * @returns {{
 *   did: string,
 *   multibase: string,
 *   keyId: string,
 *   publicKey: Uint8Array,
 *   privateKey: Uint8Array,
 *   sign: (message: Uint8Array | string) => string,
 *   verify: (signatureHex: string, message: Uint8Array | string) => boolean,
 *   didDocument: Record<string, unknown>
 * }}
 */
export function createDidKeyAgent (seed, derivationPath = "m/observer-protocol'/agent/0/0/0") {
  const { privateKey, publicKey } = deriveEd25519Keypair(seed, derivationPath)
  const multibase = publicKeyMultibase(publicKey)
  const did = DID_KEY_PREFIX + multibase
  const keyId = `${did}#${multibase}`

  return {
    did,
    multibase,
    keyId,
    publicKey,
    privateKey,
    sign: (message) => signChallenge(message, privateKey),
    verify: (signatureHex, message) => verifySignature(signatureHex, message, publicKey),
    didDocument: buildDidKeyDocument(did, multibase)
  }
}

/**
 * Build the W3C DID document for an Ed25519 `did:key`. The verification-method
 * id fragment is the multibase value itself; the same key is referenced by both
 * `authentication` and `assertionMethod` — so the signing key is always in
 * `assertionMethod` (strict-W3C-verification safe).
 *
 * @param {string} did
 * @param {string} multibase - The `z…` multibase public key.
 * @returns {Record<string, unknown>}
 */
export function buildDidKeyDocument (did, multibase) {
  const keyId = `${did}#${multibase}`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ],
    id: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: multibase
      }
    ],
    authentication: [keyId],
    assertionMethod: [keyId]
  }
}
