// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

/** @typedef {import('./src/trust-protocol.js').TrustProtocolConfig} TrustProtocolConfig */
/** @typedef {import('./src/trust-protocol.js').RegisterOptions} RegisterOptions */
/** @typedef {import('./src/trust-protocol.js').RegisterResult} RegisterResult */
/** @typedef {import('./src/trust-protocol.js').VerifyResult} VerifyResult */
/** @typedef {import('./src/trust-protocol.js').BilateralVerifyResult} BilateralVerifyResult */
/** @typedef {import('./src/trust-protocol.js').AttestPaymentOptions} AttestPaymentOptions */
/** @typedef {import('./src/trust-protocol.js').AttestPaymentResult} AttestPaymentResult */

export { default } from './src/observer-trust-protocol.js'
export { default as ObserverTrustProtocol } from './src/observer-trust-protocol.js'
export { default as TrustProtocol, ITrustProtocol, NotImplementedError } from './src/trust-protocol.js'
export { OpClient } from './src/op-client.js'
export {
  deriveEd25519Keypair,
  deriveAgentId,
  buildDid,
  buildDidDocument,
  publicKeyMultibase,
  signChallenge,
  verifySignature
} from './src/did-utils.js'
export {
  DEFAULT_API_BASE,
  DEFAULT_DID_DERIVATION_PATH,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_TRUSTED_ISSUERS,
  DID_PREFIX,
  VERIFICATION_METHOD_TYPE
} from './src/config.js'

// ── AIP v0.8 mandate surface ──────────────────────────────────────────────
export { SCHEMA_ALLOWLIST, isAllowedSchema } from './src/schema-allowlist.js'
export { withinScope } from './src/mandate.js'
export { PolicyGate, AdvisoryGate } from './src/policy-gate.js'
export { WdkEnforcementGate } from './src/wdk-enforcement-gate.js'
export {
  VerificationError,
  verifyMandate,
  canonicalizeForSigning,
  resolveDidWeb,
  verifyCredentialProof,
  findAssertionMethod,
  decodePublicKeyMultibase,
  decodeSignatureMultibase,
  base58Decode
} from './src/credential-verify.js'
export { buildSettlementAttestation } from './src/attestation.js'

// ── did:key creation and document building ────────────────────────────────
export { createDidKeyAgent, buildDidKeyDocument } from './src/did-key.js'

// ── document signing and verification (Ed25519Signature2026 / JCS) ────────
export { signDocument, verifyDocument } from './src/proof.js'

// ── delegation schema constant ────────────────────────────────────────────
export { DELEGATION_SCHEMA_V2_1 } from './src/config.js'
