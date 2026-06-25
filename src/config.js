// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

/**
 * Default Observer Protocol API base URL. Override via TrustProtocolConfig.apiBase.
 *
 * @type {string}
 */
export const DEFAULT_API_BASE = 'https://api.observerprotocol.org'

/**
 * BIP-32 derivation path for the agent's Ed25519 signing key, derived from the
 * wallet seed. Domain-separated under purpose 7000 to avoid collision with
 * BIP-44 coin types (44'/0' Bitcoin, 44'/60' Ethereum, etc).
 *
 * The path is "m/7000'/0'/0'/0/0" — fixed for v1. Subsequent agents from the
 * same wallet seed (multi-agent support) will increment the last index.
 *
 * @type {string}
 */
export const DEFAULT_DID_DERIVATION_PATH = "m/7000'/0'/0'/0/0"

/**
 * Default request timeout for OP API calls (milliseconds).
 *
 * @type {number}
 */
export const DEFAULT_REQUEST_TIMEOUT_MS = 15_000

/**
 * Identifier prefix for the OP DID method. All agents have DIDs of the form
 * `did:web:observerprotocol.org:agents:{agent_id}`.
 *
 * @type {string}
 */
export const DID_PREFIX = 'did:web:observerprotocol.org:agents:'

/**
 * Verification method type for Ed25519 keys in DID documents.
 *
 * Note: the constant value `Ed25519VerificationKey2020` is the W3C
 * verification-method type and is independent of the signature suite name.
 * AIP v0.6 renamed the signature suite from `Ed25519Signature2020` to
 * `Ed25519Signature2026` (the W3C `2020` suite implies URDNA2015
 * canonicalization; OP uses JCS-style, so the year-stamp is neutral).
 * This package does not consume the signature suite name directly —
 * verification is via challenge-response, not credential-proof parsing.
 *
 * @type {string}
 */
export const VERIFICATION_METHOD_TYPE = 'Ed25519VerificationKey2020'

/**
 * Default trusted-issuer DID set for the AIP v0.8 mandate surface.
 * Override via ObserverTrustOptions.trustedIssuers in user code.
 *
 * @type {ReadonlyArray<string>}
 */
export const DEFAULT_TRUSTED_ISSUERS = Object.freeze([
  'did:web:observerprotocol.org'
])

/**
 * The current, allowlisted AIP v0.8 delegation schema (frozen URL).
 * Per schema immutability policy: every schema change gets a new URL;
 * this version is frozen forever once published.
 *
 * @type {string}
 */
export const DELEGATION_SCHEMA_V2_1 = 'https://observerprotocol.org/schemas/delegation/v2.1.json'

/**
 * Ed25519 key derivation paths for the three OP roles in a community install.
 *
 * These paths are consumed by createDidKeyAgent(seed, path) on both the
 * bootstrap side (key generation) and the wallet-service side (DID derivation
 * from the stored seed). The WBC binds the wallet DID that results from
 * WALLET; if the path ever changes, the binding silently points at the wrong
 * address. Always import from here — never hardcode the literals.
 *
 * @type {string}
 */
export const BOOTSTRAP_PATH_PRINCIPAL = "m/observer-protocol'/principal/0/0/0"
export const BOOTSTRAP_PATH_AGENT = "m/observer-protocol'/agent/0/0/0"
export const BOOTSTRAP_PATH_WALLET = "m/observer-protocol'/wallet/0/0/0"
