// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import TrustProtocol from './trust-protocol.js'
import { OpClient } from './op-client.js'
import {
  deriveEd25519Keypair,
  deriveAgentId,
  buildDid,
  buildDidDocument,
  signChallenge
} from './did-utils.js'
import { DEFAULT_DID_DERIVATION_PATH } from './config.js'

/** @typedef {import('./trust-protocol.js').TrustProtocolConfig} TrustProtocolConfig */
/** @typedef {import('./trust-protocol.js').RegisterOptions} RegisterOptions */
/** @typedef {import('./trust-protocol.js').RegisterResult} RegisterResult */
/** @typedef {import('./trust-protocol.js').VerifyResult} VerifyResult */
/** @typedef {import('./trust-protocol.js').BilateralVerifyResult} BilateralVerifyResult */
/** @typedef {import('./trust-protocol.js').AttestPaymentOptions} AttestPaymentOptions */
/** @typedef {import('./trust-protocol.js').AttestPaymentResult} AttestPaymentResult */

/**
 * Observer Protocol implementation of {@link TrustProtocol}.
 *
 * Binds a `@tetherto/wdk-wallet-evm` (or compatible) account to an Observer Protocol
 * agent identity. Derives a deterministic Ed25519 signing keypair from the wallet
 * seed (domain-separated under `m/7000'/0'/0'/0/0`), so the same wallet always
 * resolves to the same DID across sessions.
 *
 * @example
 * import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'
 * import { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'
 *
 * const account = new WalletAccountEvm(seedPhrase, "0'/0/0", { provider: 'https://...' })
 * const trust = new ObserverTrustProtocol(account, { apiBase: 'https://api.observerprotocol.org' })
 *
 * const { did } = await trust.register({ alias: 'my-agent' })
 * const counterparty = await trust.verify('seller-agent-7')
 * const handshake = await trust.bilateralVerify('seller-agent-7')
 * if (handshake.ok) {
 *   const txHash = await account.transfer({ ... })
 *   await trust.attestPayment({ txHash, recipient: 'seller-agent-7', chain: 'evm' })
 * }
 */
export default class ObserverTrustProtocol extends TrustProtocol {
  /**
   * @param {object} account - WDK wallet account (EVM today; future: TRON, Solana, …).
   * @param {TrustProtocolConfig} [config] - Protocol configuration.
   */
  constructor (account, config = {}) {
    super(account, config)
    /** @private */
    this._client = new OpClient({
      apiBase: config.apiBase,
      timeoutMs: config.requestTimeoutMs,
      headers: config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : undefined
    })
    /** @private */
    this._derivationPath = config.didDerivationPath || DEFAULT_DID_DERIVATION_PATH
    /** @private — populated lazily on first register/sign call */
    this._identity = null
  }

  /**
   * @param {RegisterOptions} options - Alias + metadata.
   * @returns {Promise<RegisterResult>} Registered identity.
   */
  async register (options) {
    if (!options || typeof options.alias !== 'string' || !options.alias.length) {
      throw new TypeError('register({alias}): alias must be a non-empty string')
    }
    const identity = await this._ensureIdentity()
    const merged = {
      ...(this._config.defaultMetadata || {}),
      ...(options.metadata || {})
    }
    // Map our metadata onto the live API's first-class query parameters.
    // `chains` must be a JSON-array-encoded string per the live API contract.
    const chainsList = Array.isArray(merged.chains)
      ? merged.chains
      : (typeof merged.chains === 'string' ? merged.chains.split(',').map(s => s.trim()).filter(Boolean) : ['evm'])
    const args = {
      public_key: bytesToHex(identity.publicKey),
      alias: options.alias,
      agent_name: merged.agent_name || options.alias,
      framework: merged.framework || 'wdk',
      wallet_standard: merged.wallet_standard || 'wdk-evm',
      chains: JSON.stringify(chainsList),
      ...(merged.org_id && { org_id: merged.org_id }),
      ...(merged.legal_entity_id && { legal_entity_id: merged.legal_entity_id }),
      ...(merged.ows_vault_name && { ows_vault_name: merged.ows_vault_name })
    }
    const res = await this._client.registerAgent(args)
    // The API assigns its own agent_id (distinct from any local derivation).
    // Trust the API-assigned id and construct the DID from it. If the API
    // returns a did/did_document directly, prefer those; else build locally.
    const apiAgentId = /** @type {string} */ (res.agent_id || res.id)
    if (!apiAgentId) {
      throw new Error(`register: API response missing agent_id (got: ${JSON.stringify(Object.keys(res || {}))})`)
    }
    const did = /** @type {string} */ (res.did || buildDid(apiAgentId))
    const didDocument = /** @type {Record<string,unknown>} */ (
      res.did_document || buildDidDocument(apiAgentId, identity.publicKey)
    )
    // Cache the API-assigned agent_id for subsequent challenge / attest calls.
    this._identity = { ...identity, agentId: apiAgentId, did }
    return { agentId: apiAgentId, did, didDocument }
  }

  /**
   * @param {string} alias - Counterparty alias or DID.
   * @returns {Promise<VerifyResult>} Counterparty identity + VAC + trust score.
   */
  async verify (alias) {
    if (typeof alias !== 'string' || !alias.length) {
      throw new TypeError('verify(alias): alias must be a non-empty string')
    }
    const agentId = await this._resolveAliasToAgentId(alias)
    const [didDocument, vac, trustScore] = await Promise.all([
      this._client.getAgentDidDocument(agentId),
      this._client.getVac(agentId),
      this._client.getTrustScore(agentId).catch(() => null)
    ])
    return {
      did: /** @type {string} */ (didDocument.id),
      didDocument,
      vac,
      ...(trustScore && { trustScore })
    }
  }

  /**
   * @param {string} recipientAlias - Recipient alias or DID.
   * @returns {Promise<BilateralVerifyResult>} Combined sender + recipient proof.
   */
  async bilateralVerify (recipientAlias) {
    const identity = await this._ensureIdentity()
    if (!identity.agentId) {
      return {
        ok: false,
        senderProof: null,
        recipient: null,
        reason: 'sender not registered: call register({alias}) first'
      }
    }

    let challenge
    try {
      challenge = await this._client.getChallenge(identity.agentId)
    } catch (err) {
      return {
        ok: false,
        senderProof: null,
        recipient: null,
        reason: `sender challenge failed: ${err.message}`
      }
    }

    // The challenge response shape varies; accept any of: nonce, challenge,
    // challenge_string. Defensive about the field names the live API returns.
    const nonce = /** @type {string} */ (challenge.nonce || challenge.challenge || challenge.challenge_string)
    const challengeId = /** @type {string|undefined} */ (challenge.challenge_id || challenge.id)
    if (!nonce) {
      return {
        ok: false,
        senderProof: null,
        recipient: null,
        reason: 'sender challenge response missing nonce / challenge field'
      }
    }
    const signature = signChallenge(nonce, identity.privateKey)
    let verifyRes
    try {
      verifyRes = await this._client.verifyAgent({
        agent_id: identity.agentId,
        signed_challenge: signature,
        ...(challengeId && { challenge_id: challengeId })
      })
    } catch (err) {
      return {
        ok: false,
        senderProof: null,
        recipient: null,
        reason: `sender verify failed: ${err.message}`
      }
    }

    // verified flag may live as 'verified' or 'success' or absence-of-error
    const verified = verifyRes.verified !== undefined ? verifyRes.verified : verifyRes.success !== false
    if (!verified) {
      return {
        ok: false,
        senderProof: null,
        recipient: null,
        reason: 'sender signature rejected by backend'
      }
    }

    let recipient
    try {
      recipient = await this.verify(recipientAlias)
    } catch (err) {
      return {
        ok: false,
        senderProof: { did: identity.did, signature, nonce: challenge.nonce },
        recipient: null,
        reason: `recipient resolution failed: ${err.message}`
      }
    }

    return {
      ok: true,
      senderProof: {
        did: /** @type {string} */ (verifyRes.did || identity.did),
        signature,
        nonce
      },
      recipient
    }
  }

  /**
   * @param {AttestPaymentOptions} options - Attestation options.
   * @returns {Promise<AttestPaymentResult>} Backend acknowledgment + URLs.
   */
  async attestPayment (options) {
    if (!options || typeof options.txHash !== 'string' || !options.txHash.length) {
      throw new TypeError('attestPayment({txHash, recipient, chain}): txHash required')
    }
    const identity = await this._ensureIdentity()
    if (!identity.agentId) {
      throw new Error('cannot attest before register(): no agent identity bound')
    }
    const recipientDid = options.recipient.startsWith('did:')
      ? options.recipient
      : await this._resolveAliasToDid(options.recipient)

    // AuditEventRequest body shape per live OpenAPI schema:
    //   receipt_reference (REQ)  — idempotency key, use txHash
    //   agent (REQ)              — { agent_id, did? }
    //   transaction (REQ)        — { amount: {value, currency}, category, rail?, counterparty? }
    //   metadata (opt)
    const category = /** @type {string} */ (options.metadata?.category || 'digital_goods')
    const eventBody = {
      receipt_reference: options.txHash,
      agent: {
        agent_id: identity.agentId,
        did: identity.did
      },
      transaction: {
        amount: {
          value: options.amount !== undefined ? String(options.amount) : '0',
          currency: options.token || 'USDT'
        },
        category,
        ...(options.chain && { rail: options.chain }),
        counterparty: { did: recipientDid }
      },
      metadata: {
        tx_hash: options.txHash,
        ...(options.metadata || {})
      }
    }
    const event = await this._client.writeVerifiedEvent(eventBody)

    /** @type {AttestPaymentResult} */
    const result = {
      eventId: /** @type {string} */ (event.event_id || event.id),
      ...(event.receipt_url && { receiptUrl: /** @type {string} */ (event.receipt_url) }),
      ...(event.dashboard_url && { dashboardUrl: /** @type {string} */ (event.dashboard_url) })
    }

    if (options.pinErc8004) {
      const pinChain = options.chain === 'evm' ? 'base' : (options.chain || 'base')
      const pinRes = await this._client.pinErc8004({
        agent_id: identity.agentId,
        chain: pinChain
      })
      result.erc8004 = {
        tokenId: pinRes.token_id,
        txHash: pinRes.tx_hash,
        status: pinRes.status
      }
    }

    return result
  }

  // ── internals ────────────────────────────────────────────────────────────

  /**
   * Derive (and cache) this account's Ed25519 keypair from the wallet seed.
   * The API-assigned `agentId` and `did` are populated by `register()`; pre-
   * register, both are `null` (the locally-derivable agent_id is intentionally
   * NOT used as a stand-in because the API generates its own and that's the
   * one used for subsequent challenge / attest calls).
   *
   * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array, agentId: string|null, did: string|null}>}
   * @private
   */
  async _ensureIdentity () {
    if (this._identity) return this._identity
    const seed = await this._extractAccountSeed()
    const { privateKey, publicKey } = deriveEd25519Keypair(seed, this._derivationPath)
    this._identity = { privateKey, publicKey, agentId: null, did: null }
    return this._identity
  }

  /**
   * Extract a stable seed bytes from the bound wallet account. The WDK wallet
   * accounts expose seed material via `_seedBytes` / `seedBytes` / `mnemonic`
   * across versions; we try in order and fail loudly if none are usable.
   *
   * @returns {Promise<Uint8Array>}
   * @private
   */
  async _extractAccountSeed () {
    const a = this._account
    if (a._seedBytes instanceof Uint8Array) return a._seedBytes
    if (typeof a.seedBytes === 'function') return a.seedBytes()
    if (typeof a.getSeed === 'function') return a.getSeed()
    if (typeof a._mnemonic === 'string') {
      // Fallback: hash the mnemonic deterministically. Not BIP-32; module-internal.
      const enc = new TextEncoder().encode(a._mnemonic)
      const { sha256 } = await import('@noble/hashes/sha256')
      return sha256(enc)
    }
    throw new Error('Cannot extract seed from wallet account: pass a non-read-only account that exposes _seedBytes / seedBytes() / getSeed()')
  }

  /**
   * Try to read the underlying EVM address for inclusion in registration metadata.
   *
   * @returns {string | undefined}
   * @private
   */
  _extractAccountAddress () {
    const a = this._account
    if (typeof a.address === 'string') return a.address
    if (typeof a.getAddress === 'function') {
      try { return a.getAddress() } catch { /* ignore */ }
    }
    return undefined
  }

  /**
   * @param {string} alias
   * @returns {Promise<string>}
   * @private
   */
  async _resolveAliasToAgentId (alias) {
    if (alias.startsWith('did:web:observerprotocol.org:agents:')) {
      return alias.slice('did:web:observerprotocol.org:agents:'.length)
    }
    if (/^[0-9a-f]{32}$/i.test(alias)) return alias
    const list = /** @type {{agents?: Array<{agent_id: string, alias?: string}>}} */ (
      await this._client.get(`/observer/agents/list?alias=${encodeURIComponent(alias)}`)
    )
    const hit = (list.agents || []).find(a => a.alias === alias)
    if (!hit) throw new Error(`No agent found for alias "${alias}"`)
    return hit.agent_id
  }

  /**
   * @param {string} alias
   * @returns {Promise<string>}
   * @private
   */
  async _resolveAliasToDid (alias) {
    const id = await this._resolveAliasToAgentId(alias)
    return buildDid(id)
  }
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 * @private
 */
function bytesToHex (bytes) {
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}
