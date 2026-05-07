// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { DEFAULT_API_BASE, DEFAULT_REQUEST_TIMEOUT_MS } from './config.js'

/**
 * Thin HTTP wrapper around the Observer Protocol public API
 * (default `https://api.observerprotocol.org`).
 *
 * Handles JSON encode/decode, request timeout, structured error throwing.
 * Stateless — no caching, no retries. Caller decides retry policy.
 */
export class OpClient {
  /**
   * @param {object} [config]
   * @param {string} [config.apiBase] - Base URL for the Observer Protocol API.
   * @param {number} [config.timeoutMs] - Per-request timeout in milliseconds.
   * @param {Record<string,string>} [config.headers] - Default headers (e.g. `{ Authorization: 'Bearer ...' }`).
   * @param {typeof fetch} [config.fetchImpl] - Override the global `fetch` for testing.
   */
  constructor (config = {}) {
    this._apiBase = (config.apiBase || DEFAULT_API_BASE).replace(/\/+$/, '')
    this._timeoutMs = config.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS
    this._defaultHeaders = config.headers || {}
    this._fetch = config.fetchImpl || globalThis.fetch
    if (typeof this._fetch !== 'function') {
      throw new Error('OpClient requires a fetch implementation. Pass config.fetchImpl or run on a runtime that provides global fetch.')
    }
  }

  /**
   * GET request.
   *
   * @param {string} path - Path relative to apiBase (e.g. "/agents/abc/did.json").
   * @returns {Promise<unknown>} Parsed JSON response.
   */
  async get (path) {
    return this._request('GET', path)
  }

  /**
   * POST request with JSON body.
   *
   * @param {string} path - Path relative to apiBase.
   * @param {Record<string,unknown>} body - JSON-serializable body.
   * @returns {Promise<unknown>} Parsed JSON response.
   */
  async post (path, body) {
    return this._request('POST', path, body)
  }

  /**
   * Resolve an agent's DID document.
   *
   * Reads from the api. subdomain (the canonical dynamic source). The W3C
   * did:web spec mandates the apex URL `observerprotocol.org/agents/{id}/did.json`;
   * Netlify proxies that path to this endpoint.
   *
   * @param {string} agentId - Agent identifier.
   * @returns {Promise<Record<string,unknown>>} DID document.
   */
  async getAgentDidDocument (agentId) {
    return /** @type {Record<string,unknown>} */ (await this.get(`/agents/${agentId}/did.json`))
  }

  /**
   * Get an agent's VAC summary.
   *
   * @param {string} agentId - Agent identifier.
   * @returns {Promise<Record<string,unknown>>} VAC summary object.
   */
  async getVac (agentId) {
    return /** @type {Record<string,unknown>} */ (await this.get(`/vac/${agentId}`))
  }

  /**
   * Register an agent with Observer Protocol.
   *
   * NOTE: this endpoint accepts all fields as query parameters (not JSON body),
   * per the current api.observerprotocol.org OpenAPI spec.
   *
   * @param {object} args
   * @param {string} args.public_key - Hex-encoded Ed25519 public key.
   * @param {string} [args.alias] - Human-readable agent alias.
   * @param {string} [args.agent_name] - Display name.
   * @param {string} [args.framework] - Agent framework label (e.g. "wdk").
   * @param {string} [args.wallet_standard] - Wallet standard label (e.g. "wdk-evm").
   * @param {string} [args.chains] - Comma-separated chain identifiers.
   * @param {string} [args.org_id] - Organization identifier (optional).
   * @param {string} [args.legal_entity_id] - Legal entity identifier (optional).
   * @param {string} [args.ows_vault_name] - OWS vault name (optional).
   * @returns {Promise<Record<string,unknown>>} Registration response (agent_id, did, did_document, …).
   */
  async registerAgent (args) {
    const qs = this._encodeQuery(args)
    return /** @type {Record<string,unknown>} */ (await this.post(`/observer/register-agent?${qs}`))
  }

  /**
   * Begin challenge-response identity verification. Returns a nonce to sign.
   *
   * NOTE: query parameter (not body).
   *
   * @param {string} agentId - Agent identifier.
   * @returns {Promise<Record<string,unknown>>} Challenge response (nonce / challenge / id, varies).
   */
  async getChallenge (agentId) {
    return /** @type {Record<string,unknown>} */ (
      await this.post(`/observer/challenge?agent_id=${encodeURIComponent(agentId)}`)
    )
  }

  /**
   * Complete challenge-response by submitting the signed nonce as a query
   * parameter (per current API spec).
   *
   * @param {object} args
   * @param {string} args.agent_id - Agent identifier.
   * @param {string} args.signed_challenge - Hex-encoded Ed25519 signature over the nonce.
   * @param {string} [args.challenge_id] - Server-side challenge id, if returned by getChallenge.
   * @returns {Promise<Record<string,unknown>>}
   */
  async verifyAgent (args) {
    const qs = this._encodeQuery(args)
    return /** @type {Record<string,unknown>} */ (await this.post(`/observer/verify-agent?${qs}`))
  }

  /**
   * Get an agent's composite trust score (AT-ARS).
   *
   * @param {string} agentId - Agent identifier.
   * @returns {Promise<Record<string,unknown>>}
   */
  async getTrustScore (agentId) {
    return /** @type {Record<string,unknown>} */ (await this.get(`/api/v1/trust/score/${agentId}`))
  }

  /**
   * Write a verified-event audit record (canonical post-payment attestation path).
   *
   * Body shape per the live `AuditEventRequest` schema:
   *
   *   receipt_reference         REQ string  — opaque idempotency key
   *   agent                     REQ AuditAgent  ({ agent_id, did? })
   *   transaction               REQ AuditTransaction ({ amount, category, rail?, counterparty?, integrator_reference? })
   *   settlement_reference      opt
   *   verification              opt
   *   metadata                  opt object
   *
   * @param {object} body
   * @param {string} body.receipt_reference - Idempotency / receipt id.
   * @param {{agent_id: string, did?: string}} body.agent - Agent identity.
   * @param {{amount: object, category: string, rail?: string, counterparty?: object, integrator_reference?: string}} body.transaction - Transaction details.
   * @param {object} [body.settlement_reference] - Settlement reference.
   * @param {object} [body.verification] - Verification metadata.
   * @param {Record<string,unknown>} [body.metadata] - Free-form metadata.
   * @returns {Promise<Record<string,unknown>>}
   */
  async writeVerifiedEvent (body) {
    return /** @type {Record<string,unknown>} */ (
      await this.post('/v1/audit/verified-event', body)
    )
  }

  /**
   * Pin an agent's registration to ERC-8004 (Level 3 chain anchoring).
   *
   * @param {object} body
   * @param {string} body.agent_id - Agent identifier.
   * @param {string} body.chain - Target EVM chain (e.g. "base", "ethereum").
   * @param {string} [body.delegation_id] - Delegation credential ID (optional).
   * @returns {Promise<{token_id: string, tx_hash: string, status: string}>}
   */
  async pinErc8004 (body) {
    return /** @type {{token_id: string, tx_hash: string, status: string}} */ (
      await this.post('/api/v1/erc8004/registration/pin', body)
    )
  }

  /**
   * Get an agent's ERC-8004 summary (NFT info, indexer status, etc).
   *
   * @param {string} agentId - Agent identifier.
   * @returns {Promise<Record<string,unknown>>}
   */
  async getErc8004Summary (agentId) {
    return /** @type {Record<string,unknown>} */ (
      await this.get(`/api/v1/erc8004/agent/${agentId}/summary`)
    )
  }

  /**
   * URL-encode a flat object as a query string. Skips undefined / null values.
   *
   * @param {Record<string, unknown>} args
   * @returns {string}
   * @private
   */
  _encodeQuery (args) {
    const parts = []
    for (const [k, v] of Object.entries(args || {})) {
      if (v === undefined || v === null) continue
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    }
    return parts.join('&')
  }

  // ── internals ────────────────────────────────────────────────────────────

  /**
   * @param {string} method
   * @param {string} path
   * @param {Record<string,unknown>} [body]
   * @returns {Promise<unknown>}
   * @private
   */
  async _request (method, path, body) {
    const url = this._apiBase + (path.startsWith('/') ? path : '/' + path)
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), this._timeoutMs)
    try {
      const init = {
        method,
        headers: { Accept: 'application/json', ...this._defaultHeaders },
        signal: controller.signal
      }
      if (body !== undefined) {
        init.headers['Content-Type'] = 'application/json'
        init.body = JSON.stringify(body)
      }
      const res = await this._fetch(url, init)
      const text = await res.text()
      let data = null
      if (text) {
        try {
          data = JSON.parse(text)
        } catch {
          data = text
        }
      }
      if (!res.ok) {
        const err = new Error(`OP API ${method} ${path} → HTTP ${res.status}`)
        err.status = res.status
        err.body = data
        throw err
      }
      return data
    } catch (err) {
      if (err.name === 'AbortError') {
        const tErr = new Error(`OP API ${method} ${path} timed out after ${this._timeoutMs}ms`)
        tErr.cause = err
        throw tErr
      }
      throw err
    } finally {
      clearTimeout(timeoutId)
    }
  }
}
