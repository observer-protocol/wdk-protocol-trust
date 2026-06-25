// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { readFileSync } from 'node:fs'
import {
  verifyMandate,
  verifyCredentialProof,
  resolveDidWeb,
  VerificationError
} from './credential-verify.js'
import { buildDidKeyDocument } from './did-key.js'
import { withinScope } from './mandate.js'

/**
 * COMMUNITY GATE SECURITY CAVEAT — action is agent-stated intent, not decoded
 * on-chain bytes. A skill that declares amount:5 but builds a transaction for
 * 500 is caught by the enterprise RuntimeAdapter (which decodes actual on-chain
 * bytes via ResolvedTransfer) and NOT by this gate. This is the headline v1
 * limitation: this gate enforces against what the agent declares, not what the
 * transaction executes. The enterprise path (wdk-op-policy + enforceMandate)
 * closes this gap via ProposalBinding.
 */

// ── DID resolution ────────────────────────────────────────────────────────

function resolveDidKey (did) {
  const multibase = did.slice('did:key:'.length)
  return Promise.resolve(buildDidKeyDocument(did, multibase))
}

function resolveDid (did) {
  if (did.startsWith('did:key:')) return resolveDidKey(did)
  return resolveDidWeb(did)
}

// ── Internal helpers ──────────────────────────────────────────────────────

function denyGate (code, message, notes) {
  return {
    allow: false,
    reasons: [{ ruleType: 'gate_error', ruleField: code, message }],
    advisories: [],
    mandateValidUntil: '',
    notes
  }
}

// ── WBC verification ──────────────────────────────────────────────────────

async function verifyWbc (wbcPath, walletId, mandateIssuer, issuanceMode) {
  const notes = []
  let wbc
  try {
    wbc = JSON.parse(readFileSync(wbcPath, 'utf8'))
  } catch (err) {
    return { ok: false, code: 'wbc_read', message: `[bind] cannot read WBC at ${wbcPath}: ${err.message}`, notes }
  }

  if (!wbc.issuer || typeof wbc.issuer !== 'string') {
    return { ok: false, code: 'wbc_malformed', message: '[bind] WBC missing issuer', notes }
  }
  if (!wbc.credentialSubject?.walletAddress) {
    return { ok: false, code: 'wbc_malformed', message: '[bind] WBC credentialSubject.walletAddress missing', notes }
  }

  const nowMs = Date.now()
  const wbcFrom = Date.parse(wbc.validFrom)
  const wbcUntil = wbc.validUntil ? Date.parse(wbc.validUntil) : Infinity
  if (nowMs < wbcFrom) {
    return { ok: false, code: 'wbc_not_yet_valid', message: `[bind] WBC not yet valid (validFrom ${wbc.validFrom})`, notes }
  }
  if (nowMs > wbcUntil) {
    return { ok: false, code: 'wbc_expired', message: `[bind] WBC expired (validUntil ${wbc.validUntil})`, notes }
  }

  // Verify WBC proof against its issuer's DID document.
  try {
    const wbcDidDoc = await resolveDid(wbc.issuer)
    verifyCredentialProof(wbc, wbcDidDoc)
  } catch (err) {
    const detail = err instanceof VerificationError ? err.message : String(err)
    return { ok: false, code: 'wbc_proof_invalid', message: `[bind] WBC proof verification failed: ${detail}`, notes }
  }

  // BIND: wallet address must match the signing wallet.
  // When walletId is absent the caller has not supplied runtime wallet context;
  // the LINK check still fires. This matches the enterprise adapter behaviour
  // where ctx.wallet_id is optional (only checked when present).
  if (walletId != null) {
    const bound = wbc.credentialSubject.walletAddress
    if (bound.toLowerCase() !== walletId.toLowerCase()) {
      return {
        ok: false,
        code: 'wbc_address_mismatch',
        message: `[bind] WBC walletAddress ${bound} does not match transaction wallet ${walletId}`,
        notes
      }
    }
  }

  // LINK: WBC controller and mandate principal must be the same operator.
  const mode = issuanceMode ?? wbc.credentialSubject?.issuanceMode ?? 'dev'
  if (mode === 'dev') {
    if (wbc.issuer !== mandateIssuer) {
      return {
        ok: false,
        code: 'link_issuer_mismatch',
        message: `[link] dev-mode: WBC controller (${wbc.issuer}) !== mandate principal (${mandateIssuer}) — cross-principal pairing denied`,
        notes
      }
    }
    notes.push(`issuer-linkage/dev: operator DID equality confirmed (${wbc.issuer})`)
  } else {
    // Full mode requires L1 principal-binding chain verification.
    // SCAFFOLD: fail-closed until cosign_verify gate is implemented.
    return {
      ok: false,
      code: 'link_full_mode_unimplemented',
      message: `[link] full-mode: L1 principal-binding chain verification not implemented in v1 — deny until cosign_verify is wired`,
      notes
    }
  }

  return { ok: true, notes }
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * BIND→LINK→AUTHORIZE gate — community JavaScript implementation.
 *
 * Evaluates a proposed agent action against a signed SpendMandate. Optionally
 * verifies a WalletBindingCredential to enforce that the transacting wallet
 * was bound by the mandate's principal (BIND) and that the WBC and mandate
 * share the same operator identity (LINK).
 *
 * This is the canonical community gate. hermes-gate's SpendGate is a thin
 * class wrapper around this function. The enterprise gate (wdk-op-policy's
 * runRuntimeAdapter) differs in one critical way: it evaluates against
 * decoded on-chain bytes (ResolvedTransfer), whereas this function evaluates
 * against agent-stated intent. That gap is the headline v1 community limitation.
 *
 * @param {{
 *   rail: string,
 *   amount: string,
 *   currency: string,
 *   category?: string,
 *   wallet_id?: string
 * }} action - Agent-stated spend intent (flat MCP surface). wallet_id is the
 *   signing wallet's DID or address; required only when walletBindingCredentialPath
 *   is set and BIND address verification is desired.
 *
 * @param {{
 *   mandatePath: string,
 *   agentDid: string,
 *   trustedIssuers?: string[],
 *   walletBindingCredentialPath?: string,
 *   issuanceMode?: 'dev' | 'full'
 * }} config
 *
 * @returns {Promise<{
 *   allow: boolean,
 *   reasons: object[],
 *   advisories: object[],
 *   mandateValidUntil: string,
 *   notes: string[]
 * }>}
 */
export async function runRuntimeAdapter (action, config) {
  const notes = []

  // ── 1. Read mandate from disk ─────────────────────────────────────────
  let raw
  try {
    raw = JSON.parse(readFileSync(config.mandatePath, 'utf8'))
  } catch (err) {
    return denyGate('mandate_read', `cannot read mandate at ${config.mandatePath}: ${err.message}`, notes)
  }

  // ── 2. Verify mandate (proof + validity + issuer trust) ───────────────
  let mandate
  try {
    mandate = await verifyMandate(raw, {
      trustedIssuers: config.trustedIssuers?.length > 0 ? config.trustedIssuers : [raw.issuer],
      resolveDid: raw.issuer?.startsWith('did:key:') ? resolveDidKey : resolveDidWeb
    })
  } catch (err) {
    return denyGate('mandate_invalid', err.message, notes)
  }

  // ── 3. Signer-boundary check ──────────────────────────────────────────
  // Extract signing DID from the cryptographically-verified proof, not the
  // raw issuer field. Proof verification in step 2 already bound this key.
  const vm = mandate.raw?.proof?.verificationMethod ?? ''
  const signingDid = vm.includes('#') ? vm.split('#')[0] : vm

  if (signingDid === config.agentDid) {
    return denyGate('self_signed_mandate',
      'mandate signing key belongs to agent DID — self-authorization denied', notes)
  }
  if (mandate.subjectDid !== config.agentDid) {
    return denyGate('subject_mismatch',
      `mandate subject ${mandate.subjectDid} does not match agent DID ${config.agentDid}`, notes)
  }
  if (config.trustedIssuers?.length > 0 && !config.trustedIssuers.includes(signingDid)) {
    return denyGate('untrusted_issuer',
      `signing DID ${signingDid} is not in trusted-issuer set`, notes)
  }

  // ── 4. BIND + LINK (when WBC configured) ─────────────────────────────
  if (config.walletBindingCredentialPath) {
    const wbcResult = await verifyWbc(
      config.walletBindingCredentialPath,
      action.wallet_id ?? null,
      mandate.issuer,
      config.issuanceMode
    )
    if (!wbcResult.ok) {
      return denyGate(wbcResult.code, wbcResult.message, [...notes, ...wbcResult.notes])
    }
    notes.push(...wbcResult.notes)
  }

  // ── 5. AUTHORIZE — withinScope (community: against agent-stated intent) ──
  const scopeAction = {
    rail: action.rail,
    amount: { amount: action.amount, currency: action.currency },
    ...(action.category ? { category: action.category } : {})
  }

  const result = withinScope(scopeAction, mandate)
  return {
    allow: result.allow,
    reasons: result.reasons || [],
    advisories: result.advisories || [],
    mandateValidUntil: mandate.validUntil || '',
    notes
  }
}
