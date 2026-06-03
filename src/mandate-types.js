// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

/**
 * @file Type definitions for the AIP v0.8 mandate surface.
 *
 * Mirrors the on-credential shape served at
 * https://observerprotocol.org/schemas/delegation/v2.1.json — see the
 * observer-protocol/aip repository (aip-v0.8-draft-1.md) for the normative
 * spec. Runtime helpers (withinScope, gates, attest) live in sibling files.
 */

/**
 * Flat `{amount, currency}` shape used by per_transaction_ceiling, the
 * cumulative_budget body, and proposed-action amounts. Amount is a decimal
 * string to avoid float coercion at the wire level. Currency is an ISO 4217
 * code, a rail-native token symbol (e.g. `USDT`, `BTC`), or a rail-native
 * unit (`sats`).
 *
 * @typedef {object} Money
 * @property {string} amount
 * @property {string} currency
 */

/**
 * Optional cumulative-budget declaration on actionScope. ADVISORY in v0.8 —
 * surfaced but never grounds a deny. `window` is locked to
 * `"credential_validity"` (the cap applies cumulatively over
 * `validFrom → validUntil`); rolling-/calendar-window semantics are reserved
 * for a future draft.
 *
 * @typedef {object} CumulativeBudget
 * @property {string} amount
 * @property {string} currency
 * @property {'credential_validity'} window
 */

/**
 * Spending-mandate surface (AIP v0.8 §1.1–§1.3). Closed shape:
 * `additionalProperties: false`. Reserved-advisory fields
 * (allowed_counterparty_types, geographic_restriction) are surfaced when
 * present but MUST NOT ground a deny in this adapter.
 *
 * @typedef {object} ActionScope
 * @property {string[]} allowed_rails
 * @property {Money} per_transaction_ceiling
 * @property {string[]} [allowed_transaction_categories]
 * @property {CumulativeBudget} [cumulative_budget]
 * @property {string[]} [allowed_counterparty_types]
 * @property {{allowed?: string[], disallowed?: string[]}} [geographic_restriction]
 */

/**
 * AuthorizationLevel-gated configuration. Exactly one of `oneTime`,
 * `recurring`, or `policy` is present, matching `authorizationLevel`.
 *
 * @typedef {object} AuthorizationConfig
 * @property {{
 *   counterparty_did: string,
 *   amount: string,
 *   currency: string,
 *   rail: string,
 *   execution_deadline?: string,
 *   purchase_description?: string
 * }} [oneTime]
 * @property {{
 *   counterparty_did: string,
 *   ceiling_amount: string,
 *   ceiling_currency: string,
 *   period: string,
 *   allowed_rails?: string[],
 *   per_transaction_max?: string,
 *   valid_until?: string
 * }} [recurring]
 * @property {{
 *   policy_id: string,
 *   rail_preference: string[],
 *   escalation_threshold?: object,
 *   fallback_rules?: object,
 *   per_rail_caps?: object,
 *   time_windows?: object
 * }} [policy]
 */

/**
 * Verified mandate — the output of `verifyMandate(credential)`. Carries the
 * essential bound fields for downstream withinScope and attest steps.
 *
 * @typedef {object} Mandate
 * @property {string} credentialId
 * @property {string} issuer
 * @property {string} subjectDid
 * @property {string} validFrom
 * @property {string} validUntil
 * @property {'one-time' | 'recurring' | 'policy'} authorizationLevel
 * @property {AuthorizationConfig} authorizationConfig
 * @property {ActionScope} actionScope
 * @property {string} credentialSchemaId
 * @property {object} raw The full credential as verified, for downstream
 *   canonical-hash binding inside attest().
 */

/**
 * A proposed action against a mandate. Currency / amount shape mirrors
 * ActionScope.per_transaction_ceiling. `category` is required for
 * actionScope.allowed_transaction_categories checks; `counterparty_did`
 * is required for authorizationLevel-gated rules.
 *
 * @typedef {object} ProposedAction
 * @property {string} rail
 * @property {Money} amount
 * @property {string} [category]
 * @property {string} [counterparty_did]
 * @property {string} [proposalHash] SHA-256 hex of rail-canonical pre-sign
 *   bytes. Required for attest(); optional at withinScope time so callers
 *   can pre-flight before they have the signed-tx bytes.
 */

/**
 * Result of a `withinScope` evaluation. `allow` is the binding decision;
 * `reasons` carry structured deny reasons (empty on allow). `advisories`
 * carry surfaced-but-non-binding flags (e.g. cumulative-budget over-spend
 * when attestation history is available client-side).
 *
 * @typedef {object} Decision
 * @property {boolean} allow
 * @property {DenyReason[]} reasons
 * @property {Advisory[]} advisories
 */

/**
 * @typedef {object} DenyReason
 * @property {'amountLimits' | 'actionScope' | 'authorization' | 'currencyMismatch' | 'schemaMismatch'} ruleType
 * @property {string} ruleField
 * @property {string} message
 * @property {*} [currentValue]
 * @property {*} [proposedValue]
 */

/**
 * @typedef {object} Advisory
 * @property {'cumulative_budget' | 'allowed_counterparty_types' | 'geographic_restriction'} field
 * @property {string} message
 */

/**
 * PolicyGate is the seam to Tether's WDK pre-sign policy hook (PR #55). It
 * is intentionally minimal: a single `evaluate(action, mandate)` method that
 * returns a decision. The default `AdvisoryGate` runs `withinScope`
 * client-side; the post-#55 `WdkPolicyHookGate` will adapt to WDK's hook so
 * the decision is honored inside WDK's transaction path.
 *
 * @typedef {object} PolicyGate
 * @property {(action: ProposedAction, mandate: Mandate) => Promise<Decision> | Decision} evaluate
 */

// JSDoc-only file. The empty export keeps it valid ESM and lets tsc emit
// declaration files alongside the runtime modules.
export {}
