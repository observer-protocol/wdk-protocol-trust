// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

/**
 * @file Pure withinScope evaluator for the AIP v0.8 spending mandate.
 *
 * I/O-free per the Observer Protocol evaluator source-of-truth invariant:
 * no FX, no oracles, no HTTP, no chain RPCs, no DB calls. Input is
 * `(proposedAction, mandate)`; output is `{allow, reasons, advisories}`.
 *
 * Spec reference: aip-v0.8-draft-1.md §1.2, §1.3, §3.2.
 */

/**
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 * @typedef {import('./mandate-types.js').ProposedAction} ProposedAction
 * @typedef {import('./mandate-types.js').Decision} Decision
 * @typedef {import('./mandate-types.js').DenyReason} DenyReason
 * @typedef {import('./mandate-types.js').Advisory} Advisory
 */

/**
 * Parse a positive decimal-string amount into a normalized BigInt scaled by
 * the longer of the two fractional widths in a later comparison. Returned
 * shape: `{int, frac}` where both are digit strings. Throws on malformed.
 *
 * @private
 * @param {string} s
 * @returns {{int: string, frac: string}}
 */
function _parseDecimal (s) {
  if (typeof s !== 'string' || s.length === 0) {
    throw new TypeError('amount must be a non-empty string')
  }
  if (!/^[0-9]+(\.[0-9]+)?$/.test(s)) {
    throw new Error('amount must be a positive decimal string: ' + s)
  }
  const [int, frac = ''] = s.split('.')
  return { int, frac }
}

/**
 * Compare two positive decimal strings. Returns -1 if `a < b`, 0 if equal,
 * 1 if `a > b`. Same-currency comparison only — caller MUST verify currency
 * match before calling.
 *
 * @private
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function _compareAmounts (a, b) {
  const A = _parseDecimal(a)
  const B = _parseDecimal(b)
  const fracLen = Math.max(A.frac.length, B.frac.length)
  const aBig = BigInt(A.int + A.frac.padEnd(fracLen, '0'))
  const bBig = BigInt(B.int + B.frac.padEnd(fracLen, '0'))
  return aBig < bBig ? -1 : aBig > bBig ? 1 : 0
}

/**
 * Check whether `nowMs` is strictly before the ISO 8601 deadline. Returns
 * `true` if the deadline is malformed (caller treats malformed deadlines as
 * deny — see callers below).
 *
 * @private
 * @param {string} isoDeadline
 * @param {number} nowMs
 * @returns {boolean} true iff deadline is malformed or has passed
 */
function _isAfter (isoDeadline, nowMs) {
  const t = Date.parse(isoDeadline)
  if (Number.isNaN(t)) return true
  return nowMs >= t
}

/**
 * Evaluate a proposed action against a verified mandate. Pure, I/O-free.
 *
 * Binding deny rules (cause `allow: false`):
 * - currency mismatch vs per_transaction_ceiling (no FX)
 * - amount exceeds per_transaction_ceiling
 * - rail not in actionScope.allowed_rails
 * - category not in actionScope.allowed_transaction_categories (when present)
 * - authorizationLevel-gated rule violations (oneTime / recurring / policy)
 *
 * Advisory surfacing (does NOT affect `allow`):
 * - cumulative_budget present (§1.2)
 * - allowed_counterparty_types present (§1.3)
 * - geographic_restriction present (§1.3)
 * - recurring.period present (stateful — adapter has no state)
 * - policy.{time_windows, escalation_threshold, fallback_rules} present
 *
 * @param {ProposedAction} action
 * @param {Mandate} mandate
 * @param {{nowMs?: number}} [options]
 * @returns {Decision}
 */
export function withinScope (action, mandate, options = {}) {
  if (action === null || typeof action !== 'object') {
    throw new TypeError('withinScope(action, mandate): action must be an object')
  }
  if (mandate === null || typeof mandate !== 'object') {
    throw new TypeError('withinScope(action, mandate): mandate must be an object')
  }
  const nowMs = options.nowMs ?? Date.now()

  /** @type {DenyReason[]} */
  const reasons = []
  /** @type {Advisory[]} */
  const advisories = []
  const scope = mandate.actionScope

  if (scope === null || typeof scope !== 'object') {
    reasons.push({
      ruleType: 'actionScope',
      ruleField: 'actionScope',
      message: 'mandate.actionScope missing'
    })
    return { allow: false, reasons, advisories }
  }

  // --- Binding: rail ----------------------------------------------------
  if (!Array.isArray(scope.allowed_rails) || scope.allowed_rails.length === 0) {
    reasons.push({
      ruleType: 'actionScope',
      ruleField: 'allowed_rails',
      message: 'actionScope.allowed_rails must be a non-empty list'
    })
  } else if (!scope.allowed_rails.includes(action.rail)) {
    reasons.push({
      ruleType: 'actionScope',
      ruleField: 'allowed_rails',
      message: 'proposed rail not in actionScope.allowed_rails',
      currentValue: scope.allowed_rails,
      proposedValue: action.rail
    })
  }

  // --- Binding: per_transaction_ceiling (same-currency only, no FX) -----
  const ceiling = scope.per_transaction_ceiling
  if (!ceiling || typeof ceiling.amount !== 'string' || typeof ceiling.currency !== 'string') {
    reasons.push({
      ruleType: 'actionScope',
      ruleField: 'per_transaction_ceiling',
      message: 'actionScope.per_transaction_ceiling missing or malformed'
    })
  } else if (!action.amount || typeof action.amount.amount !== 'string' || typeof action.amount.currency !== 'string') {
    reasons.push({
      ruleType: 'amountLimits',
      ruleField: 'per_transaction_ceiling',
      message: 'proposed action amount missing or malformed'
    })
  } else if (action.amount.currency !== ceiling.currency) {
    reasons.push({
      ruleType: 'currencyMismatch',
      ruleField: 'per_transaction_ceiling',
      message: 'proposed amount currency does not match per_transaction_ceiling currency; no FX conversion in withinScope',
      currentValue: ceiling.currency,
      proposedValue: action.amount.currency
    })
  } else {
    try {
      if (_compareAmounts(action.amount.amount, ceiling.amount) > 0) {
        reasons.push({
          ruleType: 'amountLimits',
          ruleField: 'per_transaction_ceiling',
          message: 'proposed amount exceeds per_transaction_ceiling',
          currentValue: { amount: ceiling.amount, currency: ceiling.currency },
          proposedValue: { amount: action.amount.amount, currency: action.amount.currency }
        })
      }
    } catch (err) {
      reasons.push({
        ruleType: 'amountLimits',
        ruleField: 'per_transaction_ceiling',
        message: 'amount parse error: ' + err.message
      })
    }
  }

  // --- Binding: category ------------------------------------------------
  if (Array.isArray(scope.allowed_transaction_categories) && scope.allowed_transaction_categories.length > 0) {
    if (typeof action.category !== 'string' || !scope.allowed_transaction_categories.includes(action.category)) {
      reasons.push({
        ruleType: 'actionScope',
        ruleField: 'allowed_transaction_categories',
        message: 'proposed category not in actionScope.allowed_transaction_categories',
        currentValue: scope.allowed_transaction_categories,
        proposedValue: action.category
      })
    }
  }

  // --- Binding: authorizationLevel-gated --------------------------------
  const level = mandate.authorizationLevel
  const cfg = mandate.authorizationConfig
  if (level === 'one-time') {
    _evalOneTime(action, cfg && cfg.oneTime, nowMs, reasons)
  } else if (level === 'recurring') {
    _evalRecurring(action, cfg && cfg.recurring, nowMs, reasons, advisories)
  } else if (level === 'policy') {
    _evalPolicy(action, cfg && cfg.policy, reasons, advisories)
  } else if (level !== undefined) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'authorizationLevel',
      message: 'unknown authorizationLevel: ' + level
    })
  }

  // --- Advisories on actionScope ---------------------------------------
  if (scope.cumulative_budget) {
    advisories.push({
      field: 'cumulative_budget',
      message: 'cumulative_budget declared (advisory in AIP v0.8; not enforced here)'
    })
  }
  if (Array.isArray(scope.allowed_counterparty_types) && scope.allowed_counterparty_types.length > 0) {
    advisories.push({
      field: 'allowed_counterparty_types',
      message: 'allowed_counterparty_types declared (advisory in AIP v0.8)'
    })
  }
  if (scope.geographic_restriction && typeof scope.geographic_restriction === 'object') {
    advisories.push({
      field: 'geographic_restriction',
      message: 'geographic_restriction declared (advisory in AIP v0.8)'
    })
  }

  return {
    allow: reasons.length === 0,
    reasons,
    advisories
  }
}

/**
 * @private
 * @param {ProposedAction} action
 * @param {object | undefined} cfg
 * @param {number} nowMs
 * @param {DenyReason[]} reasons
 */
function _evalOneTime (action, cfg, nowMs, reasons) {
  if (!cfg || typeof cfg !== 'object') {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'authorizationConfig.oneTime',
      message: 'authorizationLevel=one-time but authorizationConfig.oneTime missing'
    })
    return
  }
  if (typeof action.counterparty_did === 'string' && action.counterparty_did !== cfg.counterparty_did) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'oneTime.counterparty_did',
      message: 'proposed counterparty does not match one-time authorization',
      currentValue: cfg.counterparty_did,
      proposedValue: action.counterparty_did
    })
  }
  if (action.rail !== cfg.rail) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'oneTime.rail',
      message: 'proposed rail does not match one-time authorization',
      currentValue: cfg.rail,
      proposedValue: action.rail
    })
  }
  if (action.amount && typeof action.amount.currency === 'string' && action.amount.currency !== cfg.currency) {
    reasons.push({
      ruleType: 'currencyMismatch',
      ruleField: 'oneTime.currency',
      message: 'proposed currency does not match one-time authorization; no FX conversion',
      currentValue: cfg.currency,
      proposedValue: action.amount.currency
    })
  }
  if (action.amount && typeof action.amount.amount === 'string') {
    try {
      if (_compareAmounts(action.amount.amount, cfg.amount) !== 0) {
        reasons.push({
          ruleType: 'authorization',
          ruleField: 'oneTime.amount',
          message: 'proposed amount must exactly equal one-time authorization amount',
          currentValue: cfg.amount,
          proposedValue: action.amount.amount
        })
      }
    } catch (err) {
      reasons.push({
        ruleType: 'authorization',
        ruleField: 'oneTime.amount',
        message: 'amount parse error: ' + err.message
      })
    }
  }
  if (typeof cfg.execution_deadline === 'string' && _isAfter(cfg.execution_deadline, nowMs)) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'oneTime.execution_deadline',
      message: 'one-time authorization has passed execution_deadline',
      currentValue: cfg.execution_deadline,
      proposedValue: new Date(nowMs).toISOString()
    })
  }
}

/**
 * @private
 * @param {ProposedAction} action
 * @param {object | undefined} cfg
 * @param {number} nowMs
 * @param {DenyReason[]} reasons
 * @param {Advisory[]} advisories
 */
function _evalRecurring (action, cfg, nowMs, reasons, advisories) {
  if (!cfg || typeof cfg !== 'object') {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'authorizationConfig.recurring',
      message: 'authorizationLevel=recurring but authorizationConfig.recurring missing'
    })
    return
  }
  if (typeof action.counterparty_did === 'string' && action.counterparty_did !== cfg.counterparty_did) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'recurring.counterparty_did',
      message: 'proposed counterparty does not match recurring authorization',
      currentValue: cfg.counterparty_did,
      proposedValue: action.counterparty_did
    })
  }
  if (Array.isArray(cfg.allowed_rails) && cfg.allowed_rails.length > 0 && !cfg.allowed_rails.includes(action.rail)) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'recurring.allowed_rails',
      message: 'proposed rail not in recurring.allowed_rails',
      currentValue: cfg.allowed_rails,
      proposedValue: action.rail
    })
  }
  if (action.amount && typeof action.amount.currency === 'string' && action.amount.currency !== cfg.ceiling_currency) {
    reasons.push({
      ruleType: 'currencyMismatch',
      ruleField: 'recurring.ceiling_currency',
      message: 'proposed currency does not match recurring ceiling currency; no FX conversion',
      currentValue: cfg.ceiling_currency,
      proposedValue: action.amount.currency
    })
  } else if (action.amount && typeof action.amount.amount === 'string') {
    try {
      if (typeof cfg.per_transaction_max === 'string' &&
          _compareAmounts(action.amount.amount, cfg.per_transaction_max) > 0) {
        reasons.push({
          ruleType: 'amountLimits',
          ruleField: 'recurring.per_transaction_max',
          message: 'proposed amount exceeds recurring.per_transaction_max',
          currentValue: cfg.per_transaction_max,
          proposedValue: action.amount.amount
        })
      }
      if (_compareAmounts(action.amount.amount, cfg.ceiling_amount) > 0) {
        reasons.push({
          ruleType: 'amountLimits',
          ruleField: 'recurring.ceiling_amount',
          message: 'proposed amount exceeds recurring.ceiling_amount',
          currentValue: cfg.ceiling_amount,
          proposedValue: action.amount.amount
        })
      }
    } catch (err) {
      reasons.push({
        ruleType: 'amountLimits',
        ruleField: 'recurring.ceiling_amount',
        message: 'amount parse error: ' + err.message
      })
    }
  }
  if (typeof cfg.valid_until === 'string' && _isAfter(cfg.valid_until, nowMs)) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'recurring.valid_until',
      message: 'recurring authorization has passed valid_until',
      currentValue: cfg.valid_until,
      proposedValue: new Date(nowMs).toISOString()
    })
  }
  if (typeof cfg.period === 'string') {
    advisories.push({
      field: 'cumulative_budget',
      message: 'recurring.period declared (' + cfg.period + ') — stateful, not enforced by withinScope; rely on server-side re-evaluation or in-process state'
    })
  }
}

/**
 * @private
 * @param {ProposedAction} action
 * @param {object | undefined} cfg
 * @param {DenyReason[]} reasons
 * @param {Advisory[]} advisories
 */
function _evalPolicy (action, cfg, reasons, advisories) {
  if (!cfg || typeof cfg !== 'object') {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'authorizationConfig.policy',
      message: 'authorizationLevel=policy but authorizationConfig.policy missing'
    })
    return
  }
  if (Array.isArray(cfg.rail_preference) && cfg.rail_preference.length > 0 && !cfg.rail_preference.includes(action.rail)) {
    reasons.push({
      ruleType: 'authorization',
      ruleField: 'policy.rail_preference',
      message: 'proposed rail not in policy.rail_preference',
      currentValue: cfg.rail_preference,
      proposedValue: action.rail
    })
  }
  if (cfg.per_rail_caps && typeof cfg.per_rail_caps === 'object') {
    const cap = cfg.per_rail_caps[action.rail]
    if (cap && action.amount) {
      if (typeof cap.currency === 'string' && action.amount.currency !== cap.currency) {
        reasons.push({
          ruleType: 'currencyMismatch',
          ruleField: 'policy.per_rail_caps.' + action.rail,
          message: 'proposed currency does not match per-rail cap currency; no FX conversion',
          currentValue: cap.currency,
          proposedValue: action.amount.currency
        })
      } else if (typeof cap.amount === 'string') {
        try {
          if (_compareAmounts(action.amount.amount, cap.amount) > 0) {
            reasons.push({
              ruleType: 'amountLimits',
              ruleField: 'policy.per_rail_caps.' + action.rail,
              message: 'proposed amount exceeds policy per-rail cap',
              currentValue: cap,
              proposedValue: action.amount
            })
          }
        } catch (err) {
          reasons.push({
            ruleType: 'amountLimits',
            ruleField: 'policy.per_rail_caps.' + action.rail,
            message: 'amount parse error: ' + err.message
          })
        }
      }
    }
  }
  if (cfg.time_windows) {
    advisories.push({
      field: 'cumulative_budget',
      message: 'policy.time_windows declared — stateful/clock-bound; not enforced by withinScope'
    })
  }
  if (cfg.escalation_threshold || cfg.fallback_rules) {
    advisories.push({
      field: 'cumulative_budget',
      message: 'policy.escalation_threshold / fallback_rules declared — not evaluated by withinScope (no external lookups)'
    })
  }
}

// Exposed only for internal unit tests of decimal compare logic.
export const _internals = { _compareAmounts, _parseDecimal, _isAfter }
