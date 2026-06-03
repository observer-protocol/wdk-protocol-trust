// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { withinScope } from '../index.js'

function mandate (overrides = {}) {
  return {
    credentialId: 'urn:uuid:test',
    issuer: 'did:web:observerprotocol.org',
    subjectDid: 'did:web:observerprotocol.org:agents:test',
    validFrom: '2026-01-01T00:00:00Z',
    validUntil: '2027-01-01T00:00:00Z',
    authorizationLevel: 'recurring',
    authorizationConfig: {
      recurring: {
        counterparty_did: 'did:web:example.com:agents:vendor',
        ceiling_amount: '1000',
        ceiling_currency: 'USDT',
        period: 'monthly',
        per_transaction_max: '100'
      }
    },
    actionScope: {
      allowed_rails: ['usdt_tron', 'lightning'],
      per_transaction_ceiling: { amount: '100', currency: 'USDT' },
      allowed_transaction_categories: ['ai_inference_credits']
    },
    credentialSchemaId: 'https://observerprotocol.org/schemas/delegation/v2.1.json',
    raw: {},
    ...overrides
  }
}

function baseAction (overrides = {}) {
  return {
    rail: 'usdt_tron',
    amount: { amount: '50', currency: 'USDT' },
    category: 'ai_inference_credits',
    counterparty_did: 'did:web:example.com:agents:vendor',
    ...overrides
  }
}

describe('withinScope — binding deny rules', () => {
  test('allow on in-scope action', () => {
    const d = withinScope(baseAction(), mandate())
    expect(d.allow).toBe(true)
    expect(d.reasons).toEqual([])
  })

  test('deny on rail not in allowed_rails', () => {
    const d = withinScope(baseAction({ rail: 'ethereum-mainnet' }), mandate())
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'allowed_rails')).toBeTruthy()
  })

  test('deny on amount exceeding per_transaction_ceiling', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '101', currency: 'USDT' } }),
      mandate()
    )
    expect(d.allow).toBe(false)
    const r = d.reasons.find(x => x.ruleField === 'per_transaction_ceiling' && x.ruleType === 'amountLimits')
    expect(r).toBeTruthy()
  })

  test('deny with no FX on currency mismatch', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '50', currency: 'USD' } }),
      mandate()
    )
    expect(d.allow).toBe(false)
    const r = d.reasons.find(x => x.ruleType === 'currencyMismatch')
    expect(r).toBeTruthy()
    expect(r.message).toMatch(/no FX/i)
  })

  test('deny on category not in allowed_transaction_categories', () => {
    const d = withinScope(
      baseAction({ category: 'something_else' }),
      mandate()
    )
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'allowed_transaction_categories')).toBeTruthy()
  })

  test('decimal compare: 100.00 vs 100 are equal (allow)', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '100.00', currency: 'USDT' } }),
      mandate()
    )
    expect(d.allow).toBe(true)
  })

  test('decimal compare: 100.01 over 100 (deny)', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '100.01', currency: 'USDT' } }),
      mandate()
    )
    expect(d.allow).toBe(false)
  })
})

describe('withinScope — authorizationLevel one-time', () => {
  const oneTimeMandate = mandate({
    authorizationLevel: 'one-time',
    authorizationConfig: {
      oneTime: {
        counterparty_did: 'did:web:example.com:agents:vendor',
        amount: '50',
        currency: 'USDT',
        rail: 'usdt_tron',
        execution_deadline: '2027-01-01T00:00:00Z'
      }
    }
  })

  test('allow on exact match', () => {
    const d = withinScope(baseAction(), oneTimeMandate)
    expect(d.allow).toBe(true)
  })

  test('deny on amount not exactly equal (one-time)', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '40', currency: 'USDT' } }),
      oneTimeMandate
    )
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'oneTime.amount')).toBeTruthy()
  })

  test('deny on past execution_deadline', () => {
    const m = mandate({
      authorizationLevel: 'one-time',
      authorizationConfig: {
        oneTime: {
          counterparty_did: 'did:web:example.com:agents:vendor',
          amount: '50',
          currency: 'USDT',
          rail: 'usdt_tron',
          execution_deadline: '2024-01-01T00:00:00Z'
        }
      }
    })
    const d = withinScope(baseAction(), m, { nowMs: Date.parse('2026-06-01T00:00:00Z') })
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'oneTime.execution_deadline')).toBeTruthy()
  })
})

describe('withinScope — authorizationLevel recurring', () => {
  test('deny when proposed exceeds per_transaction_max but under ceiling', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '99', currency: 'USDT' } }),
      mandate({
        authorizationConfig: {
          recurring: {
            counterparty_did: 'did:web:example.com:agents:vendor',
            ceiling_amount: '1000',
            ceiling_currency: 'USDT',
            period: 'monthly',
            per_transaction_max: '50'
          }
        }
      })
    )
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'recurring.per_transaction_max')).toBeTruthy()
  })

  test('period surfaces an advisory (not a deny)', () => {
    const d = withinScope(baseAction(), mandate())
    expect(d.advisories.find(a => a.message.includes('period'))).toBeTruthy()
  })
})

describe('withinScope — authorizationLevel policy', () => {
  test('deny on rail not in policy.rail_preference', () => {
    const d = withinScope(
      baseAction({ rail: 'ethereum-mainnet' }),
      mandate({
        authorizationLevel: 'policy',
        authorizationConfig: {
          policy: {
            policy_id: 'policy-x',
            rail_preference: ['usdt_tron', 'lightning']
          }
        },
        actionScope: { ...mandate().actionScope, allowed_rails: ['ethereum-mainnet', 'usdt_tron', 'lightning'] }
      })
    )
    expect(d.allow).toBe(false)
    expect(d.reasons.find(r => r.ruleField === 'policy.rail_preference')).toBeTruthy()
  })

  test('deny on per-rail cap exceeded — no FX on cap currency mismatch', () => {
    const d = withinScope(
      baseAction({ amount: { amount: '50', currency: 'USD' } }),
      mandate({
        authorizationLevel: 'policy',
        authorizationConfig: {
          policy: {
            policy_id: 'policy-x',
            rail_preference: ['usdt_tron'],
            per_rail_caps: { usdt_tron: { amount: '40', currency: 'USDT' } }
          }
        }
      })
    )
    expect(d.allow).toBe(false)
    // Currency mismatch shows up on the per_transaction_ceiling check first,
    // and again on the per-rail-cap currency check.
    expect(d.reasons.some(r => r.ruleType === 'currencyMismatch')).toBe(true)
  })
})

describe('withinScope — advisories on actionScope', () => {
  test('cumulative_budget surfaces (does NOT deny)', () => {
    const m = mandate()
    m.actionScope = {
      ...m.actionScope,
      cumulative_budget: { amount: '500', currency: 'USDT', window: 'credential_validity' }
    }
    const d = withinScope(baseAction(), m)
    expect(d.allow).toBe(true)
    expect(d.advisories.find(a => a.field === 'cumulative_budget')).toBeTruthy()
  })

  test('allowed_counterparty_types surfaces (advisory)', () => {
    const m = mandate()
    m.actionScope = { ...m.actionScope, allowed_counterparty_types: ['verified_merchant'] }
    const d = withinScope(baseAction(), m)
    expect(d.allow).toBe(true)
    expect(d.advisories.find(a => a.field === 'allowed_counterparty_types')).toBeTruthy()
  })

  test('geographic_restriction surfaces (advisory)', () => {
    const m = mandate()
    m.actionScope = { ...m.actionScope, geographic_restriction: { allowed: ['US'] } }
    const d = withinScope(baseAction(), m)
    expect(d.allow).toBe(true)
    expect(d.advisories.find(a => a.field === 'geographic_restriction')).toBeTruthy()
  })
})
