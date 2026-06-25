// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { WdkEnforcementGate } from '../index.js'

// A fake `registerObserverPolicy` injected via the DI seam, so the composition
// is provable without installing the optional peer dependency.
function makeRegisterSpy () {
  const calls = []
  const register = (wdk, cfg, opts) => {
    calls.push({ wdk, cfg, opts })
    return wdk // registerObserverPolicy returns the wdk instance for chaining
  }
  register.calls = calls
  return register
}

const POLICY = { credentialPath: '~/.op/agent.json', issuerDid: 'did:web:observerprotocol.org' }
const WALLETS = { bitcoin: 'bip122:000000000019d6689c085ae165831e93' }

describe('WdkEnforcementGate', () => {
  test('install() delegates to registerObserverPolicy with (wdk, {policy, wallets}, options)', async () => {
    const register = makeRegisterSpy()
    const gate = new WdkEnforcementGate({ policy: POLICY, wallets: WALLETS, register })
    const wdk = { registerPolicy: () => {} }

    const out = await gate.install(wdk, { wallet: 'bitcoin' })

    expect(out).toBe(wdk)
    expect(register.calls).toHaveLength(1)
    const { wdk: passedWdk, cfg, opts } = register.calls[0]
    expect(passedWdk).toBe(wdk)
    expect(cfg).toEqual({ policy: POLICY, wallets: WALLETS })
    expect(opts).toEqual({ wallet: 'bitcoin' })
  })

  test('per-call opts override constructor config', async () => {
    const register = makeRegisterSpy()
    const overridePolicy = { credentialPath: '/other.json' }
    const gate = new WdkEnforcementGate({ policy: POLICY, wallets: WALLETS, options: { idPrefix: 'base' }, register })
    const wdk = { registerPolicy: () => {} }

    await gate.install(wdk, { wallet: ['a', 'b'], policy: overridePolicy, ops: ['transfer'], idPrefix: 'over' })

    const { cfg, opts } = register.calls[0]
    expect(cfg.policy).toBe(overridePolicy)
    expect(cfg.wallets).toBe(WALLETS)
    expect(opts).toEqual({ idPrefix: 'over', wallet: ['a', 'b'], ops: ['transfer'] })
  })

  test('install() fails closed when wallet label is missing', async () => {
    const gate = new WdkEnforcementGate({ policy: POLICY, wallets: WALLETS, register: makeRegisterSpy() })
    await expect(gate.install({ registerPolicy: () => {} }, {})).rejects.toThrow(/wallet/)
  })

  test('install() requires policy and wallets', async () => {
    const gate = new WdkEnforcementGate({ register: makeRegisterSpy() })
    await expect(gate.install({ registerPolicy: () => {} }, { wallet: 'x' })).rejects.toThrow(/policy/)
    await expect(gate.install({ registerPolicy: () => {} }, { wallet: 'x', policy: POLICY })).rejects.toThrow(/wallets/)
  })

  test('evaluate() throws — OP does not re-decide policy per trade (scope §6)', () => {
    const gate = new WdkEnforcementGate({ policy: POLICY, wallets: WALLETS })
    expect(() => gate.evaluate({}, {})).toThrow(/does not re-decide/)
  })

  test('without the peer dep installed, install() surfaces a clear actionable error', async () => {
    // No `register` injected → real lazy import path. The optional peer dep is
    // not installed in this package, so the import must fail with guidance.
    const gate = new WdkEnforcementGate({ policy: POLICY, wallets: WALLETS })
    await expect(gate.install({ registerPolicy: () => {} }, { wallet: 'bitcoin' }))
      .rejects.toThrow(/@observer-protocol\/wdk-op-policy/)
  })
})
