// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { NotImplementedError } from './policy-gate.js'

/**
 * @typedef {import('./mandate-types.js').ProposedAction} ProposedAction
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 */

/**
 * Concrete enforcement gate that composes
 * [`@observer-protocol/wdk-op-policy`](https://www.npmjs.com/package/@observer-protocol/wdk-op-policy)
 * to install Tether WDK's native transaction-policy enforcement (WDK PR #55)
 * on a WDK instance.
 *
 * **Design invariant — OP attests, WDK enforces (reference scope §6).** OP does
 * NOT re-decide policy in this gate. `wdk-op-policy.registerObserverPolicy`
 * installs an ALLOW + DENY rule pair that WDK evaluates *inside its own signing
 * path*, fail-closed, before the key signs. OP's contribution is verifying the
 * signed delegation credential and **attesting** the outcome (a signed
 * `PolicyEvaluationCredential`) — never gating the transaction in OP code.
 * `evaluate()` therefore intentionally throws: there is no OP-side per-trade
 * decision to expose. The local-decisioning fallback is `AdvisoryGate`, and it
 * is only appropriate for rails with no native WDK engine.
 *
 * `@observer-protocol/wdk-op-policy` (and its own `@tetherto/wdk` peer) is an
 * **optional** peer dependency, lazily imported by {@link install} so the
 * umbrella stays importable by consumers who only need VAC verify / attest.
 */
export class WdkEnforcementGate {
  /**
   * @param {object} [config]
   * @param {Record<string, unknown>} [config.policy] Default OP verifier policy
   *   object (credentialPath, issuerDid, schemaAllowlist, rails, revocation,
   *   auditLog, …) — same vocabulary as the OWS / mppx engines. May be
   *   overridden per-call in {@link install}.
   * @param {Record<string, string>} [config.wallets] Default WDK wallet-label →
   *   CAIP-2 map. Each CAIP-2 MUST resolve to a rail in `policy.rails`.
   * @param {object} [config.options] Default `ObserverPolicyOptions`
   *   (wallet, ops, scope, accounts, conditionTimeoutMs, idPrefix).
   * @param {Function} [config.register] Test/DI seam: a `registerObserverPolicy`
   *   implementation to use instead of the lazily-imported peer dependency.
   */
  constructor (config = {}) {
    this._policy = config.policy
    this._wallets = config.wallets
    this._options = config.options || {}
    /** @private */
    this._register = config.register || null
  }

  /**
   * Install OP-verified WDK PR #55 enforcement on a WDK instance. Emits the
   * ALLOW + DENY policy pair via `wdk-op-policy`; every governed write op then
   * verifies the signed delegation credential before WDK signs, fail-closed.
   *
   * @param {{ registerPolicy: Function }} wdk A WDK instance carrying the PR #55
   *   transaction policy engine (`@tetherto/wdk >= 1.0.0-beta.11`).
   * @param {object} [opts] Overrides merged over the constructor config.
   * @param {Record<string, unknown>} [opts.policy]
   * @param {Record<string, string>} [opts.wallets]
   * @param {string | string[]} [opts.wallet] WDK wallet label(s) to govern
   *   (required by `registerObserverPolicy`).
   * @param {string[]} [opts.ops]
   * @param {'project' | 'account'} [opts.scope]
   * @param {Array<string | number>} [opts.accounts]
   * @param {number} [opts.conditionTimeoutMs]
   * @param {string} [opts.idPrefix]
   * @returns {Promise<object>} the WDK instance, for chaining.
   */
  async install (wdk, opts = {}) {
    const { policy = this._policy, wallets = this._wallets, ...policyOptions } = opts
    if (!policy) throw new Error('WdkEnforcementGate.install requires a `policy` (config or opts)')
    if (!wallets) throw new Error('WdkEnforcementGate.install requires a `wallets` map (config or opts)')

    const register = this._register || await this._loadRegister()
    const options = { ...this._options, ...policyOptions }
    if (!options.wallet) {
      throw new Error('WdkEnforcementGate.install requires `wallet` (the WDK wallet label to govern)')
    }
    return register(wdk, { policy, wallets }, options)
  }

  /**
   * Lazily resolve `registerObserverPolicy` from the optional peer dependency.
   * @private
   * @returns {Promise<Function>}
   */
  async _loadRegister () {
    try {
      const mod = await import('@observer-protocol/wdk-op-policy')
      return mod.registerObserverPolicy
    } catch (err) {
      throw new Error(
        'WdkEnforcementGate requires the optional peer dependency ' +
        '`@observer-protocol/wdk-op-policy` (with `@tetherto/wdk >= 1.0.0-beta.11`). ' +
        'Install it to enable WDK PR #55 enforcement. Underlying error: ' + err.message
      )
    }
  }

  /**
   * Intentionally unsupported. Enforcement is delegated to WDK (PR #55); OP does
   * not re-decide policy per trade (reference scope §6). Install enforcement via
   * {@link install}; for rails with no native WDK engine, use `AdvisoryGate`.
   *
   * @param {ProposedAction} _action
   * @param {Mandate} _mandate
   * @returns {never}
   */
  evaluate (_action, _mandate) {
    throw new NotImplementedError(
      'WdkEnforcementGate does not re-decide policy in OP code: enforcement is ' +
      'delegated to WDK PR #55 (install it via WdkEnforcementGate.install) and OP ' +
      'attests the outcome. Use AdvisoryGate only as a fallback where no native ' +
      'WDK engine exists for the rail.'
    )
  }
}
