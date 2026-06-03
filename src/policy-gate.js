// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

import { withinScope } from './mandate.js'

/**
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 * @typedef {import('./mandate-types.js').ProposedAction} ProposedAction
 * @typedef {import('./mandate-types.js').Decision} Decision
 */

/**
 * Abstract PolicyGate. The seam between this adapter's `withinScope`
 * evaluator and Tether's WDK pre-sign policy hook (PR #55). A concrete gate
 * decides where the binding happens — client-side advisory, or inside WDK's
 * transaction path once PR #55 lands.
 *
 * @abstract
 */
export class PolicyGate {
  /**
   * @param {ProposedAction} _action
   * @param {Mandate} _mandate
   * @returns {Promise<Decision> | Decision}
   */
  async evaluate (_action, _mandate) {
    throw new NotImplementedError('PolicyGate.evaluate must be implemented by a concrete gate')
  }
}

/**
 * Default gate: runs `withinScope` client-side and returns the decision.
 *
 * Honest label: the developer's `if (!decision.allow) throw …` is what
 * actually gates the WDK transaction. The signing path itself is not
 * intercepted — that requires the WDK PR #55 hook (`WdkPolicyHookGate`).
 * For agents that fully control their own send-call ordering (the common
 * case today), this is sufficient.
 */
export class AdvisoryGate extends PolicyGate {
  /**
   * @param {ProposedAction} action
   * @param {Mandate} mandate
   * @returns {Decision}
   */
  evaluate (action, mandate) {
    return withinScope(action, mandate)
  }
}

/**
 * Post-#55 gate: adapts to Tether WDK's pre-sign policy-hook API so the
 * decision is honored inside WDK's signing path itself.
 *
 * STUB. The exact shape of WDK's hook is not yet final — implementing
 * against a guessed signature would be throwaway. Concrete implementation
 * lands when PR #55 (or its successor) merges. Until then, use
 * `AdvisoryGate` and gate at the call site.
 *
 * Reference: observer-protocol/aip discussion of the PolicyGate seam in the
 * WDK implementation brief.
 */
export class WdkPolicyHookGate extends PolicyGate {
  /**
   * @param {ProposedAction} _action
   * @param {Mandate} _mandate
   * @returns {Decision}
   */
  evaluate (_action, _mandate) {
    throw new NotImplementedError(
      'WdkPolicyHookGate is a stub awaiting Tether WDK PR #55. ' +
      'Use AdvisoryGate (the default) until the WDK policy-hook interface lands.'
    )
  }
}

export class NotImplementedError extends Error {
  /** @param {string} [message] */
  constructor (message = 'not implemented') {
    super(message)
    this.name = 'NotImplementedError'
  }
}
