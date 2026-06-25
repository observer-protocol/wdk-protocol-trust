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
 * actually gates the transaction. The signing path itself is not intercepted —
 * that requires WDK's native policy engine (PR #55), composed via
 * `WdkEnforcementGate`. Use `AdvisoryGate` only as a fallback for rails with no
 * native WDK engine, or for agents that fully control their own send-call
 * ordering.
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

// Post-#55 enforcement is delegated to Tether WDK's native transaction-policy
// engine (PR #55), composed via `@observer-protocol/wdk-op-policy`. That gate
// lives in `wdk-enforcement-gate.js` as `WdkEnforcementGate` — it INSTALLS the
// WDK rule pair (it does not re-decide policy in OP code; see scope §6). The
// abstract `PolicyGate.evaluate` seam here exists for the `AdvisoryGate`
// fallback only, used where a rail has no native WDK engine.

export class NotImplementedError extends Error {
  /** @param {string} [message] */
  constructor (message = 'not implemented') {
    super(message)
    this.name = 'NotImplementedError'
  }
}
