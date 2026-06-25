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
    evaluate(_action: ProposedAction, _mandate: Mandate): Promise<Decision> | Decision;
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
    evaluate(action: ProposedAction, mandate: Mandate): Decision;
}
export class NotImplementedError extends Error {
    /** @param {string} [message] */
    constructor(message?: string);
}
export type Mandate = import("./mandate-types.js").Mandate;
export type ProposedAction = import("./mandate-types.js").ProposedAction;
export type Decision = import("./mandate-types.js").Decision;
