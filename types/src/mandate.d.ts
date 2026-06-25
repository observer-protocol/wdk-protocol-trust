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
export function withinScope(action: ProposedAction, mandate: Mandate, options?: {
    nowMs?: number;
}): Decision;
export namespace _internals {
    export { _compareAmounts };
    export { _parseDecimal };
    export { _isAfter };
}
export type Mandate = import("./mandate-types.js").Mandate;
export type ProposedAction = import("./mandate-types.js").ProposedAction;
export type Decision = import("./mandate-types.js").Decision;
export type DenyReason = import("./mandate-types.js").DenyReason;
export type Advisory = import("./mandate-types.js").Advisory;
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
declare function _compareAmounts(a: string, b: string): number;
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
declare function _parseDecimal(s: string): {
    int: string;
    frac: string;
};
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
declare function _isAfter(isoDeadline: string, nowMs: number): boolean;
export {};
