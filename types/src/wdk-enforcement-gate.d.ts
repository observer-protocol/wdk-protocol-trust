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
    constructor(config?: {
        policy?: Record<string, unknown> | undefined;
        wallets?: Record<string, string> | undefined;
        options?: object;
        register?: Function | undefined;
    });
    _policy: Record<string, unknown> | undefined;
    _wallets: Record<string, string> | undefined;
    _options: any;
    /** @private */
    private _register;
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
    install(wdk: {
        registerPolicy: Function;
    }, opts?: {
        policy?: Record<string, unknown> | undefined;
        wallets?: Record<string, string> | undefined;
        wallet?: string | string[] | undefined;
        ops?: string[] | undefined;
        scope?: "project" | "account" | undefined;
        accounts?: (string | number)[] | undefined;
        conditionTimeoutMs?: number | undefined;
        idPrefix?: string | undefined;
    }): Promise<object>;
    /**
     * Lazily resolve `registerObserverPolicy` from the optional peer dependency.
     * @private
     * @returns {Promise<Function>}
     */
    private _loadRegister;
    /**
     * Intentionally unsupported. Enforcement is delegated to WDK (PR #55); OP does
     * not re-decide policy per trade (reference scope §6). Install enforcement via
     * {@link install}; for rails with no native WDK engine, use `AdvisoryGate`.
     *
     * @param {ProposedAction} _action
     * @param {Mandate} _mandate
     * @returns {never}
     */
    evaluate(_action: ProposedAction, _mandate: Mandate): never;
}
export type ProposedAction = import("./mandate-types.js").ProposedAction;
export type Mandate = import("./mandate-types.js").Mandate;
