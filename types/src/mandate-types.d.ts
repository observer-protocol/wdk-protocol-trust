/**
 * Flat `{amount, currency}` shape used by per_transaction_ceiling, the
 * cumulative_budget body, and proposed-action amounts. Amount is a decimal
 * string to avoid float coercion at the wire level. Currency is an ISO 4217
 * code, a rail-native token symbol (e.g. `USDT`, `BTC`), or a rail-native
 * unit (`sats`).
 */
export type Money = {
    amount: string;
    currency: string;
};
/**
 * Optional cumulative-budget declaration on actionScope. ADVISORY in v0.8 —
 * surfaced but never grounds a deny. `window` is locked to
 * `"credential_validity"` (the cap applies cumulatively over
 * `validFrom → validUntil`); rolling-/calendar-window semantics are reserved
 * for a future draft.
 */
export type CumulativeBudget = {
    amount: string;
    currency: string;
    window: "credential_validity";
};
/**
 * Spending-mandate surface (AIP v0.8 §1.1–§1.3). Closed shape:
 * `additionalProperties: false`. Reserved-advisory fields
 * (allowed_counterparty_types, geographic_restriction) are surfaced when
 * present but MUST NOT ground a deny in this adapter.
 */
export type ActionScope = {
    allowed_rails: string[];
    per_transaction_ceiling: Money;
    allowed_transaction_categories?: string[] | undefined;
    cumulative_budget?: CumulativeBudget | undefined;
    allowed_counterparty_types?: string[] | undefined;
    geographic_restriction?: {
        allowed?: string[];
        disallowed?: string[];
    } | undefined;
};
/**
 * AuthorizationLevel-gated configuration. Exactly one of `oneTime`,
 * `recurring`, or `policy` is present, matching `authorizationLevel`.
 */
export type AuthorizationConfig = {
    oneTime?: {
        counterparty_did: string;
        amount: string;
        currency: string;
        rail: string;
        execution_deadline?: string;
        purchase_description?: string;
    } | undefined;
    recurring?: {
        counterparty_did: string;
        ceiling_amount: string;
        ceiling_currency: string;
        period: string;
        allowed_rails?: string[];
        per_transaction_max?: string;
        valid_until?: string;
    } | undefined;
    policy?: {
        policy_id: string;
        rail_preference: string[];
        escalation_threshold?: object;
        fallback_rules?: object;
        per_rail_caps?: object;
        time_windows?: object;
    } | undefined;
};
/**
 * Verified mandate — the output of `verifyMandate(credential)`. Carries the
 * essential bound fields for downstream withinScope and attest steps.
 */
export type Mandate = {
    credentialId: string;
    issuer: string;
    subjectDid: string;
    validFrom: string;
    validUntil: string;
    authorizationLevel: "one-time" | "recurring" | "policy";
    authorizationConfig: AuthorizationConfig;
    actionScope: ActionScope;
    credentialSchemaId: string;
    /**
     * The full credential as verified, for downstream
     * canonical-hash binding inside attest().
     */
    raw: object;
};
/**
 * A proposed action against a mandate. Currency / amount shape mirrors
 * ActionScope.per_transaction_ceiling. `category` is required for
 * actionScope.allowed_transaction_categories checks; `counterparty_did`
 * is required for authorizationLevel-gated rules.
 */
export type ProposedAction = {
    rail: string;
    amount: Money;
    category?: string | undefined;
    counterparty_did?: string | undefined;
    /**
     * SHA-256 hex of rail-canonical pre-sign
     * bytes. Required for attest(); optional at withinScope time so callers
     * can pre-flight before they have the signed-tx bytes.
     */
    proposalHash?: string | undefined;
};
/**
 * Result of a `withinScope` evaluation. `allow` is the binding decision;
 * `reasons` carry structured deny reasons (empty on allow). `advisories`
 * carry surfaced-but-non-binding flags (e.g. cumulative-budget over-spend
 * when attestation history is available client-side).
 */
export type Decision = {
    allow: boolean;
    reasons: DenyReason[];
    advisories: Advisory[];
};
export type DenyReason = {
    ruleType: "amountLimits" | "actionScope" | "authorization" | "currencyMismatch" | "schemaMismatch";
    ruleField: string;
    message: string;
    currentValue?: any;
    proposedValue?: any;
};
export type Advisory = {
    field: "cumulative_budget" | "allowed_counterparty_types" | "geographic_restriction";
    message: string;
};
/**
 * PolicyGate is the local-decisioning seam: a single `evaluate(action,
 * mandate)` method returning a decision. The default `AdvisoryGate` runs
 * `withinScope` client-side, for rails with no native WDK engine. Where WDK
 * PR #55 is present, enforcement is instead delegated to WDK and installed via
 * `WdkEnforcementGate` (composing `@observer-protocol/wdk-op-policy`); OP
 * attests the outcome rather than re-deciding here.
 */
export type PolicyGate = {
    evaluate: (action: ProposedAction, mandate: Mandate) => Promise<Decision> | Decision;
};
