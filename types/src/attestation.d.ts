/**
 * @typedef {import('./mandate-types.js').Mandate} Mandate
 * @typedef {import('./mandate-types.js').ProposedAction} ProposedAction
 */
/**
 * Build and sign a `ObserverSettlementAttestation`. Binds:
 *   - the delegation credential (by id, schema URL, and SHA-256 of its
 *     JCS-canonical bytes — the proof block included, so the binding is
 *     to the exact signed bytes the issuer produced)
 *   - the proposed action (rail, amount, category, counterparty, optional
 *     pre-sign proposal hash)
 *   - the settlement (rail and rail-native reference)
 *   - this adapter as evaluator (id + version)
 *   - a timestamp
 *
 * The whole envelope is signed by the agent's attestation key using
 * Ed25519Signature2026 over canonicalized bytes (same sort-keys + compact
 * JSON algorithm used for delegation signing).
 *
 * This is the centerpiece surface from the WDK implementation brief: a
 * portable, anchored attestation binding *this* agent to *this* scoped
 * mandate at *this* settlement, signed independently of any payment rail.
 *
 * @param {{
 *   credential: object,
 *   action: ProposedAction,
 *   settlement: { rail: string, ref: string } | string,
 *   attestationKey: Uint8Array,
 *   verificationMethod: string,
 *   issuerDid: string,
 *   subjectDid?: string,
 *   nowMs?: number,
 *   id?: string
 * }} args
 * @returns {object} The signed attestation.
 */
export function buildSettlementAttestation(args: {
    credential: object;
    action: ProposedAction;
    settlement: {
        rail: string;
        ref: string;
    } | string;
    attestationKey: Uint8Array;
    verificationMethod: string;
    issuerDid: string;
    subjectDid?: string;
    nowMs?: number;
    id?: string;
}): object;
export type Mandate = import("./mandate-types.js").Mandate;
export type ProposedAction = import("./mandate-types.js").ProposedAction;
