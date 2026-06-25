/** @typedef {import('./trust-protocol.js').TrustProtocolConfig} TrustProtocolConfig */
/** @typedef {import('./trust-protocol.js').RegisterOptions} RegisterOptions */
/** @typedef {import('./trust-protocol.js').RegisterResult} RegisterResult */
/** @typedef {import('./trust-protocol.js').VerifyResult} VerifyResult */
/** @typedef {import('./trust-protocol.js').BilateralVerifyResult} BilateralVerifyResult */
/** @typedef {import('./trust-protocol.js').AttestPaymentOptions} AttestPaymentOptions */
/** @typedef {import('./trust-protocol.js').AttestPaymentResult} AttestPaymentResult */
/**
 * Observer Protocol implementation of {@link TrustProtocol}.
 *
 * Binds a `@tetherto/wdk-wallet-evm` (or compatible) account to an Observer Protocol
 * agent identity. Derives a deterministic Ed25519 signing keypair from the wallet
 * seed (domain-separated under `m/7000'/0'/0'/0/0`), so the same wallet always
 * resolves to the same DID across sessions.
 *
 * @example
 * import ObserverTrustProtocol from '@observer-protocol/wdk-protocol-trust'
 * import { WalletAccountEvm } from '@tetherto/wdk-wallet-evm'
 *
 * const account = new WalletAccountEvm(seedPhrase, "0'/0/0", { provider: 'https://...' })
 * const trust = new ObserverTrustProtocol(account, { apiBase: 'https://api.observerprotocol.org' })
 *
 * const { did } = await trust.register({ alias: 'my-agent' })
 * const counterparty = await trust.verify('seller-agent-7')
 * const handshake = await trust.bilateralVerify('seller-agent-7')
 * if (handshake.ok) {
 *   const txHash = await account.transfer({ ... })
 *   await trust.attestPayment({ txHash, recipient: 'seller-agent-7', chain: 'evm' })
 * }
 */
export default class ObserverTrustProtocol extends TrustProtocol {
    /** @private */
    private _client;
    /** @private */
    private _derivationPath;
    /** @private — populated lazily on first register/sign call */
    private _identity;
    /** @private — AIP v0.8 mandate-surface options */
    private _trustedIssuers;
    /** @private */
    private _schemaAllowlist;
    /** @private */
    private _gate;
    /**
     * @private
     * Optional separate attestation key (Uint8Array of length 32, raw
     * Ed25519 secret). When unset, attest() derives one from the wallet
     * seed under the same derivation path as the agent DID key — but the
     * brief calls for this to be DISTINCT from the WDK wallet key in
     * production. Pass `config.attestationKey` to honour that separation.
     */
    private _attestationKey;
    /** @private */
    private _erc8004;
    /**
     * @param {RegisterOptions} options - Alias + metadata.
     * @returns {Promise<RegisterResult>} Registered identity.
     */
    register(options: RegisterOptions): Promise<RegisterResult>;
    /**
     * @param {string} alias - Counterparty alias or DID.
     * @returns {Promise<VerifyResult>} Counterparty identity + VAC + trust score.
     */
    verify(alias: string): Promise<VerifyResult>;
    /**
     * @param {string} recipientAlias - Recipient alias or DID.
     * @returns {Promise<BilateralVerifyResult>} Combined sender + recipient proof.
     */
    bilateralVerify(recipientAlias: string): Promise<BilateralVerifyResult>;
    /**
     * @param {AttestPaymentOptions} options - Attestation options.
     * @returns {Promise<AttestPaymentResult>} Backend acknowledgment + URLs.
     */
    attestPayment(options: AttestPaymentOptions): Promise<AttestPaymentResult>;
    /**
     * Verify an `ObserverDelegationCredential` against the AIP v0.8 mandate
     * surface. Does: shape validation, credentialSchema.id allowlist check,
     * trusted-issuer check, validity-window check, did:web resolution, and
     * Ed25519Signature2026 proof verification bound to an assertionMethod
     * key in the issuer DID document.
     *
     * Status-list (revocation) checking is intentionally NOT performed here
     * in v1; callers requiring revocation SHOULD layer it on top.
     *
     * Distinct from {@link verify} (the v0.5-era handshake against a string
     * alias). Both methods coexist; use the one that matches your flow.
     *
     * @param {object} credential
     * @param {{nowMs?: number, resolveDid?: (did: string) => Promise<object>}} [opts]
     * @returns {Promise<import('./mandate-types.js').Mandate>}
     */
    verifyMandate(credential: object, opts?: {
        nowMs?: number;
        resolveDid?: (did: string) => Promise<object>;
    }): Promise<import("./mandate-types.js").Mandate>;
    /**
     * Evaluate a proposed action against a verified mandate. Pure and
     * I/O-free per the Observer Protocol evaluator source-of-truth invariant.
     *
     * Delegates to the configured `PolicyGate`. The default {@link AdvisoryGate}
     * runs `withinScope` client-side, for rails with no native WDK engine. Where
     * WDK PR #55 is available, enforcement is instead delegated to WDK and
     * installed via `WdkEnforcementGate` (composing `@observer-protocol/wdk-op-policy`) —
     * OP attests the outcome rather than re-deciding here (scope §6).
     *
     * @param {import('./mandate-types.js').ProposedAction} action
     * @param {import('./mandate-types.js').Mandate} mandate
     * @returns {Promise<import('./mandate-types.js').Decision> | import('./mandate-types.js').Decision}
     */
    withinScope(action: import("./mandate-types.js").ProposedAction, mandate: import("./mandate-types.js").Mandate): Promise<import("./mandate-types.js").Decision> | import("./mandate-types.js").Decision;
    /**
     * Sign an `ObserverSettlementAttestation` binding {delegation credential,
     * proposed action, settlement reference, evaluator, timestamp} with the
     * agent's attestation key. The signed envelope is portable: any verifier
     * with the agent DID can independently check that the agent attested to
     * this exact (mandate, action, settlement) tuple.
     *
     * `attestationKey` MUST be distinct from the WDK wallet key in
     * production — pass it via `config.attestationKey` on the constructor.
     * If not supplied, this method falls back to the wallet-seed-derived
     * key (the same key used for OP API challenge-response); the fallback
     * is for early-development only and emits no warning.
     *
     * Optional ERC-8004 anchoring is gated by `config.erc8004` (a stub-
     * compatible anchorer object with an `anchor(attestation)` method).
     * If `args.anchor === true` and an anchorer is configured, the call is
     * awaited and the returned anchor reference is added to the attestation's
     * `credentialSubject.settlement.anchored` field BEFORE signing.
     *
     * @param {{
     *   credential: object,
     *   action: import('./mandate-types.js').ProposedAction,
     *   settlement: {rail: string, ref: string} | string,
     *   anchor?: boolean
     * }} args
     * @returns {Promise<object>} The signed attestation envelope.
     */
    attest(args: {
        credential: object;
        action: import("./mandate-types.js").ProposedAction;
        settlement: {
            rail: string;
            ref: string;
        } | string;
        anchor?: boolean;
    }): Promise<object>;
    /**
     * @private
     * @param {{publicKey: Uint8Array, did: string|null}} identity
     * @returns {string}
     */
    private _derivedDidFromKeypair;
    /**
     * Derive (and cache) this account's Ed25519 keypair from the wallet seed.
     * The API-assigned `agentId` and `did` are populated by `register()`; pre-
     * register, both are `null` (the locally-derivable agent_id is intentionally
     * NOT used as a stand-in because the API generates its own and that's the
     * one used for subsequent challenge / attest calls).
     *
     * @returns {Promise<{privateKey: Uint8Array, publicKey: Uint8Array, agentId: string|null, did: string|null}>}
     * @private
     */
    private _ensureIdentity;
    /**
     * Extract a stable seed bytes from the bound wallet account. The WDK wallet
     * accounts expose seed material via `_seedBytes` / `seedBytes` / `mnemonic`
     * across versions; we try in order and fail loudly if none are usable.
     *
     * @returns {Promise<Uint8Array>}
     * @private
     */
    private _extractAccountSeed;
    /**
     * Try to read the underlying EVM address for inclusion in registration metadata.
     *
     * @returns {string | undefined}
     * @private
     */
    private _extractAccountAddress;
    /**
     * @param {string} alias
     * @returns {Promise<string>}
     * @private
     */
    private _resolveAliasToAgentId;
    /**
     * @param {string} alias
     * @returns {Promise<string>}
     * @private
     */
    private _resolveAliasToDid;
}
export type TrustProtocolConfig = import("./trust-protocol.js").TrustProtocolConfig;
export type RegisterOptions = import("./trust-protocol.js").RegisterOptions;
export type RegisterResult = import("./trust-protocol.js").RegisterResult;
export type VerifyResult = import("./trust-protocol.js").VerifyResult;
export type BilateralVerifyResult = import("./trust-protocol.js").BilateralVerifyResult;
export type AttestPaymentOptions = import("./trust-protocol.js").AttestPaymentOptions;
export type AttestPaymentResult = import("./trust-protocol.js").AttestPaymentResult;
import TrustProtocol from './trust-protocol.js';
