/**
 * @typedef {object} TrustProtocolConfig
 * @property {string} [apiBase] - Base URL for the agent identity / verification backend.
 * @property {string} [apiKey] - Integrator API key for authenticated AT-layer endpoints
 *   (e.g. `/v1/audit/verified-event`, `/v1/chain/verify`). Sent as `Authorization: Bearer <key>`.
 *   OP-layer endpoints (DID resolution, VAC lookup, register, challenge) are public and do not
 *   require an API key.
 * @property {number} [requestTimeoutMs] - Per-request timeout for backend calls.
 * @property {string} [didDerivationPath] - Domain-separated path for deriving the agent
 *   signing key from the wallet seed (default: `m/7000'/0'/0'/0/0`).
 * @property {Record<string,unknown>} [defaultMetadata] - Metadata attached to register() by default.
 */
/**
 * @typedef {object} RegisterOptions
 * @property {string} alias - Human-readable agent alias (e.g. "samantha-agent-1").
 * @property {Record<string,unknown>} [metadata] - Free-form metadata merged with defaults.
 */
/**
 * @typedef {object} RegisterResult
 * @property {string} agentId - 32-char hex agent identifier.
 * @property {string} did - Full DID string (e.g. `did:web:observerprotocol.org:agents:{id}`).
 * @property {Record<string,unknown>} didDocument - W3C DID document.
 */
/**
 * @typedef {object} VerifyResult
 * @property {string} did - DID resolved for the alias.
 * @property {Record<string,unknown>} didDocument - W3C DID document.
 * @property {Record<string,unknown>} vac - VAC summary (verified agent credential).
 * @property {Record<string,unknown>} [trustScore] - reputation / trust score breakdown.
 */
/**
 * @typedef {object} BilateralVerifyResult
 * @property {boolean} ok - True if both sides verified successfully.
 * @property {{did: string, signature: string, nonce: string}} senderProof - Sender's challenge-response proof.
 * @property {VerifyResult} recipient - Recipient's identity package.
 * @property {string} [reason] - Failure reason if ok=false.
 */
/**
 * @typedef {object} AttestPaymentOptions
 * @property {string} txHash - Settlement transaction hash.
 * @property {string} recipient - Recipient DID or alias.
 * @property {string} chain - Rail identifier ("evm", "lightning", "tron", "x402", ...).
 * @property {bigint | number | string} [amount] - Amount transferred (in base unit).
 * @property {string} [token] - Token symbol or address (e.g. "USDT").
 * @property {boolean} [pinErc8004] - If true, also pin the registration to ERC-8004 (Level 3 anchoring).
 * @property {Record<string,unknown>} [metadata] - Free-form additional metadata.
 */
/**
 * @typedef {object} AttestPaymentResult
 * @property {string} eventId - Audit event ID assigned by the backend.
 * @property {string} [receiptUrl] - URL to the signed verification receipt VC (if available).
 * @property {string} [dashboardUrl] - URL to the AT Enterprise dashboard view (if available).
 * @property {{tokenId: string, txHash: string, status: string}} [erc8004] - ERC-8004 pin result, if requested.
 */
/**
 * @interface ITrustProtocol
 *
 * The trust protocol category.
 *
 * Conceptually parallel to the existing WDK protocol categories — `BridgeProtocol`,
 * `SwapProtocol`, `FiatProtocol`, `LendingProtocol`. Trust is **not** currently a
 * recognized WDK protocol category; this interface is proposed as a fifth category
 * and shipped here as a reference implementation. See README §"Where this fits in
 * WDK's architecture" for the design discussion.
 *
 * Four logical operations cover the full lifecycle of agent-to-agent payment trust:
 *
 *   register          — issue an agent identity (DID + VC) bound to a wallet account
 *   verify            — resolve another agent's identity + reputation
 *   bilateralVerify   — both-party identity proof before payment commits
 *   attestPayment     — write a signed audit event after settlement
 *
 * Implementations bind to a specific wallet account and may target one or more
 * settlement rails. The reference implementation in this package targets EVM via
 * `@tetherto/wdk-wallet-evm`; future bindings can target TRON, Lightning, Solana,
 * etc, by extending this base.
 */
export class ITrustProtocol {
    /**
     * Register the bound wallet account as an agent identity on the trust backend.
     *
     * Idempotent semantics: registering the same account twice with the same alias
     * should return the same `agentId` / `did` (the agent identifier is derived
     * deterministically from the wallet seed; aliases may collide and the backend
     * resolves collisions per its own policy).
     *
     * @param {RegisterOptions} options - Registration options.
     * @returns {Promise<RegisterResult>} Identity package.
     */
    register(options: RegisterOptions): Promise<RegisterResult>;
    /**
     * Resolve another agent's identity and reputation from the trust backend.
     *
     * @param {string} alias - Counterparty alias (or DID; implementations may accept either).
     * @returns {Promise<VerifyResult>} Counterparty identity + VAC + trust score.
     */
    verify(alias: string): Promise<VerifyResult>;
    /**
     * Run a bilateral verification handshake before a payment executes:
     * (1) prove this account's identity to the backend via challenge-response,
     * (2) resolve the counterparty's identity, (3) return both proofs.
     *
     * Use cases: chargeback prevention (the receipt of bilateral verification is
     * cryptographic evidence that both parties were identity-bound at the moment
     * of payment authorization).
     *
     * @param {string} recipientAlias - Alias or DID of the payment counterparty.
     * @returns {Promise<BilateralVerifyResult>} Combined sender + recipient proof package.
     */
    bilateralVerify(recipientAlias: string): Promise<BilateralVerifyResult>;
    /**
     * Attest a settled payment to the trust backend after on-chain confirmation.
     *
     * Writes a signed audit event recording the (sender DID, recipient DID, tx hash,
     * chain, amount) tuple. Optionally pins the agent's registration to ERC-8004
     * for Level 3 chain anchoring.
     *
     * @param {AttestPaymentOptions} options - Attestation options.
     * @returns {Promise<AttestPaymentResult>} Backend acknowledgment + URLs.
     */
    attestPayment(options: AttestPaymentOptions): Promise<AttestPaymentResult>;
}
/**
 * Abstract base class for trust protocol implementations. Subclasses bind to a
 * specific wallet account type (EVM, TRON, Solana, …) and implement the four
 * operations defined by {@link ITrustProtocol}.
 *
 * Mirrors the `BridgeProtocol` / `SwapProtocol` pattern in `@tetherto/wdk-wallet/protocols`.
 *
 * @abstract
 * @implements {ITrustProtocol}
 */
export default class TrustProtocol implements ITrustProtocol {
    /**
     * @param {object} account - The bound wallet account (e.g. `WalletAccountEvm`).
     * @param {TrustProtocolConfig} [config] - Trust protocol configuration.
     */
    constructor(account: object, config?: TrustProtocolConfig);
    /** @protected */
    protected _account: any;
    /** @protected */
    protected _config: TrustProtocolConfig;
    /**
     * Read-only access to the bound wallet account.
     *
     * @returns {object} The wallet account.
     */
    get account(): object;
    /**
     * Read-only access to the protocol configuration.
     *
     * @returns {TrustProtocolConfig} The config.
     */
    get config(): TrustProtocolConfig;
    /** @abstract */
    register(options: any): Promise<void>;
    /** @abstract */
    verify(alias: any): Promise<void>;
    /** @abstract */
    bilateralVerify(recipientAlias: any): Promise<void>;
    /** @abstract */
    attestPayment(options: any): Promise<void>;
}
/**
 * Thrown by the abstract base class when a subclass forgets to override a method.
 * Mirrors `NotImplementedError` from `@tetherto/wdk-wallet/errors`.
 */
export class NotImplementedError extends Error {
    /**
     * @param {string} method - Name of the unimplemented method.
     */
    constructor(method: string);
}
export type TrustProtocolConfig = {
    /**
     * - Base URL for the agent identity / verification backend.
     */
    apiBase?: string | undefined;
    /**
     * - Integrator API key for authenticated AT-layer endpoints
     * (e.g. `/v1/audit/verified-event`, `/v1/chain/verify`). Sent as `Authorization: Bearer <key>`.
     * OP-layer endpoints (DID resolution, VAC lookup, register, challenge) are public and do not
     * require an API key.
     */
    apiKey?: string | undefined;
    /**
     * - Per-request timeout for backend calls.
     */
    requestTimeoutMs?: number | undefined;
    /**
     * - Domain-separated path for deriving the agent
     * signing key from the wallet seed (default: `m/7000'/0'/0'/0/0`).
     */
    didDerivationPath?: string | undefined;
    /**
     * - Metadata attached to register() by default.
     */
    defaultMetadata?: Record<string, unknown> | undefined;
};
export type RegisterOptions = {
    /**
     * - Human-readable agent alias (e.g. "samantha-agent-1").
     */
    alias: string;
    /**
     * - Free-form metadata merged with defaults.
     */
    metadata?: Record<string, unknown> | undefined;
};
export type RegisterResult = {
    /**
     * - 32-char hex agent identifier.
     */
    agentId: string;
    /**
     * - Full DID string (e.g. `did:web:observerprotocol.org:agents:{id}`).
     */
    did: string;
    /**
     * - W3C DID document.
     */
    didDocument: Record<string, unknown>;
};
export type VerifyResult = {
    /**
     * - DID resolved for the alias.
     */
    did: string;
    /**
     * - W3C DID document.
     */
    didDocument: Record<string, unknown>;
    /**
     * - VAC summary (verified agent credential).
     */
    vac: Record<string, unknown>;
    /**
     * - reputation / trust score breakdown.
     */
    trustScore?: Record<string, unknown> | undefined;
};
export type BilateralVerifyResult = {
    /**
     * - True if both sides verified successfully.
     */
    ok: boolean;
    /**
     * - Sender's challenge-response proof.
     */
    senderProof: {
        did: string;
        signature: string;
        nonce: string;
    };
    /**
     * - Recipient's identity package.
     */
    recipient: VerifyResult;
    /**
     * - Failure reason if ok=false.
     */
    reason?: string | undefined;
};
export type AttestPaymentOptions = {
    /**
     * - Settlement transaction hash.
     */
    txHash: string;
    /**
     * - Recipient DID or alias.
     */
    recipient: string;
    /**
     * - Rail identifier ("evm", "lightning", "tron", "x402", ...).
     */
    chain: string;
    /**
     * - Amount transferred (in base unit).
     */
    amount?: string | number | bigint | undefined;
    /**
     * - Token symbol or address (e.g. "USDT").
     */
    token?: string | undefined;
    /**
     * - If true, also pin the registration to ERC-8004 (Level 3 anchoring).
     */
    pinErc8004?: boolean | undefined;
    /**
     * - Free-form additional metadata.
     */
    metadata?: Record<string, unknown> | undefined;
};
export type AttestPaymentResult = {
    /**
     * - Audit event ID assigned by the backend.
     */
    eventId: string;
    /**
     * - URL to the signed verification receipt VC (if available).
     */
    receiptUrl?: string | undefined;
    /**
     * - URL to the AT Enterprise dashboard view (if available).
     */
    dashboardUrl?: string | undefined;
    /**
     * - ERC-8004 pin result, if requested.
     */
    erc8004?: {
        tokenId: string;
        txHash: string;
        status: string;
    } | undefined;
};
