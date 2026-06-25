/**
 * Thin HTTP wrapper around the Observer Protocol public API
 * (default `https://api.observerprotocol.org`).
 *
 * Handles JSON encode/decode, request timeout, structured error throwing.
 * Stateless — no caching, no retries. Caller decides retry policy.
 */
export class OpClient {
    /**
     * @param {object} [config]
     * @param {string} [config.apiBase] - Base URL for the Observer Protocol API.
     * @param {number} [config.timeoutMs] - Per-request timeout in milliseconds.
     * @param {Record<string,string>} [config.headers] - Default headers (e.g. `{ Authorization: 'Bearer ...' }`).
     * @param {typeof fetch} [config.fetchImpl] - Override the global `fetch` for testing.
     */
    constructor(config?: {
        apiBase?: string | undefined;
        timeoutMs?: number | undefined;
        headers?: Record<string, string> | undefined;
        fetchImpl?: typeof fetch | undefined;
    });
    _apiBase: string;
    _timeoutMs: number;
    _defaultHeaders: Record<string, string>;
    _fetch: typeof fetch;
    /**
     * GET request.
     *
     * @param {string} path - Path relative to apiBase (e.g. "/agents/abc/did.json").
     * @returns {Promise<unknown>} Parsed JSON response.
     */
    get(path: string): Promise<unknown>;
    /**
     * POST request with JSON body.
     *
     * @param {string} path - Path relative to apiBase.
     * @param {Record<string,unknown>} body - JSON-serializable body.
     * @returns {Promise<unknown>} Parsed JSON response.
     */
    post(path: string, body: Record<string, unknown>): Promise<unknown>;
    /**
     * Resolve an agent's DID document.
     *
     * Reads from the api. subdomain (the canonical dynamic source). The W3C
     * did:web spec mandates the apex URL `observerprotocol.org/agents/{id}/did.json`;
     * Netlify proxies that path to this endpoint.
     *
     * @param {string} agentId - Agent identifier.
     * @returns {Promise<Record<string,unknown>>} DID document.
     */
    getAgentDidDocument(agentId: string): Promise<Record<string, unknown>>;
    /**
     * Get an agent's VAC summary.
     *
     * @param {string} agentId - Agent identifier.
     * @returns {Promise<Record<string,unknown>>} VAC summary object.
     */
    getVac(agentId: string): Promise<Record<string, unknown>>;
    /**
     * Register an agent with Observer Protocol.
     *
     * NOTE: this endpoint accepts all fields as query parameters (not JSON body),
     * per the current api.observerprotocol.org OpenAPI spec.
     *
     * @param {object} args
     * @param {string} args.public_key - Hex-encoded Ed25519 public key.
     * @param {string} [args.alias] - Human-readable agent alias.
     * @param {string} [args.agent_name] - Display name.
     * @param {string} [args.framework] - Agent framework label (e.g. "wdk").
     * @param {string} [args.wallet_standard] - Wallet standard label (e.g. "wdk-evm").
     * @param {string} [args.chains] - Comma-separated chain identifiers.
     * @param {string} [args.org_id] - Organization identifier (optional).
     * @param {string} [args.legal_entity_id] - Legal entity identifier (optional).
     * @param {string} [args.ows_vault_name] - OWS vault name (optional).
     * @returns {Promise<Record<string,unknown>>} Registration response (agent_id, did, did_document, …).
     */
    registerAgent(args: {
        public_key: string;
        alias?: string | undefined;
        agent_name?: string | undefined;
        framework?: string | undefined;
        wallet_standard?: string | undefined;
        chains?: string | undefined;
        org_id?: string | undefined;
        legal_entity_id?: string | undefined;
        ows_vault_name?: string | undefined;
    }): Promise<Record<string, unknown>>;
    /**
     * Begin challenge-response identity verification. Returns a nonce to sign.
     *
     * NOTE: query parameter (not body).
     *
     * @param {string} agentId - Agent identifier.
     * @returns {Promise<Record<string,unknown>>} Challenge response (nonce / challenge / id, varies).
     */
    getChallenge(agentId: string): Promise<Record<string, unknown>>;
    /**
     * Complete challenge-response by submitting the signed nonce as a query
     * parameter (per current API spec).
     *
     * @param {object} args
     * @param {string} args.agent_id - Agent identifier.
     * @param {string} args.signed_challenge - Hex-encoded Ed25519 signature over the nonce.
     * @param {string} [args.challenge_id] - Server-side challenge id, if returned by getChallenge.
     * @returns {Promise<Record<string,unknown>>}
     */
    verifyAgent(args: {
        agent_id: string;
        signed_challenge: string;
        challenge_id?: string | undefined;
    }): Promise<Record<string, unknown>>;
    /**
     * Get an agent's composite reputation / trust score from the OP API.
     *
     * @param {string} agentId - Agent identifier.
     * @returns {Promise<Record<string,unknown>>}
     */
    getTrustScore(agentId: string): Promise<Record<string, unknown>>;
    /**
     * Write a verified-event audit record (canonical post-payment attestation path).
     *
     * Body shape per the live `AuditEventRequest` schema:
     *
     *   receipt_reference         REQ string  — opaque idempotency key
     *   agent                     REQ AuditAgent  ({ agent_id, did? })
     *   transaction               REQ AuditTransaction ({ amount, category, rail?, counterparty?, integrator_reference? })
     *   settlement_reference      opt
     *   verification              opt
     *   metadata                  opt object
     *
     * @param {object} body
     * @param {string} body.receipt_reference - Idempotency / receipt id.
     * @param {{agent_id: string, did?: string}} body.agent - Agent identity.
     * @param {{amount: object, category: string, rail?: string, counterparty?: object, integrator_reference?: string}} body.transaction - Transaction details.
     * @param {object} [body.settlement_reference] - Settlement reference.
     * @param {object} [body.verification] - Verification metadata.
     * @param {Record<string,unknown>} [body.metadata] - Free-form metadata.
     * @returns {Promise<Record<string,unknown>>}
     */
    writeVerifiedEvent(body: {
        receipt_reference: string;
        agent: {
            agent_id: string;
            did?: string;
        };
        transaction: {
            amount: object;
            category: string;
            rail?: string;
            counterparty?: object;
            integrator_reference?: string;
        };
        settlement_reference?: object;
        verification?: object;
        metadata?: Record<string, unknown> | undefined;
    }): Promise<Record<string, unknown>>;
    /**
     * Pin an agent's registration to ERC-8004 (Level 3 chain anchoring).
     *
     * @param {object} body
     * @param {string} body.agent_id - Agent identifier.
     * @param {string} body.chain - Target EVM chain (e.g. "base", "ethereum").
     * @param {string} [body.delegation_id] - Delegation credential ID (optional).
     * @returns {Promise<{token_id: string, tx_hash: string, status: string}>}
     */
    pinErc8004(body: {
        agent_id: string;
        chain: string;
        delegation_id?: string | undefined;
    }): Promise<{
        token_id: string;
        tx_hash: string;
        status: string;
    }>;
    /**
     * Get an agent's ERC-8004 summary (NFT info, indexer status, etc).
     *
     * @param {string} agentId - Agent identifier.
     * @returns {Promise<Record<string,unknown>>}
     */
    getErc8004Summary(agentId: string): Promise<Record<string, unknown>>;
    /**
     * URL-encode a flat object as a query string. Skips undefined / null values.
     *
     * @param {Record<string, unknown>} args
     * @returns {string}
     * @private
     */
    private _encodeQuery;
    /**
     * @param {string} method
     * @param {string} path
     * @param {Record<string,unknown>} [body]
     * @returns {Promise<unknown>}
     * @private
     */
    private _request;
}
