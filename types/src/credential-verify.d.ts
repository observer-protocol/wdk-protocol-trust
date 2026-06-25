/**
 * Canonicalize a credential for signing/verifying. Matches the Sovereign
 * issuer's canonicalization exactly: exclude the `proof` field, recursively
 * sort object keys lexicographically, JSON.stringify with no whitespace.
 *
 * Note: this is not full RFC 8785 JCS — it is the sort-keys-and-compact
 * subset, which matches the Python `json.dumps(..., sort_keys=True,
 * separators=(',', ':'))` used in the reference issuer. The two MUST stay
 * byte-identical; if the issuer ever switches to full RFC 8785, this
 * function moves with it via a new schema URL (per the schema immutability
 * policy).
 *
 * @param {object} credential
 * @returns {string}
 */
export function canonicalizeForSigning(credential: object): string;
/**
 * Decode a Bitcoin-alphabet base58 string to raw bytes.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function base58Decode(str: string): Uint8Array;
/**
 * Decode a multibase base58btc Ed25519 public key (z-prefixed, with the
 * 0xed 0x01 multicodec header). Returns the raw 32-byte public key.
 *
 * @param {string} mb
 * @returns {Uint8Array}
 */
export function decodePublicKeyMultibase(mb: string): Uint8Array;
/**
 * Decode a multibase base58btc signature value (z-prefixed). Returns the
 * raw 64-byte signature.
 *
 * @param {string} mb
 * @returns {Uint8Array}
 */
export function decodeSignatureMultibase(mb: string): Uint8Array;
/**
 * Resolve a `did:web:...` DID to its DID document URL and fetch it.
 *
 * Mapping (per the did:web spec):
 *   did:web:example.org              → https://example.org/.well-known/did.json
 *   did:web:example.org:user:alice   → https://example.org/user/alice/did.json
 *
 * @param {string} did
 * @param {{fetchImpl?: typeof fetch, timeoutMs?: number}} [opts]
 * @returns {Promise<object>} The DID document.
 */
export function resolveDidWeb(did: string, opts?: {
    fetchImpl?: typeof fetch;
    timeoutMs?: number;
}): Promise<object>;
/**
 * Locate a verification method in a DID document by its full id
 * (e.g. `did:web:observerprotocol.org#key-2`). Returns the verification
 * method object, or throws.
 *
 * Verifies the method is referenced in `assertionMethod` so that keys
 * present only in `verificationMethod` (e.g. retained-for-history v0.6
 * `#key-1`) cannot be used to verify newly-issued credentials. Mirrors the
 * normative check in AIP v0.8 §3.4 / §4.
 *
 * @param {object} didDocument
 * @param {string} verificationMethodId
 * @returns {object}
 */
export function findAssertionMethod(didDocument: object, verificationMethodId: string): object;
/**
 * Verify the W3C VC proof on a credential. Returns true on success; throws
 * `VerificationError` with a machine-readable code on failure.
 *
 * @param {object} credential
 * @param {object} didDocument
 * @returns {boolean}
 */
export function verifyCredentialProof(credential: object, didDocument: object): boolean;
/**
 * Verify an `ObserverDelegationCredential` against the AIP v0.8 mandate
 * surface. Performs:
 *
 *   1. Shape validation (required fields present).
 *   2. credentialSchema.id is in the recognised allowlist (default:
 *      v2.1.json). Unknown URLs are rejected — the adapter does NOT fetch
 *      arbitrary schema URLs.
 *   3. issuer is in the trusted-issuer set.
 *   4. validFrom ≤ now ≤ validUntil.
 *   5. did:web resolution of the issuer.
 *   6. assertionMethod-bound Ed25519 signature verification over the
 *      canonical credential bytes.
 *
 * The status-list check (per AIP v0.6 §7) is NOT performed here in v1 —
 * it requires fetching the BitstringStatusListCredential, which is a
 * separate trust surface. Callers that require revocation checking
 * SHOULD layer it on top of this method, or use the OP API directly.
 *
 * @param {object} credential
 * @param {{
 *   trustedIssuers?: ReadonlyArray<string>,
 *   schemaAllowlist?: ReadonlyArray<string>,
 *   resolveDid?: (did: string) => Promise<object>,
 *   nowMs?: number
 * }} [options]
 * @returns {Promise<Mandate>}
 */
export function verifyMandate(credential: object, options?: {
    trustedIssuers?: ReadonlyArray<string>;
    schemaAllowlist?: ReadonlyArray<string>;
    resolveDid?: (did: string) => Promise<object>;
    nowMs?: number;
}): Promise<Mandate>;
/**
 * VerificationError carries a machine-readable `code` so callers can branch
 * on failure mode without parsing messages.
 */
export class VerificationError extends Error {
    /**
     * @param {string} code
     * @param {string} message
     */
    constructor(code: string, message: string);
    code: string;
}
export type Mandate = import("./mandate-types.js").Mandate;
