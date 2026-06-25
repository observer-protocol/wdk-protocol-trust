/**
 * Derive a deterministic Ed25519 keypair from a wallet account's seed material
 * and a derivation path string. The path is hashed with HMAC-SHA512 over the
 * raw seed bytes; the first 32 bytes of the result become the Ed25519 secret
 * key. This is NOT BIP-32 derivation (Ed25519 has its own SLIP-0010 spec); it
 * is a domain-separated KDF chosen for simplicity and determinism within this
 * module's scope.
 *
 * The result is stable across calls: same seed + same path → same keypair.
 *
 * @param {Uint8Array | string} seed - Raw seed bytes or hex-encoded seed.
 * @param {string} derivationPath - Domain-separation path (e.g. "m/7000'/0'/0'/0/0").
 * @returns {{privateKey: Uint8Array, publicKey: Uint8Array}} The derived keypair.
 */
export function deriveEd25519Keypair(seed: Uint8Array | string, derivationPath: string): {
    privateKey: Uint8Array;
    publicKey: Uint8Array;
};
/**
 * Encode a 32-byte Ed25519 public key as multibase base58btc with the
 * `z` prefix and the Ed25519 multicodec header (0xed, 0x01), per W3C
 * `Ed25519VerificationKey2020`.
 *
 * @param {Uint8Array} publicKey - 32-byte raw Ed25519 public key.
 * @returns {string} Multibase string (e.g. "z6Mk...").
 */
export function publicKeyMultibase(publicKey: Uint8Array): string;
/**
 * Compute the agent_id (per OP convention: SHA-256 of the multibase pubkey, hex-encoded
 * first 32 chars). This is deterministic given the public key.
 *
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key.
 * @returns {string} 32-char lowercase hex agent_id.
 */
export function deriveAgentId(publicKey: Uint8Array): string;
/**
 * Construct the full agent DID for a given agent_id.
 *
 * @param {string} agentId - 32-char hex agent identifier.
 * @returns {string} The DID (e.g. "did:web:observerprotocol.org:agents:abc...").
 */
export function buildDid(agentId: string): string;
/**
 * Build a W3C-conformant DID document for the given agent.
 *
 * @param {string} agentId - The agent identifier.
 * @param {Uint8Array} publicKey - The agent's 32-byte Ed25519 public key.
 * @returns {Record<string, unknown>} DID document object.
 */
export function buildDidDocument(agentId: string, publicKey: Uint8Array): Record<string, unknown>;
/**
 * Sign a challenge with the agent's Ed25519 private key.
 *
 * @param {Uint8Array | string} message - Message bytes or UTF-8 string.
 * @param {Uint8Array} privateKey - 32-byte Ed25519 private key.
 * @returns {string} Hex-encoded signature.
 */
export function signChallenge(message: Uint8Array | string, privateKey: Uint8Array): string;
/**
 * Verify an Ed25519 signature.
 *
 * @param {string} signatureHex - Hex-encoded signature.
 * @param {Uint8Array | string} message - Original message.
 * @param {Uint8Array} publicKey - 32-byte Ed25519 public key.
 * @returns {boolean} True if signature is valid.
 */
export function verifySignature(signatureHex: string, message: Uint8Array | string, publicKey: Uint8Array): boolean;
