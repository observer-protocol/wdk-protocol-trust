# Agent Guide

This repository implements the Observer Protocol trust layer for the Tether WDK ecosystem. It follows the same conventions as the official `@tetherto/wdk-protocol-*` modules to make integration mechanical.

## Project Overview

- **Architecture:** Modular. `TrustProtocol` is the abstract base (proposed as a new WDK protocol category alongside Bridge / Swap / Fiat / Lending). `ObserverTrustProtocol` is the concrete Observer Protocol implementation. `OpClient` wraps the Observer Protocol public API.
- **Runtime:** Supports both Node.js (≥18, native `fetch`) and Bare runtime via the `bare` exports condition.

## Tech Stack & Tooling

- **Language:** JavaScript (ES2022+).
- **Module System:** ES Modules (`"type": "module"`).
- **Type Checking:** TypeScript is used purely for generating type declarations (`.d.ts`). Source remains JavaScript with JSDoc.
  - Command: `npm run build:types`
- **Linting:** `standard` (JavaScript Standard Style).
  - Command: `npm run lint` / `npm run lint:fix`
- **Testing:** `jest` (configured with `experimental-vm-modules` for ESM).
  - Command: `npm test`
- **Crypto:** `@noble/curves` (Ed25519), `@noble/hashes` (SHA-256, HMAC-SHA512).

## Coding Conventions

- **File Naming:** kebab-case (e.g. `observer-trust-protocol.js`).
- **Class Naming:** PascalCase (e.g. `ObserverTrustProtocol`).
- **Private Members:** prefixed with `_` and explicitly documented with `@private`.
- **Imports:** explicit file extensions are mandatory.
- **Copyright:** all source files include the standard Apache-2.0 header (Observer Protocol, Inc., 2026).

## Documentation (JSDoc)

Source code is strictly typed using JSDoc comments to support `build:types`.

- **Types:** use `@typedef` to define or import types.
- **Methods:** use `@param`, `@returns`, `@throws`.
- **Generics:** use `@template`.

## Development Workflow

1. **Install:** `npm install`
2. **Lint:** `npm run lint`
3. **Test:** `npm test`
4. **Build Types:** `npm run build:types`
5. **Run example:** `npm run example` (registers an agent against the live API — see `examples/full-flow.mjs`)

## Key Files

- `index.js`: main entry point (re-exports).
- `bare.js`: Bare runtime entry.
- `src/trust-protocol.js`: abstract `TrustProtocol` base + `ITrustProtocol` interface (proposed new WDK protocol category).
- `src/observer-trust-protocol.js`: concrete Observer Protocol implementation.
- `src/op-client.js`: thin HTTP wrapper around `api.observerprotocol.org`.
- `src/did-utils.js`: deterministic Ed25519 derivation, multibase encoding, DID document construction, signing/verification.
- `src/config.js`: defaults (API base, derivation path, timeouts).
- `tests/`: jest smoke tests.
- `examples/full-flow.mjs`: runnable end-to-end demonstration.

## Repository Specifics

- **Domain:** agent identity and trust for the agentic economy.
- **Key Technology:** W3C `did:web` + Verifiable Credentials, Ed25519 signatures, Bitstring Status List v1.0 (revocation), ERC-8004 (chain anchoring).
- **Strategic positioning:** trust is proposed as a new WDK protocol category. See README §"Where this fits in WDK's architecture".
- **Compatibility:** v0.1 binds to `@tetherto/wdk-wallet-evm`. Future bindings (TRON, Solana, Lightning) will extend the same abstract base.
