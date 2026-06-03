// Copyright 2026 Observer Protocol, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

'use strict'

/**
 * The set of `credentialSchema.id` URLs this adapter recognises for the
 * AIP v0.8 mandate surface.
 *
 * Per the Observer Protocol schema immutability policy, every schema change
 * mints a new URL; old URLs serve their published bytes forever. This adapter
 * implements AIP v0.8 spending semantics (snake_case actionScope,
 * per_transaction_ceiling flat shape, cumulative_budget with window enum,
 * closed additionalProperties); it accepts only credentials whose
 * `credentialSchema.id` matches a URL in this allowlist.
 *
 * `https://observerprotocol.org/schemas/delegation/v2.json` is deliberately
 * EXCLUDED. Reason: v2.json uses the older `cumulative_ceiling` / `period`
 * vocabulary that does NOT match this adapter's logic. Accepting v2.json
 * credentials would mean either misinterpreting their fields or silently
 * skipping logic — both wrong. v0.7-era credentials (e.g. the maxi-0001
 * trading demo) are validated by tooling pinned to v2.json elsewhere.
 *
 * Future schema versions extend this set via append; the adapter is not
 * rewritten on every bump.
 *
 * @type {ReadonlyArray<string>}
 */
export const SCHEMA_ALLOWLIST = Object.freeze([
  'https://observerprotocol.org/schemas/delegation/v2.1.json'
])

/**
 * Check whether a credential's `credentialSchema.id` is in the recognised
 * allowlist. Returns `true` if recognised, `false` otherwise.
 *
 * @param {string | undefined | null} schemaId
 * @param {ReadonlyArray<string>} [allowlist] Optional override (e.g. for tests
 *   or for clients that want to expand the recognised set).
 * @returns {boolean}
 */
export function isAllowedSchema (schemaId, allowlist = SCHEMA_ALLOWLIST) {
  if (typeof schemaId !== 'string' || schemaId.length === 0) return false
  return allowlist.includes(schemaId)
}
