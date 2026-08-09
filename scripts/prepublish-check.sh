#!/usr/bin/env bash
# Pack this package and install the tarball into a throwaway project.
#
# WHY THIS EXISTS. 0.2.0-beta.3 was published with the peer range ">=0.1.0,<0.3".
# npm semver joins comparators with a SPACE; a comma makes the range unparseable, so
# npm treats it as a dist-tag and aborts with EINVALIDTAGNAME before fetching anything.
# The package was therefore uninstallable by the exact command observerprotocol.org
# printed for it, and it stayed that way because nothing ran between `npm version` and
# `npm publish`. There is no CI in this repository and there was no prepublish hook.
#
# This is that missing step. It is deliberately an INSTALL and not a lint: a manifest
# can be valid JSON, pass every schema check, and still be unresolvable. The only thing
# that proves a package installs is installing it.
#
# It discriminates, which is the property that matters: run against beta.3 it fails with
# EINVALIDTAGNAME, run against beta.4 it succeeds. A check that cannot fail is not a check.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP" "$ROOT"/observer-protocol-*-*.tgz; }
trap cleanup EXIT

echo "prepublish: packing $(node -p "require('$ROOT/package.json').name")@$(node -p "require('$ROOT/package.json').version")"
TARBALL="$(npm pack --silent | tail -1)"
[ -f "$ROOT/$TARBALL" ] || { echo "prepublish: FAILED — npm pack produced no tarball"; exit 1; }

echo "prepublish: installing $TARBALL into a clean project"
cd "$TMP"
npm init -y >/dev/null 2>&1

if npm install "$ROOT/$TARBALL" --no-audit --no-fund >"$TMP/install.log" 2>&1; then
  echo "prepublish: OK — the tarball installs clean"
else
  echo "prepublish: FAILED — this package would be published uninstallable"
  echo
  sed 's/^/    /' "$TMP/install.log" | head -20
  echo
  echo "    Publishing is irreversible: the version number is burned whether or not it works."
  exit 1
fi
