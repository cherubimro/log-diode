#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# build + proof (this project's units) + core sanity + syslog loopback.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/env.sh"
cd "$here/.."

echo "=== build ==="; ./tools/build.sh >/dev/null 2>&1; echo ok

echo "=== SPARK proof (expect 0 unproved) ==="
./tools/prove.sh >/dev/null 2>&1
if grep -qE '(medium|high|low):' obj/gnatprove/gnatprove.out 2>/dev/null; then
    echo "UNPROVED checks remain:"; grep -E '(medium|high|low):' obj/gnatprove/gnatprove.out; exit 1
fi
grep -E '^Total' obj/gnatprove/gnatprove.out | tail -1

echo "=== core sanity ==="; ./bin/test_core

echo "=== syslog loopback (amp -> diode -> deamp) ==="
./tools/loopback-test.sh >/dev/null 2>&1 && echo "ok" || { echo FAIL; exit 1; }

# prove.sh wiped the SPARKNaCl objects to scope itself; leave the tree buildable.
./tools/build.sh >/dev/null 2>&1 || true
echo "=== all green ==="
