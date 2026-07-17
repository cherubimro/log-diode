#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# gnatprove over log-diode's own units.  Expect: 0 unproved, 0 justified.
# The RS codec + relay + secure are vendored already-proven from opc-diode; the
# NEW proven units here are the syslog PRI parser and the batch framing.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/env.sh"
cd "$here/.."
rm -rf obj
UNITS=( syslog.adb log_batch.adb secure.adb )
U_ARGS=(); for u in "${UNITS[@]}"; do U_ARGS+=(-u "$u"); done
exec gnatprove -P log_diode.gpr "${U_ARGS[@]}" \
     -j1 --level=2 --steps=25000 --no-subprojects --report=all "$@"
