#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/env.sh"
cd "$here/.."
if [ ! -e deps/sparknacl/lib/libSparknacl.a ]; then
    SPARKNACL_EXTERNAL=False gprbuild -q -P deps/sparknacl/sparknacl.gpr
fi
exec gprbuild -P log_diode.gpr "$@"
