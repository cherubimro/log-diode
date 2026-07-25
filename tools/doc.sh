#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build the tutorial PDFs under docs/tutorial/.
#
#   ./tools/doc.sh              both documents
#   ./tools/doc.sh quickstart   just the quick start
#   ./tools/doc.sh handbook     just the handbook
#   ./tools/doc.sh clean        remove LaTeX intermediates
#
# Unlike the other tools/ scripts this does NOT need the GNAT toolchain --
# only pdflatex + latexmk.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/../docs/tutorial"

for prog in pdflatex latexmk; do
    command -v "$prog" >/dev/null 2>&1 || {
        echo "tools/doc.sh: $prog not found -- install TeX Live" >&2
        echo "  openSUSE: zypper in texlive-latexmk texlive-collection-latexrecommended" >&2
        echo "  Debian:   apt install latexmk texlive-latex-recommended texlive-pictures" >&2
        exit 1
    }
done

make "${@:-all}"

if [ "${1:-all}" != "clean" ] && [ "${1:-all}" != "distclean" ]; then
    echo
    echo "built:"
    for f in *.pdf; do
        [ -e "$f" ] && printf '  %s  (%s pages)\n' \
            "docs/tutorial/$f" "$(pdfinfo "$f" 2>/dev/null | awk '/^Pages/{print $2}')"
    done
fi
