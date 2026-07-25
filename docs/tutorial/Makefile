# SPDX-License-Identifier: AGPL-3.0-or-later
# Build the log-diode tutorial PDFs.  Needs pdflatex + latexmk (TeX Live),
# with tikz, tcolorbox, listings, booktabs, microtype -- all in
# texlive-collection-latexrecommended.
#
#   make            both PDFs
#   make quickstart just the quick start
#   make handbook   just the handbook
#   make clean      remove LaTeX intermediates (keeps the PDFs)
#   make distclean  remove intermediates and PDFs

LATEXMK ?= latexmk
LATEXMKFLAGS ?= -pdf -interaction=nonstopmode -halt-on-error -file-line-error

DOCS := diode-quickstart data-diode-handbook
PDFS := $(addsuffix .pdf,$(DOCS))

.PHONY: all quickstart handbook clean distclean watch

all: $(PDFS)

quickstart: diode-quickstart.pdf
handbook:   data-diode-handbook.pdf

# Both documents share common.tex, so either rebuilds when it changes.
%.pdf: %.tex common.tex
	$(LATEXMK) $(LATEXMKFLAGS) $<

# Continuous rebuild while editing:  make watch DOC=data-diode-handbook
DOC ?= data-diode-handbook
watch:
	$(LATEXMK) $(LATEXMKFLAGS) -pvc $(DOC).tex

clean:
	$(LATEXMK) -c $(addsuffix .tex,$(DOCS)) 2>/dev/null || true
	rm -f *.aux *.log *.out *.toc *.fls *.fdb_latexmk *.synctex.gz

distclean: clean
	rm -f $(PDFS)
