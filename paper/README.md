# IEEE review paper — source files

**Title:** Explainable and Risk-Aware Intrusion Detection Systems: A Review of Machine Learning,
Behavioural Detection, and Human-in-the-Loop Response

| Path | Contents |
|---|---|
| `main.tex` | Full paper (IEEEtran `conference` class), tables, equations, TikZ diagrams (Figs. 4–6) |
| `references.bib` | 39 verified BibTeX records (all cited, none missing) |
| `figures/` | Data graphs (Figs. 1–3) as vector PDFs |
| `data/` | CSV data behind Figs. 1–3; each file's header cites the exact source table |
| `scripts/make_figures.py` | Regenerates `figures/*.pdf` from `data/*.csv` (Python + Matplotlib) |
| `scripts/check_paper.py` | Checks citations ↔ bibliography, labels ↔ refs, figure files, word count |

## Before submission

1. Check the author block (five authors, Sharda University); Mayank Kumar Goyal's e-mail was completed as `mayank.goyal2@sharda.ac.in`.
2. Compile and confirm the PDF is **6–8 pages** (estimated ~7; not yet verified by compilation).
3. Check the reference list against the original papers once more.

## Compiling

`main.tex` is self-contained: the graphs are drawn with pgfplots inside the file and the
reference list is embedded (`thebibliography`), so no figure files and no BibTeX run are needed.

**Overleaf (easiest):** create a blank project, upload only `main.tex`, set the compiler to
pdfLaTeX, and compile. IEEEtran, TikZ and pgfplots are preinstalled.

If you edit `references.bib`, run `python scripts/build_bibliography.py` to regenerate the
embedded reference list. `figures/*.pdf` are standalone copies of the graphs (e.g., for slides).

**Locally (TeX Live or MiKTeX):**

```bash
pdflatex main
bibtex main
pdflatex main
pdflatex main
```

**Regenerate graphs:** `python scripts/make_figures.py` (needs matplotlib).

## How numbers were sourced

- Fig. 2 and the per-class F1 in Fig. 3: Sarhan, Layeghy & Portmann, Tables 8 and 9 (read from arXiv:2101.11315v2).
- UNSW-NB15 record counts (Fig. 3, Table III): Moustafa & Slay, MilCIS 2015, Table VIII.
- KDD Cup 99 duplicates (78% / 75%): Tavallaee et al., CISDA 2009, Tables I–II.
- Shone et al. accuracies (97.85%, 85.42%, 89.22%): the paper's results section.
- Fig. 1: publication years of the 39 included references (`data/fig1_included_studies.csv`).

DOIs or page ranges that could not be confirmed were left out rather than guessed. Preprints
(Xu et al. 2024, CyLens 2025) are labelled as preprints.
