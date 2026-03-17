# Deliverables Build Guide

## Directory Structure

```
deliverables/
  report/
    report.tex          # LaTeX source (main document)
    references.bib      # BibTeX bibliography
  slides/
    slides.md           # Marp Markdown slide deck
  figures/
    pipeline.tex        # Pipeline architecture diagram (standalone TikZ)
    f1_comparison.tex   # F1 score bar chart (standalone pgfplots)
    tpr_fpr_tradeoff.tex # TPR vs FPR scatter plot (standalone pgfplots)
    rejection_reasons.tex # Rejection breakdown chart (standalone pgfplots)
    specificity_comparison.tex # Specificity bar chart (standalone pgfplots)
  BUILD.md              # This file
```

## Building the Report (LaTeX)

### Prerequisites
- TeX Live 2023+ or equivalent (pdflatex, bibtex)
- or `tectonic` (verified locally)
- Required packages: `booktabs`, `hyperref`, `cleveref`, `pgfplots`, `tikz`,
  `geometry`, `graphicx`, `xcolor`, `amsmath`, `natbib` or `biblatex`

### Compile Steps

```bash
cd deliverables/report
pdflatex report.tex
bibtex report
pdflatex report.tex
pdflatex report.tex
```

This produces `report.pdf`.

### Quick Build (latexmk)

```bash
cd deliverables/report
latexmk -pdf report.tex
```

### Verified Local Build (tectonic)

```bash
cd deliverables/report
tectonic report.tex
```

This is the build path verified in the local workspace.

### Docker Alternative (if no local TeX)

```bash
docker run --rm -v "$(pwd)/deliverables/report:/data" texlive/texlive:latest \
  bash -c "cd /data && pdflatex report.tex && bibtex report && pdflatex report.tex && pdflatex report.tex"
```

## Building the Slides (Marp)

### Prerequisites
- Node.js 18+ and npm, OR
- Marp CLI: `npm install -g @marp-team/marp-cli`

### Export to PDF

```bash
cd deliverables/slides
marp slides.md --pdf --allow-local-files
```

This produces `slides.pdf`.

### Export to PPTX

```bash
marp slides.md --pptx --allow-local-files
```

### Export to HTML

```bash
marp slides.md --html --allow-local-files
```

### Preview (live reload)

```bash
marp -s slides.md
```

Opens a browser at `http://localhost:8080`.

### Docker Alternative

```bash
docker run --rm -v "$(pwd)/deliverables/slides:/home/marp/app" \
  marpteam/marp-cli slides.md --pdf --allow-local-files
```

## Building Standalone Figures

Each figure in `figures/` is a standalone LaTeX document that compiles independently.

```bash
cd deliverables/figures
for f in *.tex; do pdflatex "$f"; done
```

This produces individual PDF files:
- `pipeline.pdf`
- `f1_comparison.pdf`
- `tpr_fpr_tradeoff.pdf`
- `rejection_reasons.pdf`
- `specificity_comparison.pdf`

These can be used as standalone graphics or included in external documents.

The report already includes equivalent figures inline (using TikZ/pgfplots directly),
so building these standalone files is optional.

## Data Sources

All metrics in the report and slides are sourced from:

```
artifacts/final_motif_audit/
  primary_summary.json
  replay_summary.json
  comparison_summary.json
  comparison_rows.csv
  significance_vs_primary.json
  failure_analysis.json
  run_manifest.json
```

No numbers were invented or estimated. Every metric traces to these saved artifacts.

## Verification

To verify that report numbers match saved artifacts:

```bash
# Check primary mean F1
python3 -c "
import json
with open('artifacts/final_motif_audit/primary_summary.json') as f:
    d = json.load(f)
print(f'mean_f1 = {d[\"mean_f1\"]}')
print(f'mean_tpr_target = {d[\"mean_tpr_target\"]}')
print(f'mean_fpr_benign = {d[\"mean_fpr_benign\"]}')
print(f'mean_rule_specificity = {d[\"mean_rule_specificity\"]}')
print(f'families_ok = {d[\"families_ok\"]} / {d[\"families_total\"]}')
"
```

## Submission Checklist

- [ ] `report.pdf` compiled without errors
- [ ] `slides.pdf` exported cleanly
- [ ] All tables match saved artifact numbers
- [ ] No overclaims (check for "significantly better" vs topstrings)
- [ ] 128/138 coverage gap is visible in both report and slides
- [ ] YAMME/PackGenome appear only in Related Work
- [ ] Replay described as a check on saved outputs, not as exact equality
