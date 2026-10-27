# SLIC-J — Seven Sins Revisited

Course project, **Cloud SRE and Security** — Adheil Gupta (23BDS002), Om Pandey (23BDS040).

Selected paper: A. Rahman, C. Parnin, L. Williams, *The Seven Sins: Security Smells in Infrastructure as Code Scripts*, ICSE 2019 (`inputs/icse19_slic.pdf`).

This repository:

1. **Reimplements SLIC** in Python in two forms: the rules as printed in the paper (Tables II/III), and a token-level port of the released Ruby code (`all_in_one.rb`). The port matches the original tool on 120 of 120 findings.
2. **Ports SLIC to Ansible and Chef** (`SLIC-J`) and adds a new smell: **TLS verification disabled** (CWE-295).
3. **Adds context-aware triage.** Code computes context facts and masks secrets. A decision model (TypeSafe **Jev**, through OpenRouter) answers one typed question per finding. Code makes the final keep/drop decision.
4. **Evaluates** all of this on the GLITCH oracle datasets (RQ1–RQ3), on 206k scripts (RQ2), and against prompt-injection comments (RQ4).

The research paper is `paper/main.pdf` (LaTeX source `paper/main.tex`).

## Headline results

| | Result |
|---|---|
| RQ1 | A reimplementation from the paper alone matches the original SLIC on 58% of findings (Jaccard). The code port matches it at 0.99. We list six differences between the paper and the code, including one check whose output never reaches the report. |
| RQ2 | SLIC-J micro-F1 is 0.64 / 0.82 / 0.63 (Puppet / Ansible / Chef). GLITCH v2 scores 0.62 / 0.86 / 0.54. The new TLS smell is in 1.01% of 107,955 Ansible scripts, with 59/60 sampled findings correct. |
| RQ3 | Jev triage moves precision from 0.561 to 0.782 and recall from 0.858 to 0.812 (F1 0.679 → 0.797, McNemar p = 2e-15). For hard-coded secrets, false alarms drop from 80 to 4. Claude Haiku 5.5 reaches F1 0.811 (difference not significant) at 4× the cost and 3× the latency. |
| RQ4 | One injected comment flips 97.5% of a decision model's true findings to "safe". A chat LLM ignores the injection, but a "dummy value" comment flips up to 20% of its true findings. Removing comments from the model input brings every attack down to ≤ 1.6%. |

## Layout

```
slicj/                    the tool
  parsers/puppet.py       token-level Puppet lexer -> SLIC tokens
  parsers/ansible.py      ruamel.yaml walker (+ line-based fallback)
  parsers/chef.py         line-level Chef reader
  rules.py                rule sets: paper | code | slicj (+ TLS smell)
  slic_original.py        faithful port of the released all_in_one.rb (RQ1)
  context.py              context facts, placeholder/entropy/key-format checks, masking
  triage.py               state builder + Jev / chat-LLM / Claude-CLI backends (disk cache)
  evaluate.py             GLITCH matching protocol, precision/recall
  cli.py                  python -m slicj scan DIR
experiments/              one script per research question + analysis.py (tables/figures)
tests/                    pytest, incl. the paper's Fig. 4 / Fig. 5 examples
results/                  all outputs; results/cache holds every model request/response
paper/                    LaTeX paper, generated tables and figures, compiled PDF
inputs/                   the selected paper, the reference deck, the earlier planning chat
data/, tools/, .venv/     downloaded datasets and tools (git-ignored, re-creatable)
```

## Use the linter

```bash
.venv/bin/python -m slicj scan path/to/repo --rules slicj --out report.csv
# report.csv: per-script counts (SLIC format); report_lines.csv: one row per finding with line number
```

## Reproduce everything

All downloads stay inside this folder.

```bash
# 1. environment
export UV_CACHE_DIR=$PWD/.cache/uv
uv venv --python python3 .venv && uv pip install --python .venv/bin/python -r requirements.txt

# 2. data: GLITCH replication package (1.8 GB docker image tar, MD5 d9de60550dc558ad227ab14ceef64654)
mkdir -p data/downloads/glitch_pkg
curl -L -o data/downloads/glitch_pkg/glitch-latest.tar https://ndownloader.figshare.com/files/36939973
.venv/bin/python -I experiments/extract_glitch.py data/downloads/glitch_pkg/glitch-latest.tar data/glitch_rootfs

# 3. baselines (optional: their outputs are already in results/baselines)
#    original SLIC: gem install --install-dir tools/gems puppet-lint -v 2.5.2
.venv/bin/python experiments/run_original_slic.py data/glitch_rootfs/RESULTS/puppet/oracle-dataset results/baselines/slic_original_rerun_puppet.csv
#    GLITCH v2: see tools/GLITCH (uv venv tools/glitch-venv, plus librego from the GLITCH release)

# 4. experiments
.venv/bin/python -m pytest -q tests
.venv/bin/python experiments/rq1_detection.py          # RQ1 + RQ2 accuracy
.venv/bin/python experiments/rq2_prevalence.py puppet chef ansible
.venv/bin/python experiments/rq2_tls_sample.py         # TLS precision sample (labels in results/rq2/tls_sample.csv)
# RQ3 model scores; cached responses make these free to re-run (OPENROUTER_API_KEY in .env for new calls)
.venv/bin/python experiments/score_models.py jev-full --backend jev --model typesafe/jev-1.13 --variant full
.venv/bin/python experiments/rq3_triage.py --with jev-line jev-full jev-full_nocomments <other score names>
.venv/bin/python experiments/rq4_adversarial.py jev inception/mercury-decide:free free-mercury 0 4 full_strict
.venv/bin/python experiments/analysis.py               # tables, figures, statistics -> paper/
cd paper && ../tools/tectonic -X compile main.tex
```

To run RQ4 on Jev itself (it needs OpenRouter credits):

```bash
.venv/bin/python experiments/score_models.py jev-full_strict --backend jev --model typesafe/jev-1.13 --variant full_strict
.venv/bin/python experiments/rq4_adversarial.py jev typesafe/jev-1.13 jev 0 8 full_strict
```

## Notes and limits

- The OpenRouter key is in `.env` (git-ignored). Its credit limit is $2, and it expires on 2026-11-25. RQ3 used about $0.20. The account's free allowance then ran out. That is why RQ4 uses a free decision model and the Claude Code CLI instead of Jev.
- TLS precision was judged by one rater. Have a second team member fill in a `label_rater2` column in `results/rq2/tls_sample.csv`, then report Cohen's κ.
- The paper's author block has no institute name yet (`paper/main.tex`, line with `TODO`).
