# SLIC-J — Seven Sins Revisited

Course project, **Cloud SRE and Security** — Adheil Gupta (23BDS002), Om Pandey (23BDS040).

Selected paper: A. Rahman, C. Parnin, L. Williams, *The Seven Sins: Security Smells in Infrastructure as Code Scripts*, ICSE 2019.

This repository:

1. **Ports SLIC to Python.** The port follows the released Ruby code (`all_in_one.rb`) token by token. It matches the original tool on 120 of 120 findings.
2. **Extends the port to Ansible and Chef** (`SLIC-J`) and adds a new smell: **TLS verification disabled** (CWE-295). The rules were tuned on a fixed 30% of the oracle files and tested on the other 70%.
3. **Adds context-aware triage.** Code computes context facts and masks secrets. A decision model (TypeSafe **Jev**, through OpenRouter) answers one typed question per finding. Code makes the final keep/drop decision.
4. **Evaluates** all of this in four topics: Reproduction, Portability (GLITCH oracles and 206k scripts), Triage, and Robustness (prompt-injection comments).

The research paper is `paper/main.pdf` (LaTeX source `paper/main.tex`). The two-person talk is `presentation/Seven_Sins_Revisited_Presentation.pptx`, with `presentation/speaker_script.md`.

## Headline results

| | Result |
|---|---|
| Reproduction | The code port matches the original SLIC at Jaccard 0.99 (120 of 120 findings, 1 extra). An earlier rebuild from the rules printed in the paper matched at 0.58. The study follows the code. |
| Portability | SLIC-J micro-F1 on the 70% test split is 0.59 / 0.67 / 0.56 (Puppet / Ansible / Chef). GLITCH v2 scores 0.65 / 0.74 / 0.50. On all files (including the 30% tuning split): 0.64 / 0.82 / 0.63 against 0.62 / 0.86 / 0.54. The new TLS smell is in 1.01% of 107,955 Ansible scripts, with 59/60 sampled findings correct. |
| Triage | Jev triage moves precision from 0.561 to 0.782 and recall from 0.858 to 0.812 (F1 0.679 → 0.797, McNemar p = 2e-15). For hard-coded secrets, false alarms drop from 80 to 4. Claude Haiku 5.5 reaches F1 0.811 (difference not significant) at 4× the cost and 3× the latency. |
| Robustness | One injected comment flips 97.5% of a decision model's true findings to "safe". A chat LLM ignores the injection, but a "dummy value" comment flips up to 20% of its true findings. Removing comments from the model input brings every attack down to ≤ 1.6% at each model's tuned threshold (rates are higher at a fixed 0.5, see the paper). |

## Layout

```
slicj/                    the tool
  parsers/puppet.py       token-level Puppet lexer -> SLIC tokens
  parsers/ansible.py      ruamel.yaml walker (+ line-based fallback)
  parsers/chef.py         line-level Chef reader
  rules.py                rule sets: paper | code | slicj (+ TLS smell)
  slic_original.py        faithful port of the released all_in_one.rb (Reproduction)
  context.py              context facts, placeholder/entropy/key-format checks, masking
  triage.py               state builder + Jev / chat-LLM / Claude-CLI backends (disk cache)
  evaluate.py             GLITCH matching protocol, precision/recall
  cli.py                  python -m slicj scan DIR
experiments/              one script per topic + analysis.py (tables/figures)
tests/                    pytest, incl. the paper's Fig. 4 / Fig. 5 examples
results/                  all outputs; results/cache holds every model request/response
paper/                    LaTeX paper, generated tables and figures, compiled PDF
presentation/             slide deck, speaker script, deck generator
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
.venv/bin/python experiments/rq1_detection.py          # Reproduction + Portability accuracy
.venv/bin/python experiments/rq2_prevalence.py puppet chef ansible
.venv/bin/python experiments/rq2_tls_sample.py         # TLS precision sample (labels in results/rq2/tls_sample.csv)
# Triage model scores; cached responses make these free to re-run (OPENROUTER_API_KEY in .env for new calls)
.venv/bin/python experiments/score_models.py jev-full --backend jev --model typesafe/jev-1.13 --variant full
.venv/bin/python experiments/rq3_triage.py --with jev-line jev-full jev-full_nocomments <other score names>
.venv/bin/python experiments/rq4_adversarial.py jev inception/mercury-decide:free free-mercury 0 4 full_strict
.venv/bin/python experiments/analysis.py               # tables, figures, statistics -> paper/
cd paper && ../tools/tectonic -X compile main.tex
```

To run the robustness test on Jev itself (it needs OpenRouter credits):

```bash
.venv/bin/python experiments/score_models.py jev-full_strict --backend jev --model typesafe/jev-1.13 --variant full_strict
.venv/bin/python experiments/rq4_adversarial.py jev typesafe/jev-1.13 jev 0 8 full_strict
```

## Notes and limits

- The OpenRouter key is in `.env` (git-ignored). Its credit limit is $2, and it expires on 2026-11-25. The triage experiments used about $0.20. The account's free allowance then ran out. That is why the robustness test uses a free decision model and the Claude Code CLI instead of Jev.
- TLS precision was judged by one rater. Have a second team member fill in a `label_rater2` column in `results/rq2/tls_sample.csv`, then report Cohen's κ.
- The paper's author block has no institute name yet (`paper/main.tex`, line with `TODO`).
