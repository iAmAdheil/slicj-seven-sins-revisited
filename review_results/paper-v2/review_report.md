# Paper audit: SLIC-J (v1 → v2)

- Paper: `paper/main.tex` (v2 on branch `paper-v2`). The v1 PDF is `review_results/paper-v2/main_v1.pdf`. The v1 source is at commit `5453ff1`.
- Mode: `quick-audit` script run + reviewer pass. Execution: **sequential single-agent** (one agent read the paper in turn as editor, methods, claims-vs-evidence and logic reviewer). This is not an independent panel.
- `[Script]` = found by `paper-audit/scripts/audit.py` in this session. `[LLM]` = found by reading the paper and checking it against `results/`.

## 1. Script findings

| Finding | v1 | v2 | Note |
|---|---|---|---|
| [Script] "Undefined reference" for every table label | 6 | 9 | False alarm. The labels are in `\input{tables/...}` files that the checker does not read. The compiled log has no undefined reference. |
| [Script] Placeholder text (`TODO` on line 20, author block) | open | **open** | Needs your department and institute. |
| [Script] `fig:pipeline` never cited | open | fixed | Cited in the Approach section. |
| [Script] Long paragraph: abstract (303 words) | open | fixed | Abstract is now about 250 words. |
| [Script] Long paragraph: v1 RQ1 results (337 words) | open | fixed | Section removed (item 2). |
| [Script] Long paragraph at line 122 | - | false alarm | This is the TikZ diagram, not prose. |
| [Script] Undefined acronyms (SRE, XML, ...) | open | partly fixed | SRE is defined. USD, LOC, IP are standard. |

## 2. Reviewer findings in v1 (fixed in v2)

| # | Severity | Finding | Evidence | Fix |
|---|---|---|---|---|
| 1 | major | Portability claim relied on all-file F1, which includes the files used to tune the rules. | v1 abstract: "0.64/0.82/0.63 ... against 0.62/0.86/0.54 for GLITCH". On the 70% test split SLIC-J leads only on Chef (`results/rq1/detection.json`). | New Table II reports both splits. Text and abstract say GLITCH v2 leads on Puppet and Ansible. |
| 2 | major | Triage table caption names a Brier column that does not exist. | `tables/rq3.tex` caption: "AUC, Brier and ECE use the raw scores". | Removed "Brier" from caption and setup. |
| 3 | major | The hybrid's "best ranking, calibration and precision" claim cannot move to Jev. | Jev AUC 0.808 < Liquid d1-ultra / Perplexity 0.865. Jev precision 0.782 < Liquid 0.813. | Hybrid removed (item 11). No replacement claim is made. |
| 4 | moderate | Robustness caption gave one Mercury-Decide threshold (0.05). The "removed" state uses 0.02. | `results/stats.json` → `rq4.free-mercury.threshold_removed = 0.0159`. | Caption gives both thresholds. |
| 5 | moderate | Precision/recall figure drew the Haiku CLI point in the "Rules" colour. | `analysis.py` coloured only names that start with `llm`. | `claudecli` now uses the chat-LLM colour. |
| 6 | moderate | Hard-coded section reference "Section V-C" breaks when sections move. | v1 line 361. | Replaced with `\ref`. |
| 7 | moderate | Corpus share: v1 states the cause of the lower share as fact, without a test. | "our rules no longer count variable references" | Now "A likely reason". |
| 8 | moderate | "80 → 4 false secret alarms" comes from one CV seed but read as a general result. | `tables/rq3_smell.tex` caption: "last CV seed". | Abstract and conclusion say "in one cross-validation run". |
| 9 | minor | Robustness table: `n` (attacked findings) differs from the flip-rate denominator (kept findings). | Haiku n=59, rates over 55. | Caption defines `n`. Text gives "of 55" and "of 122". |
| 10 | minor | Two bib entries never cited. | `sharma2016config`, `greshake2023injection`. | Both now cited (Introduction, Robustness method). |
| 11 | minor | Slogans and course-brief text read as filler. | "Rules propose, a model disposes, and code stays in charge"; "This paper is a course project with the brief ...". | Removed. |
| 12 | minor | Calibration text depended on the reliability diagram. | v1 lines 309-314. | Short calibration note now cites the ECE and F1@0.5 columns (Haiku F1@0.5 = 0.644, below the rules). |

## 3. Open issues in v2 (not fixed)

1. **[Script] Author block TODO.** Add department and institute (`paper/main.tex`, line 20).
2. **[LLM] Unchecked number.** "the mean probability for true findings drops from 0.80 to 0.02" (Robustness results) comes from v1. This session did not recompute it.
3. **[LLM] Candidate set includes tuning files.** The triage evaluation uses all 269 candidates, including the 30% tuning files. The paper states this in Threats (Internal). A test-split-only triage table would remove the doubt.
4. **[LLM] Small oracles.** 176 smells in total, and fewer than 10 for weak crypto and empty password. Stated in Threats.
5. **[LLM] TLS precision has one rater.** Stated in Threats. A second rater and Cohen's κ would close it.
6. **[LLM] Robustness not tested on Jev.** Stated in Threats (External).
7. **Slides still use the old framing** in places (see section 5).

## 4. Change list status

| Item | Status | Where |
|---|---|---|
| 1 Independent study, new title | done | Title, abstract, introduction. SLIC appears only where needed. |
| 2 Code version is the study; short note with Jaccard and metrics | done | Reproduction → "Note on versions" + Table I (`tables/repro.tex`). The six differences are removed. |
| 3 Full-pipeline diagram in Approach | done | Fig. 1 (TikZ), replaces the old text box. |
| 4 Topic names instead of RQ1-RQ4 | done | Paper, table captions, slides, speaker script, README. |
| 5 Related-studies paragraph (GLITCH, SLAC) in the introduction | done | Introduction ¶3. GASEL, Opdebeeck and IntelliSA stay in Related Work. |
| 6 SLIC-J rule set with 30/70 split + table | done | Portability → Method + Table II (`tables/split.tex`). |
| 7 Short text after each figure and table | done (paper only) | "Reading:" note under each table. Figure captions state what the figure shows. |
| 8 Remove secret-precision figure | done | Figure and generator removed. Text rewritten. |
| 9 Portability Part A / Part B | done | Sec. VI-B (oracles), VI-C (corpora). |
| 10 PR figure in Triage | done | `placeins` keeps it in Sec. VII. |
| 11 Remove hybrid and LogReg | done | `analysis.py`, tables, figure, text, statistics, slides. |
| 12 One SLIC-J row per technology in the per-smell table | done | Also removed the duplicate "SLIC (original, re-run)" row. |
| 13 Remove reliability diagram | done | Short calibration note kept. |
| 14 Flip-rate table in Robustness | done | Table VII in Sec. VIII. |
| 15 Method + results per topic | done | Sections V-VIII. Overview (III) and shared setup (IV) come first. |

## 5. Slides: content that still follows v1

The deck was rebuilt for items 4 and 11 only. These slides still use the v1 framing:

- Slide 4 and slide 6: "Can we rebuild SLIC from the paper?" and the paper-rules result.
- Slide 7: the six paper-code differences (item 2 removes these from the paper).
- Slide 8: the all-files F1 comparison only. No test-split numbers.
- Footer and title: "Seven Sins Revisited" (the paper title changed).
