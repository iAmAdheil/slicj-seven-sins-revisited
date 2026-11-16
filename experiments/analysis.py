"""Tables, figures and statistics for the paper.

Inputs:  results/rq1/detection.json, results/rq2/prevalence_*.json, results/rq2/tls_sample.csv,
         results/rq3/summary.json, results/rq3/decisions.json, results/rq3/candidates.jsonl,
         results/rq4_*.json, results/cache/** (cost and latency)
Outputs: paper/tables/*.tex, paper/figures/*.pdf, results/stats.json
"""
from __future__ import annotations

import csv
import glob
import json
import os
import sys
from collections import defaultdict

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from experiments.common import ROOT  # noqa
from slicj.rules import LABEL, SEVEN  # noqa

import matplotlib  # noqa
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa

TAB = ROOT / "paper" / "tables"
FIG = ROOT / "paper" / "figures"
TAB.mkdir(parents=True, exist_ok=True)
FIG.mkdir(parents=True, exist_ok=True)
R = ROOT / "results"

# validated categorical palette (dataviz reference palette, slots 1-4, light mode)
BLUE, ORANGE = "#2a78d6", "#eb6834"
INK, INK2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.edgecolor": INK2, "axes.labelcolor": INK,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
                     "axes.axisbelow": True, "legend.frameon": False, "pdf.fonttype": 42})

NICE = {
    "rules": "SLIC-J rules only", "context-filter": "Practitioner-context filter",
    "jev-line": "Jev 1.13, line only", "jev-full": "Jev 1.13, full context", "jev-full_nocomments": "Jev 1.13, full, no comments",
    "dm-typesafe_jev-1.14": "Jev 1.14, full context", "dm-openai_gpt-6-luna-decisions": "GPT-6 Luna Decisions",
    "dm-liquid_d1-ultra": "Liquid d1-ultra", "dm-perplexity_pplx-decider-v1.2": "Perplexity Decider v1.2",
    "dm-inception_mercury-decide": "Inception Mercury-Decide", "dm-cloudflare_clef": "Cloudflare Clef",
    "dm-microsoft_microsoft-decision-1": "Microsoft Decision-1", "dm-upstage_solar-decide": "Upstage Solar-Decide",
    "llm-anthropic_claude-haiku-5.5": "Claude Haiku 5.5 (chat LLM)", "claudecli-full": "Claude Haiku 5.5 via CLI (robustness arm)", "free-mercury-full": "Mercury-Decide (free tier)",
}
CACHE_DIR = {
    "jev-line": ("decisions", "typesafe_jev-1.13"), "jev-full": ("decisions", "typesafe_jev-1.13"),
    "dm-typesafe_jev-1.14": ("decisions", "typesafe_jev-1.14"),
    "dm-openai_gpt-6-luna-decisions": ("decisions", "openai_gpt-6-luna-decisions"),
    "dm-liquid_d1-ultra": ("decisions", "liquid_d1-ultra"),
    "dm-perplexity_pplx-decider-v1.2": ("decisions", "perplexity_pplx-decider-v1.2"),
    "dm-inception_mercury-decide": ("decisions", "inception_mercury-decide"),
    "dm-cloudflare_clef": ("decisions", "cloudflare_clef"),
    "dm-microsoft_microsoft-decision-1": ("decisions", "microsoft_microsoft-decision-1"),
    "dm-upstage_solar-decide": ("decisions", "upstage_solar-decide"),
    "llm-anthropic_claude-haiku-5.5": ("chat", "anthropic_claude-haiku-5.5"),
}


def note(text, width=r"\linewidth"):
    """Short reading note printed under a table, inside the float."""
    return rf"\par\vspace{{3pt}}\parbox{{{width}}}{{\footnotesize\emph{{Reading:}} {text}}}"


def f2(x, nd=2):
    return "--" if x is None else f"{x:.{nd}f}"


# ------------------------------------------------------------------ cost / latency from the cache
def cost_latency(score_name):
    """Cost per 1,000 findings (USD) and median latency (s), from the cached API responses
    that belong to the states of this run."""
    sf = R / "rq3" / f"scores_{score_name}.json"
    if score_name not in CACHE_DIR or not sf.exists():
        return None, None
    kind, d = CACHE_DIR[score_name]
    meta = json.load(open(sf))
    # read every cached response for this model whose request variant matches
    costs, lats = [], []
    for p in glob.glob(str(R / "cache" / kind / d / "*.json")):
        j = json.load(open(p))
        req = j["request"]
        st = req.get("state") if kind == "decisions" else None
        if kind == "decisions":
            is_full = isinstance(st, dict) and "code_window" in st
            want_full = meta["variant"] != "line"
            if "linter_finding" not in (st or {}) or is_full != want_full:
                continue
            if want_full and ("comment_text_untrusted" in st.get("linter_finding", {})) != (meta["variant"] == "full_nocomments"):
                continue
        resp = j["response"]
        c = resp.get("usage", {}).get("cost")
        if c is not None:
            costs.append(float(c))
        if "_latency_s" in resp:
            lats.append(float(resp["_latency_s"]))
    if not costs:
        return None, None
    return 1000 * float(np.mean(costs)), (float(np.median(lats)) if lats else None)


# ------------------------------------------------------------------ Reproduction and Portability tables
BASELINE = {"puppet": "SLIC (original)", "ansible": "SLAC (original)", "chef": "SLAC (original)"}


def table_reproduction(det):
    """Paper rules vs. code port on the Puppet oracle: agreement with the original tool and accuracy."""
    rows = [("Released SLIC code (used)", "ours: SLIC code port"), ("Rules printed in the paper", "ours: paper rules")]
    lines = [r"\begin{table}[t]\centering\caption{Reproduction: two rebuilds of SLIC on the GLITCH Puppet oracle "
             r"(54 marked smells). Jaccard compares each rebuild's findings with the original tool's output.}"
             r"\label{tab:repro}",
             r"\scriptsize\setlength{\tabcolsep}{3pt}\begin{tabular}{lccccccc}\toprule",
             r"Rebuild & Jaccard & TP & FP & Missed & P & R & F1 \\ \midrule"]
    for name, key in rows:
        m = det[f"puppet|all|{key}"]["micro"]
        a = det[f"agreement|{key}|SLIC (original)"]
        lines.append(f"{name} & {a['jaccard']:.2f} & {m['tp']} & {m['fp']} & {m['fn']} & {f2(m['precision'])} & "
                     f"{f2(m['recall'])} & {f2(m['f1'])} \\\\")
    lines.append(r"\bottomrule\end{tabular}")
    lines.append(note("the code rebuild reproduces the tool (Jaccard 0.99). The printed rules give a higher F1 on "
                      "this oracle, but they are a different detector, so the study continues with the code."))
    lines.append(r"\end{table}")
    (TAB / "repro.tex").write_text("\n".join(lines))


def table_split(det):
    """F1 on all oracle files and on the 70% test split that rule tuning never saw."""
    order = [("puppet", BASELINE["puppet"], "Original SLIC"), ("puppet", "GLITCH v2 (live)", "GLITCH v2"),
             ("puppet", "SLIC-J rules", "SLIC-J"),
             ("ansible", BASELINE["ansible"], "Original SLAC"), ("ansible", "GLITCH v2 (live)", "GLITCH v2"),
             ("ansible", "SLIC-J rules", "SLIC-J"),
             ("chef", BASELINE["chef"], "Original SLAC"), ("chef", "GLITCH v2 (live)", "GLITCH v2"),
             ("chef", "SLIC-J rules", "SLIC-J")]
    best = {}
    for tech, key, _ in order:
        for sp in ("all", "test"):
            f = round(det[f"{tech}|{sp}|{key}"]["micro"]["f1"], 2)
            best[(tech, sp)] = max(best.get((tech, sp), 0), f)
    lines = [r"\begin{table}[t]\centering\caption{Portability (A): micro-averaged accuracy of the rules alone, on all "
             r"oracle files and on the 70\% test split. SLIC-J's rules were tuned on the other 30\%.}\label{tab:split}",
             r"\scriptsize\setlength{\tabcolsep}{3pt}\begin{tabular}{llccc}\toprule",
             r"Tech & Tool & F1 (all files) & P / R (test) & F1 (test) \\ \midrule"]
    prev = None
    for tech, key, name in order:
        if prev and tech != prev:
            lines.append(r"\midrule")
        a, t = det[f"{tech}|all|{key}"]["micro"], det[f"{tech}|test|{key}"]["micro"]
        fa, ft = round(a["f1"], 2), round(t["f1"], 2)
        cell = lambda v, sp: rf"\textbf{{{v:.2f}}}" if v == best[(tech, sp)] else f"{v:.2f}"
        lines.append(f"{tech.capitalize() if tech != prev else ''} & {name} & {cell(fa, 'all')} & "
                     f"{f2(t['precision'])} / {f2(t['recall'])} & {cell(ft, 'test')} \\\\")
        prev = tech
    lines.append(r"\bottomrule\end{tabular}")
    lines.append(note("bold marks the best F1 per technology. On the test files, GLITCH v2 leads on Puppet and "
                      "Ansible and SLIC-J leads on Chef. The all-files column includes the tuning files, which "
                      "favours SLIC-J."))
    lines.append(r"\end{table}")
    (TAB / "split.tex").write_text("\n".join(lines))


def table_rq1():
    det = json.load(open(R / "rq1" / "detection.json"))
    order = {"puppet": ["SLIC (original)", "GLITCH ASE'22", "GLITCH v2 (live)", "SLIC-J rules"],
             "ansible": ["SLAC (original)", "GLITCH ASE'22", "GLITCH v2 (live)", "SLIC-J rules"],
             "chef": ["SLAC (original)", "GLITCH ASE'22", "GLITCH v2 (live)", "SLIC-J rules"]}
    short = ["Adm", "Emp", "Sec", "IP", "Sus", "HTTP", "Cry"]
    lines = [r"\begin{table*}[t]\centering\caption{Portability (A): precision / recall per smell on the three GLITCH "
             r"oracle datasets (all files, GLITCH matching protocol). Micro values pool the seven smells. "
             r"`--' = no prediction or no true instance.}\label{tab:rq1}",
             r"\scriptsize\setlength{\tabcolsep}{3pt}\begin{tabular}{ll" + "c" * 7 + "ccc}\\toprule",
             "Tech & Tool & " + " & ".join(short) + r" & P$_\mu$ & R$_\mu$ & F1$_\mu$ \\ \midrule"]
    for tech, tools in order.items():
        for i, t in enumerate(tools):
            r = det.get(f"{tech}|all|{t}")
            if not r:
                continue
            cells = []
            for s in SEVEN:
                p, rc = r[s]["precision"], r[s]["recall"]
                cells.append(f"{f2(p)}/{f2(rc)}" if (p is not None or rc is not None) else "--")
            name = t.replace("_", r"\_")
            if t == "SLIC-J rules":
                name = r"\textbf{SLIC-J rules}"
            lines.append((tech.capitalize() if i == 0 else "") + f" & {name} & " + " & ".join(cells) +
                         f" & {f2(r['micro']['precision'])} & {f2(r['micro']['recall'])} & {f2(r['micro']['f1'])} \\\\")
        lines.append(r"\midrule")
    lines[-1] = r"\bottomrule\end{tabular}"
    lines.append(note("hard-coded secrets (Sec) are the weak smell for every tool: no tool reaches 0.45 precision "
                      "on them. Invalid IP binding is solved by all tools.", r"\textwidth"))
    lines.append(r"\end{table*}")
    (TAB / "rq1.tex").write_text("\n".join(lines))
    table_reproduction(det)
    table_split(det)
    a = det["agreement|ours: SLIC code port|SLIC (original)"]
    b = det["agreement|ours: paper rules|SLIC (original)"]
    return {"port_vs_original": a, "paper_vs_original": b}


# ------------------------------------------------------------------ RQ2 table
def table_rq2():
    techs = ["puppet", "ansible", "chef"]
    d = {t: json.load(open(R / "rq2" / f"prevalence_{t}.json")) for t in techs}
    lines = [r"\begin{table}[t]\centering\caption{Portability (B): the seven smells and the new TLS smell in the "
             r"GLITCH corpora (occurrences / density per KLOC / \% of scripts).}\label{tab:rq2}",
             r"\scriptsize\setlength{\tabcolsep}{1.6pt}\begin{tabular}{lrrr}\toprule",
             r" & Puppet & Ansible & Chef \\",
             "Scripts & " + " & ".join(f"{d[t]['scripts']:,}" for t in techs) + r" \\",
             "KLOC & " + " & ".join(f"{d[t]['loc']/1000:,.0f}" for t in techs) + r" \\ \midrule"]
    for s in SEVEN + ["tls_verify_disabled"]:
        cells = []
        for t in techs:
            v = d[t]["smells"][s]
            cells.append(f"{v['occurrences']:,} / {v['density_per_kloc']:.2f} / {v['script_pct']:.1f}")
        nm = LABEL[s] if s != "tls_verify_disabled" else r"\textit{TLS verif.\ disabled (new)}"
        lines.append(f"{nm} & " + " & ".join(cells) + r" \\")
    lines.append(r"\midrule Any of seven (\% scripts) & " + " & ".join(f"{d[t]['seven_sins_any_pct']:.1f}" for t in techs)
                 + r" \\")
    lines.append(r"\bottomrule\end{tabular}")
    lines.append(note("hard-coded secrets are the most frequent smell in Puppet and Ansible, and HTTP without TLS in "
                      "Chef. The TLS smell is rare in Puppet and Chef but occurs in 1\\% of Ansible scripts."))
    lines.append(r"\end{table}")
    (TAB / "rq2.tex").write_text("\n".join(lines))
    rows = list(csv.DictReader(open(R / "rq2" / "tls_sample.csv")))
    tp = sum(r["label_rater1"] == "TP" for r in rows)
    return {"tls_sample_n": len(rows), "tls_sample_tp": tp, "tls_precision": tp / len(rows),
            "tls_ansible_validate_certs": dict(d["ansible"]["tls_top_patterns"]).get("validate_certs")}


# ------------------------------------------------------------------ RQ3 statistics
def mcnemar(a, b, y):
    """Exact McNemar on per-candidate correctness of two keep/drop decision vectors."""
    from scipy.stats import binomtest
    ca, cb = (a == y), (b == y)
    n01 = int((ca & ~cb).sum())
    n10 = int((~ca & cb).sum())
    p = binomtest(n01, n01 + n10, 0.5).pvalue if n01 + n10 else 1.0
    return n01, n10, float(p)


def boot_f1_diff(a, b, y, groups, total_true_by_group, B=2000, seed=0):
    """File-level (cluster) bootstrap of F1(a) - F1(b), with recall over all oracle smells."""
    rng = np.random.RandomState(seed)
    ug = np.unique(groups)
    idx = {g: np.where(groups == g)[0] for g in ug}
    diffs = []
    for _ in range(B):
        sample = rng.choice(ug, len(ug), replace=True)
        rows = np.concatenate([idx[g] for g in sample])
        tt = sum(total_true_by_group.get(g, 0) for g in sample)

        def f1(k):
            tp = (k[rows] & y[rows]).sum()
            fp = (k[rows] & ~y[rows]).sum()
            p = tp / (tp + fp) if tp + fp else 0
            r = tp / tt if tt else 0
            return 2 * p * r / (p + r) if p + r else 0
        diffs.append(f1(a) - f1(b))
    d = np.array(diffs)
    return float(np.mean(d)), float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def rq3():
    summ = json.load(open(R / "rq3" / "summary.json"))
    dec = json.load(open(R / "rq3" / "decisions.json"))
    y = np.array(dec["labels"], bool)
    groups = np.array(dec["groups"])
    smells = np.array(dec["smells"])
    # oracle smells per file (for recall in the bootstrap)
    sys.path.insert(0, str(ROOT))
    from experiments.common import ORACLES, oracle
    ttg = defaultdict(int)
    for t in ORACLES:
        for o in oracle(t):
            if o.smell in SEVEN:
                ttg[f"{t}|{o.file}"] += 1
    D = {k.split("|")[0]: np.array(v, bool) for k, v in dec["decisions"].items() if k.endswith("|all")}
    stats = {}
    for a, b in [("jev-full", "rules"), ("jev-full", "jev-line"),
                 ("llm-anthropic_claude-haiku-5.5", "jev-full"), ("jev-full", "context-filter")]:
        if a in D and b in D:
            n01, n10, p = mcnemar(D[a], D[b], y)
            m, lo, hi = boot_f1_diff(D[a], D[b], y, groups, ttg)
            stats[f"{a} vs {b}"] = {"a_right_b_wrong": n01, "a_wrong_b_right": n10, "mcnemar_p": p,
                                    "dF1_mean": m, "dF1_ci95": [lo, hi]}
    # main table
    show = ["rules", "context-filter", "jev-line", "jev-full", "jev-full_nocomments", "dm-typesafe_jev-1.14",
            "dm-openai_gpt-6-luna-decisions", "dm-liquid_d1-ultra", "dm-perplexity_pplx-decider-v1.2",
            "dm-inception_mercury-decide", "dm-cloudflare_clef", "dm-microsoft_microsoft-decision-1",
            "dm-upstage_solar-decide", "llm-anthropic_claude-haiku-5.5", "claudecli-full"]
    cl = {}
    lines = [r"\begin{table*}[t]\centering\caption{Triage of the 269 SLIC-J candidates (151 TP, 118 FP, "
             r"176 oracle smells). Mean $\pm$ s.d.\ over 10 seeds of grouped 5-fold CV, threshold tuned in-fold. "
             r"Recall counts all oracle smells, so the rules' ceiling is 0.858. AUC and ECE use the raw "
             r"scores. Cost is USD per 1{,}000 findings. Latency is the median per call.}\label{tab:rq3}",
             r"\scriptsize\setlength{\tabcolsep}{4pt}\begin{tabular}{llcccccccc}\toprule",
             r"Type & Method & Precision & Recall & F1 & F1 @0.5 & AUC & ECE & \$/1k & Lat.\,(s) \\ \midrule"]
    typ = lambda m: ("Rules" if m in ("rules", "context-filter") else
                     "Chat LLM" if m.startswith(("llm", "claudecli")) else "Decision model")
    prev = None
    for m in show:
        r = summ.get(f"{m}|all")
        if not r:
            continue
        c, lat = cost_latency("jev-full" if m == "jev-full_nocomments" else m)
        cl[m] = (c, lat)
        t = typ(m)
        if prev and t != prev:
            lines.append(r"\midrule")
        prev = t
        at05 = r.get("at_0.5", {}).get("F1")
        bold = m in ("jev-full",)
        nm = NICE.get(m, m)
        nm = rf"\textbf{{{nm}}}" if bold else nm
        lines.append(f"{t} & {nm} & {r['P']:.3f}$\\pm${r['P_sd']:.3f} & {r['R']:.3f}$\\pm${r['R_sd']:.3f} & "
                     f"{r['F1']:.3f}$\\pm${r['F1_sd']:.3f} & {f2(at05, 3)} & {f2(r.get('AUC'), 3)} & "
                     f"{f2(r.get('ECE'), 3)} & {f2(c, 3) if c is not None else ('--' if m.startswith('claudecli') else '0')} & {f2(lat, 2)} \\\\")
    lines.append(r"\bottomrule\end{tabular}")
    lines.append(note("seven of the nine decision models reach F1 0.75--0.80, against 0.68 for the rules, and the gain "
                      "comes mostly from precision. Jev and the chat LLM are within 0.02 F1 of each other, but the chat "
                      "LLM costs about four times as much.", r"\textwidth"))
    lines.append(r"\end{table*}")
    (TAB / "rq3.tex").write_text("\n".join(lines))

    # per-smell table: rules vs jev-full (decisions of the last CV seed)
    nsm = defaultdict(int)
    for t in ORACLES:
        for o in oracle(t):
            if o.smell in SEVEN:
                nsm[o.smell] += 1
    lines = [r"\begin{table}[t]\centering\caption{Triage per smell: precision / recall before and after Jev "
             r"(last CV seed). $n$ = oracle instances.}\label{tab:rq3smell}",
             r"\scriptsize\setlength{\tabcolsep}{3pt}\begin{tabular}{lrcc}\toprule",
             r"Smell & $n$ & Rules & Jev full \\ \midrule"]
    per = {}
    for s in SEVEN:
        m = smells == s
        cells = []
        for meth in ("rules", "jev-full"):
            k = D[meth]
            tp = int((k & y & m).sum())
            fp = int((k & ~y & m).sum())
            p = tp / (tp + fp) if tp + fp else None
            rc = tp / nsm[s] if nsm[s] else None
            per.setdefault(s, {})[meth] = {"tp": tp, "fp": fp, "P": p, "R": rc}
            cells.append(f"{f2(p)}/{f2(rc)}")
        lines.append(f"{LABEL[s]} & {nsm[s]} & " + " & ".join(cells) + r" \\")
    lines.append(r"\bottomrule\end{tabular}")
    lines.append(note("most of the gain comes from hard-coded secrets. Smells that the rules already detect "
                      "precisely, such as admin by default and IP binding, are left unchanged."))
    lines.append(r"\end{table}")
    (TAB / "rq3_smell.tex").write_text("\n".join(lines))
    return stats, per, cl


# ------------------------------------------------------------------ figures
def fig_pr():
    summ = json.load(open(R / "rq3" / "summary.json"))
    pts = [(m, summ[f"{m}|all"]) for m in NICE if f"{m}|all" in summ and m != "free-mercury-full"
           and m != "jev-full_nocomments"]
    fig, ax = plt.subplots(figsize=(3.45, 3.0))
    for m, r in pts:
        if m.startswith("jev") or "jev-1.14" in m:
            col, z = BLUE, 3
        elif m.startswith(("llm", "claudecli")):
            col, z = ORANGE, 3
        elif m.startswith("dm-"):
            col, z = "#9b9a96", 2
        else:
            col, z = INK2, 2
        ax.errorbar(r["R"], r["P"], xerr=r["R_sd"], yerr=r["P_sd"], fmt="o", ms=4.5, color=col, ecolor=col,
                    elinewidth=0.8, capsize=0, zorder=z, mec="white", mew=0.6)
    lab = {"rules": (-20, 7), "context-filter": (5, -10), "jev-line": (-14, -12),
           "jev-full": (5, -10), "llm-anthropic_claude-haiku-5.5": (-14, 7),
           "dm-microsoft_microsoft-decision-1": (5, -3), "dm-upstage_solar-decide": (5, -3)}
    short = {"rules": "Rules only", "context-filter": "Practitioner filter",
             "jev-line": "Jev (line)", "jev-full": "Jev (full)", "llm-anthropic_claude-haiku-5.5": "Haiku 5.5",
             "dm-microsoft_microsoft-decision-1": "MS Decision-1",
             "dm-upstage_solar-decide": "Solar-Decide"}
    for m, r in pts:
        if m in lab:
            ax.annotate(short[m], (r["R"], r["P"]), xytext=lab[m], textcoords="offset points", fontsize=6.5,
                        color=INK)
    ax.set_xlabel("Recall (all oracle smells)")
    ax.set_ylabel("Precision")
    ax.set_xlim(0.71, 0.88)
    ax.set_ylim(0.53, 0.87)
    from matplotlib.lines import Line2D
    h = [Line2D([], [], marker="o", ls="", color=c, label=l, ms=4.5) for c, l in
         [(INK2, "Rules"), (BLUE, "Jev"), ("#9b9a96", "Other decision models"), (ORANGE, "Chat LLM")]]
    ax.legend(handles=h, fontsize=6, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=2, handletextpad=0.2,
              columnspacing=0.8)
    fig.tight_layout(pad=0.3)
    fig.savefig(FIG / "fig_pr.pdf")
    fig.savefig(FIG / "fig_pr.png", dpi=200)
    plt.close(fig)


def rq4():
    out = {}
    for path in sorted(glob.glob(str(R / "rq3" / "rq4_*.json"))):
        d = json.load(open(path))
        out[os.path.basename(path)[4:-5]] = d
    if not out:
        return {}
    lines = [r"\begin{table}[t]\centering\caption{Robustness: flip rate (kept true findings that the model drops after "
             r"one misleading comment is inserted), with comments visible / removed from the state, at each model's "
             r"tuned threshold (Mercury-Decide 0.05 visible, 0.02 removed; Haiku 0.12). $n$ = attacked true findings.}\label{tab:rq4}",
             r"\scriptsize\setlength{\tabcolsep}{3pt}\begin{tabular}{llcc}\toprule",
             r"Model & Attack (position) & Visible & Removed \\ \midrule"]
    for tag, d in out.items():
        name = {"free-mercury": f"Mercury-Decide ($n$={d['n_targets']})",
                "claudecli": f"Claude Haiku 5.5 ($n$={d['n_targets']})"}.get(tag, tag)
        first = True
        for k, v in d["attacks"].items():
            a, pos = k.split("|")
            vis, rem = v["visible_comments"], v["comments_removed"]
            lines.append(f"{name if first else ''} & {a} ({pos}) & {vis['flip_rate']*100:.1f}\\% ({vis['flips']}) & "
                         f"{rem['flip_rate']*100:.1f}\\% ({rem['flips']}) \\\\")
            first = False
        lines.append(r"\midrule")
    lines[-1] = r"\bottomrule\end{tabular}"
    lines.append(note("the decision model obeys the injected instruction, while the chat LLM believes the placeholder "
                      "claim. With comments removed, no attack flips more than 1.6\\%."))
    lines.append(r"\end{table}")
    (TAB / "rq4.tex").write_text("\n".join(lines))
    # figure: grouped bars per attack, two series (visible vs removed), one panel per model
    fig, axes = plt.subplots(1, len(out), figsize=(3.45 if len(out) == 1 else 7.0, 2.2), sharey=True, squeeze=False)
    for ax, (tag, d) in zip(axes[0], out.items()):
        keys = list(d["attacks"].keys())
        x = np.arange(len(keys))
        vis = [d["attacks"][k]["visible_comments"]["flip_rate"] * 100 for k in keys]
        rem = [d["attacks"][k]["comments_removed"]["flip_rate"] * 100 for k in keys]
        w = 0.38
        b1 = ax.bar(x - w / 2 - 0.01, vis, w, color=ORANGE, label="Comments visible")
        b2 = ax.bar(x + w / 2 + 0.01, rem, w, color=BLUE, label="Comments removed (mitigation)")
        for bars in (b1, b2):
            for b in bars:
                ax.annotate(f"{b.get_height():.0f}", (b.get_x() + b.get_width() / 2, b.get_height()),
                            xytext=(0, 1.5), textcoords="offset points", ha="center", fontsize=5.5, color=INK)
        ax.set_xticks(x)
        ax.set_xticklabels([k.replace("|", "\n") for k in keys], fontsize=5.8)
        ax.set_title({"free-mercury": "Mercury-Decide (decision model)", "claudecli": "Claude Haiku 5.5 (chat LLM)"}
                     .get(tag, tag), fontsize=7)
        ax.grid(axis="x", visible=False)
    axes[0][0].set_ylabel("Flip rate (% of kept true findings)")
    axes[0][0].legend(fontsize=6, loc="upper left")
    fig.tight_layout(pad=0.3)
    fig.savefig(FIG / "fig_rq4.pdf")
    fig.savefig(FIG / "fig_rq4.png", dpi=200)
    plt.close(fig)
    res = {}
    rows = [json.loads(l) for l in open(R / "rq3" / "candidates.jsonl")]
    for k, d in out.items():
        res[k] = {"threshold_full": d["threshold_full"], "threshold_removed": d["threshold_nocomments"],
                  "n_targets": d["n_targets"], "attacks": {}}
        clean_full = json.load(open(R / "rq3" / f"scores_{k}-full.json"))["scores"]
        clean_rem = json.load(open(R / "rq3" / f"scores_{k}-{d.get('mitigation', 'full_strict')}.json"))["scores"]
        bf = np.array([clean_full[i] for i in d["targets"]], float)
        br = np.array([clean_rem[i] for i in d["targets"]], float)
        for a, v in d["attacks"].items():
            pt = d["per_target"][a]
            af, ar = np.array(pt["full"], float), np.array(pt["nocomments"], float)
            at05 = {"visible": float(((bf >= .5) & (af < .5)).sum() / max(1, (bf >= .5).sum())),
                    "removed": float(((br >= .5) & (ar < .5)).sum() / max(1, (br >= .5).sum())),
                    "kept_visible": int((bf >= .5).sum()), "kept_removed": int((br >= .5).sum())}
            res[k]["attacks"][a] = {"visible": v["visible_comments"], "removed": v["comments_removed"],
                                    "flip_rate_at_0.5": at05}
    return res


def main():
    out = {"rq1": table_rq1(), "rq2": table_rq2()}
    st, per, cl = rq3()
    out["rq3_tests"] = st
    out["rq3_per_smell_last_seed"] = per
    out["rq3_cost_latency"] = cl
    out["rq4"] = rq4()
    fig_pr()
    with open(R / "stats.json", "w") as fh:
        json.dump(out, fh, indent=1, default=float)
    print(json.dumps({"rq1": out["rq1"], "rq2": out["rq2"], "tests": st, "cost_latency": cl}, indent=1, default=float))


if __name__ == "__main__":
    main()
