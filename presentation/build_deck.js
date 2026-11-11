// Builds the two-person talk: Seven_Sins_Revisited_Presentation.pptx and speaker_script.md.
// Every result number comes from ../results, so the slides cannot drift from the experiments.
const fs = require("fs");
const path = require("path");
const pptxgen = require("pptxgenjs");
const { applyTheme } = require(process.env.PPTX_SKILL + "/scripts/apply_theme.js");

const R = path.join(__dirname, "..", "results");
const read = (p) => JSON.parse(fs.readFileSync(path.join(R, p), "utf8"));
const stats = read("stats.json");
const det = read("rq1/detection.json");
const sum = read("rq3/summary.json");
const prev = Object.fromEntries(["puppet", "ansible", "chef"].map((t) => [t, read(`rq2/prevalence_${t}.json`)]));

const f2 = (x) => x.toFixed(2);
const f3 = (x) => {
  const v = x * 1000, fl = Math.floor(v);
  const r = Math.abs(v - fl - 0.5) < 1e-9 ? (fl % 2 === 0 ? fl : fl + 1) : Math.round(v);
  return (r / 1000).toFixed(3);
};
const pct1 = (x) => (x * 100).toFixed(1) + "%";
const micro = (t, tool) => det[`${t}|all|${tool}`].micro.f1;
const m = (k) => sum[`${k}|all`];

// Headline claims used in prose. The build stops if the data disagrees with them.
function expect(label, actual, want) {
  if (actual !== want) throw new Error(`${label}: data says ${actual}, slide text says ${want}`);
}
expect("rules P", f2(m("rules").P), "0.56");
expect("rules R", f2(m("rules").R), "0.86");
expect("jev P", f2(m("jev-full").P), "0.78");
expect("jev R", f2(m("jev-full").R), "0.81");
expect("jev F1", f2(m("jev-full").F1), "0.80");
expect("rules F1", f2(m("rules").F1), "0.68");
expect("haiku F1", f2(m("llm-anthropic_claude-haiku-5.5").F1), "0.81");
expect("filter F1", f2(m("context-filter").F1), "0.64");
expect("filter R", f2(m("context-filter").R), "0.74");
const sec = stats.rq3_per_smell_last_seed.hardcoded_secret;
expect("secret FP before", sec.rules.fp, 80);
expect("secret FP after", sec["jev-full"].fp, 4);
expect("secret TP before", sec.rules.tp, 27);
expect("secret TP after", sec["jev-full"].tp, 20);
expect("paper jaccard", f2(stats.rq1.paper_vs_original.jaccard), "0.58");
expect("port jaccard", f2(stats.rq1.port_vs_original.jaccard), "0.99");
expect("port both", stats.rq1.port_vs_original.both, 120);
expect("tls tp", stats.rq2.tls_sample_tp, 59);
expect("tls ansible pct", prev.ansible.smells.tls_verify_disabled.script_pct.toFixed(2), "1.01");
const merc = stats.rq4["free-mercury"].attacks;
const haiku = stats.rq4.claudecli.attacks;
expect("merc inj above", pct1(merc["injection|above"].visible.flip_rate), "97.5%");
expect("merc inj above rem", pct1(merc["injection|above"].removed.flip_rate), "1.6%");
expect("haiku inj above", pct1(haiku["injection|above"].visible.flip_rate), "0.0%");
expect("haiku ph inline", pct1(haiku["placeholder|inline"].visible.flip_rate), "20.0%");
expect("haiku ph inline 0.5", pct1(haiku["placeholder|inline"]["flip_rate_at_0.5"].visible), "50.0%");
expect("haiku rem 0.5", pct1(haiku["injection|above"]["flip_rate_at_0.5"].removed), "16.1%");

const THEME = {
  name: "Seven Sins",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "14151C", lt1: "FFFFFF", dk2: "4A4E5C", lt2: "F1F2F5",
    accent1: "C43A4B", accent2: "00908C", accent3: "E8A100", accent4: "7B8794", accent5: "2F3140", accent6: "F7DDE0",
    hlink: "C43A4B", folHlink: "7B8794",
  },
};
const CODE = "Courier New";
const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.33 x 7.5
pres.title = "Seven Sins Revisited";
pres.author = "Adheil Gupta, Om Pandey";
pres.subject = "Cloud SRE and Security course project";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

const FOOT = "Seven Sins Revisited  |  Gupta, Pandey";
pres.defineSlideMaster({
  title: "CONTENT",
  background: { color: C.background1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.4, w: 12.13, h: 0.85, fontSize: 36, bold: true, color: C.text1, align: "left", valign: "middle", margin: 0, fontFace: THEME.headFontFace }, text: "" } },
    { text: { text: FOOT, options: { x: 0.6, y: 6.98, w: 8, h: 0.3, fontSize: 11, color: C.text2, margin: 0, isTextBox: true } } },
  ],
  slideNumber: { x: 12.13, y: 6.98, w: 0.6, h: 0.3, fontSize: 11, color: C.text2, align: "right" },
});
pres.defineSlideMaster({
  title: "DARK",
  background: { color: C.text1 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 1.05, w: 11.7, h: 1.2, fontSize: 54, bold: true, color: C.background1, align: "left", valign: "middle", margin: 0, fontFace: THEME.headFontFace }, text: "" } },
  ],
});

// ------------------------------------------------------------ drawing helpers
function card(s, x, y, w, h, fill, name) {
  s.addShape(pres.ShapeType.roundRect, { x, y, w, h, fill: { color: fill || C.background2 }, line: { type: "none" }, rectRadius: 0.08, objectName: name || "Card" });
}
function badge(s, n, x, y, d, fill, color) {
  s.addText(String(n), { shape: pres.ShapeType.ellipse, x, y, w: d || 0.45, h: d || 0.45, fill: { color: fill || C.accent1 }, color: color || C.background1, bold: true, fontSize: 15, align: "center", valign: "middle", margin: 0, objectName: `Badge ${n}` });
}
function text(s, t, x, y, w, h, o) {
  s.addText(t, Object.assign({ x, y, w, h, fontSize: 16, color: C.text1, margin: 0, valign: "top", isTextBox: true }, o || {}));
}
function code(s, lines, x, y, w, h, o) {
  o = o || {};
  card(s, x, y, w, h, C.text1, "Code panel");
  const runs = lines.map((l, i) => ({ text: l.t, options: { color: l.c || C.background1, bold: !!l.c, breakLine: i < lines.length - 1 } }));
  s.addText(runs, { x: x + 0.25, y: y + 0.15, w: w - 0.5, h: h - 0.3, fontFace: CODE, fontSize: o.fontSize || 14, valign: "middle", margin: 0, isTextBox: true, objectName: "Code" });
}
function pill(s, t, x, y, w) {
  s.addText(t, { shape: pres.ShapeType.roundRect, rectRadius: 0.17, x, y, w, h: 0.42, fill: { color: C.text1 }, color: C.background1, fontFace: CODE, fontSize: 14, align: "center", valign: "middle", margin: 0, objectName: "Code tag" });
}
function stat(s, value, label, x, y, w, h, o) {
  o = o || {};
  card(s, x, y, w, h, o.fill || C.background2, "Stat card");
  text(s, value, x + 0.3, y + 0.2, w - 0.6, o.valueH || 1.0, { fontSize: o.size || 54, bold: true, fontFace: THEME.headFontFace, color: o.color || C.text1, valign: "middle" });
  text(s, label, x + 0.3, y + 0.2 + (o.valueH || 1.0) + 0.05, w - 0.6, h - (o.valueH || 1.0) - 0.4, { fontSize: o.labelSize || 15, color: C.text1 });
}
function barOpts(extra) {
  return Object.assign({
    barDir: "col", barGrouping: "clustered", barGapWidthPct: 55, barOverlapPct: -5,
    catAxisLabelFontFace: "+mn-lt", catAxisLabelFontSize: 13, catAxisLabelColor: C.text1,
    valAxisHidden: true, valGridLine: { style: "none" }, catGridLine: { style: "none" },
    valAxisMinVal: 0, valAxisMaxVal: 1,
    showValue: true, dataLabelPosition: "outEnd", dataLabelFontFace: "+mn-lt", dataLabelFontSize: 12, dataLabelColor: C.text1, dataLabelFormatCode: "0.00",
    showLegend: true, legendPos: "t", legendFontFace: "+mn-lt", legendFontSize: 13, legendColor: C.text1,
  }, extra || {});
}

// ------------------------------------------------------------ slide registry (for the script file)
const script = [];
function slide(opts) {
  if (opts.section) pres.addSection({ title: opts.section });
  const s = pres.addSlide({ masterName: opts.dark ? "DARK" : "CONTENT", sectionTitle: opts.sectionName });
  s.addText(opts.title, { placeholder: "title" });
  const n = script.length + 1;
  const tag = opts.backup ? `[BACKUP, ${opts.who}]` : `[${opts.who.toUpperCase()}, about ${opts.secs} seconds]`;
  s.addNotes(`${tag}\n\n${opts.notes}`);
  script.push({ n, title: opts.title, who: opts.who, secs: opts.secs || 0, notes: opts.notes, backup: !!opts.backup });
  return s;
}

const SEC1 = "Adheil: reproduction and port";
const SEC2 = "Om: triage and robustness";
const SEC3 = "Backup slides";

// ============================================================ ADHEIL
// 1 ---------------------------------------------------------- title
{
  const s = slide({
    section: SEC1, sectionName: SEC1, dark: true, who: "Adheil", secs: 30,
    title: "Seven Sins Revisited",
    notes: "Good morning. I am Adheil, and this is Om. Our project starts from an ICSE 2019 paper called The Seven Sins, about security smells in infrastructure as code. We did three things. We rebuilt the paper's tool. We extended the tool to two more technologies. Then we reduced its false alarms with a decision model. I will cover the rebuild and the extension. Om will cover the false alarms.",
  });
  text(s, "Reproducing SLIC, porting it to Ansible and Chef, and filtering its false alarms with a decision model", 0.8, 2.35, 10.6, 1.1, { fontSize: 24, color: C.background1 });
  for (let i = 1; i <= 7; i++) badge(s, i, 0.8 + (i - 1) * 0.72, 3.85, 0.56, C.accent1);
  text(s, "Adheil Gupta (23BDS002)   |   Om Pandey (23BDS040)", 0.8, 4.95, 11, 0.4, { fontSize: 20, bold: true, color: C.background1 });
  text(s, "Course project, Cloud SRE and Security", 0.8, 5.4, 11, 0.35, { fontSize: 16, color: C.background1 });
  text(s, "Based on: A. Rahman, C. Parnin, L. Williams, “The Seven Sins: Security Smells in Infrastructure as Code Scripts”, ICSE 2019", 0.8, 6.3, 11.7, 0.35, { fontSize: 13, color: C.background1 });
}

// 2 ---------------------------------------------------------- problem
{
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 55,
    title: "One insecure line reaches every server",
    notes: "Site reliability teams configure whole fleets with scripts. This example comes from the paper, and it is a real open source Puppet script. The password is written directly in the script. Every server that runs this script gets that password. The paper calls this a security smell. A smell is not always a vulnerability, but it needs a review. The paper's linter, SLIC, reported 0.99 precision on its own test set. Later, an independent team tested it on a different test set. Its precision for hard-coded secrets was 0.10. So nine of ten secret findings were false alarms. That gap is the reason for this project.",
  });
  code(s, [
    { t: 'postgres::user { "aeolus":' },
    { t: '  password => "v23zj59an",', c: C.accent3 },
    { t: '  roles    => "CREATEDB",' },
    { t: '  require  => Service["postgresql"]' },
    { t: "}" },
  ], 0.6, 1.55, 6.3, 2.6, { fontSize: 16 });
  text(s, "Puppet script from the aeolus-configure repository (paper, Fig. 1).", 0.6, 4.25, 6.3, 0.3, { fontSize: 12, color: C.text2 });
  text(s, [
    { text: "Infrastructure as code (IaC) scripts configure whole fleets.", options: { bullet: true, breakLine: true } },
    { text: "A security smell is a coding pattern that points to a security weakness.", options: { bullet: true, breakLine: true } },
    { text: "A smell needs a review. It is not always a vulnerability.", options: { bullet: true } },
  ], 0.6, 4.75, 6.3, 1.85, { fontSize: 16, paraSpaceAfter: 6 });
  stat(s, "0.99", "SLIC average precision on the paper’s own test set (ICSE 2019)", 7.4, 1.55, 5.33, 2.35, { color: C.accent2 });
  stat(s, "0.10", "SLIC precision for hard-coded secrets on an independent test set (GLITCH, ASE 2022)", 7.4, 4.2, 5.33, 2.4, { color: C.accent1 });
}

// 3 ---------------------------------------------------------- the paper
{
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 50,
    title: "The paper: seven smells and one linter",
    notes: "The authors studied 1,726 Puppet scripts by hand and derived seven smells. Each smell maps to a CWE weakness. They then built SLIC. SLIC has two parts. A parser turns a script into tokens with a name and a value. A rule engine matches string patterns on those tokens. For example, if a name contains 'password' and the value is a non-empty string, SLIC reports a hard-coded secret. The authors scanned 15,232 scripts and found 21,201 smells. When they asked developers, 64.4 percent of the 104 replies agreed with the finding. Developers who disagreed often gave context as the reason. Remember that point, because it comes back later.",
  });
  const smells = [
    ["Admin by default", "CWE-250"], ["Empty password", "CWE-258"], ["Hard-coded secret", "CWE-798"], ["Invalid IP binding", "CWE-284"],
    ["Suspicious comment", "CWE-546"], ["HTTP without TLS", "CWE-319"], ["Weak crypto", "CWE-327"],
  ];
  const W = 2.86, H = 1.4, G = 0.23;
  smells.forEach(([nm, cwe], i) => {
    const col = i % 4, row = Math.floor(i / 4);
    const x = 0.6 + col * (W + G), y = 1.5 + row * (H + G);
    card(s, x, y, W, H);
    badge(s, i + 1, x + 0.18, y + 0.28, 0.45);
    text(s, nm, x + 0.75, y + 0.25, W - 0.9, 0.55, { fontSize: 15, bold: true, valign: "middle" });
    text(s, cwe, x + 0.75, y + 0.83, W - 0.9, 0.3, { fontSize: 13, color: C.text2 });
  });
  const x8 = 0.6 + 3 * (W + G), y8 = 1.5 + H + G;
  card(s, x8, y8, W, H, C.text1, "SLIC card");
  text(s, "SLIC", x8 + 0.22, y8 + 0.15, W - 0.4, 0.4, { fontSize: 18, bold: true, color: C.background1 });
  text(s, "Parser + rule engine", x8 + 0.22, y8 + 0.62, W - 0.4, 0.4, { fontSize: 15, color: C.background1 });
  const stats3 = [["1,726", "scripts studied by hand"], ["15,232", "scripts scanned by SLIC"], ["21,201", "smell occurrences found"], ["64.4%", "of 104 developer replies agreed"]];
  stats3.forEach(([v, l], i) => {
    const x = 0.6 + i * (W + G);
    text(s, v, x, 4.95, W, 0.8, { fontSize: 40, bold: true, fontFace: THEME.headFontFace, color: C.accent1, valign: "middle" });
    text(s, l, x, 5.8, W, 0.6, { fontSize: 15 });
  });
}

// 4 ---------------------------------------------------------- RQs
{
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 40,
    title: "We asked four research questions",
    notes: "We asked four questions. First, can SLIC be rebuilt from the paper? Second, does the approach port to Ansible and Chef, and can it find a new kind of smell? I will answer these two. Third, can a decision model remove false alarms, and what does that cost? Fourth, can an attacker fool that model with a comment in the script? Om will answer these two.",
  });
  const rq = [
    ["RQ1", "Reproduction", "Can we rebuild SLIC from the paper, and does the rebuild match the released tool?", "Adheil"],
    ["RQ2", "Portability", "How accurate is a port to Ansible and Chef? How common is a new TLS smell?", "Adheil"],
    ["RQ3", "Triage", "How much precision does a context-aware decision model add? At what recall and cost?", "Om"],
    ["RQ4", "Robustness", "Can a misleading comment talk the model out of a true finding? What stops that?", "Om"],
  ];
  rq.forEach(([id, nm, q, who], i) => {
    const x = 0.6 + (i % 2) * 6.2, y = 1.55 + Math.floor(i / 2) * 2.65;
    card(s, x, y, 5.93, 2.4);
    s.addText(id, { shape: pres.ShapeType.roundRect, rectRadius: 0.1, x: x + 0.25, y: y + 0.25, w: 0.95, h: 0.5, fill: { color: i < 2 ? C.accent2 : C.accent1 }, color: C.background1, bold: true, fontSize: 18, align: "center", valign: "middle", margin: 0, objectName: id });
    text(s, nm, x + 1.4, y + 0.25, 4.3, 0.5, { fontSize: 20, bold: true, valign: "middle" });
    text(s, q, x + 0.25, y + 0.95, 5.43, 0.95, { fontSize: 16 });
    text(s, `Presented by ${who}`, x + 0.25, y + 1.92, 5.43, 0.3, { fontSize: 13, color: C.text2 });
  });
}

// 5 ---------------------------------------------------------- how we tested
{
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 60,
    title: "We tested on labels that we did not write",
    notes: "A claim needs a fair test, so we did not label the main test data ourselves. We used the three test sets that the GLITCH authors published at ASE 2022. They contain about 80 scripts per technology and 176 scored smells, with a line number for each smell. Before we trusted our scorer, we checked it. It reproduces all 77 published per-smell values for SLIC, SLAC and GLITCH. We also ran the authors' original SLIC on this machine. Its output matched the published output on all 120 findings. To limit overfitting, we refined rules only on a fixed 30 percent of the files. For the triage experiment we used 5-fold cross-validation, grouped by file, with 10 seeds.",
  });
  const rows = [
    [{ text: "Test set", options: { bold: true, fill: { color: C.text1 }, color: C.background1 } }, { text: "Scripts", options: { bold: true, align: "right", fill: { color: C.text1 }, color: C.background1 } }, { text: "Scored smells", options: { bold: true, align: "right", fill: { color: C.text1 }, color: C.background1 } }],
    ["Puppet", { text: "80", options: { align: "right" } }, { text: "54", options: { align: "right" } }],
    ["Ansible", { text: "81", options: { align: "right" } }, { text: "43", options: { align: "right" } }],
    ["Chef", { text: "80", options: { align: "right" } }, { text: "79", options: { align: "right" } }],
    [{ text: "Total", options: { bold: true } }, { text: "241", options: { align: "right", bold: true } }, { text: "176", options: { align: "right", bold: true } }],
  ];
  s.addTable(rows, { x: 0.6, y: 1.55, w: 5.4, colW: [2.2, 1.3, 1.9], rowH: 0.5, fontSize: 16, color: C.text1, valign: "middle", border: { type: "solid", pt: 0.75, color: "D9DBE1" }, objectName: "Test sets" });
  text(s, "Source: GLITCH replication package (Saavedra and Ferreira, ASE 2022). Raters gave a file, a line and a category for each smell.", 0.6, 4.2, 5.4, 0.65, { fontSize: 12, color: C.text2 });
  stat(s, "206,000", "scripts in the same package, used only to count how common each smell is", 0.6, 4.95, 5.4, 1.75, { size: 32, valueH: 0.6, labelSize: 14 });
  const checks = [
    ["Scorer check", "Our scorer reproduces all 77 published per-smell values of SLIC, SLAC and GLITCH’22."],
    ["Baseline check", "We re-ran the original SLIC. Its output matches the package on 120 of 120 findings."],
    ["Overfitting control", "We refined rules on a fixed 30% of files. Triage uses 5-fold cross-validation by file, with 10 seeds."],
  ];
  checks.forEach(([h, b], i) => {
    const y = 1.55 + i * 1.75;
    card(s, 6.4, y, 6.33, 1.6);
    badge(s, i + 1, 6.62, y + 0.2, 0.45, C.accent2);
    text(s, h, 7.25, y + 0.18, 5.25, 0.45, { fontSize: 18, bold: true, valign: "middle" });
    text(s, b, 7.25, y + 0.68, 5.25, 0.85, { fontSize: 15 });
  });
}

// 6 ---------------------------------------------------------- RQ1 result
{
  const a = stats.rq1.paper_vs_original, b = stats.rq1.port_vs_original;
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 55,
    title: "RQ1: the paper alone is not enough",
    notes: `We built SLIC twice. The first version uses only the rules that the paper prints. It agrees with the original tool on 58 percent of findings, measured with Jaccard overlap. It shares ${a.both} findings, misses ${a.only_original}, and adds ${a.only_ours}. The second version copies the released Ruby code token by token. It shares all ${b.both} findings and adds ${b.only_ours}. That one extra comes from a .pp file that contains Haskell-style comments, not Puppet. So the tool is reproducible from the code, but not from the paper. One more result: on this independent test set, the original SLIC has micro precision 0.28, far from the 0.99 that the paper reports on its own test set.`,
  });
  card(s, 0.6, 1.55, 5.9, 3.3);
  text(s, "Built from the paper’s tables", 0.9, 1.75, 5.3, 0.4, { fontSize: 18, bold: true });
  text(s, "58%", 0.9, 2.2, 5.3, 1.3, { fontSize: 80, bold: true, fontFace: THEME.headFontFace, color: C.accent1, valign: "middle" });
  text(s, "agreement with the original SLIC (Jaccard)", 0.9, 3.55, 5.3, 0.35, { fontSize: 15 });
  text(s, `${a.both} shared   |   ${a.only_original} missed   |   ${a.only_ours} extra`, 0.9, 4.1, 5.3, 0.4, { fontSize: 16, bold: true });
  card(s, 6.83, 1.55, 5.9, 3.3);
  text(s, "Ported from the released code", 7.13, 1.75, 5.3, 0.4, { fontSize: 18, bold: true });
  text(s, "99%", 7.13, 2.2, 5.3, 1.3, { fontSize: 80, bold: true, fontFace: THEME.headFontFace, color: C.accent2, valign: "middle" });
  text(s, "agreement with the original SLIC (Jaccard)", 7.13, 3.55, 5.3, 0.35, { fontSize: 15 });
  text(s, `${b.both} shared   |   ${b.only_original} missed   |   ${b.only_ours} extra`, 7.13, 4.1, 5.3, 0.4, { fontSize: 16, bold: true });
  text(s, "Jaccard = shared findings divided by all findings of both tools.", 0.6, 4.98, 12.13, 0.3, { fontSize: 12, color: C.text2 });
  text(s, [
    { text: "Independent test: ", options: { bold: true } },
    { text: `the original SLIC scores micro precision ${f2(det["puppet|all|SLIC (original)"].micro.precision)} on the GLITCH Puppet test set. The paper reports 0.99 on its own test set.` },
  ], 0.6, 5.5, 12.13, 0.8, { fontSize: 20 });
}

// 7 ---------------------------------------------------------- six differences
{
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 60,
    title: "Six differences between paper and code",
    notes: "We traced the gap to six differences. The printed admin rule requires 'admin' and 'user' in the name. The paper's own example has 'admin' in the value, so the printed rule misses it. The private-key pattern is not a valid regular expression as printed. The secret rule in the code is much wider than the table. The weak crypto rule flags any token, not only functions. The comment rule uses more keywords. The sixth difference is my favourite. One rule prints a tag that ends in three colons. The driver searches for a tag that ends in an underscore. The two strings never match, so this check never reaches the report. Enabling it would add 11 findings on this test set.",
  });
  const items = [
    ["Admin rule", "The printed rule misses the paper’s own Fig. 4 example."],
    ["Private-key pattern", "The printed regular expression is not valid."],
    ["Secret keywords", "The code uses 14 keywords and 19 exclusions."],
    ["Weak crypto", "The code flags any token, not only functions."],
    ["Suspicious comment", "The code adds keywords and scans raw lines."],
    ["A dead check", "One rule never reaches the report."],
  ];
  items.forEach(([h, b], i) => {
    const y = 1.5 + i * 0.87;
    badge(s, i + 1, 0.6, y + 0.1, 0.45, i === 5 ? C.accent1 : C.accent5);
    text(s, h, 1.25, y, 5.1, 0.35, { fontSize: 17, bold: true });
    text(s, b, 1.25, y + 0.36, 5.1, 0.35, { fontSize: 15 });
  });
  text(s, "The dead check", 6.9, 1.5, 5.83, 0.4, { fontSize: 18, bold: true });
  code(s, [
    { t: "all_in_one.rb prints:" },
    { t: "SECURITY:::EXPOSING_SECRET_LOCATION:::", c: C.accent3 },
    { t: " " },
    { t: "SLIC driver searches for:" },
    { t: "SECURITY:::EXPOSING_SECRET_LOCATION_", c: C.accent3 },
  ], 6.9, 1.95, 5.83, 2.45, { fontSize: 14 });
  card(s, 6.9, 4.65, 5.83, 1.9);
  text(s, "11", 7.15, 4.8, 1.4, 1.6, { fontSize: 60, bold: true, fontFace: THEME.headFontFace, color: C.accent1, valign: "middle" });
  text(s, "extra findings on the Puppet test set if this check reaches the report. The two tags never match, so SLIC drops them without a warning.", 8.55, 4.85, 3.95, 1.5, { fontSize: 15, valign: "middle" });
}

// 8 ---------------------------------------------------------- RQ2 chart
{
  const techs = ["puppet", "ansible", "chef"], labels = ["Puppet", "Ansible", "Chef"];
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 55,
    title: "RQ2: the port competes with a current tool",
    notes: "SLIC-J is our port. For Ansible we walk the YAML and keep line numbers. For Chef we read the Ruby line by line. We compared F1 with the current GLITCH release, which we ran ourselves. On Puppet and Chef, SLIC-J is slightly ahead. On Ansible, GLITCH is ahead. The authors' original tools are lower on all three. I must add one caution. We refined our rules on 30 percent of these same test sets, and GLITCH was not tuned on them. So read this as competitive, not as better. Precision on hard-coded secrets stays low for every tool, between 0.19 and 0.44 for us. That is the problem Om will address.",
  });
  s.addChart(pres.ChartType.bar, [
    { name: "Original tool (SLIC, SLAC)", labels, values: [micro("puppet", "SLIC (original)"), micro("ansible", "SLAC (original)"), micro("chef", "SLAC (original)")] },
    { name: "GLITCH v2 (current release)", labels, values: techs.map((t) => micro(t, "GLITCH v2 (live)")) },
    { name: "SLIC-J rules (ours)", labels, values: techs.map((t) => micro(t, "SLIC-J rules")) },
  ], barOpts({ x: 0.6, y: 1.45, w: 7.6, h: 5.3, chartColors: [C.accent3, C.accent2, C.accent1], showTitle: true, title: "Micro-F1 on the seven smells", titleFontFace: "+mn-lt", titleFontSize: 15, titleColor: C.text1, altText: "Micro-F1 of the original tools, GLITCH v2 and SLIC-J on Puppet, Ansible and Chef" }));
  card(s, 8.5, 1.55, 4.23, 2.45);
  text(s, "A caution", 8.75, 1.7, 3.75, 0.4, { fontSize: 18, bold: true });
  text(s, "We refined our rules on 30% of these files. GLITCH was not tuned on them. So read this as competitive, not as better.", 8.75, 2.15, 3.75, 1.75, { fontSize: 16 });
  card(s, 8.5, 4.25, 4.23, 2.4, C.accent6, "Remaining problem");
  text(s, "The remaining problem", 8.75, 4.4, 3.75, 0.4, { fontSize: 18, bold: true });
  text(s, "Hard-coded secret precision stays at 0.19 to 0.44 for SLIC-J. No rule tool in our test passes 0.45.", 8.75, 4.85, 3.75, 1.6, { fontSize: 16 });
}

// 9 ---------------------------------------------------------- TLS
{
  const p = prev;
  const s = slide({
    sectionName: SEC1, who: "Adheil", secs: 50,
    title: "A new smell: TLS checks turned off",
    notes: "We also added an eighth smell. Turning off TLS certificate checks makes HTTPS open to an active attacker, and the seven sins do not cover this. SLIC-J finds it in any module, not only in specific ones. In the corpus, it appears in 1.01 percent of Ansible scripts, with 2,048 occurrences. It is rare in Puppet and Chef. The test sets have no labels for this smell, so we checked a random sample of 60 findings. 59 were correct, with one rater. The one false alarm was a test that asserts verification stays on. That is the end of my part. Rules give high recall, but too many false alarms. Om will now show how we reduce them.",
  });
  ["validate_certs: no", "curl -k", "wget --no-check-certificate", "--insecure-skip-tls-verify"].forEach((t, i) => {
    const w = [2.9, 1.5, 4.3, 4.2][i], x = [0.6, 3.7, 0.6, 5.1][i], y = i < 2 ? 1.55 : 2.15;
    pill(s, t, x, y, w);
  });
  text(s, "CWE-295, improper certificate validation. Without the check, an active attacker can read HTTPS traffic. The seven sins do not cover this.", 0.6, 2.85, 8.7, 0.8, { fontSize: 16 });
  stat(s, "1.01%", `of ${p.ansible.scripts.toLocaleString("en-US")} Ansible scripts (${p.ansible.smells.tls_verify_disabled.occurrences.toLocaleString("en-US")} occurrences)`, 0.6, 3.95, 3.95, 2.45, { color: C.accent1, size: 54, labelSize: 16 });
  stat(s, `${p.puppet.smells.tls_verify_disabled.script_pct.toFixed(2)}%  |  ${p.chef.smells.tls_verify_disabled.script_pct.toFixed(2)}%`, "of Puppet scripts  |  of Chef scripts", 4.79, 3.95, 3.95, 2.45, { size: 32, labelSize: 16 });
  stat(s, "59 / 60", "sampled findings are correct. One rater checked the sample.", 8.98, 3.95, 3.75, 2.45, { color: C.accent2, size: 44, labelSize: 16 });
  card(s, 9.6, 1.55, 3.13, 2.05, C.accent6, "False alarm");
  text(s, "The one false alarm", 9.8, 1.65, 2.75, 0.35, { fontSize: 15, bold: true });
  text(s, "A test asserts OPENSTACK_SSL_NO_VERIFY = False, so the check stays on.", 9.8, 2.03, 2.75, 1.5, { fontSize: 14 });
}

// ============================================================ OM
// 10 --------------------------------------------------------- triage design
{
  const s = slide({
    section: SEC2, sectionName: SEC2, who: "Om", secs: 70,
    title: "Rules propose, a model decides",
    notes: "Thanks, Adheil. We keep the rules, because they are cheap and deterministic, and they find most smells. We add a step behind them. First, code collects facts about each finding: is the value a literal or a variable, does it look like a placeholder, is it a known key format, where does the URL point. Second, code masks anything that could be a working secret. The model sees only the shape of the value. Third, a decision model answers one question: is this a genuine instance of this smell, by this definition? We use TypeSafe Jev. It does not write text. It returns a probability. Fourth, code makes the final decision with a threshold tuned on training folds. So the model is one replaceable part, and code stays in control.",
  });
  const steps = [
    ["Rules", "Find candidates with high recall", C.accent5],
    ["Facts", "Code reads value kind, shape, entropy, URL host, path", C.accent5],
    ["Masking", "Code hides any value that may be a real secret", C.accent5],
    ["Decision model", "Jev answers one question and returns a probability", C.accent1],
    ["Threshold", "Code keeps or drops the finding", C.accent5],
  ];
  const W = 2.2, G = 0.2825;
  steps.forEach(([h, b, col], i) => {
    const x = 0.6 + i * (W + G);
    card(s, x, 1.55, W, 2.2, i === 3 ? C.accent6 : C.background2);
    badge(s, i + 1, x + 0.18, 1.72, 0.45, col);
    text(s, h, x + 0.72, 1.72, W - 0.82, 0.45, { fontSize: 15, bold: true, valign: "middle" });
    text(s, b, x + 0.18, 2.33, W - 0.33, 1.3, { fontSize: 15 });
  });
  text(s, "What leaves the machine", 0.6, 4.0, 6, 0.35, { fontSize: 18, bold: true });
  code(s, [
    { t: 'In the script:  db_password: "Zx9#qL2!vT7pW4rK"' },
    { t: "Model sees:     Zx************rK (len 16)", c: C.accent3 },
    { t: "                entropy_bucket: high" },
  ], 0.6, 4.4, 7.3, 1.55, { fontSize: 14 });
  text(s, "Illustrative value. Placeholders such as “changeme” are sent in clear.", 0.6, 6.03, 7.3, 0.3, { fontSize: 12, color: C.text2 });
  text(s, "The one question", 8.2, 4.0, 4.5, 0.35, { fontSize: 18, bold: true });
  card(s, 8.2, 4.4, 4.53, 2.2);
  text(s, "“Is the linter finding a genuine instance of the named security smell in this code, according to the definition?”", 8.42, 4.55, 4.1, 1.35, { fontSize: 15, italic: true });
  text(s, "Answer: P(yes), a number from 0 to 1", 8.42, 5.98, 4.1, 0.4, { fontSize: 15, bold: true });
}

// 11 --------------------------------------------------------- RQ3 main
{
  const t = stats.rq3_tests["jev-full vs rules"];
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 55,
    title: "RQ3: precision up 0.22, recall down 0.05",
    notes: `We tested 269 candidate findings: 151 true and 118 false. The rules alone have precision 0.56 and recall 0.86. With Jev and the full context, precision rises to 0.78 and recall falls to 0.81. F1 rises from 0.68 to 0.80. Recall counts all 176 labelled smells, so the rules' own misses count against us. The result is significant. In a paired test, the triage step corrected ${t.a_right_b_wrong} decisions and broke ${t.a_wrong_b_right}. The McNemar p-value is about 2 times 10 to the minus 15. A file-level bootstrap gives an F1 gain of 0.125, with a 95 percent interval from 0.08 to 0.18. Context also helped: the full state beat the flagged line alone by 0.03 F1, and that interval excludes zero.`,
  });
  const labels = ["Precision", "Recall", "F1"];
  s.addChart(pres.ChartType.bar, [
    { name: "Rules only", labels, values: [m("rules").P, m("rules").R, m("rules").F1] },
    { name: "Rules + Jev (full context)", labels, values: [m("jev-full").P, m("jev-full").R, m("jev-full").F1] },
  ], barOpts({ x: 0.6, y: 1.45, w: 7.4, h: 5.3, chartColors: [C.accent4, C.accent1], altText: "Precision, recall and F1 of rules only and rules plus Jev" }));
  stat(s, "+0.125", `F1 gain. 95% bootstrap interval: ${f2(t.dF1_ci95[0])} to ${f2(t.dF1_ci95[1])}`, 8.3, 1.55, 4.43, 1.9, { color: C.accent1, size: 40, valueH: 0.75 });
  stat(s, `${t.a_right_b_wrong} vs ${t.a_wrong_b_right}`, "decisions corrected vs broken. McNemar p ≈ 2 × 10⁻¹⁵", 8.3, 3.65, 4.43, 1.9, { size: 40, valueH: 0.75 });
  text(s, "269 candidates (151 true, 118 false). 5-fold cross-validation by file, 10 seeds. Recall counts all 176 labelled smells.", 8.3, 5.75, 4.43, 0.9, { fontSize: 13, color: C.text2 });
}

// 12 --------------------------------------------------------- per smell
{
  const per = stats.rq3_per_smell_last_seed;
  const order = [["hardcoded_secret", "Secret"], ["suspicious_comment", "Comment"], ["http_without_tls", "HTTP"], ["admin_by_default", "Admin"], ["empty_password", "Empty pw"], ["invalid_bind", "IP bind"], ["weak_crypto", "Crypto"]];
  const labels = order.map((o) => o[1]);
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 50,
    title: "Most of the gain comes from secrets",
    notes: "This chart shows precision per smell. Almost all of the gain comes from hard-coded secrets. False alarms fall from 80 to 4, and precision rises from 0.25 to 0.83. The price is 7 of 27 true secrets. These are mostly plain service names like nginx and zabbix, and placeholder passwords like foo. The labels count these as smells, but a reviewer may call them harmless. HTTP does not change, because Jev keeps all those findings. Many HTTP 'false alarms' look real to us, for example http colon slash slash download dot sonatype dot com. So those may be missed labels in the test set. The values on this slide come from one cross-validation seed.",
  });
  s.addChart(pres.ChartType.bar, [
    { name: "Rules only", labels, values: order.map((o) => per[o[0]].rules.P) },
    { name: "Rules + Jev", labels, values: order.map((o) => per[o[0]]["jev-full"].P) },
  ], barOpts({ x: 0.6, y: 1.45, w: 8.0, h: 5.3, chartColors: [C.accent4, C.accent1], valAxisMaxVal: 1.1, showTitle: true, title: "Precision per smell (one cross-validation seed)", titleFontFace: "+mn-lt", titleFontSize: 15, titleColor: C.text1, altText: "Precision per smell for rules only and rules plus Jev" }));
  stat(s, "80 → 4", "false hard-coded secret alarms", 8.85, 1.55, 3.88, 1.75, { color: C.accent1, size: 40, valueH: 0.75 });
  stat(s, "27 → 20", "true hard-coded secrets kept", 8.85, 3.45, 3.88, 1.75, { size: 40, valueH: 0.75 });
  text(s, "Lost secrets are mostly plain service names (nginx, zabbix) and placeholders (foo, fixme). The labels count these as smells.", 8.85, 5.35, 3.88, 1.3, { fontSize: 15 });
}

// 13 --------------------------------------------------------- models
{
  const list = [
    ["llm-anthropic_claude-haiku-5.5", "Claude Haiku 5.5 (chat)"], ["dm-openai_gpt-6-luna-decisions", "GPT-6 Luna Decisions"], ["jev-full", "Jev 1.13"], ["dm-liquid_d1-ultra", "Liquid d1-ultra"],
    ["dm-perplexity_pplx-decider-v1.2", "Perplexity Decider"], ["dm-typesafe_jev-1.14", "Jev 1.14"], ["dm-inception_mercury-decide", "Mercury-Decide"], ["dm-cloudflare_clef", "Cloudflare Clef"],
    ["logreg", "LogReg on our facts"], ["dm-upstage_solar-decide", "Upstage Solar-Decide"], ["rules", "Rules only"], ["dm-microsoft_microsoft-decision-1", "Microsoft Decision-1"],
  ];
  const rev = [...list].reverse(); // horizontal bars draw bottom-up
  const t = stats.rq3_tests["llm-anthropic_claude-haiku-5.5 vs jev-full"];
  const cj = stats.rq3_cost_latency["jev-full"], ch = stats.rq3_cost_latency["llm-anthropic_claude-haiku-5.5"];
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 55,
    title: "A chat model is not significantly better",
    notes: `We replaced Jev with other models. The API makes that a one-line change. Claude Haiku has the highest F1, 0.81, but the paired difference to Jev is not significant: p is 0.33, and the interval includes zero. Haiku costs about four times more and takes about three times longer per call. Jev costs ${cj[0].toFixed(3)} dollars per thousand findings. Most decision models land between 0.75 and 0.80. Two are no better than the rules alone. So we conclude: pin the model version, and test before you trust a model. Jev also beats a simple logistic regression in paired decisions, but its F1 interval includes zero. We do not claim that Jev is the best model. We claim that this design works, and the model can be replaced.`,
  });
  s.addChart(pres.ChartType.bar, [{ name: "F1", labels: rev.map((x) => x[1]), values: rev.map((x) => m(x[0]).F1) }], barOpts({
    x: 0.6, y: 1.45, w: 7.6, h: 5.35, barDir: "bar", chartColors: rev.map((x) => (x[0] === "jev-full" ? "C43A4B" : x[0].startsWith("llm") ? "E8A100" : x[0] === "rules" || x[0] === "logreg" ? "4A4E5C" : "7B8794")),
    showLegend: false, barGapWidthPct: 30, valAxisMaxVal: 1, catAxisLabelFontSize: 12, altText: "F1 of twelve triage methods, sorted",
  }));
  const hdr = (x, a) => ({ text: x, options: { bold: true, align: a || "right", fill: { color: C.text1 }, color: C.background1 } });
  const r = (x) => ({ text: x, options: { align: "right" } });
  s.addTable([
    [hdr("", "left"), hdr("Jev 1.13"), hdr("Haiku 5.5")],
    ["F1", r(f2(m("jev-full").F1)), r(f2(m("llm-anthropic_claude-haiku-5.5").F1))],
    ["USD per 1,000", r(cj[0].toFixed(3)), r(ch[0].toFixed(3))],
    ["Median latency", r(`${f2(cj[1])} s`), r(`${f2(ch[1])} s`)],
  ], { x: 8.45, y: 1.55, w: 4.28, colW: [1.88, 1.2, 1.2], rowH: 0.5, fontSize: 15, color: C.text1, valign: "middle", border: { type: "solid", pt: 0.75, color: "D9DBE1" }, objectName: "Jev vs Haiku" });
  card(s, 8.45, 3.8, 4.28, 1.3);
  text(s, `Paired test: p = ${f2(t.mcnemar_p)}. The F1 difference interval, ${f2(t.dF1_ci95[0])} to ${f2(t.dF1_ci95[1])}, includes zero.`, 8.65, 3.92, 3.88, 1.05, { fontSize: 15, valign: "middle" });
  card(s, 8.45, 5.3, 4.28, 1.35, C.accent6, "Lesson");
  text(s, "Pin the version and test first. Two decision models are no better than the rules.", 8.65, 5.42, 3.88, 1.1, { fontSize: 15, bold: true, valign: "middle" });
}

// 14 --------------------------------------------------------- practitioner surprise
{
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 45,
    title: "A surprise: practitioner context hurt F1",
    notes: "Here is a result we did not expect. The original paper quotes developers who reject findings because of context, for example 'it's using http on localhost, what's the risk?'. So we wrote a filter with those arguments. It drops placeholder passwords, loopback URLs and similar cases. It made F1 worse: 0.64 against 0.68 for rules alone. Recall fell from 0.86 to 0.74. The reason is the test set. Its raters label a password like 'vagrant' as a smell, because by definition it is one. A developer may still not fix it. So 'is it a smell?' and 'should we fix it?' are two different questions, and this test set answers only the first. A future study should label both.",
  });
  card(s, 0.6, 1.55, 5.93, 3.2);
  text(s, "What a developer said (paper, RQ4)", 0.85, 1.72, 5.4, 0.4, { fontSize: 18, bold: true });
  text(s, "“It’s using http on localhost, what’s the risk?”", 0.85, 2.25, 5.4, 1.0, { fontSize: 24, italic: true, fontFace: THEME.headFontFace, valign: "middle" });
  text(s, "So we wrote a filter that drops placeholder secrets, file paths, and loopback or namespace URLs.", 0.85, 3.45, 5.4, 1.1, { fontSize: 16 });
  card(s, 6.8, 1.55, 5.93, 3.2);
  text(s, "What the test-set raters labelled as smells", 7.05, 1.72, 5.45, 0.4, { fontSize: 18, bold: true });
  pill(s, "password => 'password'", 7.05, 2.28, 3.5);
  pill(s, "password: ChangeThisPa55w0rd", 7.05, 2.8, 4.3);
  pill(s, "password 'vagrant'", 7.05, 3.32, 3.0);
  text(s, "By definition these are hard-coded secrets, so the filter dropped true labels.", 7.05, 3.88, 5.45, 0.75, { fontSize: 16 });
  [["0.68", "F1, rules only", C.accent4], ["0.64", "F1, with the practitioner filter", C.accent1]].forEach(([v, l, col], i) => {
    const x = 0.6 + i * 3.05;
    text(s, v, x, 4.95, 2.85, 0.8, { fontSize: 44, bold: true, fontFace: THEME.headFontFace, color: i ? C.accent1 : C.text2, valign: "middle" });
    text(s, l, x, 5.78, 2.85, 0.65, { fontSize: 15 });
  });
  card(s, 6.8, 4.95, 5.93, 1.65, C.text1, "Key point");
  text(s, "“Is it a smell?” and “Should we fix it?” are different questions. This test set answers only the first.", 7.05, 5.05, 5.45, 1.45, { fontSize: 18, bold: true, color: C.background1, valign: "middle" });
}

// 15 --------------------------------------------------------- RQ4
{
  const keys = ["placeholder|above", "placeholder|inline", "approval|above", "approval|inline", "injection|above", "injection|inline"];
  const labels = [["above", "inline", "above", "inline", "above", "inline"], ["placeholder", "", "approval", "", "injection", ""]];
  const series = (A, kind) => keys.map((k) => A[k][kind].flip_rate * 100);
  const opts = (x, title) => barOpts({ x, y: 1.4, w: 6.0, h: 3.65, chartColors: [C.accent1, C.accent2], valAxisMaxVal: 115, dataLabelFormatCode: "0", catAxisLabelFontSize: 12, dataLabelFontSize: 12, legendFontSize: 12, showTitle: true, title, titleFontFace: "+mn-lt", titleFontSize: 15, titleColor: C.text1, altText: title });
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 70,
    title: "RQ4: one comment can fool the model",
    notes: "Anyone who can open a pull request can add a comment. So we inserted one comment next to each true finding and measured how often the model changed its mind. We used three texts: a false claim that the value is a dummy, a false claim of security approval, and a direct instruction to answer false. On the decision model, the direct instruction above the line flips 97.5 percent of true findings. Claude Haiku ignores that instruction, but it believes the dummy-value claim: up to 20 percent flip. Then we tested a fix: remove all comments from the model's input. Flips fall to 1.6 percent or less, with no loss of accuracy. Our first fix missed one field, the flagged line, and 45 percent of inline attacks still worked. So a fix must cover every field. Two cautions. These rates are at each model's tuned threshold, and backup slide 18 shows a threshold of 0.5, where rates are higher. Also, the API credit ran out, so we did not run this on Jev itself.",
  });
  s.addChart(pres.ChartType.bar, [
    { name: "Comments visible", labels, values: series(merc, "visible") },
    { name: "Comments removed", labels, values: series(merc, "removed") },
  ], opts(0.45, "Mercury-Decide, decision model: flip rate, % (n = 132)"));
  s.addChart(pres.ChartType.bar, [
    { name: "Comments visible", labels, values: series(haiku, "visible") },
    { name: "Comments removed", labels, values: series(haiku, "removed") },
  ], opts(6.88, "Claude Haiku 5.5, chat model: flip rate, % (n = 59)"));
  const notes4 = [
    ["97.5%", "A direct instruction flips the decision model."],
    ["20.0%", "Haiku ignores instructions, but it believes “dummy value”."],
    ["≤ 1.6%", "With comments removed, at the tuned threshold."],
    ["45.2%", "Inline flips left by our first fix, which missed one field."],
  ];
  notes4.forEach(([v, l], i) => {
    const x = 0.6 + i * 3.08;
    card(s, x, 5.15, 2.9, 1.3, i === 2 ? C.accent6 : C.background2);
    text(s, v, x + 0.15, 5.2, 2.6, 0.5, { fontSize: 24, bold: true, fontFace: THEME.headFontFace, valign: "middle" });
    text(s, l, x + 0.15, 5.7, 2.65, 0.72, { fontSize: 14 });
  });
  text(s, "Flip = a kept true finding becomes “drop”. Tuned thresholds: 0.05 (Mercury), 0.12 (Haiku). Jev itself was not attacked: API credit ran out.", 0.6, 6.53, 12.13, 0.3, { fontSize: 12, color: C.text2 });
}

// 16 --------------------------------------------------------- limits
{
  const s = slide({
    sectionName: SEC2, who: "Om", secs: 55,
    title: "What our results do not show",
    notes: "We want to be clear about the limits. The test sets are small, and rare smells have fewer than ten instances, so per-smell numbers for those are weak. The labels contain noise. We refined the rules on 30 percent of the same files, so the candidate generator is not fully independent of the test data. Jev itself was not attacked in RQ4. The attack rates depend on the threshold. And one rater checked the TLS sample. All the code and the numbers are public, so anyone can check or extend this work.",
  });
  const lim = [
    ["Small test sets", "176 labelled smells in total. Weak crypto and empty password have 10 or fewer."],
    ["Label noise", "Some “false” HTTP findings look real, so the labels may miss true smells."],
    ["Rules saw part of the data", "We refined rules on 30% of the same files that cross-validation uses."],
    ["Jev not attacked", "RQ4 used Mercury-Decide and Haiku. The script runs on Jev with API credit."],
    ["Threshold matters", "At a fixed 0.5, attack rates rise. Haiku placeholder flips reach 50%. See slide 18."],
    ["One rater for TLS", "One rater checked the 60 sampled findings. Agreement is not measured."],
  ];
  lim.forEach(([h, b], i) => {
    const x = 0.6 + (i % 3) * 4.14, y = 1.55 + Math.floor(i / 3) * 2.6;
    card(s, x, y, 3.85, 2.35);
    text(s, h, x + 0.25, y + 0.2, 3.35, 0.45, { fontSize: 18, bold: true, valign: "top" });
    text(s, b, x + 0.25, y + 0.72, 3.35, 1.5, { fontSize: 16 });
  });
}

// 17 --------------------------------------------------------- takeaways
{
  const s = slide({
    sectionName: SEC2, dark: true, who: "Om", secs: 40,
    title: "Three takeaways",
    notes: "Three takeaways. One: publish rules as tested code, because the paper alone did not reproduce the tool. Two: keep rules in front and put a decision model behind them. Precision rose from 0.56 to 0.78 for a few cents per thousand findings. Three: keep comments out of the model's input, because one comment can reverse its decision. The code, data links and paper are on GitHub. Thank you. We are happy to take your questions.",
  });
  const tk = [
    ["Publish rules as tested code", "From the paper: 58% agreement. From the code: 99%."],
    ["Keep rules first, then add a model", "Precision 0.56 → 0.78, recall 0.86 → 0.81, at USD 0.035 per 1,000 findings."],
    ["Keep comments out of model input", "One comment flips up to 97.5% of true findings. Removal brings this to 1.6% at the tuned threshold."],
  ];
  tk.forEach(([h, b], i) => {
    const y = 2.4 + i * 1.15;
    badge(s, i + 1, 0.8, y + 0.05, 0.6, C.accent1);
    text(s, h, 1.65, y, 10.8, 0.45, { fontSize: 24, bold: true, color: C.background1 });
    text(s, b, 1.65, y + 0.47, 10.8, 0.4, { fontSize: 16, color: C.background1 });
  });
  text(s, "Thank you. Questions?", 0.8, 5.95, 6.5, 0.6, { fontSize: 28, bold: true, fontFace: THEME.headFontFace, color: C.background1, valign: "middle" });
  text(s, "github.com/iAmAdheil/slicj-seven-sins-revisited", 0.8, 6.55, 11.7, 0.35, { fontSize: 15, color: C.background1 });
}

// ============================================================ BACKUP
const hd = (x, a) => ({ text: x, options: { bold: true, align: a || "right", fill: { color: C.text1 }, color: C.background1 } });
const rr = (x, b) => ({ text: x, options: { align: "right", bold: !!b } });
const tblOpts = (o) => Object.assign({ fontSize: 14, color: C.text1, valign: "middle", border: { type: "solid", pt: 0.75, color: "D9DBE1" } }, o);

// B1 RQ4 at fixed threshold
{
  const s = slide({
    section: SEC3, sectionName: SEC3, backup: true, who: "Om",
    title: "Backup: RQ4 at a fixed threshold of 0.5",
    notes: "Use this slide if the professor asks about thresholds. The tuned thresholds are low, 0.05 and 0.12, because F1 on this data rewards keeping almost everything. At a threshold of 0.5, attack rates are higher. Haiku placeholder flips reach about 50 percent. With comments removed, Haiku still shows 16.1 percent in the 'above' position. That number is the same for all three attack texts, because after comment removal the three inputs are identical. So the attack text is not the cause. The likely cause is the shift of one line number, which moves some scores across 0.5.",
  });
  const keys = ["placeholder|above", "placeholder|inline", "approval|above", "approval|inline", "injection|above", "injection|inline"];
  const body = keys.map((k) => {
    const a = merc[k], b = haiku[k];
    return [k.replace("|", ", "), rr(pct1(a.visible.flip_rate)), rr(pct1(a["flip_rate_at_0.5"].visible)), rr(pct1(a["flip_rate_at_0.5"].removed)), rr(pct1(b.visible.flip_rate)), rr(pct1(b["flip_rate_at_0.5"].visible)), rr(pct1(b["flip_rate_at_0.5"].removed))];
  });
  s.addTable([
    [hd("Attack, position", "left"), hd("Mercury tuned, visible"), hd("Mercury 0.5, visible"), hd("Mercury 0.5, removed"), hd("Haiku tuned, visible"), hd("Haiku 0.5, visible"), hd("Haiku 0.5, removed")],
    ...body,
  ], tblOpts({ x: 0.6, y: 1.5, w: 12.13, colW: [2.83, 1.55, 1.55, 1.55, 1.55, 1.55, 1.55], rowH: [0.8, 0.45, 0.45, 0.45, 0.45, 0.45, 0.45], objectName: "RQ4 thresholds" }));
  text(s, "With comments removed, the “above” inputs are identical across the three attack texts. The remaining flips therefore do not come from the attack text. The likely cause is the shift of one line number, which moves scores near 0.5.", 0.6, 5.3, 12.13, 0.95, { fontSize: 16 });
  text(s, "Kept true findings at 0.5: Mercury 105 (visible), 106 (removed). Haiku 32 (visible), 31 (removed).", 0.6, 6.35, 12.13, 0.3, { fontSize: 12, color: C.text2 });
}

// B2 RQ3 table
{
  const s = slide({
    sectionName: SEC3, backup: true, who: "Om",
    title: "Backup: RQ3 results for key methods",
    notes: "Mean over 10 seeds of grouped 5-fold cross-validation, with the threshold tuned inside the training folds. AUC and ECE use the raw scores. The hybrid is a logistic regression over the facts plus Jev's probability. It has the best AUC and calibration and the highest precision, but its tuned threshold gives lower recall. The full table with all models is in the paper.",
  });
  const list = [["rules", "Rules only"], ["context-filter", "Practitioner filter"], ["logreg", "LogReg on facts"], ["jev-line", "Jev 1.13, line only"], ["jev-full", "Jev 1.13, full context"], ["jev-full_nocomments", "Jev 1.13, no comments"], ["llm-anthropic_claude-haiku-5.5", "Claude Haiku 5.5"], ["hybrid:jev-full", "Hybrid: LogReg + Jev"]];
  s.addTable([
    [hd("Method", "left"), hd("Precision"), hd("Recall"), hd("F1"), hd("AUC"), hd("ECE")],
    ...list.map(([k, nm]) => [{ text: nm, options: { bold: k === "jev-full" } }, rr(f3(m(k).P), k === "jev-full"), rr(f3(m(k).R), k === "jev-full"), rr(f3(m(k).F1), k === "jev-full"), rr(m(k).AUC ? f3(m(k).AUC) : "–"), rr(m(k).ECE ? f3(m(k).ECE) : "–")]),
  ], tblOpts({ x: 0.6, y: 1.5, w: 12.13, colW: [4.63, 1.5, 1.5, 1.5, 1.5, 1.5], rowH: 0.5, objectName: "RQ3 table" }));
  text(s, "AUC = how well scores rank true above false. ECE = gap between predicted and observed rates (lower is better).", 0.6, 6.25, 12.13, 0.3, { fontSize: 12, color: C.text2 });
}

// B3 tests
{
  const T = stats.rq3_tests;
  const s = slide({
    sectionName: SEC3, backup: true, who: "Om",
    title: "Backup: paired statistical tests",
    notes: "McNemar compares two methods on the same candidates, using only the cases where they disagree. The bootstrap resamples files, not findings, because findings in one file are not independent. A difference is clear when the interval excludes zero. Note that Jev versus logistic regression has a significant McNemar test, but its F1 interval includes zero, so we describe that one as weaker evidence.",
  });
  const rowsT = [["jev-full vs rules", "Jev vs rules only"], ["jev-full vs context-filter", "Jev vs practitioner filter"], ["jev-full vs logreg", "Jev vs LogReg"], ["jev-full vs jev-line", "Jev full vs Jev line only"], ["llm-anthropic_claude-haiku-5.5 vs jev-full", "Haiku vs Jev"], ["hybrid:jev-full vs jev-full", "Hybrid vs Jev"]];
  const fp = (p) => (p < 0.001 ? p.toExponential(1) : p.toFixed(3));
  s.addTable([
    [hd("Comparison (A vs B)", "left"), hd("A right, B wrong"), hd("A wrong, B right"), hd("McNemar p"), hd("ΔF1"), hd("95% interval")],
    ...rowsT.map(([k, nm]) => [nm, rr(String(T[k].a_right_b_wrong)), rr(String(T[k].a_wrong_b_right)), rr(fp(T[k].mcnemar_p)), rr((T[k].dF1_mean >= 0 ? "+" : "") + f3(T[k].dF1_mean)), rr(`${f3(T[k].dF1_ci95[0])} to ${f3(T[k].dF1_ci95[1])}`)]),
  ], tblOpts({ x: 0.6, y: 1.5, w: 12.13, colW: [3.83, 1.5, 1.5, 1.4, 1.2, 2.7], rowH: [0.75, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5], objectName: "Tests" }));
  text(s, "Decisions come from one cross-validation seed. The bootstrap resamples files (2,000 samples).", 0.6, 5.5, 12.13, 0.3, { fontSize: 12, color: C.text2 });
}

// B4 prevalence
{
  const s = slide({
    sectionName: SEC3, backup: true, who: "Adheil",
    title: "Backup: smell prevalence in the corpora",
    notes: "Percent of scripts with at least one occurrence. Script selection follows GLITCH, by file extension, so some YAML files are not Ansible. Our any-smell rate of 14.5 to 18.7 percent is below SLAC's published 25 to 30 percent. Two reasons may explain this: our rules do not count variable references as hard-coded, and the corpus is different. These counts are rule findings before triage, so they include false alarms.",
  });
  const names = [["admin_by_default", "Admin by default"], ["empty_password", "Empty password"], ["hardcoded_secret", "Hard-coded secret"], ["invalid_bind", "Invalid IP binding"], ["suspicious_comment", "Suspicious comment"], ["http_without_tls", "HTTP without TLS"], ["weak_crypto", "Weak crypto"], ["tls_verify_disabled", "TLS checks off (new)"]];
  const T = ["puppet", "ansible", "chef"];
  s.addTable([
    [hd("% of scripts", "left"), hd("Puppet"), hd("Ansible"), hd("Chef")],
    ...names.map(([k, nm]) => [nm, ...T.map((t) => rr(prev[t].smells[k].script_pct.toFixed(2)))]),
    [{ text: "Any of the seven", options: { bold: true } }, ...T.map((t) => rr(prev[t].seven_sins_any_pct.toFixed(1), true))],
    [{ text: "Scripts", options: { bold: true } }, ...T.map((t) => rr(prev[t].scripts.toLocaleString("en-US"), true))],
  ], tblOpts({ x: 0.6, y: 1.45, w: 12.13, colW: [5.23, 2.3, 2.3, 2.3], rowH: 0.42, objectName: "Prevalence" }));
  text(s, "Rule findings before triage, so these counts include false alarms.", 0.6, 6.3, 12.13, 0.3, { fontSize: 12, color: C.text2 });
}

// B5 demo
{
  const s = slide({
    sectionName: SEC3, backup: true, who: "Adheil",
    title: "Backup: live demo of the linter",
    notes: "If the professor asks to see it run, open a terminal in the project folder and run these commands. The scan needs no API key and finishes at once. The tests take less than a second. The fixture site.yml has a hard-coded password, an HTTP URL, validate_certs set to no, and curl dash k.",
  });
  code(s, [
    { t: "# scan the example scripts" },
    { t: ".venv/bin/python -m slicj scan tests/fixtures --out results/demo_scan.csv", c: C.accent3 },
    { t: "cat results/demo_scan_lines.csv", c: C.accent3 },
    { t: " " },
    { t: "# run the test suite" },
    { t: ".venv/bin/python -m pytest -q tests", c: C.accent3 },
  ], 0.6, 1.55, 12.13, 2.85, { fontSize: 16 });
  text(s, "The report gives one row per finding, with file, line, smell, name and value.", 0.6, 4.65, 12.13, 0.4, { fontSize: 16 });
  text(s, "Code, paper and result files: github.com/iAmAdheil/slicj-seven-sins-revisited", 0.6, 5.1, 12.13, 0.4, { fontSize: 16, bold: true });
}

// ------------------------------------------------------------ speaker script
const QA = [
  ["Why did SLIC score 0.99 in the paper and much lower here?", "Adheil", "The test sets differ. The paper's raters labelled 140 scripts where most scripts had no smell. The GLITCH set was built to contain more smell candidates, and its raters use a wider admin definition. We cannot run SLIC on the paper's own set, because its figshare link now returns a 404."],
  ["Is your port really better than GLITCH?", "Adheil", "We do not claim that. It is ahead on Puppet and Chef and behind on Ansible. We refined our rules on 30 percent of these files, and GLITCH was not tuned on them. So 'competitive' is the correct word."],
  ["Why is the recall ceiling 0.858?", "Adheil", "The rules produce 151 of the 176 labelled smells. Triage can only drop candidates, so it cannot recover the other 25."],
  ["What is Jaccard and why use it?", "Adheil", "Shared findings divided by all findings of both tools. It measures whether two tools report the same things, not whether those things are correct."],
  ["Why is your any-smell rate lower than SLAC's?", "Adheil", "Our rules do not count variable references or lookups as hard-coded. The corpus also differs, so we cannot separate the two effects."],
  ["How do you stop overfitting?", "Om", "Thresholds and logistic weights are fit only on training folds, and folds are grouped by file. The remaining risk: rule refinement looked at 30 percent of the same files. We list that as a threat."],
  ["What is McNemar, and why a file-level bootstrap?", "Om", "McNemar compares two methods on the same items, using only the items where they disagree. We resample files because findings in one file are not independent."],
  ["Why Jev and not Haiku, which scored higher?", "Om", "The difference is not significant. Jev costs about a quarter as much and is about three times faster per call. The design does not depend on Jev. A team can use either model."],
  ["What is calibration, and is Jev calibrated?", "Om", "A calibrated 0.8 means about 80 percent of those cases are true. Jev is not well calibrated: ECE is 0.152. The hybrid is better at 0.073, so tune thresholds on your own sample."],
  ["Why are the RQ4 thresholds so low?", "Om", "F1 on this data rewards keeping almost everything, so the best threshold is near 0.05 to 0.12. That is why backup slide 18 also shows 0.5, where attack rates are higher."],
  ["Why was RQ4 not run on Jev?", "Om", "The OpenRouter free allowance ran out after RQ3. We used a free decision model and the Claude CLI. The script runs unchanged on Jev with credit. So we do not know Jev's own flip rate."],
  ["The Haiku arm ran through a CLI. Does that matter?", "Om", "The CLI loads a user-level instruction file, so the context is not empty. It is the same for clean and attacked inputs. On RQ3 the CLI arm scores F1 0.809 and the API arm 0.811, so the two paths agree closely."],
  ["Does masking fully protect secrets?", "Om", "No. It masks values that do not look like placeholders or plain identifiers, and lines with a sensitive name. A secret on a line with an unrelated name can reach the model. It reduces exposure. It does not remove it."],
  ["How does this differ from IntelliSA (MSR 2026)?", "Om", "IntelliSA also uses rules and then a neural filter, and it reports F1 83 percent on its own data. We add a verified reproduction of SLIC, a new smell, a comparison of decision models, calibration, secret masking and a prompt-injection test. The data sets differ, so the F1 values are not directly comparable."],
  ["Which parts did each of you do?", "Both", "ANSWER THIS IN YOUR OWN WORDS. See the note at the top of this file."],
  ["Did you use AI tools?", "Both", "ANSWER THIS HONESTLY, as your course policy requires. See the note at the top of this file."],
];
const talk = script.filter((x) => !x.backup);
const tot = (w) => talk.filter((x) => x.who === w).reduce((a, x) => a + x.secs, 0);
const fmt = (s) => `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
let md = `# Speaker script: Seven Sins Revisited\n\nGenerated by \`build_deck.js\` from the same source as the slides. The script is also in the speaker notes of each slide.\n\n`;
md += `**Planned time:** ${fmt(tot("Adheil") + tot("Om"))} (Adheil ${fmt(tot("Adheil"))}, Om ${fmt(tot("Om"))}), then questions.\n\n`;
md += `**Hand-offs:** Adheil gives the opening and slides 1 to 9. Om gives slides 10 to 17 and the close.\n\n`;
md += `**If the slot is 10 minutes:** skip slides 3, 7 and 14, and move the details of slide 12 to questions.\n\n`;
md += `## Before you present\n\n1. Fill in the speaker split. It comes from the plan in your earlier chat. Change it to match who did what.\n2. Check the 60 TLS labels in \`results/rq2/tls_sample.csv\`. The slides say "one rater". That must be true for one of you.\n3. Prepare honest answers to the last two questions below.\n4. Run the demo commands on backup slide 22 once on the presenting laptop.\n\n`;
md += `## Script\n\n`;
for (const x of script) {
  if (x === script.find((y) => y.backup)) md += `## Backup slides (use only if asked)\n\n`;
  md += `### Slide ${x.n}: ${x.title}\n\n**${x.who}**${x.backup ? "" : `, about ${x.secs} seconds`}\n\n${x.notes}\n\n`;
}
md += `## Likely questions\n\n`;
for (const [q, w, a] of QA) md += `**Q: ${q}** (${w})\n\n${a}\n\n`;
fs.writeFileSync(path.join(__dirname, "speaker_script.md"), md);

// word-rate check: spoken English is about 130 to 150 words per minute
for (const x of talk) {
  const words = x.notes.split(/\s+/).length;
  const need = Math.round((words / 140) * 60);
  if (need > x.secs + 8) console.log(`timing: slide ${x.n} needs about ${need}s for ${words} words, planned ${x.secs}s`);
}
console.log(`talk ${fmt(tot("Adheil") + tot("Om"))}; Adheil ${fmt(tot("Adheil"))}; Om ${fmt(tot("Om"))}; slides ${script.length}`);

(async () => {
  const out = path.join(__dirname, "Seven_Sins_Revisited_Presentation.pptx");
  await pres.writeFile({ fileName: out });
  await applyTheme(out, THEME);
  console.log("wrote", out);
})();
