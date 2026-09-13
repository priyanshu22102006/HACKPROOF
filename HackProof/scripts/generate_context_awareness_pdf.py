#!/usr/bin/env python3
"""Generate a comprehensive, publication-grade PDF guide explaining how HACKPROOF Context Awareness works."""

import os
import shutil
import subprocess
import sys


def generate_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HACKPROOF: Context Awareness Engine & Evidence Correlation</title>
<style>
  @page {
    size: A4 portrait;
    margin: 14mm 12mm 14mm 12mm;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.45;
    font-size: 9pt;
    margin: 0;
    padding: 0;
  }
  .header-card {
    background: linear-gradient(135deg, #090d16 0%, #1e1b4b 55%, #312e81 100%);
    color: #ffffff;
    padding: 20px 22px;
    border-radius: 10px;
    margin-bottom: 16px;
  }
  .header-badge {
    display: inline-block;
    background: rgba(99, 102, 241, 0.35);
    color: #c7d2fe;
    border: 1px solid rgba(165, 180, 252, 0.4);
    font-size: 7.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 3px 10px;
    border-radius: 20px;
    margin-bottom: 6px;
  }
  .header-title {
    font-size: 16pt;
    font-weight: 800;
    margin: 0 0 4px 0;
  }
  .header-desc {
    font-size: 9.5pt;
    color: #cbd5e1;
    margin: 0;
  }
  h2 {
    font-size: 11.5pt;
    font-weight: 800;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 4px;
    margin: 16px 0 10px 0;
    display: flex;
    align-items: center;
  }
  h2 .num {
    background: #4338ca;
    color: white;
    width: 20px;
    height: 20px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 8pt;
    margin-right: 8px;
  }
  h3 {
    font-size: 10pt;
    font-weight: 700;
    color: #1e1b4b;
    margin: 12px 0 6px 0;
  }
  p { margin: 0 0 8px 0; }
  
  .card-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 12px;
  }
  .card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 10px 12px;
  }
  .card.highlight {
    border-left: 4px solid #4338ca;
    background: #fdfefe;
  }
  .card.warning {
    border-left: 4px solid #f59e0b;
    background: #fffbeb;
  }
  .card.danger {
    border-left: 4px solid #ef4444;
    background: #fef2f2;
  }
  .card-title {
    font-size: 9.5pt;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 4px;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0 12px 0;
    font-size: 8.5pt;
  }
  th {
    background: #f1f5f9;
    color: #334155;
    font-weight: 700;
    text-align: left;
    padding: 6px 8px;
    border: 1px solid #cbd5e1;
  }
  td {
    padding: 5px 8px;
    border: 1px solid #e2e8f0;
    vertical-align: top;
  }
  tr:nth-child(even) td { background: #f8fafc; }

  .badge-clean {
    background: #dcfce7;
    color: #166534;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 7.5pt;
  }
  .badge-warn {
    background: #fef3c7;
    color: #92400e;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 7.5pt;
  }
  .badge-danger {
    background: #fee2e2;
    color: #991b1b;
    padding: 2px 6px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 7.5pt;
  }

  pre, code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8pt;
  }
  pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 10px 12px;
    border-radius: 6px;
    overflow-x: hidden;
    line-height: 1.35;
    margin: 6px 0 10px 0;
    white-space: pre-wrap;
  }
  .terminal-box {
    background: #090d16;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: ui-monospace, Menlo, monospace;
    font-size: 8pt;
    line-height: 1.4;
    margin: 8px 0;
  }
  .t-green { color: #4ade80; font-weight: bold; }
  .t-red { color: #f87171; font-weight: bold; }
  .t-yellow { color: #facc15; font-weight: bold; }
  .t-cyan { color: #38bdf8; }
  .t-dim { color: #94a3b8; }

  .page-break {
    page-break-after: always;
  }
  .footer {
    font-size: 7.5pt;
    color: #94a3b8;
    text-align: center;
    margin-top: 14px;
    border-top: 1px solid #e2e8f0;
    padding-top: 6px;
  }
</style>
</head>
<body>

<!-- PAGE 1 -->
<div class="header-card">
  <div class="header-badge">HACKPROOF Provenance System • Architecture Specification</div>
  <h1 class="header-title">Context Awareness Engine: How It Works & Calculates</h1>
  <p class="header-desc">
    Complete mathematical and algorithmic specification for cross-plane evidence correlation, directed graph synthesis, anti-double-counting, and deterministic provenance risk scoring.
  </p>
</div>

<h2><span class="num">1</span> Executive Summary: The Context Problem</h2>
<p>
  Standard security tools evaluate checks in total isolation. A signature check notes an unsigned commit; a file check notes a <code>.gitignore</code> rule; a similarity checker flags a matched code block. 
  In a high-stakes hackathon audit, this creates two catastrophic failure modes:
</p>
<div class="card-grid">
  <div class="card danger">
    <div class="card-title">1. Fragmented Narrative Blindness</div>
    Judges receive 20+ isolated rows with no way to tell whether an unsigned commit and an uncommitted source file are part of a coordinated code smuggling attack or two harmless unrelated oversights.
  </div>
  <div class="card warning">
    <div class="card-title">2. Double-Counting Injustice</div>
    If a single stolen file triggers a similarity flag, a concealment flag, and a pre-T0 timestamp warning, naive scanners penalize the team 3 separate times for the exact same event.
  </div>
</div>
<p>
  The <strong>Context Awareness Engine</strong> sits above all four analyzer planes (GPG claim plane, .gitignore system plane, timestamp claim plane, and GitHub server plane). It translates raw findings into a directed evidence graph, correlates related entities, eliminates double-counting, and computes a deterministic risk verdict.
</p>

<h2><span class="num">2</span> 4-Stage Architectural Pipeline</h2>
<div class="card card.highlight" style="margin-bottom: 10px;">
  <strong>Pipeline Execution Flow:</strong><br>
  <code>Raw Findings (23 Checks) + Gitignore Blame View + Similarity Hits</code><br>
  &nbsp;&nbsp;➔ <strong>Stage 1 (Normalizer)</strong>: Ingests & maps findings into uniform <code>EvidenceItem</code> entities.<br>
  &nbsp;&nbsp;➔ <strong>Stage 2 (EvidenceGraph)</strong>: Constructs in-memory directed graph with typed nodes & edges.<br>
  &nbsp;&nbsp;➔ <strong>Stage 3 (Correlator)</strong>: Applies Rules 1–7, performs single-event grouping, builds narrative trees.<br>
  &nbsp;&nbsp;➔ <strong>Stage 4 (Risk Engine)</strong>: Calculates deterministic status badge, risk level, and confidence.
</div>

<table>
  <thead>
    <tr>
      <th style="width: 22%;">Module</th>
      <th style="width: 25%;">Source File</th>
      <th>Primary Responsibility & Algorithmic Function</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Normalization</strong></td>
      <td><code>core/context/normalizer.py</code></td>
      <td>
        Extracts entities (file path, commit SHA, author, email, timestamp, key ID). Enforces clone-safety by honoring <code>evaluable=False</code> so machine-local configs are never falsified.
      </td>
    </tr>
    <tr>
      <td><strong>Evidence Graph</strong></td>
      <td><code>core/context/graph.py</code></td>
      <td>
        In-memory graph storing 9 typed nodes (<code>File</code>, <code>Commit</code>, <code>Author</code>, etc.) and 10 typed directed edges (<code>AUTHORED_BY</code>, <code>INTRODUCED_BY</code>, <code>MATCHES</code>, etc.).
      </td>
    </tr>
    <tr>
      <td><strong>Correlation Engine</strong></td>
      <td><code>core/context/correlator.py</code></td>
      <td>
        Executes Rules 1 to 7. Groups related items by file and commit. Distinguishes benign build artifacts from real source concealment. Consolidates redundant signals into single chains.
      </td>
    </tr>
    <tr>
      <td><strong>Risk Engine</strong></td>
      <td><code>core/context/risk.py</code></td>
      <td>
        Evaluates chain severity rankings. Emits overall status, confidence level, key drivers, and unresolved advisory signals using strict deterministic logic (zero LLM).
      </td>
    </tr>
  </tbody>
</table>

<div class="footer">Page 1 • HACKPROOF Provenance System • Context Awareness Technical Guide</div>
<div class="page-break"></div>

<!-- PAGE 2 -->
<h2><span class="num">3</span> The 7 Deterministic Correlation Rules</h2>
<p>
  Every connection made by the engine is governed by seven deterministic rules. If a rule condition is met, the engine creates or merges a <code>CorrelationChain</code>:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 14%;">Rule</th>
      <th style="width: 24%;">Trigger Condition</th>
      <th style="width: 28%;">Graph Traversal & Linkage</th>
      <th style="width: 18%;">Severity & Badge</th>
      <th>Narrative Output</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Rule 1</strong></td>
      <td>Similarity match ≥ 75% <strong>AND</strong> source repo date &lt; $T_0$.</td>
      <td><code>(File) ─[MATCHES]─► (ExtRepo) ─[PREDATES]─► (T0)</code></td>
      <td><span class="badge-danger">hard_flag</span><br><strong>CONCERN</strong></td>
      <td>Pre-existing code importation / plagiarism detected.</td>
    </tr>
    <tr>
      <td><strong>Rule 2</strong></td>
      <td>File similarity match &gt; threshold <strong>AND</strong> Git blame attribution available.</td>
      <td><code>(File) ─[INTRODUCED_BY]─► (Commit) ─[AUTHORED_BY]─► (Author)</code></td>
      <td><span class="badge-warn">flag</span><br><strong>WARNING</strong></td>
      <td>Attributed code match with exact author, commit SHA, and date.</td>
    </tr>
    <tr>
      <td><strong>Rule 3</strong></td>
      <td>Author != GPG signer <strong>OR</strong> signer not in team roster.</td>
      <td><code>(Commit) ─[AUTHORED_BY]─► (Author) &amp; (Commit) ─[SIGNED_BY]─► (Key)</code></td>
      <td><span class="badge-warn">flag</span> / <span class="badge-danger">hard_flag</span><br><strong>CONCERN</strong></td>
      <td>Identity spoofing, shared account, or unregistered key usage.</td>
    </tr>
    <tr>
      <td><strong>Rule 4</strong></td>
      <td>File hidden in .gitignore or index flag (<code>skip-worktree</code>).</td>
      <td><code>(File) ─[HIDDEN_BY]─► (Rule) ─[INTRODUCED_BY]─► (Commit)</code></td>
      <td><span class="badge-clean">info</span> (Build artifact)<br><span class="badge-warn">flag</span> (Source code)</td>
      <td>Separates benign vendor folders (dist/, node_modules/) from source concealment.</td>
    </tr>
    <tr>
      <td><strong>Rule 5</strong></td>
      <td>Commit timestamp &lt; $T_0$ <strong>OR</strong> Author/Committer delta &gt; 24h.</td>
      <td><code>(Commit) ─[OCCURRED_AT]─► (Timestamp) ─[OUT_OF_BOUNDS]</code></td>
      <td><span class="badge-danger">hard_flag</span> / <span class="badge-warn">flag</span><br><strong>WARNING</strong></td>
      <td>Out-of-bounds commit, pre-baked history, or timestamp manipulation.</td>
    </tr>
    <tr>
      <td><strong>Rule 6</strong></td>
      <td>Commit in local clone missing from GitHub <strong>OR</strong> force-push detected.</td>
      <td><code>(Commit) ─[PUSHED_IN]─► (GitHub Events)</code></td>
      <td><span class="badge-warn">flag</span> / <span class="badge-danger">hard_flag</span><br><strong>WARNING</strong></td>
      <td>Unpushed work or history rewriting to conceal prior development.</td>
    </tr>
    <tr>
      <td><strong>Rule 7</strong></td>
      <td>Multiple signals point to the same root file or commit entity.</td>
      <td>Consolidates all items into <strong>1 CorrelationChain</strong>.</td>
      <td><strong>Worst Severity</strong><br>of component items</td>
      <td><strong>Anti-Double-Counting</strong>: single event with supporting evidence.</td>
    </tr>
  </tbody>
</table>

<h2><span class="num">4</span> Anti-Double-Counting & Single-Event Grouping</h2>
<p>
  Anti-double-counting is achieved through entity-keyed grouping and identity consumption:
</p>
<div class="card-grid">
  <div class="card highlight">
    <div class="card-title">Mathematical Formulation</div>
    Let $E = \{e_1, e_2, \dots, e_n\}$ be the set of raw evidence items.<br>
    The correlator maps $E$ into an equivalence relation over root entities $R$:
    $$\text{Chain}(r) = \{ e \in E \mid \text{entity}(e) = r \}$$
    $$\text{Deduplicated Count} = |E| - |\text{Chains}|$$
    The total penalty applied to a team reflects $|\text{Chains}|$, ensuring an incident is penalized exactly once.
  </div>
  <div class="card highlight">
    <div class="card-title">Benign Artifact Filter Formula</div>
    A concealed path $P$ is classified as <strong>Benign</strong> if:
    $$\text{dir}(P) \cap \{\text{node\_modules}, \text{dist}, \text{build}, \text{.venv}\} \neq \emptyset$$
    $$\text{OR } \text{ext}(P) \in \{\text{.min.js}, \text{.lock}, \text{.map}, \text{.env}\}$$
    If Benign $\to$ marked <span class="badge-clean">CLEAN</span> ($Severity = \text{info}$).<br>
    If Real Source File ($P \in \text{Source}$) $\to$ marked <span class="badge-warn">ACTIVE CONCEALMENT</span>.
  </div>
</div>

<h2><span class="num">5</span> Deterministic Risk Scoring Formula</h2>
<p>
  The overall verdict and confidence level are calculated deterministically:
</p>
<div class="terminal-box">
  <span class="t-cyan">Overall Status Calculation:</span><br>
  &bull; If $\exists c \in \text{Chains}$ with $\text{severity}(c) = \texttt{hard\_flag}$ &nbsp;➔ <span class="t-red">🚨 HIGH-RISK PROVENANCE CONCERN</span> (Risk: HIGH, Conf: HIGH)<br>
  &bull; Else if $\exists c \in \text{Chains}$ with $\text{severity}(c) = \texttt{flag}$ &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ <span class="t-yellow">⚠️ EVIDENCE CORRELATION: MEDIUM RISK</span> (Risk: MEDIUM, Conf: HIGH if &gt;1 flag else MED)<br>
  &bull; Else &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;➔ <span class="t-green">✅ VERIFIED / CLEAN</span> (Risk: LOW, Conf: HIGH)
</div>

<div class="footer">Page 2 • HACKPROOF Provenance System • Context Awareness Technical Guide</div>
<div class="page-break"></div>

<!-- PAGE 3 -->
<h2><span class="num">6</span> Terminal Output & Visual Narrative Interpretation</h2>

<h3>Case 1: Clean Hackathon Submission</h3>
<p>When all checks pass and all commits, timestamps, and files align with hackathon rules:</p>
<div class="terminal-box">
================================================================================<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;CONTEXT AWARENESS SUMMARY<br>
================================================================================<br>
Status:     <span class="t-green">✅ VERIFIED / CLEAN</span>  [Confidence: HIGH]<br>
Correlation Overview:<br>
  &bull; No anomalous chains detected across all analysis modules.<br>
  &bull; All commits, keys, files, and timestamps correlate consistently with hackathon rules.<br>
================================================================================
</div>

<h3>Case 2: Multi-Signal Provenance Tampering</h3>
<p>When a participant smuggled pre-existing code and attempted concealment:</p>
<div class="terminal-box">
================================================================================<br>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;CONTEXT AWARENESS SUMMARY<br>
================================================================================<br>
Status:     <span class="t-red">🚨 HIGH-RISK PROVENANCE CONCERN</span>  [Confidence: HIGH]<br>
Correlation Overview:<br>
  &bull; 2 anomalous chain(s) identified from 7 raw evidence item(s)<br>
  &bull; Consolidated 5 redundant/multi-plane signal(s) into single event chains<br>
<br>
<span class="t-cyan">[CHAIN_001]</span> <span class="t-red">🚨 Code Provenance Match: src/auth.py</span> [CONCERN]<br>
  [FILE] src/auth.py<br>
    ├── Similarity Match: 94% identical to acme/oauth-starter/auth.ts<br>
    │   └── External Source Date: 2024-01-10 (Predates hackathon window)<br>
    ├── Introduced in Commit: a1b2c3d (committed 2h after T0)<br>
    └── Concealment Signal: Concealed file src/auth.py hidden by 'src/auth.py' committed by Alice (e4f5a6b)<br>
<br>
<span class="t-cyan">[CHAIN_002]</span> <span class="t-yellow">⚠️ Commit Integrity Analysis: 9f8e7d6</span> [WARNING]<br>
  [COMMIT] 9f8e7d6 (Bob Hacker)<br>
    ├── [IDENTITY] Signer Charlie does not match commit author Bob<br>
    └── [SIGNATURE] Commit 9f8e7d6 signature valid=False by Charlie<br>
<br>
Assessment &amp; Key Drivers:<br>
  &bull; Multi-signal correlation on src/auth.py (4 linked signals, rule: Rule 1: Similarity + Pre-hackathon source)<br>
  &bull; Multi-signal correlation on Commit 9f8e7d6 (2 linked signals, rule: Rule 3: Identity &amp; Signer correlation)<br>
================================================================================
</div>

<h2><span class="num">7</span> JSON Schema Structure</h2>
<p>When running with <code>--format json</code>, HACKPROOF emits the full evidence graph and correlation chains:</p>
<pre>{
  "repo_path": "priyanshu22102006/HACKPROOF",
  "summary": { "passed": 22, "failed": 1, "hard_flag": 0, "flag": 0, "info": 23 },
  "context_awareness": {
    "overall_status": "VERIFIED / CLEAN",
    "risk_level": "LOW",
    "confidence": "HIGH",
    "total_raw_evidence_count": 23,
    "total_chains_count": 18,
    "chains": [
      {
        "chain_id": "CHAIN_001",
        "title": "Standard Build / Env Artifact Ignored: dist/bundle.min.js",
        "severity": "info",
        "root_entity": "dist/bundle.min.js",
        "status_badge": "CLEAN",
        "rule": "Rule 4: Hidden tracking + File analysis",
        "narrative": [
          "[FILE] dist/bundle.min.js",
          "  ├── Classification: BENIGN BUILD ARTIFACT",
          "  └── Rule Origin Commit: 471668c by Pritim Mondal"
        ]
      }
    ],
    "graph": {
      "nodes": [
        { "id": "file:dist/bundle.min.js", "type": "File", "attrs": { "path": "dist/bundle.min.js" } },
        { "id": "commit:471668c", "type": "Commit", "attrs": { "sha": "471668c" } },
        { "id": "author:mondalpritim14@gmail.com", "type": "Author", "attrs": { "name": "Pritim Mondal" } }
      ],
      "edges": [
        { "source": "commit:471668c", "target": "file:dist/bundle.min.js", "type": "INTRODUCED_BY" },
        { "source": "commit:471668c", "target": "author:mondalpritim14@gmail.com", "type": "AUTHORED_BY" }
      ]
    }
  }
}</pre>

<div class="footer">Page 3 • HACKPROOF Provenance System • Context Awareness Technical Guide</div>

</body>
</html>
"""


def main() -> int:
    base_dir = "/Users/pritimmondal/Desktop/HACKPROOF"
    html_path = "/tmp/hackproof_context_awareness_doc.html"
    pdf_out = os.path.join(base_dir, "HACKPROOF_Context_Awareness_Engine.pdf")
    artifact_dir = "/Users/pritimmondal/.gemini/antigravity-ide/brain/8fb9aad3-2bea-4e40-85ff-b89956850417"
    artifact_pdf = os.path.join(artifact_dir, "HACKPROOF_Context_Awareness_Engine.pdf")

    # 1. Write HTML
    html_content = generate_html()
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not os.path.exists(chrome_bin):
        print(f"Error: Google Chrome not found at {chrome_bin}", file=sys.stderr)
        return 1

    print("==> Generating Context Awareness PDF Guide...")
    cmd = [
        chrome_bin,
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={pdf_out}",
        html_path,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error generating PDF: {res.stderr}", file=sys.stderr)
        return 1

    if os.path.exists(pdf_out):
        file_size = os.path.getsize(pdf_out)
        print(f"✅ Generated PDF: {pdf_out} ({file_size:,} bytes)")
        if os.path.isdir(artifact_dir):
            shutil.copy2(pdf_out, artifact_pdf)
            print(f"✅ Copied to Artifacts: {artifact_pdf}")
    else:
        print("Error: PDF output file was not created.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
