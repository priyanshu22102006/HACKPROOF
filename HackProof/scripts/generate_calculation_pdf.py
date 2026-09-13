#!/usr/bin/env python3
"""Generate a comprehensive PDF guide explaining how every line of HACKPROOF terminal output is calculated."""

import os
import shutil
import subprocess
import sys


def generate_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HACKPROOF: How the Terminal Output is Calculated</title>
<style>
  @page {
    size: A4 portrait;
    margin: 16mm 14mm 16mm 14mm;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.5;
    font-size: 10pt;
    margin: 0;
    padding: 0;
  }
  .header-card {
    background: linear-gradient(135deg, #090d16 0%, #1e1b4b 60%, #312e81 100%);
    color: #ffffff;
    padding: 22px 24px;
    border-radius: 10px;
    margin-bottom: 20px;
  }
  .header-badge {
    display: inline-block;
    background: rgba(99, 102, 241, 0.35);
    color: #c7d2fe;
    border: 1px solid rgba(165, 180, 252, 0.4);
    font-size: 8pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 3px 10px;
    border-radius: 20px;
    margin-bottom: 6px;
  }
  .header-title {
    font-size: 18pt;
    font-weight: 800;
    margin: 0 0 6px 0;
  }
  .header-desc {
    font-size: 10pt;
    color: #cbd5e1;
    margin: 0;
  }
  h2 {
    font-size: 12.5pt;
    font-weight: 750;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 10px;
    page-break-after: avoid;
  }
  h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 14px;
    margin-bottom: 4px;
    page-break-after: avoid;
  }
  /* Terminal sample blocks */
  .terminal-box {
    background: #090d16;
    color: #f8fafc;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8pt;
    line-height: 1.45;
    margin: 8px 0 12px 0;
    border-left: 4px solid #6366f1;
    page-break-inside: avoid;
  }
  .terminal-box .green { color: #4ade80; font-weight: bold; }
  .terminal-box .yellow { color: #facc15; font-weight: bold; }
  .terminal-box .red { color: #f87171; font-weight: bold; }
  .terminal-box .cyan { color: #38bdf8; }

  /* Explanation cards */
  .calc-card {
    border: 1px solid #e2e8f0;
    background: #f8fafc;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 14px;
    page-break-inside: avoid;
  }
  .calc-card strong { color: #0f172a; }
  .calc-card ul {
    margin: 6px 0 0 0;
    padding-left: 18px;
    font-size: 9pt;
  }
  .calc-card li { margin-bottom: 4px; }
  
  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0 14px 0;
    font-size: 8.5pt;
    page-break-inside: avoid;
  }
  th {
    background-color: #0f172a;
    color: #ffffff;
    font-weight: 600;
    text-align: left;
    padding: 6px 8px;
    border: 1px solid #0f172a;
    text-transform: uppercase;
    font-size: 8pt;
  }
  td {
    padding: 5px 8px;
    border: 1px solid #e2e8f0;
    vertical-align: top;
  }
  tr:nth-child(even) td { background-color: #f1f5f9; }

  .formula {
    background: #e0e7ff;
    color: #3730a3;
    font-family: ui-monospace, Menlo, Consolas, monospace;
    font-size: 8.5pt;
    padding: 3px 8px;
    border-radius: 4px;
    display: inline-block;
    margin: 3px 0;
    font-weight: 600;
  }
</style>
</head>
<body>

<div class="header-card">
  <div class="header-badge">ENGINE REVERSE-ENGINEERING & MATHEMATICS</div>
  <h1 class="header-title">How HACKPROOF Calculates Terminal Output</h1>
  <p class="header-desc">
    Line-by-line guide explaining the exact Git commands, mathematical formulas, and forensic logic behind every line in the terminal audit report.
  </p>
</div>

<h2>1. The Header Banner Verdict</h2>

<div class="terminal-box">
  HACKPROOF AUDIT REPORT: <span class="green">✅ ALL CHECKS PASSED (VERIFIED GENUINE WORK)</span><br>
  Target Repository : anantapathak8/Ureckon-27
</div>

<div class="calc-card">
  <strong>How it calculates the verdict:</strong>
  <ul>
    <li>The engine executes all 23 checks across Claim, System, and Server planes.</li>
    <li>Each check returns a <code>severity</code> (<code>hard_flag</code>, <code>flag</code>, or <code>info</code>) and a boolean <code>passed</code>.</li>
    <li><strong>Decision Matrix:</strong>
      <ul>
        <li>If <code>failed == 0</code>: <span class="green">✅ ALL CHECKS PASSED</span> (Genuine live build).</li>
        <li>If any <code>hard_flag</code> failed (e.g. backdated parent commits, outsider key, concealed code): <span class="red">🚨 CRITICAL INTEGRITY THREAT DETECTED</span>.</li>
        <li>If only <code>flag</code> failed (e.g. timezone mismatch, commits before kickoff): <span class="yellow">⚠️ SUSPICIOUS ACTIVITY DETECTED</span>.</li>
      </ul>
    </li>
  </ul>
</div>

<h2>2. Section [1]: Commit Signature Verification (GPG / SSH)</h2>

<div class="terminal-box">
  [1] COMMIT SIGNATURE VERIFICATION (GPG / SSH)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• Coverage: 2/2 commits verified (100%)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• <span class="yellow">⚠️ UNSIGNED COMMITS (Missing Cryptographic Proof):</span><br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Commit 447827b authored by "Ananta Pathak &lt;ananta@...&gt;"<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;→ Missing GPG signature! (Pushed from an unregistered laptop)
</div>

<div class="calc-card">
  <strong>How it extracts and computes signatures:</strong>
  <ul>
    <li><strong>Git Command:</strong> <code>git log --format="%H%x00%an%x00%ae%x00%G?%x00%GK%x00%GS"</code></li>
    <li><strong>Porcelain Flags Read:</strong>
      <ul>
        <li><code>%G?</code>: Git signature status (<code>G</code> = Good valid key, <code>B</code> = Bad/broken, <code>U</code> = Untrusted key, <code>N</code> = No signature).</li>
        <li><code>%GK</code>: 16-character or 40-character Key ID used to sign.</li>
        <li><code>%ae</code>: Git author email.</li>
      </ul>
    </li>
    <li><strong>The Math for Coverage:</strong>
      <div class="formula">Coverage Ratio = Verified Signed Commits / Total Commits × 100%</div>
      A commit is only counted as <code>Verified</code> if <code>%G? == 'G'</code> <strong>AND</strong> the signing key <code>%GK</code> is registered to that member in <code>hackproof.db</code>.
    </li>
    <li><strong>Unsigned Commits:</strong> Collected from every commit where <code>%G? == 'N'</code>.</li>
    <li><strong>Unregistered Keys:</strong> Flagged when <code>%G? == 'G'</code>, but <code>%GK</code> belongs to someone outside the team roster.</li>
    <li><strong>Identity Mismatch:</strong> Flagged when key <code>%GK</code> belongs to Alice, but author email <code>%ae</code> is Bob.</li>
  </ul>
</div>

<h2>3. Section [2]: File Concealment & .gitignore Blame Table</h2>

<div class="terminal-box">
  [2] FILE CONCEALMENT & PRE-BUILT CODE INSPECTOR (§8.f)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• Status: Clean (No hidden files, no pre-built code staging, no index manipulation).<br><br>
  &nbsp;&nbsp;&nbsp;&nbsp;• FORENSIC .GITIGNORE BLAME VIEW (§8.f):<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;┌──────┬──────────────────────┬────────────────────┬─────────────────────────┬──────────────┬─────────────┐<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│ Line │ Rule / Pattern&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ Author&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ Committed Date &amp; Time&nbsp;&nbsp; │ Timing&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ Status&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;├──────┼──────────────────────┼────────────────────┼─────────────────────────┼──────────────┼─────────────┤<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│ 1&nbsp;&nbsp;&nbsp; │ node_modules/&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ Ananta Pathak&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ 2026-08-24 00:18:16 +05 │ [LATE +2.8h] │ <span class="green">✅ CLEAN</span>&nbsp;&nbsp;&nbsp;&nbsp; │<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;│ 4&nbsp;&nbsp;&nbsp; │ .env.local&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ Ananta Pathak&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │ 2026-08-24 00:18:16 +05 │ [LATE +2.8h] │ <span class="yellow">⚠️ SUSP</span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; │<br>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;└──────┴──────────────────────┴────────────────────┴─────────────────────────┴──────────────┴─────────────┘
</div>

<div class="calc-card">
  <strong>How Status: Clean is calculated:</strong>
  <ul>
    <li><strong>Disk vs Git Ratio:</strong> <code>os.walk</code> counts all source files on disk; compares with <code>git ls-files</code>. Must be &ge; 90% tracked.</li>
    <li><strong>Index Flags:</strong> Runs <code>git ls-files -v</code> to detect stealth <code>--skip-worktree</code> (marker <code>S</code>) or <code>--assume-unchanged</code> (marker <code>M</code>).</li>
    <li><strong>Local Excludes:</strong> Inspects <code>.git/info/exclude</code> and <code>core.excludesFile</code> overrides that never get pushed to GitHub.</li>
  </ul>
</div>

<table>
  <thead>
    <tr>
      <th>Table Column</th>
      <th>Git Command / Telemetry Source</th>
      <th>Calculation & Forensic Formula</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Line</strong></td>
      <td><code>git blame --line-porcelain -- .gitignore</code></td>
      <td>Line number index of the rule in the file.</td>
    </tr>
    <tr>
      <td><strong>Rule / Pattern</strong></td>
      <td>Tab content line in porcelain output (<code>\t...</code>)</td>
      <td>The exact regex/glob rule string (e.g. <code>node_modules/</code>, <code>.env.local</code>).</td>
    </tr>
    <tr>
      <td><strong>Author</strong></td>
      <td><code>author</code> header in blame block</td>
      <td>Git committer name who introduced that exact line.</td>
    </tr>
    <tr>
      <td><strong>Committed Date</strong></td>
      <td><code>author-time</code> (epoch) &amp; <code>author-tz</code></td>
      <td>Converted from UNIX epoch: <code>datetime.fromtimestamp(author_time, tz)</code>.</td>
    </tr>
    <tr>
      <td><strong>Timing</strong></td>
      <td><code>git rev-list --max-parents=0 HEAD</code></td>
      <td>
        Finds initial commit epoch ($T_0$).<br>
        <div class="formula">Elapsed = (author_time - T0) / 3600 hours</div>
        If in initial commit: <code>[INIT]</code>. If later commit: <code>[LATE +X.Xh]</code>.
      </td>
    </tr>
    <tr>
      <td><strong>Status</strong></td>
      <td>Pattern taxonomy + <code>git check-ignore -v</code></td>
      <td>
        • <strong>✅ CLEAN:</strong> Benign build artifacts (<code>node_modules</code>, <code>dist</code>, <code>__pycache__</code>).<br>
        • <strong>⚠️ SUSP:</strong> Sensitive config/source patterns (<code>.env.local</code>, <code>*.py</code>, <code>_build/</code>).<br>
        • <strong>🚨 CONCEALED:</strong> The rule hides uncommitted code files physically on disk!
      </td>
    </tr>
  </tbody>
</table>

<h2>4. Section [3]: Build Window & Timestamps (§8.d / §8.i)</h2>

<div class="terminal-box">
  [3] HACKATHON BUILD WINDOW &amp; TIMESTAMPS (§8.d / §8.i)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• First Commit&nbsp; : 2026-08-23T21:28:10+05:30 (Commit 23c8cc1)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• Latest Commit : 2026-08-24T00:18:16+05:30 (Commit 447827b)<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• Active Span&nbsp;&nbsp; : 2h 50m across 4 commits<br>
  &nbsp;&nbsp;&nbsp;&nbsp;• Status: Clean (Monotonic chronology, consistent timezones, natural human intervals).
</div>

<div class="calc-card">
  <strong>How timestamp forensics are calculated:</strong>
  <ul>
    <li><strong>First &amp; Latest Commit:</strong> Parsed via <code>git log --reverse --format="%H%x00%ci"</code>. First is index 0; Latest is index -1.</li>
    <li><strong>Active Span:</strong>
      <div class="formula">Delta = (Latest_Epoch - First_Epoch) &rarr; Hours &amp; Minutes</div>
    </li>
    <li><strong>Parent Monotonicity Check:</strong>
      For every commit $C$ and parent $P$:
      <div class="formula">IsValid = CommitterDate(C) &ge; CommitterDate(P)</div>
      If $C < P$, commit was backdated or rebased! Flags: <code>🚨 claim.parent_monotonicity</code>.
    </li>
    <li><strong>Timezone Consistency:</strong>
      Counts occurrences of every timezone offset (e.g. <code>+05:30</code>: 4 commits). Dominant offset becomes baseline. Any commit with differing offset is flagged: <code>🚨 claim.timezone_consistency</code> (catches offshore ghost developers).
    </li>
    <li><strong>Typing Speedrun / Burst Check:</strong>
      Measures interval $\Delta T$ between consecutive commits. If $\Delta T < 2.0\text{ seconds}$ while adding &gt;100 lines of code, it flags automated code copy-pasting.
    </li>
  </ul>
</div>

<h2>5. Judge Takeaway Verdict</h2>

<div class="terminal-box">
  JUDGE TAKEAWAY: <span class="green">✅ Verified genuine build provenance. Clear for hackathon judging.</span>
</div>

<div class="calc-card">
  <strong>How the final recommendation is selected:</strong>
  <ul>
    <li><code>if is_clean</code>: <span class="green">✅ Verified genuine build provenance. Clear for hackathon judging.</span></li>
    <li><code>elif hard_flags</code>: <span class="red">🚨 High-risk cheating indicators detected. Prompt team for explanation.</span></li>
    <li><code>else</code>: <span class="yellow">⚠️ Incomplete signature coverage. Verify commits with the team.</span></li>
  </ul>
</div>

</body>
</html>
"""


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html_path = "/tmp/hackproof_calc_doc.html"
    pdf_out = os.path.join(base_dir, "HACKPROOF_Terminal_Output_Calculations.pdf")
    artifact_dir = "/Users/pritimmondal/.gemini/antigravity-ide/brain/8fb9aad3-2bea-4e40-85ff-b89956850417"
    artifact_pdf = os.path.join(artifact_dir, "HACKPROOF_Terminal_Output_Calculations.pdf")

    # 1. Write HTML
    html_content = generate_html()
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not os.path.exists(chrome_bin):
        print(f"Error: Google Chrome not found at {chrome_bin}", file=sys.stderr)
        return 1

    print("==> Generating Terminal Output Calculation PDF...")
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
