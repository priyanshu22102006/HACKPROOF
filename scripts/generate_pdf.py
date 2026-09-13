#!/usr/bin/env python3
"""Generate a publication-quality PDF document for HACKPROOF features and architecture."""

import os
import shutil
import subprocess
import sys


def generate_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>HACKPROOF: Platform Architecture & Features Documentation</title>
<style>
  @page {
    size: A4 portrait;
    margin: 18mm 16mm 18mm 16mm;
  }
  
  * {
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    line-height: 1.55;
    font-size: 10.5pt;
    margin: 0;
    padding: 0;
  }

  /* Header Banner */
  .header-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #312e81 100%);
    color: #ffffff;
    padding: 24px 28px;
    border-radius: 12px;
    margin-bottom: 24px;
    box-shadow: 0 4px 12px rgba(15, 23, 42, 0.15);
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
    margin-bottom: 8px;
  }

  .header-title {
    font-size: 20pt;
    font-weight: 800;
    letter-spacing: -0.5px;
    margin: 0 0 6px 0;
    color: #ffffff;
  }

  .header-desc {
    font-size: 10.5pt;
    color: #cbd5e1;
    margin: 0;
    max-width: 90%;
    line-height: 1.45;
  }

  h2 {
    font-size: 13.5pt;
    font-weight: 750;
    color: #0f172a;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 6px;
    margin-top: 24px;
    margin-bottom: 12px;
    page-break-after: avoid;
  }

  h3 {
    font-size: 11pt;
    font-weight: 700;
    color: #1e293b;
    margin-top: 16px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }

  p {
    margin: 0 0 10px 0;
  }

  /* Architectural Diagram Grid */
  .arch-grid {
    display: flex;
    gap: 12px;
    margin: 16px 0;
    page-break-inside: avoid;
  }

  .plane-box {
    flex: 1;
    border-radius: 8px;
    padding: 12px 14px;
    border: 1px solid #e2e8f0;
    background: #f8fafc;
  }

  .plane-server {
    border-top: 4px solid #3b82f6;
    background: #eff6ff;
  }

  .plane-system {
    border-top: 4px solid #8b5cf6;
    background: #f5f3ff;
  }

  .plane-claim {
    border-top: 4px solid #10b981;
    background: #ecfdf5;
  }

  .plane-title {
    font-size: 9.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 6px;
  }

  .plane-server .plane-title { color: #1d4ed8; }
  .plane-system .plane-title { color: #6d28d9; }
  .plane-claim .plane-title { color: #047857; }

  .plane-desc {
    font-size: 8.5pt;
    color: #475569;
    margin: 0;
    line-height: 1.4;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 12px 0 18px 0;
    font-size: 9pt;
    page-break-inside: avoid;
  }

  th {
    background-color: #0f172a;
    color: #ffffff;
    font-weight: 600;
    text-align: left;
    padding: 7px 10px;
    border: 1px solid #0f172a;
    font-size: 8.5pt;
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  td {
    padding: 6px 10px;
    border: 1px solid #e2e8f0;
    vertical-align: top;
  }

  tr:nth-child(even) td {
    background-color: #f8fafc;
  }

  /* Feature cards */
  .feature-card {
    border: 1px solid #e2e8f0;
    border-left: 4px solid #4f46e5;
    background: #ffffff;
    border-radius: 6px;
    padding: 10px 14px;
    margin-bottom: 12px;
    page-break-inside: avoid;
  }

  .feature-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 4px;
  }

  .feature-name {
    font-size: 10.5pt;
    font-weight: 700;
    color: #0f172a;
  }

  .feature-cmd {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    background: #f1f5f9;
    color: #0f172a;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 8pt;
    border: 1px solid #cbd5e1;
  }

  .feature-card ul {
    margin: 4px 0 0 0;
    padding-left: 18px;
    font-size: 9pt;
    color: #334155;
  }

  .feature-card li {
    margin-bottom: 3px;
  }

  /* Code snippet blocks */
  pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 9px 12px;
    border-radius: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8pt;
    line-height: 1.45;
    overflow-x: auto;
    margin: 8px 0 12px 0;
    page-break-inside: avoid;
  }

  code {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 8.5pt;
    background: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 3px;
  }

  pre code {
    background: transparent;
    color: inherit;
    padding: 0;
  }

  /* Callout notes */
  .callout {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-left: 4px solid #16a34a;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 9pt;
    color: #166534;
    margin: 10px 0;
    page-break-inside: avoid;
  }

  .footer-note {
    text-align: center;
    font-size: 8pt;
    color: #94a3b8;
    margin-top: 24px;
    border-top: 1px solid #e2e8f0;
    padding-top: 8px;
  }
</style>
</head>
<body>

<div class="header-card">
  <div class="header-badge">HACKPROOF FORENSIC SPECIFICATION</div>
  <h1 class="header-title">Platform Architecture & Feature Documentation</h1>
  <p class="header-desc">
    Zero-dependency, multi-plane build provenance and cryptographic integrity platform for hackathon judging, pre-built code inspection, and forensic timeline analysis.
  </p>
</div>

<h2>1. System Architecture: The Three Verification Planes</h2>
<p>
  HACKPROOF organizes all verification across three independent planes to guarantee that local machine tampering, clock manipulation, or git history rewriting cannot forge a clean verdict.
</p>

<div class="arch-grid">
  <div class="plane-box plane-server">
    <div class="plane-title">1. Server Plane</div>
    <p class="plane-desc">
      <strong>Independent Observer:</strong> Real-time GitHub webhooks (HMAC-SHA256), REST API synchronization, clock drift monitoring, and force-push history rewriting detection.
    </p>
  </div>
  <div class="plane-box plane-system">
    <div class="plane-title">2. System Plane</div>
    <p class="plane-desc">
      <strong>Hardware Inspection:</strong> Local hardware devices, stealth index flags (<code>--skip-worktree</code>), <code>.git/info/exclude</code> overrides, and uncommitted source code on disk.
    </p>
  </div>
  <div class="plane-box plane-claim">
    <div class="plane-title">3. Claim Plane</div>
    <p class="plane-desc">
      <strong>Git Repository History:</strong> Cryptographic signatures (GPG/SSH), build window boundaries (<code>--t0</code>), parent timestamp monotonicity, burst analysis, and <code>.gitignore</code> blame.
    </p>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th style="width: 20%;">Verification Plane</th>
      <th style="width: 35%;">Source of Telemetry</th>
      <th style="width: 45%;">Forensic Defense Purpose</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Claim Plane</strong></td>
      <td>Git commit graph, author dates, tree objects, <code>.gitignore</code> porcelain blame</td>
      <td>Catches backdated commits, speedrun code dumping (&lt;2s intervals), and late-added ignore rules hiding modules.</td>
    </tr>
    <tr>
      <td><strong>System Plane</strong></td>
      <td>Local working tree, git index metadata, excludes configs</td>
      <td>Catches stealth index modifications (<code>git update-index --skip-worktree</code>) and untracked code on disk.</td>
    </tr>
    <tr>
      <td><strong>Server Plane</strong></td>
      <td>GitHub App webhooks, REST polling, SQLite Roster DB</td>
      <td>Prevents clock tampering, detects force-pushes, flags unregistered laptops, and identifies long offline gaps (&gt;4h).</td>
    </tr>
  </tbody>
</table>

<h2>2. Comprehensive Inventory of Implemented Features</h2>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">1. Multi-Team Roster & Hardware Device Database</span>
    <span class="feature-cmd">hackproof-roster</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;"><code>core/roster_db.py</code> &bull; SQLite Schema (<code>hackproof.db</code>)</p>
  <ul>
    <li><strong>Relational DB Model:</strong> Manages <code>teams</code>, <code>members</code>, <code>keys</code>, and physical <code>devices</code> with foreign-key integrity.</li>
    <li><strong>Hardware Device Binding:</strong> Enrolls physical laptop MAC addresses/hostnames at check-in to bind commits to authorized hardware.</li>
    <li><strong>Global Key Uniqueness:</strong> Enforces global uniqueness on public keys to prevent cross-team identity sharing or collusion.</li>
    <li><strong>Enrollment Card Support:</strong> Exports team cryptographic credentials and imports legacy JSON roster manifests.</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">2. Cryptographic Commit Signature Verification (§8.e)</span>
    <span class="feature-cmd">hackproof-analyze --roster hackproof.db</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;"><code>analyzers/gpg_check.py</code> &bull; GPG / OpenSSH Signatures</p>
  <ul>
    <li><strong>Signature Coverage:</strong> Computes the exact percentage of commits cryptographically signed by registered team keys.</li>
    <li><strong>Unsigned Commit Detection:</strong> Flags commits pushed without cryptographic signatures (unregistered laptops).</li>
    <li><strong>Outsider Key Detection:</strong> Detects valid signatures signed by unknown keys not present on the team roster.</li>
    <li><strong>Identity Impersonation Detection:</strong> Catches identity mismatches where Git author claims to be Person A, but signature is Person B.</li>
    <li><strong>Platform Fallback Keys:</strong> Built-in support for platform-signed commits (e.g., GitHub Web-flow automated merge keys).</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">3. File Concealment & Pre-Built Code Staging (§8.f)</span>
    <span class="feature-cmd">analyzers/gitignore_check.py</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;">System & Claim Plane File Verification</p>
  <ul>
    <li><strong>Tracked Source Ratio:</strong> Compares files tracked in Git against files on disk to uncover massive hidden source trees.</li>
    <li><strong>Index Bit Tampering:</strong> Identifies stealth <code>--skip-worktree</code> and <code>--assume-unchanged</code> index flags.</li>
    <li><strong>Local Exclude Overrides:</strong> Audits <code>.git/info/exclude</code> and <code>core.excludesFile</code> overrides that never leave the laptop.</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">4. Forensic .gitignore Blame View (§8.f) & Main Window Table</span>
    <span class="feature-cmd">hackproof-analyze &bull; Section [2]</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;">Porcelain Line Attribution & Active Concealment</p>
  <ul>
    <li><strong>Porcelain Blame Parser:</strong> Uses <code>git blame --line-porcelain</code> for machine-attributed line numbers, authors, and timestamps.</li>
    <li><strong>Timing Classification:</strong> Identifies repository root commit epoch; computes <code>[INIT]</code> vs <code>[LATE +X.Xh]</code> offset for every line.</li>
    <li><strong>Active Concealment Warning:</strong> Uses <code>git check-ignore -v</code> to flag <code>🚨 CONCEALED</code> when late rules hide uncommitted source files.</li>
    <li><strong>Direct Main Window Integration:</strong> Formatted table renders natively inside the Executive Summary Card by default.</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">5. Build Window, Interval & Monotonicity Forensics (§8.d / §8.i)</span>
    <span class="feature-cmd">analyzers/claim_timestamp_check.py</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;">Timestamp Integrity & Typist Dynamics</p>
  <ul>
    <li><strong>Kickoff Window Verification (<code>--t0</code>):</strong> Flags any commits created before the official hackathon start time.</li>
    <li><strong>Parent Monotonicity:</strong> Guarantees chronological order; detects backdated parent commits, rebases, and clock tampering.</li>
    <li><strong>Speedrun / Burst Detection:</strong> Flags superhuman commit quantization (&lt; 2s intervals) indicating scripted code injection.</li>
    <li><strong>Timezone Consistency:</strong> Validates timezone offsets across commits to detect offshore proxy developers.</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">6. Stage C Server Plane: Webhook Listener & REST Polling</span>
    <span class="feature-cmd">hackproof-server &bull; hackproof-poll</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;"><code>server/webhook_server.py</code> &bull; <code>server/github_service.py</code></p>
  <ul>
    <li><strong>HMAC-SHA256 Webhook Server:</strong> Standard library HTTP server with constant-time signature verification on <code>X-Hub-Signature-256</code>.</li>
    <li><strong>Dual-Timestamp Drift Tracking:</strong> Computes drift between GitHub's <code>created_at</code> and server receipt time to detect clock skew.</li>
    <li><strong>Force-Push Detection:</strong> Records and flags any non-fast-forward updates that overwrite hackathon history.</li>
    <li><strong>Push Gap Forensics:</strong> Flags participants working offline for &gt;4 hours followed by massive code dumps.</li>
    <li><strong>REST Polling Client:</strong> Synchronizes repository creation date, branch refs, Actions runs, and GitHub signature verification.</li>
  </ul>
</div>

<div class="feature-card">
  <div class="feature-header">
    <span class="feature-name">7. Automated Remote GitHub Repo Auditing & Auto-Clone Engine</span>
    <span class="feature-cmd">hackproof-analyze &lt;owner/repo&gt;</span>
  </div>
  <p style="font-size: 8.5pt; color: #64748b; margin-bottom: 4px;">Universal Audit Target Support</p>
  <ul>
    <li><strong>Direct Remote Auditing:</strong> Audits any public/private GitHub repository without manual clone steps.</li>
    <li><strong>Full History Preservation:</strong> Clones full history (never shallow) into an isolated sandbox to ensure complete telemetry.</li>
    <li><strong>Evaluability Context:</strong> Automatically handles clone boundaries, reporting machine-local checks as <code>n/a</code> instead of false clean.</li>
    <li><strong>Automatic Teardown:</strong> Removes temporary sandbox directories upon completion.</li>
  </ul>
</div>

<h2>3. Command Reference</h2>

<pre><code># 1. Audit any remote GitHub repository directly:
hackproof-analyze octocat/Hello-World

# 2. Audit local repository with roster and event start timestamp:
hackproof-analyze . --roster hackproof.db --team-id team-pritim --t0 2026-09-13T01:00:00+05:30

# 3. Export complete machine-readable audit report to JSON:
hackproof-analyze . --format json --out audit-results.json

# 4. Start Stage C GitHub Webhook Server:
hackproof-server --host 0.0.0.0 --port 8080 --db hackproof.db --secret "YOUR_SECRET"

# 5. Poll remote GitHub repository metadata into SQLite:
hackproof-poll owner/repo --db hackproof.db

# 6. Manage multi-team roster database:
hackproof-roster list
hackproof-roster team create --team-id team-alpha --name "Team Alpha"</code></pre>

<h2>4. Verification & Test Suite Matrix</h2>

<div class="callout">
  <strong>146 Passing Tests:</strong> Zero external dependencies. All modules run using standard library Python + Git CLI.
</div>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Test Suite</th>
      <th style="width: 30%;">File Location</th>
      <th style="width: 45%;">Coverage Scope</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Engine & CLI</strong></td>
      <td><code>tests/test_engine.py</code></td>
      <td>Isolation, shallow clone detection, summary card, CLI arguments</td>
    </tr>
    <tr>
      <td><strong>GPG & Key Binding</strong></td>
      <td><code>tests/test_gpg_check.py</code></td>
      <td>Signature coverage, unsigned commits, outsider keys, platform keyrings</td>
    </tr>
    <tr>
      <td><strong>Gitignore & Blame</strong></td>
      <td><code>tests/test_gitignore_check.py</code></td>
      <td>Porcelain blame, active concealment, skip-worktree, tracked ratios</td>
    </tr>
    <tr>
      <td><strong>Claim Timestamps</strong></td>
      <td><code>tests/test_claim_timestamp_check.py</code></td>
      <td>Monotonicity, build window (<code>--t0</code>), interval bursts, timezone offset</td>
    </tr>
    <tr>
      <td><strong>Server Plane</strong></td>
      <td><code>tests/test_server_plane.py</code></td>
      <td>HMAC verification, push event parsing, force-push detection, REST client</td>
    </tr>
    <tr>
      <td><strong>Roster DB</strong></td>
      <td><code>tests/test_roster_db.py</code></td>
      <td>Relational schema, key uniqueness, hardware device binding</td>
    </tr>
    <tr>
      <td><strong>Remote Clone</strong></td>
      <td><code>tests/test_clone_analysis.py</code></td>
      <td>Clone evaluability, credential scrubbing, system plane reporting</td>
    </tr>
  </tbody>
</table>

<div class="footer-note">
  HACKPROOF Forensic Engineering Platform &bull; Built with Zero External Dependencies &bull; Verified on macOS / Linux
</div>

</body>
</html>
"""


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html_path = "/tmp/hackproof_features_doc.html"
    pdf_out = os.path.join(base_dir, "HACKPROOF_Features_Documentation.pdf")
    artifact_dir = "/Users/pritimmondal/.gemini/antigravity-ide/brain/8fb9aad3-2bea-4e40-85ff-b89956850417"
    artifact_pdf = os.path.join(artifact_dir, "HACKPROOF_Features_Documentation.pdf")

    # 1. Write HTML
    html_content = generate_html()
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    chrome_bin = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not os.path.exists(chrome_bin):
        print(f"Error: Google Chrome not found at {chrome_bin}", file=sys.stderr)
        return 1

    print("==> Generating PDF via headless Google Chrome...")
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
