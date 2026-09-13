#!/usr/bin/env python3
"""End-to-end smoke test against a throwaway project.

Creates a sandbox, runs the agent for a few seconds, performs the exact
behaviours the agent is meant to catch, then seals and prints the report.

    python scripts/simulate.py [--keep]

Nothing outside the sandbox directory is touched.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SAMPLE = '''"""A module that is about to be plagiarised."""


def fibonacci(limit):
    a, b = 0, 1
    out = []
    while a < limit:
        out.append(a)
        a, b = b, a + b
    return out


def primes_below(n):
    sieve = [True] * n
    for i in range(2, int(n ** 0.5) + 1):
        if sieve[i]:
            for j in range(i * i, n, i):
                sieve[j] = False
    return [i for i in range(2, n) if sieve[i]]
'''


def sh(cmd, cwd=None, check=False):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=check)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the sandbox for inspection")
    ap.add_argument("--seconds", type=int, default=25, help="how long to let the agent run")
    args = ap.parse_args()

    sandbox = tempfile.mkdtemp(prefix="hacksys-sim-")
    project = os.path.join(sandbox, "submission")
    downloads = os.path.join(sandbox, "Downloads")
    reference = os.path.join(sandbox, "reference-clone")
    agent_home = os.path.join(sandbox, "agent")
    for d in (project, downloads, reference, agent_home):
        os.makedirs(d, exist_ok=True)

    print(f"sandbox: {sandbox}")

    # a git repo to be the "submission"
    sh(["git", "init", "-q", project])
    sh(["git", "config", "user.email", "sim@example.com"], cwd=project)
    sh(["git", "config", "user.name", "Simulator"], cwd=project)
    with open(os.path.join(project, "README.md"), "w") as fh:
        fh.write("# sim\n")
    sh(["git", "add", "-A"], cwd=project)
    sh(["git", "commit", "-q", "-m", "initial"], cwd=project)

    # a second repo next door, of the sort people copy from
    sh(["git", "init", "-q", reference])
    with open(os.path.join(reference, "algos.py"), "w") as fh:
        fh.write(SAMPLE)

    now = datetime.now(timezone.utc)
    env = dict(os.environ, PYTHONPATH=ROOT)

    rc = subprocess.run(
        [sys.executable, "-m", "hacksys", "init",
         "--participant", "simulation",
         "--project", project,
         "--watch-root", sandbox,
         "--start", now.isoformat(),
         "--end", (now + timedelta(hours=1)).isoformat(),
         "--home", agent_home,
         "--yes"],
        env=env, capture_output=True, text=True,
    )
    if rc.returncode != 0:
        print(rc.stdout, rc.stderr)
        return 1

    config = os.path.join(agent_home, "config.toml")
    # point the agent's "staging" zone at the sandbox Downloads
    with open(config) as fh:
        lines = fh.read().splitlines()
    for i, line in enumerate(lines):
        if line.startswith("sensitive_roots"):
            lines[i] = f'sensitive_roots = ["{downloads}"]'
        elif line.startswith("git_interval"):
            lines[i] = "git_interval = 4.0"        # tight loop so a short sim sees commits
        elif line.startswith("gpg_interval"):
            lines[i] = "gpg_interval = 10.0"
    with open(config, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    agent = subprocess.Popen(
        [sys.executable, "-m", "hacksys", "--config", config, "start"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    print("agent started, giving it a moment to index…")
    time.sleep(8)

    # 1. a file lands in Downloads, then gets copied into the submission
    dl = os.path.join(downloads, "algos.py")
    with open(dl, "w") as fh:
        fh.write(SAMPLE)
    time.sleep(3)
    shutil.copy(dl, os.path.join(project, "algos.py"))
    print("  · copied Downloads/algos.py into the submission")
    time.sleep(4)

    # 2. content from the reference clone lands in the submission too
    shutil.copy(os.path.join(reference, "algos.py"), os.path.join(project, "helpers.py"))
    print("  · copied reference-clone/algos.py into the submission")
    time.sleep(4)

    # 3. an unsigned commit that adds it all
    sh(["git", "add", "-A"], cwd=project)
    sh(["git", "commit", "-q", "-m", "add algorithms"], cwd=project)
    print("  · committed (unsigned)")
    time.sleep(3)

    # 4. an amend, which rewrites what the submitted repo will show
    sh(["git", "commit", "-q", "--amend", "-m", "add algorithms (tidied)"], cwd=project)
    print("  · amended the commit")
    time.sleep(3)

    # 5. .gitignore starts hiding a source file
    with open(os.path.join(project, "secret_solver.py"), "w") as fh:
        fh.write("# the interesting part\n")
    with open(os.path.join(project, ".gitignore"), "w") as fh:
        fh.write("secret_solver.py\n")
    print("  · hid a source file with .gitignore")

    # let the git collector poll at least twice more so the amend and the
    # .gitignore change are actually observed
    time.sleep(max(12, args.seconds - 25))

    # seal stops the agent itself — going through the real path means the
    # intentional stop is recorded as intentional
    print("sealing…")
    seal = subprocess.run(
        [sys.executable, "-m", "hacksys", "--config", config, "seal", "--print-report"],
        env=env, capture_output=True, text=True,
    )
    try:
        agent.wait(timeout=20)
    except subprocess.TimeoutExpired:
        agent.kill()
    print(seal.stdout)
    if seal.stderr:
        print(seal.stderr, file=sys.stderr)

    if args.keep:
        print(f"\nsandbox kept at {sandbox}")
    else:
        shutil.rmtree(sandbox, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
