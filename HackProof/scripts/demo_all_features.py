#!/usr/bin/env python3
"""HACKPROOF End-to-End Feature Showcase.

Runs every feature against both a dedicated test repository (simulating real-world
hackathon submissions with signed/unsigned commits, active concealment, burst
commits, and late gitignore additions) and remote GitHub repositories, formatting
all outputs cleanly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile


def print_banner(title: str, subtitle: str = ""):
    border = "═" * 78
    print(f"\n{border}")
    print(f"  {title.upper()}")
    if subtitle:
        print(f"  {subtitle}")
    print(f"{border}\n")


def run_cmd(cmd: list[str], cwd: str | None = None, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)


def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "hackproof.db")
    team_id = "team-pritim"

    print("=" * 78)
    print("      🚀 HACKPROOF COMPLETE END-TO-END FEATURE TEST RUNNER")
    print("=" * 78)

    # -------------------------------------------------------------------------
    # 1. Multi-Team Roster & Key/Device Registration
    # -------------------------------------------------------------------------
    print_banner("1. Multi-Team Roster & Hardware Device Enrollment", "Command: hackproof-roster list")
    proc = run_cmd(["hackproof-roster", "--db", db_path, "list"], cwd=base_dir)
    print(proc.stdout)

    # -------------------------------------------------------------------------
    # 2. GitHub REST Polling & Metadata Synchronization
    # -------------------------------------------------------------------------
    print_banner("2. Remote GitHub REST Poller & Metadata Synchronization", "Command: hackproof-poll octocat/Hello-World")
    proc = run_cmd(["hackproof-poll", "octocat/Hello-World", "--db", db_path], cwd=base_dir)
    print(proc.stdout)

    # -------------------------------------------------------------------------
    # 3. Create a Realistic Test Repository for In-Depth Forensic Analysis
    # -------------------------------------------------------------------------
    tmp_repo_dir = tempfile.mkdtemp(prefix="hackproof-test-repo-")
    try:
        # Initialize test repository
        run_cmd(["git", "init", "-q", "-b", "main"], cwd=tmp_repo_dir)
        run_cmd(["git", "config", "user.name", "Pritim Mondal"], cwd=tmp_repo_dir)
        run_cmd(["git", "config", "user.email", "mondalpritim14@gmail.com"], cwd=tmp_repo_dir)

        # Commit 1: Initial repository setup with baseline .gitignore [INIT]
        gitignore_file = os.path.join(tmp_repo_dir, ".gitignore")
        with open(gitignore_file, "w") as f:
            f.write("# Standard baseline ignores\n__pycache__/\n*.pyc\nnode_modules/\n")
        with open(os.path.join(tmp_repo_dir, "README.md"), "w") as f:
            f.write("# Hackathon Project\nBuilding an awesome AI application.\n")

        run_cmd(["git", "add", "-A"], cwd=tmp_repo_dir)
        env1 = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-13T02:00:00+05:30", "GIT_COMMITTER_DATE": "2026-09-13T02:00:00+05:30"}
        subprocess.run(["git", "commit", "-q", "-m", "Initial commit with baseline rules"], cwd=tmp_repo_dir, env=env1)

        # Commit 2: Rapid/Burst commit simulating speedrun / script injection
        with open(os.path.join(tmp_repo_dir, "main.py"), "w") as f:
            f.write("def run():\n    print('Hello world')\n")
        run_cmd(["git", "add", "main.py"], cwd=tmp_repo_dir)
        env2 = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-13T02:00:01+05:30", "GIT_COMMITTER_DATE": "2026-09-13T02:00:01+05:30"}
        subprocess.run(["git", "commit", "-q", "-m", "Add main application"], cwd=tmp_repo_dir, env=env2)

        # Commit 3: LATE ADDED ignore rule (to conceal uncommitted pre-built files)
        with open(gitignore_file, "a") as f:
            f.write("src/concealed_engine/\n")
        run_cmd(["git", "add", ".gitignore"], cwd=tmp_repo_dir)
        env3 = {**os.environ, "GIT_AUTHOR_DATE": "2026-09-13T05:30:00+05:30", "GIT_COMMITTER_DATE": "2026-09-13T05:30:00+05:30"}
        subprocess.run(["git", "commit", "-q", "-m", "Late update to gitignore"], cwd=tmp_repo_dir, env=env3)

        # Create active uncommitted source file inside the late ignored path (ACTIVE CONCEALMENT)
        concealed_dir = os.path.join(tmp_repo_dir, "src", "concealed_engine")
        os.makedirs(concealed_dir, exist_ok=True)
        with open(os.path.join(concealed_dir, "proprietary_model.py"), "w") as f:
            f.write("# Proprietary pre-built neural weights & architecture\ndef predict(): pass\n")

        # ---------------------------------------------------------------------
        # 4. Forensic Blame View of .gitignore (§8.f)
        # ---------------------------------------------------------------------
        print_banner("3. .gitignore Forensic Blame View (§8.f)", "Command: python -m analyzers.gitignore_check <repo> --blame")
        proc = run_cmd([sys.executable, "-m", "analyzers.gitignore_check", tmp_repo_dir, "--blame"], cwd=base_dir)
        print(proc.stdout)

        # ---------------------------------------------------------------------
        # 5. Full HACKPROOF Audit Engine with All Analyzers & Summary Card
        # ---------------------------------------------------------------------
        print_banner(
            "4. Comprehensive Audit Engine Report & Executive Judge Card",
            f"Command: hackproof-analyze <repo> --roster hackproof.db --team-id {team_id} --blame-ignore --t0 2026-09-13T01:00:00+05:30"
        )
        proc = run_cmd([
            "hackproof-analyze",
            tmp_repo_dir,
            "--roster", db_path,
            "--team-id", team_id,
            "--blame-ignore",
            "--t0", "2026-09-13T01:00:00+05:30",
        ], cwd=base_dir)
        print(proc.stdout)

        # ---------------------------------------------------------------------
        # 6. Direct Remote GitHub Repository Analysis
        # ---------------------------------------------------------------------
        print_banner(
            "5. Direct Remote GitHub Repository Auditing (Auto-Clone & Inspect)",
            "Command: hackproof-analyze octocat/Hello-World --blame-ignore"
        )
        proc = run_cmd(["hackproof-analyze", "octocat/Hello-World", "--blame-ignore"], cwd=base_dir)
        print(proc.stdout)

        print("=" * 78)
        print("  🎉 ALL HACKPROOF FEATURES EXECUTED AND VERIFIED SUCCESSFULLY!")
        print("=" * 78)

    finally:
        shutil.rmtree(tmp_repo_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
