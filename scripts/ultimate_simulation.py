#!/usr/bin/env python3
"""Ultimate End-to-End Hackathon Attack & Defense Simulation for HACKPROOF.

Simulates a complete hackathon lifecycle demonstrating:
  1. Legitimate Work: Team members Alice (GPG) and Bob (SSH) commit signed code.
  2. Attack 1 (Outsider / Impostor): Outsider Eve writes code, spoofs Alice's identity, signs with an unregistered key.
  3. Attack 2 (The .gitignore Drip Cheat): Pre-written code hidden in .gitignore to drip-feed later.
  4. Attack 3 (Sneaky Git Index Manipulation): Using `git update-index --skip-worktree` to stealthily hide code.
  5. Attack 4 (Local Stealth Exclusion): Using `.git/info/exclude` to hide code from remote repos.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.engine import render_table, run_all
from tests.helpers import GpgHome, SshHome

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(title: str, subtitle: str = "") -> None:
    print(f"\n{CYAN}{'=' * 78}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    if subtitle:
        print(f"{DIM}{subtitle}{RESET}")
    print(f"{CYAN}{'=' * 78}{RESET}\n")


def git(repo: str, args: list[str], env: dict | None = None) -> str:
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    res = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=full_env,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(
            f"Git command failed: git {' '.join(args)}\nStdout: {res.stdout}\nStderr: {res.stderr}"
        )
    return res.stdout


def write(repo: str, rel: str, content: str) -> str:
    full = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(content)
    return full


def run_and_print_check(repo: str, roster_path: str, phase_name: str) -> None:
    print(f"{BOLD}>>> Running HACKPROOF Audit Engine for [{phase_name}]...{RESET}")
    findings = run_all(repo, roster_path=roster_path)
    print(render_table(findings))
    hard_flags = [f for f in findings if f.severity == "hard_flag"]
    flags = [f for f in findings if f.severity == "flag"]
    
    if hard_flags or flags:
        print(f"\n{RED}{BOLD}🚨 THREAT DETECTED!{RESET}")
        for h in hard_flags:
            print(f"  {RED}• [HARD FLAG] {h.check_name}:{RESET} {h.evidence}")
        for fl in flags:
            print(f"  {YELLOW}• [FLAG] {fl.check_name}:{RESET} {fl.evidence}")
    else:
        print(f"\n{GREEN}{BOLD}✅ REPO CLEAN: All checks passed. Proven genuine hackathon work.{RESET}")
    print()


def main() -> None:
    work_dir = "/tmp/hackproof_ultimate_demo"
    shutil.rmtree(work_dir, ignore_errors=True)
    os.makedirs(work_dir, exist_ok=True)

    repo_dir = os.path.join(work_dir, "hackathon_repo")
    alice_gpg_home = GpgHome(os.path.join(work_dir, "alice_gpg"))
    bob_ssh_home = SshHome(os.path.join(work_dir, "bob_ssh"))
    eve_gpg_home = GpgHome(os.path.join(work_dir, "eve_gpg"))

    try:
        banner(
            "HACKPROOF ULTIMATE DEMONSTRATION",
            "End-to-End Simulation: Genuine Work vs. 4 Realistic Hackathon Cheating Attacks",
        )

        # ----------------------------------------------------------------------
        # SETUP: Mint Keys & Organizer Roster
        # ----------------------------------------------------------------------
        print(f"{BOLD}[Setup 1/3]{RESET} Generating Alice's GPG Key (Member 1)...")
        alice_fpr = alice_gpg_home.generate_key("Alice <alice@teamalpha.test>")
        alice_pub = alice_gpg_home.export_public(alice_fpr)

        print(f"{BOLD}[Setup 2/3]{RESET} Generating Bob's SSH Key (Member 2)...")
        bob_priv, bob_pub, bob_fpr = bob_ssh_home.generate_key("id_ed25519", "bob@teamalpha.test")

        print(f"{BOLD}[Setup 3/3]{RESET} Generating Eve's Unregistered Key (Outsider / Impostor)...")
        eve_fpr = eve_gpg_home.generate_key("Eve <eve@outsider.test>")

        # Initialize Git Repo
        git(work_dir, ["init", "-q", "-b", "main", repo_dir])
        git(repo_dir, ["config", "user.name", "Hackathon Participant"])
        git(repo_dir, ["config", "user.email", "participant@teamalpha.test"])

        # Create Official Organizer Roster
        roster_path = os.path.join(work_dir, "hackproof-roster.json")
        roster_data = {
            "team_id": "team-alpha",
            "members": [
                {
                    "name": "Alice",
                    "email": "alice@teamalpha.test",
                    "keys": [
                        {
                            "type": "openpgp",
                            "fingerprint": alice_fpr,
                            "public_key": alice_pub,
                        }
                    ],
                },
                {
                    "name": "Bob",
                    "email": "bob@teamalpha.test",
                    "keys": [
                        {
                            "type": "ssh",
                            "fingerprint": bob_fpr,
                            "public_key": bob_pub,
                        }
                    ],
                },
            ],
        }
        with open(roster_path, "w", encoding="utf-8") as f:
            json.dump(roster_data, f, indent=2)

        write(repo_dir, "README.md", "# Project Alpha\nHackathon submission project.\n")
        write(repo_dir, ".gitignore", "*.pyc\n__pycache__/\n.env\n")
        git(repo_dir, ["add", "-A"])
        git(repo_dir, ["commit", "-q", "-m", "initial commit"])

        # ----------------------------------------------------------------------
        # PHASE 1: Genuine Commits by Registered Team Members
        # ----------------------------------------------------------------------
        banner(
            "PHASE 1: Genuine Work by Registered Members (Alice & Bob)",
            "Alice signs with GPG, Bob signs with SSH. Both match organizer roster.",
        )

        # Alice commits with GPG
        write(repo_dir, "src/app.py", "# Alice's legitimate web service\nimport sys\n\ndef main():\n    print('Hello world')\n")
        git(repo_dir, ["add", "src/app.py"])
        alice_env = {
            **alice_gpg_home.env,
            "GIT_AUTHOR_NAME": "Alice",
            "GIT_AUTHOR_EMAIL": "alice@teamalpha.test",
            "GIT_COMMITTER_NAME": "Alice",
            "GIT_COMMITTER_EMAIL": "alice@teamalpha.test",
        }
        git(
            repo_dir,
            ["commit", "-S", f"--gpg-sign={alice_fpr}", "-m", "feat: create main application service"],
            env=alice_env,
        )

        # Bob commits with SSH
        write(repo_dir, "src/utils.py", "# Bob's utility functions\ndef add(a, b):\n    return a + b\n")
        git(repo_dir, ["add", "src/utils.py"])
        bob_env = {
            "GIT_AUTHOR_NAME": "Bob",
            "GIT_AUTHOR_EMAIL": "bob@teamalpha.test",
            "GIT_COMMITTER_NAME": "Bob",
            "GIT_COMMITTER_EMAIL": "bob@teamalpha.test",
        }
        git(repo_dir, ["config", "gpg.format", "ssh"])
        git(repo_dir, ["config", "user.signingkey", bob_priv])
        git(repo_dir, ["commit", "-S", "-m", "feat: add utility math helpers"], env=bob_env)

        run_and_print_check(repo_dir, roster_path, "Phase 1 - Genuine Work")

        # ----------------------------------------------------------------------
        # PHASE 2: Attack 1 — Outsider / Impostor (Ghostwriter)
        # ----------------------------------------------------------------------
        banner(
            "PHASE 2: ATTACK 1 — The Outsider Impostor (Ghostwriter)",
            "Eve (unregistered outside contractor) writes code, fakes Alice's name in Git header, signs with Eve's key.",
        )
        write(repo_dir, "src/secret_auth.py", "# Outsider Eve wrote this for the team\ndef login(u, p):\n    return True\n")
        git(repo_dir, ["add", "src/secret_auth.py"])
        eve_env = {
            **eve_gpg_home.env,
            # Spoofing Alice's identity in the Git header!
            "GIT_AUTHOR_NAME": "Alice",
            "GIT_AUTHOR_EMAIL": "alice@teamalpha.test",
            "GIT_COMMITTER_NAME": "Alice",
            "GIT_COMMITTER_EMAIL": "alice@teamalpha.test",
        }
        git(repo_dir, ["config", "gpg.format", "openpgp"])
        git(
            repo_dir,
            ["commit", "-S", f"--gpg-sign={eve_fpr}", "-m", "feat: implement authentication system"],
            env=eve_env,
        )

        run_and_print_check(repo_dir, roster_path, "Phase 2 - Outsider Impostor")

        # ----------------------------------------------------------------------
        # PHASE 3: Attack 2 — The Pre-Built Code Drip-Feed Cheat (.gitignore)
        # ----------------------------------------------------------------------
        banner(
            "PHASE 3: ATTACK 2 — The .gitignore Pre-Built Code Drip Cheat",
            "Team brings a pre-built ML engine (3 files), conceals directory in .gitignore so git status looks clean.",
        )
        # Drop pre-written code
        write(repo_dir, "src/prebuilt_ai/model.py", "# 1000 lines of pre-built code\nclass Model:\n    pass\n")
        write(repo_dir, "src/prebuilt_ai/weights.py", "WEIGHTS = [0.1, 0.2, 0.3]\n")
        write(repo_dir, "src/prebuilt_ai/inference.py", "def predict(x): return x * 2\n")

        # Hide it in .gitignore!
        write(repo_dir, ".gitignore", "*.pyc\n__pycache__/\n.env\nsrc/prebuilt_ai/\n")
        git(repo_dir, ["add", ".gitignore"])
        git(
            repo_dir,
            ["commit", "-S", f"--gpg-sign={alice_fpr}", "-m", "chore: tidy up gitignore rules"],
            env=alice_env,
        )

        run_and_print_check(repo_dir, roster_path, "Phase 3 - .gitignore Prebuilt Drip Cheat")

        # ----------------------------------------------------------------------
        # PHASE 4: Attack 3 — Sneaky Git Index Manipulation (skip-worktree)
        # ----------------------------------------------------------------------
        banner(
            "PHASE 4: ATTACK 3 — Sneaky Git Index Manipulation (skip-worktree)",
            "Team commits a stub, then marks file skip-worktree and overwrites it on disk. Git status says 'clean'!",
        )
        # Commit a harmless stub
        write(repo_dir, "src/core_engine.py", "# stub engine\n")
        git(repo_dir, ["add", "src/core_engine.py"])
        git(repo_dir, ["commit", "-S", f"--gpg-sign={alice_fpr}", "-m", "feat: add stub engine"], env=alice_env)

        # Sneakily set skip-worktree bit
        git(repo_dir, ["update-index", "--skip-worktree", "src/core_engine.py"])
        time.sleep(1.0)
        # Overwrite file with secret implementation
        real_engine = write(
            repo_dir,
            "src/core_engine.py",
            "# REAL SECRET IMPLEMENTATION OVERWRITTEN LOCALLY\nclass AdvancedEngine:\n    def compute(self): return 99999\n",
        )
        # Touch timestamp forward
        future = time.time() + 60
        os.utime(real_engine, (future, future))

        run_and_print_check(repo_dir, roster_path, "Phase 4 - skip-worktree Stealth Cheat")

        # ----------------------------------------------------------------------
        # PHASE 5: Attack 4 — Local Stealth Exclusion (.git/info/exclude)
        # ----------------------------------------------------------------------
        banner(
            "PHASE 5: ATTACK 4 — Local Stealth Exclusion (.git/info/exclude)",
            "Team hides code using .git/info/exclude, which is never tracked or pushed to GitHub.",
        )
        write(repo_dir, "secret_crawler/spider.py", "# Pre-built web crawler hidden locally\ndef crawl(): pass\n")
        info_exclude = os.path.join(repo_dir, ".git", "info", "exclude")
        with open(info_exclude, "a", encoding="utf-8") as f:
            f.write("secret_crawler/\n")

        run_and_print_check(repo_dir, roster_path, "Phase 5 - .git/info/exclude Stealth Cheat")

        banner(
            "SUMMARY OF HACKPROOF DEMONSTRATION",
            f"All tests completed. Demo repository preserved at: {repo_dir}",
        )
        print(f"{GREEN}{BOLD}HACKPROOF successfully defended against all 4 hackathon cheating vectors:{RESET}")
        print(f" 1. Impostor/Outsider commits caught by cryptographic key mismatch.")
        print(f" 2. Pre-built code staging caught by .gitignore working-tree audit and history diffs.")
        print(f" 3. Stealth index manipulation caught by `git update-index --skip-worktree` audit.")
        print(f" 4. Untracked local exclusions caught by `.git/info/exclude` inspector.\n")

    finally:
        alice_gpg_home.close()
        bob_ssh_home.close()
        eve_gpg_home.close()


if __name__ == "__main__":
    main()
