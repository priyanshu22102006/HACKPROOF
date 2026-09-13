"""HackSys — the system-plane agent for HackProof.

Plane 1 of the HackProof architecture: a consenting participant runs this on
their own machine for the length of the hackathon. It records what happened
locally, seals it into a tamper-evident report, and hands that report to the
server, where it is compared with the repo-plane analysis of the submitted
GitHub repository.

Design commitments, in order:
  1. The participant can read everything it records, on their own disk.
  2. Gaps in monitoring are reported as loudly as findings.
  3. Nothing is ever labelled misconduct — the report states what happened.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
