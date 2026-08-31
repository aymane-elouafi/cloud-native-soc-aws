# Security & Responsible Use

This repository documents a **deliberately-vulnerable, educational purple-team lab** built in an
isolated AWS account that has since been **decommissioned**.

- All credentials shown (e.g. `finance_admin` / `finance2026`, weak defaults, lab account IDs) are
  **intentionally weak lab values** used to demonstrate the attacks. They are not live and must never
  be reused.
- Real secrets (AWS access keys, the Shuffle webhook token, the DFIR-IRIS API key, passwords) have
  been **redacted** or kept out of the repo entirely.
- The attack runners are for use **only against the isolated lab you control**. Running them against
  systems you are not explicitly authorized to test is illegal.

This project is intended for **authorized, defensive security research, detection engineering, and
training** only.
