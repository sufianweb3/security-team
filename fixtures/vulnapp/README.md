# vulnapp — INTENTIONALLY VULNERABLE TRAINING FIXTURE

**Never deploy, install, build or run this code.** It exists only as static input
for Sentinel Auditor's tests and example audit. Every credential in it is fake.
Known seeded issues are listed in `../vulnapp.expected.yaml` (ground truth used by tests).

The fixture also contains **adversarial ignore files** (`.semgrepignore`, `.gitleaks.toml`,
`.gitignore`) that try to hide its own vulnerable files from scanners. The auditor must ignore
them (tested in `tests/test_pipeline_e2e.py::test_adversarial_ignore_files_do_not_hide_findings`).
