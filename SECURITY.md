# Security Policy

This policy is for **vulnerabilities in Sentinel Auditor itself** (the code in this repository).
It is not a channel for reporting issues in systems audited with Sentinel — report those to the
affected owner or bug bounty program.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | Yes |
| 0.2.x and earlier | No |

## Reporting a vulnerability

**Do not open a public issue with exploit details.**

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Include a description, affected version, reproduction steps, and impact.

If private reporting is unavailable, open a minimal public issue asking for a private channel.
Do not include payloads, secrets, or reproduction details in that issue.

## What to include

- Affected component (`auditor/`, `hooks/`, a harness configuration, etc.)
- Version and platform
- Steps to reproduce, ideally with the bundled fixture
- Whether a documented control can be bypassed (policy, hook, scope/network guard,
  read-only snapshot, evidence verification, audit log)
- Suggested fix, if you have one

## Scope of interest

We are especially interested in issues that:

- bypass the read-only guarantee or the scope/network guard;
- escape the target snapshot or write outside `audit-output/`;
- make an unverified finding appear verified;
- allow an agent to use a shell, network or write capability outside the allowlist;
- break the audit-log hash chain or hide an action;
- make a target's ignore files suppress findings;
- leak secrets into reports, logs or model context.

## Safety rules for researchers

- Test only against your own installation and the bundled vulnerable fixture.
- Do not test against third-party systems, even if Sentinel is configured to scan them.
- Do not include real credentials or personal data in a report.
- Give us reasonable time to fix the issue before public disclosure. We will credit reporters who
  want credit.

## Response

This is a community project without a paid bug bounty program. Reports are handled on a
best-effort basis. We will acknowledge valid reports, work on a fix, and coordinate disclosure.

## Known limitations

Some boundaries are documented as known gaps rather than vulnerabilities — for example, the DNS
rebinding window, Windows read-only semantics, and harness hook coverage. Please read
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) before reporting; a known limitation may still be worth
improving, but it is not a new finding.
