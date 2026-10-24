# Resources (curated, primary sources)

## Harness documentation used for this build (fetched 2026-10-24)
- OpenCode agents: https://opencode.ai/docs/agents/
- OpenCode permissions: https://opencode.ai/docs/permissions/
- OpenCode skills: https://opencode.ai/docs/skills/
- OpenCode plugins (`tool.execute.before`): https://opencode.ai/docs/plugins/
- OpenCode providers (DeepSeek, custom): https://opencode.ai/docs/providers/
- Claude Code subagents: https://docs.anthropic.com/en/docs/claude-code/sub-agents
- Codex config reference: https://developers.openai.com/codex/config-reference
- Codex subagents / custom agents: https://developers.openai.com/codex/subagents
- Codex skills: https://developers.openai.com/codex/skills
- Codex hooks: https://developers.openai.com/codex/hooks
- Codex permission profiles: https://developers.openai.com/codex/permissions
- Agent Skills specification: https://agentskills.io/specification
- DeepSeek API & model ids: https://api-docs.deepseek.com/
- DeepSeek ↔ Codex: https://api-docs.deepseek.com/quick_start/agent_integrations/codex
- DeepSeek ↔ Claude Code: https://api-docs.deepseek.com/quick_start/agent_integrations/claude_code

## Tools (primary repositories)
- Semgrep: https://github.com/semgrep/semgrep · rules: https://github.com/semgrep/semgrep-rules
- Bandit: https://github.com/PyCQA/bandit
- Gitleaks: https://github.com/gitleaks/gitleaks
- OSV-Scanner: https://github.com/google/osv-scanner · database: https://osv.dev
- zizmor (GitHub Actions): https://github.com/zizmorcore/zizmor
- Slither (Solidity, optional): https://github.com/crytic/slither

## Vulnerability data & standards
- CWE: https://cwe.mitre.org/
- CVSS v3.1 specification: https://www.first.org/cvss/v3.1/specification-document
- CVSS v4.0: https://www.first.org/cvss/v4.0/specification-document
- GitHub Advisory Database: https://github.com/advisories
- NVD: https://nvd.nist.gov/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP Top 10: https://owasp.org/Top10/
- GitHub Actions hardening: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- GitHub Security Lab — untrusted input in Actions: https://securitylab.github.com/resources/github-actions-untrusted-input/
- GitHub Security Lab — pwn requests: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/

## Supply-chain incidents referenced
- Trivy / trivy-action compromise (CVE-2026-33634): https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- Aqua write-up: https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/
- Red Hat bulletin RHSB-2026-001 (LiteLLM, Trivy, KICS, Axios and others, March 2026):
  https://access.redhat.com/security/vulnerabilities/RHSB-2026-001
  — relevant if you put a model proxy such as LiteLLM in front of DeepSeek: pin and verify it.

## Bug bounty program rules (read before any web scope)
- HackerOne disclosure guidelines: https://www.hackerone.com/disclosure-guidelines
- Bugcrowd standard disclosure terms: https://www.bugcrowd.com/resources/essentials/standard-disclosure-terms/
- Always the specific program's policy page — it overrides everything here.
