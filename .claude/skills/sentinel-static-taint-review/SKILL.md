---
name: sentinel-static-taint-review
description: "Trace untrusted input to dangerous sinks across files (SQL, shell, file paths, deserialization, templates, SSRF, eval) and confirm or dismiss pattern-tool hits with code evidence. Use for source-code vulnerability analysis."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Static taint review

For each candidate sink (start from semgrep/bandit findings: `python -m auditor findings list <run>`):
1. Identify the SOURCE: request params/body/headers/cookies, files, env, queues, CLI args.
2. Follow PROPAGATION: assignments, helper calls, framework binding; note sanitizers/validators.
3. Confirm the SINK and whether the sanitizer is sufficient for that sink's context.
4. Check reachability: is the route registered? behind auth? feature-flagged? dead code?
5. Decide: real flow (file with source/sink roles) | false positive (explain the sanitizer or
   unreachability so the verifier can mark it) | uncertain (unverified_hypothesis + what's missing).

Sink cheat-sheet: SQL string building into execute/raw; subprocess with shell=True or string
commands; os.path.join/open/send_file with user paths (no safe_join/realpath containment);
pickle/yaml.load/marshal/ObjectInputStream/BinaryFormatter; template rendering of user strings;
outbound HTTP to user-controlled URLs (SSRF); eval/exec/Function; XML parsers with entities.
Never write or run a payload to "prove" it.
