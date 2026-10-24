---
name: sentinel-authz-review
description: "Find missing or inconsistent authentication and authorization: IDOR/BOLA, missing role checks, tenant isolation gaps, ownership checks, session issues. Use for access-control analysis of source code and API specs."
license: MIT
compatibility: opencode, claude-code, codex (Agent Skills format)
metadata:
  project: sentinel-auditor
  mode: read-only
---
# Authorization review

Method (evidence by asymmetry):
1. List every handler with its guards (decorators/middleware/policies) from the inventory.
2. Build a matrix: route × required auth × role check × ownership/tenant check.
3. Flag: (a) handlers that load an object by client-supplied id without comparing owner/tenant
   to the session principal (IDOR, CWE-639); (b) privileged handlers missing a role check that
   sibling handlers have (CWE-862); (c) checks done client-side only; (d) spec says auth
   required but code has no guard, or vice versa (CWE-306).
4. Cite BOTH the vulnerable handler and the enforcing sibling/helper as locations.
5. Preconditions must be explicit (e.g., "any authenticated user").
Never log in, create accounts, or request other users' objects.
