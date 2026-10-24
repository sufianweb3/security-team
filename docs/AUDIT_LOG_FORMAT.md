# Audit log format

File: `audit-output/<assessment>/<run>/audit-log.jsonl` (one JSON object per line), plus
`audit-output/_policy/decisions.jsonl` for hook decisions across runs.

```json
{"ts": "2026-10-23T18:45:01.123456Z", "event": "net.request", "actor": "netguard",
 "decision": "allow", "data": {"url": "...", "method": "GET", "status": 200, "bytes": 5120},
 "prev_hash": "<sha256 of previous record>", "hash": "<sha256(prev_hash + canonical record)>"}
```
| Field | Meaning |
|---|---|
| `ts` | UTC timestamp, microseconds |
| `event` | `run.start`, `ingest.local`, `ingest.repo`, `tool.run`, `tool.unavailable`, `net.request`, `net.denied`, `net.redirect_blocked`, `web.skip`, `findings.add`, `findings.status`, `run.report`, `policy.hook` |
| `actor` | component or agent name |
| `decision` | `allow` · `deny` · `skip` · null |
| `data` | event details, **redacted** before writing |
| `prev_hash`/`hash` | hash chain (genesis = 64 zeros) |

Verify: `python -m auditor log verify <run>` (also written to `audit-log.verify.txt` at report
time). Any edit, deletion or reordering breaks the chain. The chain is tamper-*evident*, not
tamper-*proof*: someone with write access can rewrite the whole file; ship logs to append-only
storage if you need stronger guarantees.
