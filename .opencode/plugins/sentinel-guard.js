// Sentinel Auditor policy guard for OpenCode.
// Runs before every tool call ("tool.execute.before") and delegates the decision to the
// same Python policy engine used by Claude Code and Codex (hooks/policy_guard.py).
// Fail closed: if Python cannot be started or returns non-zero, the tool call is blocked.
import { spawnSync } from "node:child_process"
import path from "node:path"

const candidates = () => {
  const env = process.env.SENTINEL_PYTHON
  if (env) return [env]
  return process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"]
}

export const SentinelGuard = async ({ directory, worktree }) => {
  const root = worktree || directory
  const hook = path.join(root, "hooks", "policy_guard.py")
  return {
    "tool.execute.before": async (input, output) => {
      const payload = JSON.stringify({ harness: "opencode", tool_name: input.tool, tool_input: output.args ?? {} })
      let lastErr = "python not found"
      for (const py of candidates()) {
        const args = py === "py" ? ["-3", hook] : [hook]
        const res = spawnSync(py, args, { input: payload, encoding: "utf8", cwd: root, timeout: 20000 })
        if (res.error) { lastErr = String(res.error); continue }
        if (res.status === 0) return
        throw new Error((res.stderr || "").trim() || `[sentinel policy] blocked ${input.tool}`)
      }
      throw new Error(`[sentinel policy] BLOCKED ${input.tool}: policy guard unavailable (${lastErr}); failing closed`)
    },
  }
}
