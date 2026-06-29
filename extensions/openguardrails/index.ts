/**
 * OpenGuardrails (OGR) bundled extension.
 *
 * Guards an OpenClaw assistant through the OpenGuardrails (OGR) protocol — a
 * vendor-neutral enforcement layer for AI agent safety & security. The
 * bundled-extension twin of the standalone npm/ClawHub plugin
 * `openguardrails-instrumentation-openclaw`.
 *
 * Each hooked event becomes an OGR `GuardEvent`, runs through a `Runtime` built
 * from the assistant's own guardrails policy (text/regex rules, plus optionally
 * its own model as an LLM judge), and the `Verdict` is enforced:
 *
 *   before_tool_call   allow | modify | redact → proceed
 *                      block                   → { block }
 *                      require_approval        → { requireApproval } (human gate)
 *
 *   message_sending    allow | modify | redact → deliver
 *                      block | require_approval → { cancel } (outbound guard)
 *
 * No OpenClaw core changes: this is a pure plugin and a "restrict-only" guard —
 * it can stop a would-run tool call or a would-send message, never loosen one.
 * The human-confirm gate (`requireApproval`) and enforcement stay privilege-
 * separated: the plugin decides, the user approves, the host enforces.
 */
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry"
import {
  Runtime,
  ConfigRulesDetector,
  LLMJudgeDetector,
  type Detector,
  type GuardEvent,
  type Verdict,
} from "./src/ogr-core/index.js"
import { loadGuardrailsConfig, type GuardrailsOptions } from "./src/config.js"
import { openAICompatibleBackend } from "./src/own-model.js"

let seq = 0
function id(prefix: string): string {
  seq += 1
  const rand = globalThis.crypto?.randomUUID?.().slice(0, 8) ?? seq.toString(36).padStart(8, "0")
  return `${prefix}-${seq.toString(36)}-${rand}`
}

function brief(v: Verdict): string {
  const cats = v.categories.map((c) => `${c.id}(${c.score})`).join(", ")
  const why = v.reasons.filter((r) => !r.startsWith("[")).join("; ")
  return [cats, why].filter(Boolean).join(" — ") || v.decision
}

/**
 * Lazily builds and caches the OGR runtime. The policy file lives in the
 * workspace, which is only known at `gateway_start`; tool/message hooks build
 * on first use if startup has not populated it yet.
 */
class GuardManager {
  private runtime: Runtime | undefined
  private guardMessages = true
  private workspaceDir: string | undefined
  private options: GuardrailsOptions | undefined

  configure(workspaceDir: string | undefined, options: GuardrailsOptions | undefined): void {
    this.workspaceDir = workspaceDir
    this.options = options
    this.runtime = undefined // force rebuild with the new workspace/options
    this.ensure()
  }

  private ensure(): Runtime {
    if (this.runtime) return this.runtime
    const { policy, judge, guardMessages } = loadGuardrailsConfig(this.workspaceDir, this.options)
    const detectors: Detector[] = [new ConfigRulesDetector(policy.config_rules ?? {})]
    if (judge) detectors.push(new LLMJudgeDetector(openAICompatibleBackend(judge)))
    this.guardMessages = guardMessages
    this.runtime = new Runtime(detectors, policy)
    return this.runtime
  }

  get messagesEnabled(): boolean {
    this.ensure()
    return this.guardMessages
  }

  evaluate(ev: GuardEvent): Promise<Verdict> {
    return this.ensure().evaluate(ev)
  }
}

/** Best-effort read of this plugin's config out of the OpenClaw config tree. */
function readOptions(config: unknown): GuardrailsOptions | undefined {
  const entries = (config as { plugins?: { entries?: Record<string, { config?: unknown }> } })?.plugins?.entries
  return entries?.["openguardrails"]?.config as GuardrailsOptions | undefined
}

// Annotate via the importable `definePluginEntry` symbol so the emitted
// declaration does not inline OpenClaw's non-exported `DefinedPluginEntry`
// type (TS2742 portability).
const plugin: ReturnType<typeof definePluginEntry> = definePluginEntry({
  id: "openguardrails",
  name: "OpenGuardrails",
  description:
    "Enforce the OpenGuardrails (OGR) protocol on tool calls and channel traffic — block, rewrite, or require human approval under a policy you own.",
  register(api) {
    const guard = new GuardManager()

    // Resolve the workspace-scoped policy once the Gateway is up.
    api.on("gateway_start", (_event, ctx) => {
      const c = ctx as { workspaceDir?: string; config?: unknown }
      guard.configure(c.workspaceDir, readOptions(c.config))
    })

    // Core enforcement: every tool call, before it runs.
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        const c = ctx as { agentId?: string; sessionKey?: string; channelId?: string }
        const ev: GuardEvent = {
          kind: "tool_call",
          observationPoint: "agent_hook",
          subject: {
            agent_id: c.agentId ?? "openclaw",
            agent_type: "openclaw",
            session_id: c.sessionKey,
            channel: c.channelId,
          },
          payload: { name: event.toolName, arguments: event.params },
          eventId: id("evt"),
          guardId: event.toolCallId ?? id("ga"),
          timestamp: new Date().toISOString(),
          sessionId: c.sessionKey,
          // v0.1: the principal is trusted. Channel-inbound tainting
          // (untrusted message/web/mcp content → untrusted provenance) is a
          // follow-up via message_received correlation.
          provenance: [{ source: "user", trust: "trusted" }],
        }

        const verdict = await guard.evaluate(ev)

        if (verdict.decision === "block") {
          return { block: true, blockReason: `[OpenGuardrails] ${brief(verdict)}` }
        }
        if (verdict.decision === "require_approval") {
          return {
            requireApproval: {
              title: `Approve ${event.toolName}?`,
              description: `[OpenGuardrails] ${brief(verdict)}`,
              severity: "warning",
              timeoutBehavior: "deny",
              pluginId: "openguardrails",
            },
          }
        }
        // allow | modify | redact → proceed unchanged
        return
      },
      { priority: 50 },
    )

    // Outbound guard: cancel a reply a deny verdict would forbid.
    api.on("message_sending", async (event, ctx) => {
      if (!guard.messagesEnabled) return
      const e = event as { content?: string }
      const c = ctx as { agentId?: string; sessionKey?: string; messageProvider?: string }
      const ev: GuardEvent = {
        kind: "model_output",
        observationPoint: "gateway",
        subject: { agent_id: c.agentId ?? "openclaw", agent_type: "openclaw", session_id: c.sessionKey },
        payload: { content: e.content ?? "", channel: c.messageProvider },
        eventId: id("evt"),
        guardId: id("ga"),
        timestamp: new Date().toISOString(),
        sessionId: c.sessionKey,
        provenance: [{ source: "model", trust: "unverified" }],
      }

      const verdict = await guard.evaluate(ev)
      if (verdict.decision === "block" || verdict.decision === "require_approval") {
        return {
          cancel: true,
          cancelReason: `openguardrails:${verdict.decision}`,
          metadata: { reason: brief(verdict) },
        }
      }
      return
    })
  },
})

export default plugin

export { DEFAULT_POLICY } from "./src/config.js"
export type { GuardrailsOptions, JudgeConfig } from "./src/config.js"
