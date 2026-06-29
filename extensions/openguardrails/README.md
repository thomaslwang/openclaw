# OpenGuardrails (OGR) — bundled extension

Guards an OpenClaw assistant through the **OpenGuardrails (OGR)** protocol — a
vendor-neutral enforcement layer for AI agent safety & security.

**No OpenClaw core changes.** This is a pure plugin built on OpenClaw's
in-process [plugin hooks](../../docs/plugins/hooks.md). It is *restrict-only*:
it can stop a would-run tool call or a would-send message, never loosen one.

## What it does

Each hooked event becomes an OGR `GuardEvent`, runs through a `Runtime` built
from **your own policy** (deterministic text/regex rules, plus optionally your
own model as an LLM judge), and the resulting `Verdict` is enforced:

| Hook | `allow` / `modify` / `redact` | `block` | `require_approval` |
| --- | --- | --- | --- |
| **`before_tool_call`** | proceed | `{ block }` | `{ requireApproval }` — native `/approve` human gate |
| **`message_sending`** (outbound) | deliver | `{ cancel }` | `{ cancel }` |

The human-confirm gate and enforcement stay **privilege-separated**: the plugin
*decides*, the user *approves*, the host *enforces*.

## Configure

The assistant configures its **own** guardrails. Resolution order (low → high):

1. A safe default policy (curl-pipe-to-sh, `rm -rf /`, secret-file reads, …).
2. `<workspace>/openguardrails.json` — an OGR `policy.json` the assistant can
   edit. Override the path with `policyPath` or the `OPENGUARDRAILS_POLICY` env
   var.
3. Inline plugin config (highest precedence), under
   `plugins.entries.openguardrails.config`:

```json
{
  "plugins": {
    "entries": {
      "openguardrails": {
        "config": {
          "judge": {
            "baseURL": "http://localhost:11434/v1",
            "model": "your-guard-model",
            "apiKey": "..."
          },
          "guardMessages": true
        }
      }
    }
  }
}
```

`judge` points the LLM-judge detector at any OpenAI-compatible chat endpoint.
The policy format is identical across every OGR integration (opencode, hermes,
python), so one `policy.json` works everywhere.

## Relationship to the standalone package

This bundled extension is the in-repo twin of the standalone plugin published
to npm and ClawHub as
[`openguardrails-instrumentation-openclaw`](https://www.npmjs.com/package/openguardrails-instrumentation-openclaw).
External users can install that directly:

```bash
openclaw plugins install clawhub:openguardrails-instrumentation-openclaw
```

The OGR runtime under `src/ogr-core/` is **vendored** from the zero-dependency
[`@openguardrails/core`](https://www.npmjs.com/package/@openguardrails/core)
(v0.1.1) so the extension is self-contained and adds no third-party runtime
dependency to the OpenClaw tree.

## Scope & follow-ups

- v0.1 treats the principal as trusted. Channel-inbound tainting (untrusted
  message / web / mcp content → untrusted provenance, correlated into the tool
  call) is the next step via `message_received`.
- `before_tool_call` regex rules apply to shell-style tools; structured tools
  and free-text messages are the LLM judge's domain.

## License

Apache-2.0
