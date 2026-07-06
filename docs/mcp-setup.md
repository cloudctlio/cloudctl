# Using cloudctl from AI assistants (MCP)

cloudctl ships an **MCP server** (stdio) exposing 17 tools — including
`cloudctl_debug_incident`, which runs the full VERDICT hypothesis-graph agent.
Any MCP-compatible host can call it. Verified handshake: protocol `2025-11-25`,
17 tools enumerated.

The server launches via the `cloudctl-mcp` console entry point (installed with
the package). Everywhere below you can substitute
`python -m cloudctl.mcp.server` for `cloudctl-mcp` if the script isn't on PATH.

> **Credentials:** by default cloudctl reasons with **AWS Bedrock**, so pass AWS
> credentials via env (`AWS_PROFILE`/`AWS_REGION`). To run the reasoning on a
> different model provider, set `CLOUDCTL_MODEL_PROVIDER` + the provider's API
> key — see [Model providers](#model-providers-byo-model).

---

## Claude Desktop

`claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "cloudctl": {
      "command": "cloudctl-mcp",
      "env": { "AWS_PROFILE": "your-profile", "AWS_REGION": "us-east-1" }
    }
  }
}
```

## GitHub Copilot (VS Code)

`.vscode/mcp.json` in the workspace (or the `mcp` block in user settings):

```json
{
  "servers": {
    "cloudctl": {
      "type": "stdio",
      "command": "cloudctl-mcp",
      "env": { "AWS_PROFILE": "your-profile", "AWS_REGION": "us-east-1" }
    }
  }
}
```

## Codex CLI (OpenAI)

`~/.codex/config.toml`:

```toml
[mcp_servers.cloudctl]
command = "cloudctl-mcp"
env = { AWS_PROFILE = "your-profile", AWS_REGION = "us-east-1" }
```

## Gemini CLI (Google)

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "cloudctl": {
      "command": "cloudctl-mcp",
      "env": { "AWS_PROFILE": "your-profile", "AWS_REGION": "us-east-1" }
    }
  }
}
```

---

## Try it

Once configured, ask the assistant something like:

> Use cloudctl to debug: "checkout latency spiked and orders are failing"

The host calls `cloudctl_debug_incident`; cloudctl runs parallel hypothesis
branches, tests falsifiable predictions, and returns a root cause with
confidence and per-branch verdicts.

## Model providers (BYO-model)

cloudctl's reasoning model is selectable, so the tool can run inside any host
without requiring AWS Bedrock:

| Provider | `CLOUDCTL_MODEL_PROVIDER` | Credentials | Example `CLOUDCTL_MODEL` |
|---|---|---|---|
| AWS Bedrock (default) | `bedrock` | `AWS_PROFILE` | `us.anthropic.claude-sonnet-4-6` |
| Anthropic API | `anthropic` | `ANTHROPIC_API_KEY` | `claude-sonnet-4-6` |
| OpenAI | `openai` | `OPENAI_API_KEY` | `gpt-5` |
| Google Gemini | `gemini` | `GEMINI_API_KEY` | `gemini-2.5-pro` |

> The **reasoning model** (above) is separate from **tool access**. cloudctl's
> tools read your cloud (AWS), so a *real* investigation still needs AWS
> credentials regardless of reasoning provider. To exercise the full pipeline
> without AWS, run against a recorded fixture (`CLOUDCTL_REPLAY=<fixture.jsonl>`)
> — tools are served from the recording while the reasoning runs live on your
> chosen provider.

> **API key ≠ chat subscription.** The providers use *developer API keys*
> (console.anthropic.com, aistudio.google.com), which are billed separately from
> Claude Pro / Gemini Advanced consumer subscriptions.

Add these to the `env` block for your host. See
`cloudctl/ai/model_providers.py` for the provider interface — new backends
implement one `converse(...)` method and are registered in the factory.
