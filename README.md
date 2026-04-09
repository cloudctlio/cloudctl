# cctl — Universal Cloud CLI

> One command for AWS, Azure, and GCP. Diagnose, fix, and manage cloud infrastructure with AI.

[![Security Scan](https://github.com/cloudctlio/cloudctl/actions/workflows/security.yml/badge.svg)](https://github.com/cloudctlio/cloudctl/actions/workflows/security.yml)
[![PyPI](https://img.shields.io/pypi/v/cctl)](https://pypi.org/project/cctl/)
[![Python](https://img.shields.io/pypi/pyversions/cctl)](https://pypi.org/project/cctl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What is it?

`cctl` installs the `cloudctl` command — a single CLI that works across AWS, Azure, and GCP using your existing credentials. No new login. No config files to write.

Three modes, one install:

```
cloudctl compute list --cloud all          # query all three clouds at once
cloudctl debug "payments returning 502s"   # AI diagnoses your incident
cloudctl ask "why is prod slow?"           # AI answers cloud questions
```

---

## Install

```bash
# Core CLI (AWS, Azure, GCP)
pip install cctl

# With MCP server (Claude Desktop / Cursor integration)
pip install cctl[mcp]

# With AI debug + ask commands
pip install cctl[ai]

# Everything
pip install cctl[all]
```

---

## Quick Start

```bash
# First-run: auto-detects your existing AWS/Azure/GCP credentials
cloudctl init

# See all configured cloud accounts
cloudctl accounts list

# Query across all clouds at once
cloudctl compute list --cloud all
cloudctl cost summary --cloud all
cloudctl security audit --cloud all

# Target a specific account or environment
cloudctl compute list --account prod
cloudctl database list --cloud aws --env staging
```

---

## Commands

### Infrastructure

| Command | Description |
|---|---|
| `cloudctl compute list/describe/stop/start` | VMs, Lambda, Cloud Run, ECS, GKE |
| `cloudctl storage list/describe/ls/du` | S3, Blob Storage, GCS |
| `cloudctl database list/describe/snapshots` | RDS, Azure SQL, Cloud SQL, and more |
| `cloudctl network vpcs/security-groups/lb` | VPCs, NSGs, load balancers, DNS |
| `cloudctl containers list/describe` | ECS, AKS, GKE, ACR, ECR |
| `cloudctl iam roles/users/check` | IAM roles, users, permission checks |
| `cloudctl security audit/public-resources` | Security posture and misconfigurations |
| `cloudctl cost summary/by-service` | Cost breakdown across clouds |
| `cloudctl pipeline list/analyze` | CodePipeline, Azure DevOps, Cloud Build |
| `cloudctl monitoring alerts/metrics` | CloudWatch, Azure Monitor, Cloud Monitoring |
| `cloudctl messaging topics/queues` | SQS/SNS, Service Bus, Pub/Sub |
| `cloudctl backup list/status` | Backup jobs across clouds |
| `cloudctl find <query>` | Search resources by name, tag, or type |
| `cloudctl diff <resource>` | Detect IaC drift |

### AI-Powered (requires `pip install cctl[ai]`)

| Command | Description |
|---|---|
| `cloudctl debug "<symptom>"` | Full incident diagnosis — fetches real data, finds root cause, gives IaC-aware fix steps |
| `cloudctl ask "<question>"` | Answer cloud questions using live data |
| `cloudctl ask --interactive` | Multi-turn chat with context preserved |
| `cloudctl feedback list/accuracy` | Review AI answer history and accuracy |

### Setup

| Command | Description |
|---|---|
| `cloudctl init` | First-run setup — detects existing credentials |
| `cloudctl accounts list/verify/use` | Manage cloud accounts and profiles |
| `cloudctl config get/set/list` | Manage cloudctl config |

---

## cloudctl debug

`cloudctl debug` is the flagship feature. Give it a symptom in plain English — it fetches real data from your cloud, correlates a causal timeline, runs AI analysis, detects how the affected resource was deployed, and returns IaC-aware fix steps.

```bash
cloudctl debug "payments service returning 502s since 3pm"
```

```
Diagnosing: payments service returning 502s since 3pm
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Fetching data sources...
  ✓ cloudwatch_metrics   (47 datapoints)
  ✓ cloudtrail           (23 events)
  ✓ alb_logs             (1,204 requests)
  ✓ ecs_events           (8 events)

Root Cause
  Connection pool exhausted on payments-api ECS service.
  Memory utilisation crossed 94% at 15:02 UTC — 8 minutes
  before error rate spiked. Triggered OOM kills on 3/4 tasks.

Affected Resources
  payments-api   ECS service   us-east-1
  payments-db    RDS instance  us-east-1

Deployed via: AWS CDK  ⚠ Direct changes will be overwritten on next cdk deploy

Resolution Steps
  STEP 1  Update the CDK stack — increase task memory and connection pool size:
            taskDefinition.addContainer({ memoryLimitMiB: 2048 })
            cdk deploy PaymentsStack
  STEP 2  If pipeline unavailable, scale the service directly (drift warning applies):
            aws ecs update-service --desired-count 6
  STEP 3  Fix root cause: add memory alarm at 80% to catch this earlier

[HIGH confidence — CloudWatch 24h, ALB access logs, ECS events]
Incident report saved: ~/.cloudctl/incidents/2026-04-06T15-47-payments-502.md
```

**Deployment detection** — cloudctl identifies how a resource is managed (CDK, CloudFormation, Terraform, Pulumi, Bicep, ARM, Azure DevOps, Deployment Manager, Config Connector, Cloud Build, GitHub Actions) and tailors the fix steps to your actual tooling. Detection works even without IaC tags — it inspects CloudFormation templates, ARM deployment history, GCP Deployment Manager manifests, and audit logs (CloudTrail / Activity Log / Cloud Audit Logs).

---

## MCP Server

Works with Claude Desktop, Cursor, and any MCP-compatible client (including Bedrock-hosted Claude).

```bash
pip install cctl[mcp]
cloudctl mcp config    # prints the config block to paste into claude_desktop_config.json
cloudctl-mcp           # start the MCP server
```

Once connected, the AI client can query your cloud infrastructure directly:

> "What's the cost breakdown for prod this month?"
> "List all ECS services with high CPU"
> "Show me the recent pipeline failures"

---

## How It Works

- **No new auth** — reads your existing `~/.aws/config`, `~/.azure/`, and `~/.config/gcloud/`
- **Auto output** — Rich table in terminal, clean JSON when piped (`cloudctl compute list | jq`)
- **Multi-account** — `--account prod` fuzzy-matches any profile name or AWS account ID
- **Multi-cloud** — `--cloud all` queries AWS + Azure + GCP in parallel
- **AI is optional** — all CLI commands work without AI configured; `cloudctl debug` and `cloudctl ask` require `cctl[ai]`

---

## Cloud Support

| Cloud | CLI | MCP | Debug |
|---|---|---|---|
| AWS | Full | Full | Full |
| Azure | Full | Full | Full |
| GCP | Full | Full | Full |

---

## Credentials

cloudctl never stores or manages credentials. It reads what you already have:

```bash
# AWS — standard profile setup
aws configure --profile prod

# Azure — existing az login session
az login

# GCP — existing gcloud session
gcloud auth application-default login
```

---

## AI Provider Support

`cloudctl debug` and `cloudctl ask` work with any of these AI providers:

| Provider | Config key |
|---|---|
| Anthropic (Claude) | `ai.provider: anthropic` |
| AWS Bedrock (Claude) | `ai.provider: bedrock` |
| Azure AI Foundry (Claude) | `ai.provider: azure_foundry` |
| Google Vertex AI (Claude) | `ai.provider: vertex` |

```bash
cloudctl config set ai.provider bedrock
cloudctl config set ai.model anthropic.claude-sonnet-4-6-v1
```

---

## Known Limitations

- **CloudTrail lag** — AWS management events take up to 15 minutes to appear in CloudTrail. If you run `cloudctl debug` immediately after a deployment or config change, the triggering event may not be visible yet. Wait 15 minutes and re-run for the most complete analysis.

- **S3 ALB access logs** — ALB access log analysis requires S3 access log delivery to be enabled on the load balancer (`access_logs.s3.enabled = true`). If not enabled, cloudctl falls back to CloudWatch metrics only.

- **CloudWatch Logs retention** — `cloudctl debug` searches the last 3 hours of logs by default. Log groups with short retention periods (< 3 hours) or no log delivery configured will return no results.

- **Cross-account resources** — Deployment detection and log discovery operate within a single AWS account per run. Resources that span multiple accounts (e.g., shared VPCs, cross-account RDS) require running with `--account` targeting each account separately.

- **GCP / Azure debug depth** — `cloudctl debug` has the deepest data coverage on AWS. GCP and Azure analysis uses available metrics and audit logs but does not yet include the same level of service-specific event correlation.

- **IaC detection requires audit trail** — Terraform/CDK/CloudFormation detection relies on CloudTrail events for the resource. If CloudTrail is not enabled or events have aged out, deployment method will show as `unknown`.

---

## Links

- **GitHub:** https://github.com/cloudctlio/cloudctl
- **Issues:** https://github.com/cloudctlio/cloudctl/issues
- **PyPI:** https://pypi.org/project/cctl/

---

## License

MIT
