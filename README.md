# ⚡ cctl — Universal Cloud CLI

> One command for AWS, Azure, and GCP.

[![Security Scan](https://github.com/cloudctlio/cloudctl/actions/workflows/security.yml/badge.svg)](https://github.com/cloudctlio/cloudctl/actions/workflows/security.yml)

`cctl` installs the `cloudctl` command — a universal CLI that lets you query and manage AWS, Azure, and GCP resources with one unified syntax, using your existing credentials.

## Install

```bash
pip install cctl
```

## Quick Start

```bash
cloudctl init                          # detect existing cloud credentials
cloudctl accounts list                 # show all configured accounts
cloudctl compute list                  # list EC2 instances
cloudctl storage list                  # list S3 buckets
cloudctl database list                 # list RDS instances
cloudctl cost summary                  # monthly cost breakdown
cloudctl security audit                # check for misconfigurations
```

## Commands

| Command | Description |
|---|---|
| `cloudctl init` | First-run setup — detects AWS/Azure/GCP credentials |
| `cloudctl accounts list/verify/use` | Manage cloud accounts and profiles |
| `cloudctl compute list/describe/stop/start` | EC2 instances (VMs coming for Azure/GCP) |
| `cloudctl storage list/describe/ls/du` | S3 buckets |
| `cloudctl database list/describe/snapshots` | RDS instances and snapshots |
| `cloudctl network vpcs/security-groups` | VPCs and security groups |
| `cloudctl iam roles/users/check` | IAM roles, users, permission checks |
| `cloudctl cost summary/by-service` | Cost Explorer breakdown |
| `cloudctl security audit/public-resources` | Security posture checks |
| `cloudctl pipeline list/analyze` | CodePipeline status |
| `cloudctl config get/set/list` | Manage cloudctl config |

## How It Works

- **No new auth** — reads your existing `~/.aws/config`, `~/.azure/`, and `~/.config/gcloud/`
- **Auto output** — Rich table in terminal, clean JSON when piped
- **Multi-account** — use `--account prod` to target any profile by name
- **Multi-cloud** — use `--cloud all` to query across all providers at once (Azure + GCP coming in v0.3.0)

## Status

| Cloud | Status |
|---|---|
| AWS | ✅ Implemented |
| Azure | 🔄 In progress (v0.3.0) |
| GCP | 🔄 In progress (v0.3.0) |

## Links

- **GitHub:** https://github.com/cloudctlio/cloudctl
- **Issues:** https://github.com/cloudctlio/cloudctl/issues
- **Security:** See [SECURITY.md](SECURITY.md)

## License

MIT
