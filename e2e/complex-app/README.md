# cctl complex-app test

A serverless orders app with five injectable faults that are harder than one throttled table, plus a scorer that grades cctl's `--json-out` (with `--iac-root`) against ground truth. Built and checked offline on Nov 18, 2026; nothing has been deployed.

## App (Terraform, `app/`, us-east-1, all tagged `project=cctl-complexapp` and `ManagedBy=terraform`)

```
client ──> API Gateway HTTP API ──> api Lambda ──> DynamoDB orders (PENDING)
           POST /orders, GET /orders/{id}  └─────> SQS orders ──(3 tries)──> SQS orders-dlq
                                                     │
                                                     v
                                         worker Lambda (SQS trigger, batch 1)
                                           ├─ S3 receipts/<id>.json (only orders with receipt=true)
                                           ├─ DynamoDB status=PROCESSED
                                           └─ EventBridge bus: OrderProcessed
                                                     │ rule order-processed
                                                     v
                                         notifier Lambda ──> DynamoDB notified=<time>
```

Main pieces (12): HTTP API, 3 Lambdas, DynamoDB table (on-demand), SQS queue + DLQ, S3 bucket, EventBridge bus + rule, 2 CloudWatch alarms (DLQ not empty, API 5xx). Around 35 Terraform resources counting IAM roles/policies, log groups (1-day retention, destroyed with the stack), routes, permissions. No NAT, RDS or EKS. The API stage is throttled to 30 rps so the public test URL can't run up a bill.

Worker processing time is simulated: 200 ms + 300 ms per item (small orders 1 to 3 items, large 8 to 10).

## Fault scenarios (`scenarios.json`)

IaC faults are "bad commits": text edits to `app/*.tf`, applied with `terraform apply`, so the IaC root cctl reads contains the bug and the right fix is the reverse edit. Each injected state passes `terraform validate` and `fmt -check`, and reverting restores the files byte for byte.

| ID | Fault | What the user reports | Ground-truth cause | Blamed resource | Correct IaC fix |
|---|---|---|---|---|---|
| s1 | IAM missing one action on one path | A third of orders stay PENDING | Worker policy allows `s3:PutObject` on `invoices/*`, worker writes `receipts/*`: AccessDenied only for receipt orders, then DLQ | `aws_iam_role_policy.worker` | `invoices/*` back to `receipts/*` |
| s2 | Concurrency starves the consumer (symptom far from cause, no errors logged) | Orders pile up, no errors in worker logs | `var.worker_reserved_concurrency` default 1: SQS trigger throttled, backlog, DLQ | `aws_lambda_function.worker` (via variable) | default `1` to `-1` (or ≥5, or `maximum_concurrency`) |
| s3 | Bad env var + red herring | POST /orders returns 500 after a deploy | api `QUEUE_URL` points at a nonexistent `...-orders-v2` queue. Same deploy adds a cache endpoint that logs loud but harmless `ConnectionRefused` errors on every GET (3x more GETs than POSTs) | `aws_lambda_function.api` | restore `QUEUE_URL = aws_sqs_queue.orders.url` (removing the cache line alone fails) |
| s4 | Two concurrent faults | Some orders never complete, and no confirmation notifications | (A) worker timeout 2 s, large orders take 2.6 to 3.2 s; (B) EventBridge rule now matches `OrderCompleted`, worker emits `OrderProcessed` | `aws_lambda_function.worker` and `aws_cloudwatch_event_rule.order_processed` | timeout back to 10; detail-type back to `OrderProcessed` (one IaC fix per run, so either counts) |
| s5 | Out-of-band drift | Nothing completes; "nobody deployed today" | Worker's SQS event source mapping disabled with the API, outside Terraform | `aws_lambda_event_source_mapping.worker` | **No IaC change.** `terraform plan`/`apply` to revert drift. Tests run 4's weakness of fixing AWS directly. |
| s0 | Control, optional | "API felt slow, anything wrong?" | Nothing is wrong | none | no diff; a confident made-up cause fails |

Each scenario waits until its symptom is really there (DLQ depth, queue age, POST 5xx ratio, unnotified orders or mapping state) before cctl runs, and records if it never showed.

## Scorer (`score.py`)

For each run it checks: root cause (regex groups on `root_cause`), localization (root cause names the blamed resource), confidence (and "overconfident" when HIGH on a wrong answer), time (≤600 s, wall clock from `runs/<id>.meta.json`), IaC resource (`iac_fix.resource`), fix match (diff removes the bad value and adds a correct one), drift-safe (remediation doesn't change AWS directly without going through Terraform), red herring avoided (s3). Verdict: PASS, PARTIAL (right cause, something else missed) or FAIL. `python score.py --selftest` scores 17 hand-written outputs in `fixtures/` (pass, partial and fail per scenario); all 17 come out as labelled.

## Cost and time (estimates, not measured)

- AWS infra per full run (s1 to s5, about 1 hour deployed): under $1. Mostly Lambda (~50k invocations, ~6k GB-s, ~$0.10), CloudWatch Logs ingestion (~$0.05), DynamoDB/SQS/S3/EventBridge/API Gateway a few cents each, alarms pennies.
- Bedrock for cctl: runs 1 to 3 cost $0.62 to $0.80 each on the small app. This app has more resources and logs, so guess $1 to $1.50 per scenario, $5 to $8 for s1 to s5. Total under $10. s0 adds about $1.5.
- Time: deploy 2 to 3 min; each scenario 7 to 15 min (inject 0.5 to 1 min, symptom 1 to 4 min, cctl 3 to 9 min under the time budget, revert 0.5 to 1.5 min); teardown 1 to 2 min. All five: about 45 to 75 min.

## Laptop steps (Windows, PowerShell)

Prereqs: Python 3.13, Terraform 1.9.8 (the system 0.12.28 is too old), Bedrock access to the model you use, Lambda account concurrency with at least 11 unreserved (`preflight` checks it).

1. cctl branch: the run-4 stack plus PR #39. Merged cleanly in the sandbox; full suite 1,095 passed, 2 skipped.
   ```powershell
   cd <cloudctl repo>
   git fetch origin
   git checkout -B complex-test origin/perf/time-budget
   git merge --no-edit origin/learn/remove-confidence-bump
   git merge --no-edit origin/fix/grounding-dynamodb-throttle
   git merge --no-edit origin/fix/probe-permission
   git merge --no-edit origin/fix/confidence-root-cause-chain
   git merge --no-edit origin/feat/iac-fix-suggestion
   uv venv --python 3.13 .venv; .\.venv\Scripts\Activate.ps1
   uv pip install -e ".[ai]"
   ```
   (`fix/confidence-root-cause-chain` already contains `fix/localization-upstream`. `feat/iac-fix-suggestion` contains PR #38.)
2. AWS and cctl settings, same shell:
   ```powershell
   aws sso login --profile <your SSO profile>
   $env:AWS_PROFILE = "<your SSO profile>"
   $env:AWS_REGION = "us-east-1"
   $env:TERRAFORM_BIN = "C:\path\to\terraform_1.9.8\terraform.exe"
   $env:CLOUDCTL_TERRAFORM_BIN = $env:TERRAFORM_BIN
   $env:TF_PLUGIN_CACHE_DIR = "$HOME\.terraform.d\plugin-cache"; mkdir -Force $env:TF_PLUGIN_CACHE_DIR
   # plus the same CLOUDCTL_MODEL_PROVIDER / CLOUDCTL_MODEL as runs 1-4
   ```
   If `~/.cloudctl` is fresh, run `cloudctl init` first. Consider a clean `~/.cloudctl` (run 3 may have read state from run 1).
3. From `e2e/complex-app`:
   ```powershell
   python run.py preflight
   python run.py deploy
   python run.py scenario s1      # then s2 ... s5, or: python run.py all
   python run.py score            # writes runs\scorecard.md
   python run.py teardown         # destroy + sweep for anything tagged project=cctl-complexapp
   ```
   `scenario` runs: inject, load in the background, wait for the symptom, `cloudctl debug --agent --iac-root app --json-out runs\<id>.json --verdict skip "<symptom>"`, stop load, revert, score. `python run.py cmd s1` prints the exact cctl command. cctl's output goes to `runs\<id>.log`.

The harness also sets `CLOUDCTL_DIFF_FIRST_RECORD` to `runs\<id>.diff-first.json` (built in Python, so it works when started from Git Bash; `CCTL_DIFF_FIRST_RECORD=0` turns it off) and logs one line per run saying whether the diff-first checks ran, and if not, why. Replay a recording offline with `CLOUDCTL_DIFF_FIRST_REPLAY=runs\<id>.diff-first.json`.

If a scenario dies midway, `python run.py revert <id>` puts the files and AWS back; `teardown` also reverts the text edits before destroying.

## Limits

- Not deployed or run against AWS; the Lambda code and load generator ran only against a local fake API, and the symptom checks against moto. Timing of s2 (throttling pushing messages to the DLQ) and s4 (timeout margins) are the likeliest to need tuning live; the symptom gate will say so.
- Terraform validated with providers from releases.hashicorp.com (aws 5.100.0, archive 2.8.1), since the Terraform registry is blocked here. The laptop downloads them normally; no lock file is shipped.
- The scorer uses regexes, so read each `runs\<id>.json` alongside the table before trusting a borderline verdict.
- s3's error may surface as AccessDenied (the api role only allows SendMessage on the real queue) rather than NonExistentQueue; either way the queue URL is the cause, and "add sqs:* to the role" is scored as a wrong fix.
