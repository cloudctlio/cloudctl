# Drift repair loop

`cloudctl drift` finds where live cloud state no longer matches the IaC that
should own it, decides how far it may go on its own with the **autonomy
table**, and repairs only through the [policy gate](policy-gate.md) and the
[orchestrator](control-plane.md).

```
scan (read-only, scoped creds) ──▶ classify ──▶ confidence ──▶ autonomy table ──▶ auto: repair through the gate
                                   class,        stable?         class first,         approve: waits for a person
                                   severity,     attributed?     tier × severity,     report: a person must look
                                   live policy   blast radius    platform cap, θ
```

## Quick start

```bash
cloudctl drift table                 # the autonomy table in force
cloudctl drift scan --no-repair      # detect and decide only
cloudctl drift scan                  # one pass; auto cells are repaired
cloudctl drift loop --interval 900   # keep going; also takes rollback requests from failed change runs
cloudctl drift list
cloudctl drift show <event>
cloudctl drift repair <event>                     # a person's go-ahead for an approve event
cloudctl drift repair <event> --override "why"    # a report event; the reason is audited
```

Exit codes: 0 nothing needs a person, 1 error, 5 at least one event needs a
person (approve, report, awaiting approval, failed or rejected repair).

## Detection, per cloud and tool

Every scan takes short-lived credentials from the gate's broker for that
environment (AWS STS, Azure, GCP impersonation), works in a private temporary
directory, and destroys both when it ends. It never writes to the cloud.

| Tool | Clouds | How drift is found | Tells drift from undeployed code? |
|---|---|---|---|
| Terraform / OpenTofu | AWS, Azure, GCP | `plan` (refreshes); `resource_drift` in the plan JSON | Yes |
| Pulumi | AWS, Azure, GCP | `preview --refresh` | No |
| ARM / Bicep | Azure | what-if against live resources | No |
| Kubernetes manifests | EKS, AKS, GKE | `kubectl diff` against the cluster | No |
| CloudFormation / CDK | AWS | `DetectStackDrift` and `DescribeStackResourceDrifts` | Yes |

Where the tool cannot tell drift from code that was merged but never applied,
confidence is lower (below). CloudFormation and CDK drift is always `report`:
deploying the same template again does not revert drift in CloudFormation, so
cctl has no safe repair for it. That is the one place the clouds differ in
what the loop can do on its own.

## Classification

**Class.**
- `security_incident`: any drift in identity (IAM, role assignments, service
  accounts, Kubernetes RBAC), audit logging (CloudTrail, flow logs, Config,
  GuardDuty, Security Hub, diagnostic settings, log sinks) or keys and secrets
  (KMS, Key Vault, Secret Manager, certificates); network or storage drift whose
  live state is open to the internet (`0.0.0.0/0`, `::/0`, `*`, `Internet`,
  `allUsers`, public blob access, block-public-access off); or a HIGH or
  CRITICAL finding from the gate's own Rego rules that the drift introduced.
- `failed_change`: left behind by a change run that failed (from the
  orchestrator's rollback queue). It stays `failed_change` until a scan finds
  the root clean.
- `config_drift`: everything else.

**Live-state policy.** The gate's Rego rules run twice: on the live state
(each change's `before`) and on the declared state (`after`). Only findings on
live state that the declared state does not have count, so a problem that was
already in the code does not turn every later drift into an incident. Cost,
scope, delete and plan rules are skipped, because they judge a proposed change,
not a state. If the Rego engine cannot run, confidence is 0 and severity is at
least MEDIUM.

**Severity.** Incident: CRITICAL. A repair that deletes or replaces something,
or creates a stateful resource: HIGH. A failed change: at least HIGH. Tags or
labels only: LOW. Otherwise MEDIUM, or the highest live-state finding.

## Confidence

How sure cctl is that re-applying the declared state is the right repair. It
is deterministic, and every factor is stored on the event:

| Factor | Effect |
|---|---|
| A change run on the same root is in progress | 0 (never fight a deploy) |
| The live-state policy check could not run | 0 |
| Seen once | ×0.5, so no default θ is met until a second scan finds the same plan |
| The repair would also apply undeployed code (Terraform) | ×0.5 |
| The tool cannot tell drift from undeployed code | ×0.75 |
| The repair deletes or replaces something | ×0.5 |
| More than 10 resources | ×0.8 |

## The autonomy table

The decision is made in this order, and each step can only make it more
cautious:

1. `security_incident` is always `report`, at every tier, whatever the config.
2. Tier × severity gives `auto`, `approve` or `report`.
3. A `failed_change` is never `auto`.
4. CloudFormation and CDK are `report`.
5. Only inside an `auto` cell: confidence below the tier's θ drops it to
   `approve`.

Defaults:

| Tier | LOW | MEDIUM | HIGH | CRITICAL | θ |
|---|---|---|---|---|---|
| dev | auto | auto | approve | report | 0.6 |
| test | auto | auto | approve | report | 0.6 |
| staging | auto | approve | approve | report | 0.8 |
| prod | auto | approve | approve | report | 0.9 |

Change it in the gate config:

```yaml
drift:
  autonomy:
    staging: {MEDIUM: auto}
  theta: {staging: 0.85}
```

The config is refused if it makes CRITICAL `auto` anywhere, HIGH `auto` in
prod, a more severe cell more autonomous than a milder one, or θ in prod below
0.5.

## Repair

A repair is a one-node change graph (`iac_apply` on that root) run by the
orchestrator, so it goes through every gate stage with its own credentials:
scope, policy (including the prod baseline-scanner requirement), approval
thresholds, single-use authorization and the audit chain. The repair is
pinned to the plan that was classified: if live state has moved since, the
gate's plan stage fails, nothing is applied and the event is
`repair_rejected`. The next scan classifies the new state.

If the gate wants a signed approval, the event is `awaiting_approval`; approve
it with `cloudctl gate approve` and carry on with `cloudctl change resume`
(the command is printed). Drift that is still there after a repair drops to
`approve`, so the loop never repairs the same thing over and over.

A repair rolls **forward** to what the code declares. For a failed change
that is the new code, not the state before the run: a true rollback means
reverting the code, which is a person's decision, so `failed_change` events
are never repaired automatically.

Report events can be repaired only by a person, with `--override` and a
reason that goes to the audit log. CloudFormation and CDK cannot be
overridden.

## State and audit

Events are JSON files in `~/.cloudctl/drift` (`CLOUDCTL_DRIFT_DIR`), 0600,
written atomically; a lock file stops two passes running at once. Handled
rollback requests move to `~/.cloudctl/rollbacks/done`. The audit log gets
`drift.scan.start`, `drift.detected` (class, severity, confidence, factors,
decision, items), `drift.scan.error`, `drift.live_policy.error`,
`drift.override`, `drift.repair.start`, `drift.repair.end`, `drift.resolved`
and `drift.rollback.taken`, plus the gate's own events for every repair.

## What is and is not tested

Unit tests cover classification on AWS, Azure and GCP resource types, every
confidence factor, the autonomy table and its validation, the store, and full
passes through the real gate (real Rego rules, real hash-chained audit, real
approval stage) with scripted planners and fake executors on all three
clouds: auto repair on the second sighting, incidents never repaired, the
override, prod approval, plan pinning, live-state Rego, engine failure,
active runs, recurrence, rollback intake, per-root error isolation, and the
CLI. The CloudFormation drift API is tested against a fake client.

Not done yet: no scan or repair has run against a real cloud account or a
real Terraform, Pulumi, CDK, ARM or kubectl. The loop runs as a CLI process
(`drift loop`); running it as a service with shared state is stage 4.
