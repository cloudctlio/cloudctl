# Change requests and the orchestrator

`cloudctl change` turns a plain-language request into a change graph and
carries it out, node by node, through the [policy gate](policy-gate.md).

```
request ──▶ compiler ──▶ change graph ──▶ orchestrator ──▶ gate (per node) ──▶ executor
            model +      fixed JSON        dependency      credentials, plan,  applies the
            layered      schema, DAG       order, no       policy, approval,   approved plan
            validation                     blind retry     single-use auth     only
```

## Quick start

```bash
cloudctl change compile "add the cache subnet, then roll the app" -o graph.json
# read graph.json; edit it if you like (the same strict checks apply)
cloudctl change run graph.json
cloudctl change status <run-id>
# a node over its environment's approval threshold waits:
cloudctl gate approve <request-id> --approver bob
cloudctl change resume <run-id> --approval app=<request-id>
```

Exit codes: 0 done, 1 error, 2 a node failed or was rejected, 3 the compiler
has questions, 4 waiting for approval.

## The change graph

A small DAG (at most 50 nodes). Each node is one change the gate evaluates on
its own:

- `iac_apply`: apply one IaC root (Terraform/OpenTofu, CloudFormation, CDK,
  ARM/Bicep, Pulumi, or Kubernetes manifests on EKS/AKS/GKE) in one
  environment;
- `api_action`: one direct fix by a registered fixer (AWS, Azure or GCP).

`depends_on` lists nodes that must succeed first. The JSON schema is fixed
and versioned (`cloudctl/controlplane/graph.py`); unknown keys, wrong types,
unknown references, duplicate ids and cycles are errors.

## The compiler

The model proposes; cctl validates. Any model cctl supports works
(`CLOUDCTL_MODEL_PROVIDER` = bedrock, anthropic, openai or gemini, and
`CLOUDCTL_MODEL`); the compiler talks to it through one small adapter.

| Layer | Checks |
|---|---|
| 1 shape | strict JSON against the schema |
| 2 graph | unique ids, known dependencies, no cycles, size limit |
| 3 targets | the environment exists; the IaC root belongs to that environment (`match.iac_roots`, or `--iac-root`), exists, and exactly one IaC tool manages it; an API fix has a fixer for that environment's cloud |
| 4 conflicts | no two nodes apply the same root |

Errors go back to the model once, with the exact messages, for one repair.
If the request is ambiguous (the model asks, or a node names an environment
that does not exist), the compiler returns questions instead of guessing.
The request is passed to the model as fenced data, and the model is given
only environment names, tiers, clouds, scope ids, roots and fixer names:
never credentials. The person's own wording is kept as the graph's
`request`. Model calls are written to the audit log.

## The orchestrator

- Runs nodes in dependency order, one at a time (ties broken by id, so the
  order is the same every time). Parallel execution is not built.
- Every node goes through all five gate stages with its own short-lived
  credentials.
- Needs approval: the node waits; its downstream nodes are blocked;
  independent nodes carry on. `change resume` continues with the approval.
- Rejected by the gate: nothing was applied for that node; its downstream
  nodes are skipped.
- Failed while applying: never retried, not even on resume. Downstream nodes
  are skipped, and a targeted rollback request for that one node (with the
  list of nodes already applied before it) is queued in
  `~/.cloudctl/rollbacks` for the drift repair loop. `change rollbacks` lists
  them. The queue itself changes nothing.
- A process that stopped while a node was running leaves that node as
  failed on resume (its outcome is unknown), with a rollback request.
- Run state lives in `~/.cloudctl/runs/<run-id>.json` (0600, written
  atomically, with a lock file so two processes cannot drive one run). Only
  the requester who started a run can resume it, and a stored graph that no
  longer matches its digest is refused.

## How each tool applies only what was approved

| Tool | Apply |
|---|---|
| Terraform / OpenTofu | `apply` of the saved plan file from the gate's plan stage, after checking its SHA-256. Terraform itself refuses a stale saved plan. |
| CloudFormation / CDK | Plans again with the change sets kept; if the new plan's digest differs from the approved one, deletes them and stops; otherwise executes exactly those change sets and waits for each stack. A rollback counts as a failure. |
| ARM / Bicep | What-if again; stops on a digest mismatch; otherwise deploys the same compiled template. |
| Pulumi | Preview again; stops on a digest mismatch; otherwise `pulumi up --skip-preview`. |
| Kubernetes | `kubectl diff` again; stops on a digest mismatch; otherwise `kubectl apply --server-side --field-manager=cctl`. |
| API fixes | The fixer's `apply`, with the scoped credentials. |

ARM, Pulumi and Kubernetes have no saved-plan apply, so a change someone else
makes in the seconds between the re-check and the deploy is not caught by
cctl. Terraform and CloudFormation do not have that gap.

## What is and is not tested

Unit tests cover the graph parser, all four compiler layers and the repair
loop with a scripted model, the orchestrator end to end through the real gate
(real Rego rules, real audit chain, real Ed25519 and Cedar approvals) on AWS,
Azure and GCP environments, failure, rejection, approval, crash and resume
paths, and the CLI. The executors are tested with faked tool runs and faked
CloudFormation and ARM clients. No executor has been run against a real
cloud account or a real Terraform, Pulumi, CDK or kubectl yet, and the
compiler has not been tried against a live model.
