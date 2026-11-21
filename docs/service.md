# Control-plane service

`cloudctl serve` runs the [policy gate](policy-gate.md), the
[orchestrator](control-plane.md) and the [drift repair loop](drift-loop.md)
as an HTTP API that several replicas can share. Nothing about the gate
changes: every change is still planned, checked against policy, approved
where the environment says so, applied with 900-second scoped credentials and
written to the hash-chained audit log. The service adds who is asking (an
OIDC token), shared state, and a worker pool.

```
caller ──OIDC token──▶ API (FastAPI) ──▶ PolicyGate ──▶ scoped creds ──▶ plan / apply
                          │                  │
                          ▼                  ▼
              shared state (KV)        immutable audit
     DynamoDB · Cosmos DB · Firestore   S3 Object Lock · Azure immutable blob · GCS bucket lock
```

Install: `pip install "cctl[service]"` (AWS), `"cctl[service-azure]"` or
`"cctl[service-gcp]"`.

## API

| Method and path | Role | What it does |
|---|---|---|
| `GET /healthz` | none | liveness |
| `GET /readyz` | none | 200 when the audit sink and the state store are reachable and set up right, else 503 naming the failing part |
| `POST /v1/changes:compile` | operator | plain-language request → change graph (applies nothing) |
| `POST /v1/changes` | operator | run a change graph; `202 {run_id}` |
| `GET /v1/changes`, `GET /v1/changes/{id}` | reader | runs and their nodes |
| `POST /v1/changes/{id}:resume` | operator | carry on after approvals; only the requester |
| `GET /v1/approvals`, `GET /v1/approvals/{id}` | reader | pending requests, and exactly what an approver signs |
| `POST /v1/approvals/{id}` | approver | submit an Ed25519 signature made offline |
| `GET /v1/drift`, `GET /v1/drift/{id}` | reader | drift events |
| `POST /v1/drift:scan` | operator | one drift pass (also takes queued rollbacks); `202` |
| `POST /v1/drift/{id}:repair` | operator | a person's go-ahead; `override` reason required for report-only events |
| `GET /v1/audit:verify` | auditor | verify the hash chain |

Long work answers `202` and runs on the worker pool; poll the run or event.

## Sign-in and roles

Every `/v1` call needs `Authorization: Bearer <JWT>` from your identity
provider. The token must be signed with an asymmetric algorithm (RS256/384/512,
PS256, ES256/384 or EdDSA; `HS*` and `none` are refused), come from the
configured `issuer` (https only), name the configured `audience`, and carry
`exp`, `iat` and `sub`. Keys come from `jwks_url`, by default
`<issuer>/.well-known/jwks.json` (set it explicitly if your provider publishes
keys elsewhere). Tokens over 16 KB are refused.

Roles come from a group claim (`groups` by default) through `role_map`:

| Role | May |
|---|---|
| reader | read runs, approvals, drift events |
| operator | reader, plus compile, run, resume, scan, repair |
| approver | reader, plus submit approvals |
| auditor | reader, plus verify the audit chain |

The requester recorded on a run, in the audit log and in AWS
`SourceIdentity` is the token's `email` claim (`subject_claim`).

### Approvals

Approval keys never reach the service. An approver saves the request
(`GET /v1/approvals/{id}`) to a file, signs it on their own machine, and posts
the result:

```bash
curl -fsS -H "Authorization: Bearer $TOKEN" https://cctl.example.com/v1/approvals/$ID > req.json
cloudctl gate sign req.json --approver carol > sig.json     # shows the request, asks, prints JSON
curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     --data @sig.json https://cctl.example.com/v1/approvals/$ID
```

The service checks that:

- the token has the approver role and an approver name (`preferred_username`
  by default, `approver_claim`), which must match a name under `approvers` in
  the gate config;
- the approver is not the requester, is named for that environment, and the
  same Cedar check the gate runs when the approval is spent allows it;
- the signature verifies against that approver's public key in the gate config.

Approvals are write-once and single-use in the shared store, so two replicas
cannot both spend one.

## Settings

`CLOUDCTL_SERVICE_CONFIG` (default `/etc/cctl/service.yaml`):

```yaml
gate_config: /etc/cctl/controlplane.yaml
state:
  backend: dynamodb            # dynamodb | cosmos | firestore
  table: cctl-control-plane
  region: us-east-1
  # cosmos:    endpoint, database, container
  # firestore: project, database ("(default)"), prefix ("cctl")
auth:
  issuer: https://login.example.com/
  audience: cctl-control-plane
  # jwks_url: defaults to the issuer's discovery document
  algorithms: [RS256, ES256]
  role_map:
    operator: [platform-team]
    approver: [platform-leads]
    auditor: [security]
model: {adapter: converse, region: us-east-1, tokens_per_hour: 2000000}
drift: {interval_seconds: 900, repair: true}   # 0 = no scheduled loop
workers: 4
max_body_bytes: 1048576
```

A gate config with a prod environment must use an immutable audit sink, or
the service refuses to start. `memory` state is refused unless
`allow_memory_state: true` (one local replica, for trying it out).

### Shared state

All replicas share one key-value store with conditional writes. It holds runs
(with a lease while a worker drives one), single-use approvals, drift events
(with a lease for the drift pass, so one replica scans at a time), and the
rollback queue.

| Backend | Layout | Needs |
|---|---|---|
| DynamoDB | partition key `ns`, sort key `k`; strongly consistent reads | TTL on attribute `ttl` |
| Cosmos DB | partition key `/ns`; etag conditions; Strong consistency recommended | default TTL `-1` |
| Firestore (native) | one collection per namespace, `{prefix}_{ns}`; update-time preconditions | TTL policy on `{prefix}_lease.expire_at` |

`/readyz` checks the key schema and TTL setting, so a misbuilt table keeps the
pod out of rotation.

### Model adapters

The change compiler talks to a model through an adapter. `converse` (Bedrock
Converse, any model there) is built in. Others load only by name, from the
`cloudctl.model_adapters` entry-point group of an installed package; nothing
is imported from a path given at run time. Every adapter is wrapped with a
prompt-size cap, bounded retries with backoff and an hourly token budget, and
each refusal or error is audited.

```toml
# in your adapter package's pyproject.toml
[project.entry-points."cloudctl.model_adapters"]
azure_openai = "my_pkg.adapters:make_azure_openai"   # factory(**settings) -> obj with complete(system, user)
```

## Deploying

| Piece | Path |
|---|---|
| Image | `deploy/docker/Dockerfile`: non-root (uid 10001), Terraform 1.10.5, kubectl and checkov pinned; terraform and kubectl checked against SHA256 build args |
| Helm chart | `deploy/helm/cctl-control-plane` with `values-eks.yaml`, `values-aks.yaml`, `values-gke.yaml` |
| AWS | `deploy/terraform/aws`: DynamoDB (PITR, KMS, TTL), S3 Object Lock COMPLIANCE audit bucket, KMS, IRSA role, ECR, GitHub OIDC CI role; `target-role/` for each account the plane changes |
| Azure | `deploy/terraform/azure`: Cosmos DB (serverless, Entra-only, `/ns`, TTL -1), immutable audit storage, workload identity, GitHub federated credential |
| GCP | `deploy/terraform/gcp`: Firestore (PITR, lease TTL), retention-locked audit bucket, workload identity, GitHub workload identity pool |
| CI | `.github/workflows/control-plane-deploy.yml`: manual, tests then build and push by digest, Helm deploy, OIDC login, runs in a protected GitHub environment |

The chart refuses to render without an image digest, a cloud, a gate config,
auth and non-memory state. The pod runs as non-root with a read-only root
filesystem, all capabilities dropped and the RuntimeDefault seccomp profile.
An init container checks the IaC repository out at a full commit SHA into a
pod-private volume (no branches, so what runs is what was reviewed); IaC roots
in the gate config must sit under `iac.mountPath`. A NetworkPolicy allows DNS
and HTTPS out and only the peers you list in.

Set `trustedProxies` to your ingress or load balancer range so client IPs in
logs are real; terminate TLS at the ingress.

Locking retention is irreversible on every cloud (S3 COMPLIANCE mode, a
locked Azure immutability policy, a locked GCS retention policy). The Azure
and GCP stacks leave the lock off by default for a trial
(`lock_audit_policy`); turn it on for production. S3 COMPLIANCE mode applies
from the first object.

## What is and is not tested

Tested offline: the API end to end with FastAPI's test client, real ES256
tokens and the real gate (Rego, Ed25519 approvals, hash-chained audit) on the
memory store: sign-in failures, roles, compile, run, the prod approval flow
with an offline signature, self-approval and forged-signature refusals,
resume by requester only, drift scan and override, readiness, body limits and
error masking. The shared-state contract runs on all four backends, with
DynamoDB, Cosmos DB and Firestore against in-memory fakes of their SDK calls.
The model guard and adapter registry are tested.

Not tested: no real DynamoDB, Cosmos DB, Firestore, S3, Azure Storage or GCS;
the Dockerfile has not been built, the Helm chart has not been rendered and
the Terraform has not been planned (only parsed); the workflow has not run.
Those steps are for a real account. [deploy/LIVE-TEST.md](../deploy/LIVE-TEST.md) is a by-hand live check of the AWS stores (DynamoDB and S3 Object Lock), with teardown.
