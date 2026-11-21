# The policy gate

`cloudctl cost ... --fix`, `cloudctl security audit --fix` and
`cloudctl debug --agent --resolve` (the IaC pull request) go through this
gate before they change anything. `compute stop/start` and the MCP
`stop_compute`/`start_compute` tools do not use the gate yet. If the gate is not
configured, or rejects the change, nothing is applied and nothing is pushed.
Read-only commands (`debug`, `cost`, `security audit` without `--fix`) do not
need the gate.

```
request ─▶ 1 credentials ─▶ 2 plan ─▶ 3 policy ─▶ 4 approval ─▶ 5 authorization ─▶ apply
              short-lived,     the platform's  Rego rules,    HIGH/CRITICAL     credentials and
              scoped to one    own plan tool   scanners,      rejects; big      plan handed over
              environment      → add/modify/   native cloud   prod plans need   once, then
                               destroy counts  guardrails     a signed approval destroyed
                                    │               │               │                 │
                                    └───────────────┴──── hash-chained audit log ─────┘
```

Each stage is written to the audit log before the next one runs. If the
audit write fails, the gate rejects the change.

## Quick start

```bash
pip install 'cctl[gate]'            # + gate-azure / gate-gcp for those clouds, or 'cctl[all]'
cloudctl gate init --cloud aws --account-id 111122223333 --region us-east-1 --profile dev
cloudctl gate validate
cloudctl gate engines
```

`init` writes `~/.cloudctl/controlplane.yaml` (mode 600) with one dev-tier
environment. Set `CLOUDCTL_GATE_CONFIG` to use another path.

## Stages

| Stage | What happens | Fails closed when |
|---|---|---|
| 1 credentials | AWS: STS AssumeRole, 900 s, optional session policies. Azure: workload identity federation or managed identity. GCP: service-account impersonation, 900 s. Credentials live in memory only; they cannot be pickled or copied, and every subprocess gets an environment with ambient cloud credentials removed. | The broker cannot get credentials, or they would expire before use. |
| 2 plan | Terraform / OpenTofu (`plan` + `show -json`), CloudFormation change sets, CDK (synth + change set), ARM/Bicep what-if, Pulumi preview, `kubectl diff` on EKS/AKS/GKE with a token from the scoped credentials, and direct API fixes (each fixer declares its exact change). Output: one normalised plan with add/modify/destroy counts and a SHA-256 digest. | The plan errors, is empty, or is for another environment. |
| 3 policy | Every enabled engine runs (see below). | Any engine errors or returns something malformed. In prod, no baseline scanner ran on an IaC plan. |
| 4 approval | Any HIGH or CRITICAL finding rejects outright. A plan changing more resources than the environment's `approval.threshold` needs an Ed25519-signed approval from a named approver, bound to this exact plan digest, environment and requester, checked by Cedar, used once. | Signature, digest, requester, expiry or Cedar check fails; approval already used. |
| 5 authorization | The caller gets an `Authorization` that runs the apply once with the scoped credentials, audits start and end, then destroys the credentials. | It was already used, or the credentials expired. |

## Policy engines

The gate speaks one finding format (rule id, severity LOW to CRITICAL,
message, fix hint, resource). Engines are pluggable and each one is mapped
into that format.

| Engine | Version pin | Licence | Clouds / formats | Role |
|---|---|---|---|---|
| OPA / Rego (`rego`) | regopy 1.5.2 in process, or `opa` 1.22.4 | MIT / Apache-2.0 | All plans | Built-in gate rules (`cloudctl/gate/policy/builtin/rules.yaml`), your YAML rules, Conftest-style Rego packs. Always on in prod. |
| Checkov (`checkov`) | 3.4.6 | Apache-2.0 | Terraform plan JSON, CloudFormation, ARM, Bicep, Kubernetes | Baseline scanner |
| Trivy (`trivy`) | 0.76.2 | Apache-2.0 | Terraform, CloudFormation, ARM, Kubernetes source | Baseline scanner |
| cfn-guard (`cfn_guard`) | 3.3.0 | Apache-2.0 | CloudFormation, CDK | AWS rule packs |
| Kyverno CLI (`kyverno`) | 1.20.0 | Apache-2.0 | Kubernetes | Cluster policy |
| Infracost (`infracost`) | 0.10.50 | Apache-2.0 | Terraform | Monthly cost delta (needs `INFRACOST_API_KEY`) |
| AWS native (`aws_native`) | boto3 | — | AWS | IAM Access Analyzer ValidatePolicy; SCP check through `iam:SimulatePrincipalPolicy` (Organizations decision) |
| Azure native (`azure_native`) | azure-mgmt-policyinsights | — | Azure | Azure Policy `checkPolicyRestrictions` at the resource group |
| GCP native (`gcp_native`) | google-api-python-client | — | GCP | Organization Policy `getEffectivePolicy` (locations, external IPs, public access prevention, member domains) |
| Cedar | cedarpy 4.12.2 | Apache-2.0 | — | Who may approve what (`approval/builtin/approval.cedar`) |

Not used: HashiCorp Sentinel (proprietary, cannot be bundled), OPA
Gatekeeper (admission controller, not a plan gate), tfsec (merged into
Trivy), Conftest (its pack format is supported through the Rego engine).

CLI scanners run with a pinned version (the gate checks `--version` before
use), no cloud credentials in their environment, and a timeout. The `opa`
binary runs with network built-ins disabled.

The native engines need these permissions on the gate's role:

- AWS: `access-analyzer:ValidatePolicy`, `iam:SimulatePrincipalPolicy` on the role itself.
- Azure: `Microsoft.PolicyInsights/checkPolicyRestrictions/action` on the resource group.
- GCP: `orgpolicy.policy.get` on the project.

### Built-in rules

`CCTL-SCOPE-001/002` (outside the environment's account, subscription,
resource group, project or region; wrong cloud), `CCTL-DEL-001` (stateful
resource deleted in prod: CRITICAL), `CCTL-DEL-002` (same outside prod:
MEDIUM), `CCTL-NET-001` (internet ingress on a non-web port), `CCTL-IAM-001/002`
(wildcard IAM, public principals), `CCTL-STG-001` (public storage),
`CCTL-ENC-001` (encryption turned off), `CCTL-PLAN-001` (unknown platform
actions), `CCTL-COST-001..004` (cost and model-spend limits).

Because of `CCTL-DEL-001`, an automated cost fix cannot delete a volume,
snapshot or disk in production. That is intentional.

## Production rules

`cloudctl gate validate` refuses a config with a prod environment unless:

- credentials are short-lived and federated (AWS `assume_role`, Azure
  `workload_identity` or `managed_identity`, GCP `impersonation`);
- `audit.sink` is immutable remote storage: S3 Object Lock, an Azure blob
  container with a locked immutability policy, or a GCS bucket with a locked
  retention policy;
- at least one named approver with a public key is listed;
- the Rego engine, built-in rules and the cloud's native engine are on;
- a baseline scanner (Checkov or Trivy) is on, and every CLI scanner has a
  pinned `version`;
- no rule is disabled and no built-in rule's severity is lowered.

## Approvals

```bash
cloudctl gate keygen --approver bob            # private key stays on bob's machine
# put the printed public key under `approvers:` in the config
cloudctl gate approvals list
cloudctl gate approve <request-id> --approver bob
# the requester re-runs the same command with --approval <request-id>
```

Cedar forbids approving your own change, approving in an environment you are
not listed for, approving anything with a HIGH or CRITICAL finding, and
approving an expired request. Add stricter Cedar policies in your own files;
they can only restrict.

## Audit

Records carry `seq`, `prev` and `hash` (SHA-256 over canonical JSON), with
secrets redacted. `cloudctl gate audit verify` re-hashes the whole chain;
`--diagnosis` checks the read-only diagnosis log at
`~/.cloudctl/audit/diagnosis.jsonl`. Model calls and tool calls made by the
resolution agent are audited too.

## CI

```bash
terraform plan -out tf.plan && terraform show -json tf.plan > plan.json
cloudctl gate policy eval plan.json --env staging --json   # exit 2 on HIGH/CRITICAL
```

`policy eval` runs without cloud credentials, so the native engines are
skipped and named in the output; they run at apply time.

## What is and is not tested

Unit tests cover every stage, the approval flow, the audit chain and its
tamper detection, the YAML-to-Rego rules with the real regopy engine, Cedar
with the real cedarpy, and the fixers on AWS, Azure and GCP through the real
gate. The CLI scanner adapters (Trivy, Checkov, cfn-guard, Kyverno,
Infracost, `opa`) are tested only against fake binaries printing each tool's
documented output. The native AWS, Azure and GCP checks and the credential
brokers are tested only against mocked SDK clients. Nothing has been run
against a live cloud account yet.
