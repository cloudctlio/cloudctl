# Live test of the control-plane stores (PR #50)

Run this in Git Bash on the laptop, in `C:\Users\haris\cloudctl-e2e`.

- **AWS:** profile `AdministratorAccess-866018956458`, region `us-east-1`.
- **Terraform:** `C:\Users\haris\bin\terraform1.exe` (1.10.5).
- **Git:** never merge, and never push anything. This run only checks out the branch.

## 1. Check out the branch

```bash
cd /c/Users/haris/cloudctl-e2e
git fetch origin feat/gate-stage4-service
git checkout feat/gate-stage4-service        # read-only use: no commits, no push
.venv/Scripts/python -m pip install -e ".[ai,gate,service]" pytest pytest-cov bandit pip-audit
```

## 2. Local checks (nothing in AWS)

```bash
.venv/Scripts/python -m pytest tests -q                 # 1 known failure: test_time_budget outer ceiling
.venv/Scripts/bandit -r cloudctl/ -ll -x tests/
.venv/Scripts/pip-audit --ignore-vuln CVE-2026-4539
TF=/c/Users/haris/bin/terraform1.exe
for d in deploy/terraform/aws deploy/terraform/aws/target-role deploy/terraform/azure deploy/terraform/gcp; do
  (cd "$d" && $TF init -backend=false -input=false >/dev/null && $TF validate && $TF fmt -check) || echo "FAILED: $d"
done
```

Helm and Docker checks are optional. They are not needed for this run.

## 3. Create the stores in AWS

This creates four things, and nothing else (no IAM roles, no ECR, no EKS):
- the DynamoDB table `cctl-control-plane`
- one KMS key and its alias
- the audit bucket `cctl-control-plane-audit-866018956458`, with Object Lock in COMPLIANCE mode for 1 day

```bash
cd deploy/terraform/aws
export AWS_PROFILE=AdministratorAccess-866018956458 AWS_REGION=us-east-1
$TF init -input=false
$TF plan -input=false -out=stores.tfplan \
  -target=aws_dynamodb_table.state -target=aws_kms_alias.cp \
  -target=aws_s3_bucket_object_lock_configuration.audit \
  -target=aws_s3_bucket_server_side_encryption_configuration.audit \
  -target=aws_s3_bucket_public_access_block.audit \
  -target=aws_s3_bucket_ownership_controls.audit \
  -var audit_retain_days=1 -var deletion_protection=false -var kms_deletion_window_days=7 \
  -var eks_oidc_provider_arn=arn:aws:iam::866018956458:oidc-provider/unused \
  -var eks_oidc_issuer=unused -var eks_cluster_arn=arn:aws:eks:us-east-1:866018956458:cluster/unused
```

Read the plan before applying. Apply only if it adds just the table, the key and alias, the bucket and its settings: 8 to 10 resources, all `aws_dynamodb_*`, `aws_kms_*` or `aws_s3_bucket*`.

```bash
$TF apply stores.tfplan
$TF output                                   # note audit_bucket, kms_key_arn, state_table
```

## 4. Run the live check

```bash
cd /c/Users/haris/cloudctl-e2e
.venv/Scripts/python deploy/smoke/aws_stores.py --table cctl-control-plane \
  --bucket cctl-control-plane-audit-866018956458 --kms-key "$(cd deploy/terraform/aws && $TF output -raw kms_key_arn)" \
  --profile AdministratorAccess-866018956458 --region us-east-1
```

Every line should say PASS, and the output should end with ALL PASSED. Bring back the whole output.

## What can't be deleted, and when

- **The 2 audit objects:** the check writes 2 audit records under `cctl-smoke/`. They are locked for 1 day from when the check runs, and the script prints the exact time. Nobody can delete them before then, the account root included.
- **The audit bucket:** it can't be deleted while those objects exist, so it is also stuck until that time.
- **The KMS key:** destroying it schedules deletion after 7 days. You can cancel during those 7 days. It costs about $1 a month, prorated, until it is deleted.
- **Everything else:** can be removed straight away.

## 5. Tear down

Right after the check:

```bash
cd /c/Users/haris/cloudctl-e2e/deploy/terraform/aws
$TF destroy -input=false -target=aws_dynamodb_table.state \
  -var eks_oidc_provider_arn=arn:aws:iam::866018956458:oidc-provider/unused \
  -var eks_oidc_issuer=unused -var eks_cluster_arn=arn:aws:eks:us-east-1:866018956458:cluster/unused \
  -var deletion_protection=false
```

After the lock time the script printed:

```bash
cd /c/Users/haris/cloudctl-e2e
.venv/Scripts/python deploy/smoke/aws_stores.py --table cctl-control-plane \
  --bucket cctl-control-plane-audit-866018956458 --profile AdministratorAccess-866018956458 \
  --region us-east-1 --delete-smoke-objects
cd deploy/terraform/aws
$TF destroy -input=false -var audit_retain_days=1 -var deletion_protection=false -var kms_deletion_window_days=7 \
  -var eks_oidc_provider_arn=arn:aws:iam::866018956458:oidc-provider/unused \
  -var eks_oidc_issuer=unused -var eks_cluster_arn=arn:aws:eks:us-east-1:866018956458:cluster/unused
```

The second destroy removes the bucket and its settings, and schedules the key's deletion. The Terraform state file stays in `deploy/terraform/aws/` on the laptop. Keep it until the teardown is done.
