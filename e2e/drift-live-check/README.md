# Live check: monitor drift and who made each change (PR 45)

Three live cases on the complex-app stack, run by `live_drift_check.py`:

| Case | What it changes | What cctl must report |
|---|---|---|
| `d3` | api Lambda `QUEUE_URL` set to `...-orders-v2` by hand with boto3 | drift on `QUEUE_URL`; change labelled manual / sdk; live doesn't match the IaC; fix: re-apply the IaC |
| `c2` | the same value through `lambda.tf` + `terraform apply` | no drift; change labelled iac / terraform; live matches the IaC; fix: edit the IaC |
| `alarm` | DLQ alarm threshold 0 -> 100 by hand with boto3 | monitor drift on `threshold`, labelled manual; `PutMetricAlarm` status observer; the alarm is never a cause |

Each case refuses to start unless the tree and `terraform plan` are clean (line-ending-only differences are ignored), makes the change, re-runs cctl's diff-first checks until CloudTrail shows it (usually 5 to 15 minutes, up to 25), records the result, then puts the stack back with `terraform apply` and checks nothing is left changed. The checks are read-only and make no model calls (no Bedrock cost). All three take about 20 to 75 minutes.

## Steps (Windows, Git Bash; run every command in Git Bash, not PowerShell)

1. Branch, Python, settings:
   ```bash
   cd /c/Users/haris/cloudctl-e2e
   git fetch origin feat/drift-attribution-multicloud
   git checkout feat/drift-attribution-multicloud
   git log -1 --oneline
   export PYTHONUTF8=1
   .venv/Scripts/python -c "import cloudctl.debug.diff_first.attribution, cloudctl.debug.diff_first.live_clouds; print('ok')"
   # only if that import fails (uv doesn't work here):
   #   .venv/Scripts/python -m ensurepip    # if pip is missing
   #   .venv/Scripts/python -m pip install -e ".[ai]"

   export AWS_PROFILE=AdministratorAccess-866018956458
   export AWS_REGION=us-east-1
   export TERRAFORM_BIN='C:\Users\haris\bin\terraform1.exe'
   aws sts get-caller-identity --profile "$AWS_PROFILE" || aws sso login --profile "$AWS_PROFILE"
   ```
2. Stack up:
   ```bash
   "$TERRAFORM_BIN" -chdir=e2e/complex-app/app state list 2>/dev/null | wc -l
   ```
   If that prints 0 or errors, deploy it, and tear it down in step 4:
   ```bash
   .venv/Scripts/python e2e/complex-app/run.py deploy
   ```
   If a complex-app scenario was left half-done, run `.venv/Scripts/python e2e/complex-app/run.py revert <id>` first.
3. The three cases, one at a time, then the final check:
   ```bash
   .venv/Scripts/python e2e/drift-live-check/live_drift_check.py d3
   .venv/Scripts/python e2e/drift-live-check/live_drift_check.py c2
   .venv/Scripts/python e2e/drift-live-check/live_drift_check.py alarm
   .venv/Scripts/python e2e/drift-live-check/live_drift_check.py final
   ```
   Each case reverts in a `finally`, even when a check fails. If one is interrupted before its revert (Ctrl+C, a crash), run `"$TERRAFORM_BIN" -chdir=e2e/complex-app/app apply -auto-approve -var=region=us-east-1` (for `c2`, first `git checkout -- e2e/complex-app/app/lambda.tf`), then `final`.
4. Finish:
   ```bash
   .venv/Scripts/python e2e/complex-app/run.py teardown   # only if step 2 deployed it
   git checkout develop
   ```
5. Report back: every PASS/FAIL line and the last line of each case; the contents of `e2e/complex-app/runs/drift-live-d3.json`, `drift-live-c2.json` and `drift-live-alarm.json`; whether `final` passed; whether the stack was torn down. Change nothing in the repo and push nothing.
