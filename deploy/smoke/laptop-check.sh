#!/usr/bin/env bash
# Read-only laptop check for PRs 46-50 (Git Bash on Windows, or any bash).
# Nothing here writes to AWS: terraform only inits, validates and plans.
#   1. full test suite, printing failing test ids only
#   2. terraform validate + fmt -check for the aws, azure and gcp modules
#   3. the stage 1 policy gate on a planned open-SSH security group (never applied)
# Run from the repository root:  bash deploy/smoke/laptop-check.sh
set -u
export PYTHONUTF8=1
REPO=$(pwd)
TF=${TF:-/c/Users/haris/bin/terraform1.exe}
PY=${PY:-$REPO/.venv/Scripts/python.exe}
[ -e "$PY" ] || PY=$REPO/.venv/bin/python
CC=$(dirname "$PY")/cloudctl
[ -e "$CC.exe" ] && CC=$CC.exe
WORK=${WORK:-$HOME/cctl-laptop-check}
rm -rf "$WORK" && mkdir -p "$WORK"

echo "== 0. install ($(git rev-parse --short HEAD))"
"$PY" -m pip install -q -e ".[ai,gate,service]" pytest pytest-cov 2>&1 | grep -v '^\[notice\]' \
  || true

echo "== 1. tests (failing ids only)"
# Unit tests run with no AWS profile or region set, as in CI; some read them.
env -u AWS_PROFILE -u AWS_REGION -u AWS_DEFAULT_REGION -u CLOUDCTL_GATE_CONFIG \
  "$PY" -m pytest tests -q -p no:cacheprovider --no-cov -rfE 2>&1 \
  | grep -E '^(FAILED|ERROR) |[0-9]+ (passed|failed)' | sed 's/ - .*//'

echo "== 2. terraform"
for d in aws aws/target-role azure gcp; do
  ( cd "deploy/terraform/$d" && "$TF" init -backend=false -input=false >/dev/null \
      && "$TF" validate -no-color && "$TF" fmt -check -diff && echo "OK $d" ) || echo "FAILED $d"
done

echo "== 3. policy gate (plan only, never applied)"
export AWS_PROFILE=AdministratorAccess-866018956458 AWS_REGION=us-east-1
"$PY" -m venv "$WORK/ckv"
if [ -d "$WORK/ckv/Scripts" ]; then CKV=$(cd "$WORK/ckv/Scripts" && pwd -W)/checkov.exe; CKPY=$WORK/ckv/Scripts/python.exe
else CKV=$WORK/ckv/bin/checkov; CKPY=$WORK/ckv/bin/python; fi
"$CKPY" -m pip install -q checkov==3.4.6 2>&1 | grep -v '^\[notice\]'
"$CKV" --version || echo "CHECKOV NOT INSTALLED"
CFG=$(cd "$WORK" && pwd -W 2>/dev/null || pwd)/controlplane.yaml
export CLOUDCTL_GATE_CONFIG=$CFG
"$CC" gate init --cloud aws --account-id 866018956458 --region "$AWS_REGION" \
  --profile "$AWS_PROFILE" --config "$CFG" --force >/dev/null
printf 'policy:\n  engines:\n    checkov: {enabled: true, version: "3.4.6", binary: "%s"}\n' "$CKV" >> "$CFG"
mkdir -p "$WORK/tf" && cat > "$WORK/tf/main.tf" <<'TF'
provider "aws" {}
resource "aws_security_group" "ssh" {
  name = "cctl-gate-livetest"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
TF
( cd "$WORK/tf" && "$TF" init -input=false >/dev/null && "$TF" plan -input=false -no-color -out tf.plan >/dev/null \
    && "$TF" show -json tf.plan > plan.json ) || echo "PLAN FAILED"
"$CC" gate validate --config "$CFG"
"$CC" gate engines --config "$CFG"
"$CC" gate policy eval "$WORK/tf/plan.json" --env dev --config "$CFG"; echo "policy eval exit=$?  (expected 2: rejected)"
"$CC" gate audit verify --config "$CFG"
echo "== done (scratch files in $WORK; delete with: rm -rf $WORK)"
