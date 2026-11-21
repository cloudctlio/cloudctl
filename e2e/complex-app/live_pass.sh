#!/usr/bin/env bash
# One live pass of the complex-app scenarios on a cctl branch (Git Bash on Windows, or bash).
#
#   bash live_pass.sh <expected-sha-prefix> [branch]
#
# Run it from the e2e clone after `git fetch origin <branch>`. It stops before touching
# AWS if the clone has tracked edits, the branch head is not the expected commit, or the
# AWS credentials don't work. Then it installs the branch into .venv, deploys the app,
# runs s1, s3, s4 and s5 (s2 needs Lambda concurrency headroom this account lacks),
# scores them, ALWAYS tears down (also after a failure or Ctrl-C), keeps a copy of the
# run folder, and prints the results, model ids and diff-first keys.
#
# Creates AWS resources tagged project=cctl-complexapp and makes Bedrock calls.
set -uo pipefail

want="${1:?usage: bash live_pass.sh <expected-sha-prefix> [branch]}"
branch="${2:-fix/s5-s4-lag-and-budget}"
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  git status --short --untracked-files=no
  echo "STOP: the clone has tracked edits (above). Nothing was run."; exit 1
fi
head="$(git rev-parse "origin/$branch" 2>/dev/null)"
case "$head" in
  "$want"*) ;;
  *) echo "STOP: origin/$branch is '${head:-missing}', expected $want. Run: git fetch origin $branch"; exit 1 ;;
esac
git checkout -q -B "$branch" "origin/$branch" || exit 1
echo "== cctl at $(git log --oneline -1)"

set +u  # venv activate scripts may read unset variables
# shellcheck disable=SC1091
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate || exit 1
set -u
python -m ensurepip --upgrade >/dev/null 2>&1
python -m pip install -q -e ".[ai]" || { echo "STOP: pip install failed. Nothing was deployed."; exit 1; }

export PYTHONUTF8=1
export CLOUDCTL_MODEL="${CLOUDCTL_MODEL:-us.anthropic.claude-sonnet-4-6}"
export AWS_PROFILE="${AWS_PROFILE:-AdministratorAccess-866018956458}"
export AWS_REGION="${AWS_REGION:-us-east-1}" AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
if [ -z "${TERRAFORM_BIN:-}" ] && [ -x /c/Users/haris/bin/terraform1.exe ]; then
  export TERRAFORM_BIN='C:\Users\haris\bin\terraform1.exe'
fi
[ -n "${TERRAFORM_BIN:-}" ] && export CLOUDCTL_TERRAFORM_BIN="$TERRAFORM_BIN"
aws sts get-caller-identity --query Account --output text \
  || { echo "STOP: AWS credentials failed. Run: aws sso login --profile $AWS_PROFILE"; exit 1; }

cd e2e/complex-app || exit 1
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
# Keep the previous run's files (a replay may still need them); start this pass clean.
[ -d runs ] && mv runs "runs-before-$stamp" && echo "== earlier runs moved to e2e/complex-app/runs-before-$stamp"
finish() {
  echo "== teardown (always runs)"
  python run.py teardown
  cp -r runs "runs-$stamp" 2>/dev/null && echo "== run folder copied to e2e/complex-app/runs-$stamp"
  python run.py summary
}
trap finish EXIT
trap 'exit 130' INT TERM

python run.py preflight || exit 1
python run.py deploy || exit 1
for s in s1 s3 s4 s5; do
  python run.py scenario "$s" || echo "== $s exited with an error; going on to the next scenario"
done
python run.py score
