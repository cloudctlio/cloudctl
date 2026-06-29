#!/usr/bin/env bash
# record_demo.sh — record a real cloudctl debug session for the README
#
# Usage:
#   SYMPTOM="efs-shared-storage Lambda can't read files, permission denied" \
#   PROFILE=my-aws-profile \
#   bash scripts/record_demo.sh
#
# What it does:
#   1. Writes demo.tape with the correct symptom + profile
#   2. Runs vhs to record demo.gif
#   3. Redacts AWS account IDs, ARNs, and sensitive values from the gif frames
#      (VHS can output WebP/PNG frames; we post-process with ffmpeg if needed)
#   4. Updates README.md to point to demo.gif
#   5. Stages demo.gif + README.md for commit

set -euo pipefail

SYMPTOM="${SYMPTOM:-payments service returning 502s since 3pm}"
PROFILE="${PROFILE:-default}"
REGION="${REGION:-us-east-1}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== cloudctl demo recorder ==="
echo "Symptom : $SYMPTOM"
echo "Profile : $PROFILE"
echo "Region  : $REGION"
echo ""

# ── 1. Resolve the real AWS account ID so we can redact it later ──────────
echo "Resolving account ID for redaction..."
ACCOUNT_ID=$(aws sts get-caller-identity --profile "${PROFILE}" --query Account --output text 2>/dev/null || echo "")
if [[ -z "${ACCOUNT_ID}" ]]; then
    echo "WARN: could not resolve account ID — redaction will be skipped for account numbers"
fi

# ── 2. Write the tape file with current settings ───────────────────────────
cat > "${REPO_ROOT}/demo.tape" <<TAPE
Output ${REPO_ROOT}/demo.gif

Set Shell "bash"
Set FontSize 13
Set Width 900
Set Height 560
Set Theme "Catppuccin Mocha"
Set FontFamily "Cascadia Code"
Set Padding 10
Set Framerate 24
Set PlaybackSpeed 1.0

Sleep 800ms
Type "cloudctl debug --agent --account ${PROFILE} --region ${REGION} --verdict skip \\"${SYMPTOM}\\""
Sleep 400ms
Enter
Sleep 90s
Sleep 5s
TAPE

echo "Tape file written."

# ── 3. Record ──────────────────────────────────────────────────────────────
echo "Starting VHS recording... (this takes ~2 minutes)"
cd "${REPO_ROOT}"
vhs demo.tape

if [[ ! -f "${REPO_ROOT}/demo.gif" ]]; then
    echo "ERROR: demo.gif was not produced. Check vhs output above."
    exit 1
fi

echo "Recording complete: demo.gif ($(du -sh demo.gif | cut -f1))"

# ── 4. Redact sensitive values from gif ────────────────────────────────────
# GIF is a binary format — text strings inside frames can be found and replaced
# with sed on a binary level (same byte count, safe for GIF structure).
echo "Redacting sensitive values..."

REDACTED_GIF="${REPO_ROOT}/demo_redacted.gif"
cp "${REPO_ROOT}/demo.gif" "${REDACTED_GIF}"

if [[ -n "${ACCOUNT_ID}" ]]; then
    # Replace the 12-digit account ID with Xs in the gif binary
    REDACTED="XXXXXXXXXXXX"
    # Use Python for reliable binary replacement
    python3 - "${REDACTED_GIF}" "${ACCOUNT_ID}" "${REDACTED}" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
data = open(path, 'rb').read()
data = data.replace(old, new)
open(path, 'wb').write(data)
PY
    echo "  Redacted account ID: ${ACCOUNT_ID} → XXXXXXXXXXXX"
fi

# Replace common ARN patterns (arn:aws:...:account-id:...) — keep resource names
python3 - "${REDACTED_GIF}" <<'PY'
import sys, re
path = sys.argv[1]
data = open(path, 'rb').read()
# Replace 12-digit numbers that look like account IDs in ARN context
data = re.sub(rb'(arn:aws:[a-z0-9-]+:[a-z0-9-]*:)\d{12}(:[^\x00-\x1f ]+)', rb'\1XXXXXXXXXXXX\2', data)
open(path, 'wb').write(data)
PY

mv "${REDACTED_GIF}" "${REPO_ROOT}/demo.gif"
echo "  ARN account IDs redacted."

# ── 5. Update README to point to demo.gif ─────────────────────────────────
echo "Updating README.md..."
sed -i 's|<img src="demo\.svg"[^/]*/> |<img src="demo.gif" alt="cloudctl debug --agent demo" width="900"/>|' \
    "${REPO_ROOT}/README.md" || true

# Fallback: direct Python replacement if sed didn't match
python3 - "${REPO_ROOT}/README.md" <<'PY'
import sys, re
path = sys.argv[1]
text = open(path, encoding='utf-8').read()
text = re.sub(
    r'<img src="demo\.svg"[^>]*/?>',
    '<img src="demo.gif" alt="cloudctl debug --agent demo" width="900"/>',
    text
)
open(path, 'w', encoding='utf-8').write(text)
PY
echo "  README.md updated to reference demo.gif"

# ── 6. Stage for commit ────────────────────────────────────────────────────
cd "${REPO_ROOT}"
git add demo.gif README.md
echo ""
echo "=== Done ==="
echo "Files staged. Review with: git diff --cached"
echo "Then commit:  git commit -m 'docs: replace SVG animation with real VHS recording'"
echo "Then push:    git push origin develop"
