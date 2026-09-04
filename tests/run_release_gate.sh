#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIP="${1:-}"
AP_ARCHIVES="${2:-}"
REPORT_BASE="${3:-$ROOT/reports/prestashop-validator}"

if [ -z "$ZIP" ] || [ -z "$AP_ARCHIVES" ]; then
    echo "Usage: $0 <release.zip> <ap-archive-dir> [report-base]" >&2
    exit 2
fi

echo '[1/7] PHP lint'
while IFS= read -r -d '' file; do
    php -l "$file" >/dev/null
done < <(find "$ROOT/module" -type f -name '*.php' -print0)

echo '[2/7] JavaScript syntax'
if command -v node >/dev/null 2>&1; then
    while IFS= read -r -d '' file; do
        node --check "$file" >/dev/null
    done < <(find "$ROOT/module" -type f -name '*.js' -print0)
else
    echo 'ERROR: node is required by the release gate.' >&2
    exit 2
fi

echo '[3/7] Static/project checks'
python3 "$ROOT/tests/static_checks.py"

echo '[4/7] Deterministic runtime fuzzing'
python3 "$ROOT/tests/fuzz_runtime.py"

echo '[5/7] Real AP archive patch/rollback/manual-restore matrix'
python3 "$ROOT/tests/run_patch_matrix.py" "$AP_ARCHIVES"

echo '[6/7] Final ZIP integrity and packaging scope'
unzip -t "$ZIP" >/dev/null
if unzip -Z1 "$ZIP" | grep -Eq '(^|/)(tests|\.agents|\.tools|reports|quarantine)(/|$)|(^|/)AGENTS\.md$|(^|/)README-DEV\.md$'; then
    echo 'ERROR: development/runtime files found in release ZIP.' >&2
    exit 1
fi

echo '[7/7] Official PrestaShop Validator via lozitax/ps-validator'
"$ROOT/tests/run_ps_validator.sh" "$ZIP" "$REPORT_BASE"

echo
echo 'RELEASE GATE: OK'
