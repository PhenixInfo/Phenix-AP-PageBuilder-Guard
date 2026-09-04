#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ZIP="${1:-}"
REPORT_BASE="${2:-$ROOT/reports/prestashop-validator}"
VALIDATOR="${PS_VALIDATOR_BIN:-}"

if [ -z "$ZIP" ] || [ ! -f "$ZIP" ]; then
    echo "Usage: $0 <release.zip> [report-base]" >&2
    exit 2
fi

if [ -z "${PRESTASHOP_VALIDATOR_API_KEY:-}" ]; then
    echo "ERROR: PRESTASHOP_VALIDATOR_API_KEY is not set. Official Validator is a mandatory release gate." >&2
    exit 2
fi

if [ -z "$VALIDATOR" ]; then
    if command -v ps-validator >/dev/null 2>&1; then
        VALIDATOR="$(command -v ps-validator)"
    elif [ -f "$ROOT/.tools/ps-validator/validator.php" ]; then
        VALIDATOR="$ROOT/.tools/ps-validator/validator.php"
    else
        echo "ERROR: ps-validator is not installed. Run tools/install_ps_validator.sh or set PS_VALIDATOR_BIN." >&2
        exit 2
    fi
fi

if [ "${VALIDATOR##*.}" = "php" ]; then
    CMD=(php "$VALIDATOR")
else
    CMD=("$VALIDATOR")
fi

mkdir -p "$(dirname "$REPORT_BASE")"

echo "Running official PrestaShop Validator via lozitax/ps-validator"
echo "ZIP: $ZIP"
"${CMD[@]}" "$ZIP" "$REPORT_BASE" --format=all
rc=$?
if [ "$rc" -ne 0 ]; then
    echo "ERROR: official PrestaShop Validator failed with exit code $rc." >&2
    exit "$rc"
fi

echo "Official PrestaShop Validator: OK"
