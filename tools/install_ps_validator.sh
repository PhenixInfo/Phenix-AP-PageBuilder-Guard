#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/.tools/ps-validator"
REPO="https://github.com/lozitax/ps-validator.git"

if ! command -v git >/dev/null 2>&1; then
    echo "ERROR: git is required." >&2
    exit 2
fi

if [ -d "$DEST/.git" ]; then
    echo "Updating ps-validator in $DEST"
    git -C "$DEST" pull --ff-only
else
    rm -rf "$DEST"
    mkdir -p "$(dirname "$DEST")"
    git clone --depth 1 "$REPO" "$DEST"
fi

php "$DEST/validator.php" --help >/dev/null
printf 'ps-validator ready: %s\n' "$DEST/validator.php"
