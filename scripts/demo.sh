#!/usr/bin/env bash
# One-command demo: start the vulnerable lab, scan it, show the findings, then
# start the fixed lab and show a clean scan. Record this with asciinema or a
# screen recorder for the README.
#
# Run from the repo root:  bash scripts/demo.sh
# Requires Docker. Uses the scanner virtual environment if one exists at
# scanner/.venv; otherwise falls back to `python`, which then needs the scanner
# installed (see scanner/README.md). Override with PY=/path/to/python.
set -euo pipefail

if [ -z "${PY:-}" ]; then
  if [ -x "scanner/.venv/Scripts/python.exe" ]; then
    PY="scanner/.venv/Scripts/python.exe"   # Windows venv
  elif [ -x "scanner/.venv/bin/python" ]; then
    PY="scanner/.venv/bin/python"           # macOS / Linux venv
  else
    PY="python"
  fi
fi

if ! "$PY" -c "import polarizer" >/dev/null 2>&1; then
  echo "error: the 'polarizer' package is not available to $PY." >&2
  echo "Create the scanner venv first:" >&2
  echo "  cd scanner && python -m venv .venv && .venv/Scripts/python.exe -m pip install -e . && cd .." >&2
  echo "(on macOS/Linux: .venv/bin/python -m pip install -e .)" >&2
  exit 1
fi
pause() { sleep "${DEMO_PAUSE:-1}"; }
say() { printf '\n\033[1;36m# %s\033[0m\n' "$*"; pause; }

cleanup() { docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

say "1. Start the VULNERABLE invoice lab (localhost only)"
APP_MODE=vulnerable JWT_SECRET=secret123 docker compose up -d --build --wait --wait-timeout 180
pause

say "2. Log in the fake test users and load their tokens"
eval "$("$PY" scanner/examples/get_tokens.py)"
pause

say "3. Scan it with Polarizer (expect findings and a non-zero exit)"
set +e
"$PY" -m polarizer scan --config scanner/examples/lab.yaml --allow-writes
echo "exit code: $?"
set -e

say "4. Tear down and start the FIXED lab"
docker compose down -v >/dev/null 2>&1
SECRET=$("$PY" -c "import secrets; print(secrets.token_hex(48))")
APP_MODE=fixed JWT_SECRET="$SECRET" docker compose up -d --build --wait --wait-timeout 180
pause

say "5. Same scan, now clean (exit 0)"
eval "$("$PY" scanner/examples/get_tokens.py)"
"$PY" -m polarizer scan --config scanner/examples/lab.yaml --allow-writes
echo "exit code: $?"

say "Done."
