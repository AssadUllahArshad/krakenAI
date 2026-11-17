#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ ! -x .venv/bin/python ]; then
  echo 'Run ./scripts/install.sh first.' >&2
  exit 1
fi
case "${1-}" in
  --background) exec .venv/bin/python scripts/start-background.py ;;
  "") ;;
  *) echo 'Usage: ./scripts/start.sh [--background]' >&2; exit 1 ;;
esac
if [ ! -f frontend/dist/index.html ] || [ -n "$(find frontend/src frontend/index.html frontend/vite.config.js frontend/package.json frontend/package-lock.json -type f -newer frontend/dist/index.html 2>/dev/null)" ]; then
  echo 'Building the current dashboard…' 
  npm --prefix frontend run build
fi
export KRAKEN_INFERENCE_PROXY=1
exec .venv/bin/python scripts/serve.py
