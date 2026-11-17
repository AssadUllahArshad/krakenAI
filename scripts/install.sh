#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock.txt
npm --prefix frontend ci
npm --prefix frontend run build
printf '\nInstalled. Optional browser engine: .venv/bin/playwright install chromium\nStart: ./scripts/start.sh\n'
