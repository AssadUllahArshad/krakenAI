#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ -f projects/test-app/test_calculator.py ]; then
  .venv/bin/python -m pytest tests projects/test-app -q
else
  .venv/bin/python -m pytest tests -q
fi
npm --prefix frontend run build
