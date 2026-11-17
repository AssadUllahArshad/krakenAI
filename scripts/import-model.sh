#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo 'Usage: ./scripts/import-model.sh /absolute/path/to/model.gguf' >&2
  exit 1
fi
case "$1" in /*) ;; *) echo 'Use an absolute GGUF path.' >&2; exit 1;; esac
case "$1" in *'"'*) echo 'Model path cannot contain double quotes.' >&2; exit 1;; esac
ollama list >/dev/null
model_config=$(mktemp /tmp/kraken-modelfile.XXXXXX)
trap 'rm -f "$model_config"' EXIT
printf 'FROM "%s"\nPARAMETER num_ctx 8192\nPARAMETER num_predict 2048\n' "$1" > "$model_config"
ollama create kraken -f "$model_config"
