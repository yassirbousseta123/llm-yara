#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG="${SCRIPT_DIR}/configs/default.yaml"
if [[ -f "/app/configs/default.yaml" ]]; then
  DEFAULT_CONFIG="/app/configs/default.yaml"
fi

default_output_root() {
  if [[ -d "/outputs" && -w "/outputs" ]]; then
    echo "/outputs"
  else
    echo "${SCRIPT_DIR}/outputs"
  fi
}

usage() {
  cat <<USAGE
Usage:
  ./start.sh --mode demo [--out /outputs/demo_run]
  ./start.sh --mode full --malware-dir /data/malware --benign-dir /data/benign [--out /outputs/final_run]
  ./start.sh --mode full --compare-all --malware-dir /data/malware --benign-dir /data/benign [--out /outputs/final_compare]
  ./start.sh --help

Notes:
- Static analysis only; no malware execution.
- OPENAI_API_KEY required only when --backend openai.
- OPENAI_BASE_URL supported for OpenAI-compatible endpoints.
USAGE
}

dependency_preflight() {
  if ! command -v python >/dev/null 2>&1; then
    echo "python is required but was not found on PATH" >&2
    exit 2
  fi

  python - "$BACKEND" <<'PY'
from __future__ import annotations

import importlib.util
import sys

backend = sys.argv[1]
required = ["yaml", "yara"]
if backend == "openai":
    required.append("openai")

missing = [name for name in required if importlib.util.find_spec(name) is None]
if missing:
    raise SystemExit("Missing Python modules: " + ", ".join(missing))
PY
}

MODE=""
OUT_DIR=""
MALWARE_DIR=""
BENIGN_DIR=""
BACKEND="${LLM_BACKEND:-mock}"
CONFIG_PATH="$DEFAULT_CONFIG"
COMPARE_ALL="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"; shift 2 ;;
    --out)
      OUT_DIR="$2"; shift 2 ;;
    --malware-dir)
      MALWARE_DIR="$2"; shift 2 ;;
    --benign-dir)
      BENIGN_DIR="$2"; shift 2 ;;
    --backend)
      BACKEND="$2"; shift 2 ;;
    --config)
      CONFIG_PATH="$2"; shift 2 ;;
    --compare-all)
      COMPARE_ALL="1"; shift 1 ;;
    --help|-h)
      usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo "Missing --mode" >&2
  usage
  exit 2
fi

if [[ "$BACKEND" == "openai" && -z "${OPENAI_API_KEY:-}" ]]; then
  echo "OPENAI_API_KEY is required when backend=openai" >&2
  exit 2
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo "Config file not found: $CONFIG_PATH" >&2
  exit 2
fi

dependency_preflight

if [[ -z "$OUT_DIR" ]]; then
  OUTPUT_ROOT="$(default_output_root)"
  if [[ "$MODE" == "demo" ]]; then
    OUT_DIR="${OUTPUT_ROOT}/demo_run"
  else
    OUT_DIR="${OUTPUT_ROOT}/final_run"
  fi
fi

mkdir -p "$OUT_DIR"

if [[ "$MODE" == "demo" ]]; then
  DEMO_ROOT="/tmp/llmyara_demo_data"
  python -m llmyara.cli make-demo-data --out "$DEMO_ROOT"
  MALWARE_DIR="$DEMO_ROOT/malware"
  BENIGN_DIR="$DEMO_ROOT/benign"
elif [[ "$MODE" == "full" ]]; then
  if [[ -z "$MALWARE_DIR" || -z "$BENIGN_DIR" ]]; then
    echo "--malware-dir and --benign-dir are required in full mode" >&2
    exit 2
  fi
else
  echo "Invalid --mode: $MODE" >&2
  exit 2
fi

for p in "$MALWARE_DIR" "$BENIGN_DIR"; do
  if [[ ! -d "$p" ]]; then
    echo "Input directory not found: $p" >&2
    exit 2
  fi
done

echo "[llmyara] mode=$MODE backend=$BACKEND malware_dir=$MALWARE_DIR benign_dir=$BENIGN_DIR out=$OUT_DIR"
if [[ "$COMPARE_ALL" == "1" ]]; then
  python -m llmyara.cli run-all-compare \
    --config "$CONFIG_PATH" \
    --malware-dir "$MALWARE_DIR" \
    --benign-dir "$BENIGN_DIR" \
    --out "$OUT_DIR" \
    --backend "$BACKEND"
else
  python -m llmyara.cli run-all \
    --config "$CONFIG_PATH" \
    --malware-dir "$MALWARE_DIR" \
    --benign-dir "$BENIGN_DIR" \
    --out "$OUT_DIR" \
    --backend "$BACKEND"
fi
