#!/usr/bin/env bash
# Deep audit a URL with strix. Usage: ./audit.sh https://target.com
set -e
cd "$(dirname "$0")"

TARGET="${1:-https://www.caddie.app/}"

# 1. venv
source .venv/bin/activate

# 2. LLM key check
if [ -z "$LLM_API_KEY" ]; then
  echo "LLM_API_KEY not set. Run: export STRIX_LLM=openai/gpt-4o LLM_API_KEY=sk-..."
  exit 1
fi

# 3. Docker up + wait
if ! docker info >/dev/null 2>&1; then
  echo "Starting Docker Desktop..."
  open -a Docker
  until docker info >/dev/null 2>&1; do sleep 2; done
  echo "Docker ready."
fi

# 4. Run
strix -t "$TARGET" \
  --instruction "deep audit: full OWASP Top 10, auth, IDOR, SSRF, injection, business logic. exhaustive."
