#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run docker-audit inside its container, then copy the results to the Mac.
#
#   deploy/agent/run.sh assess --model local-vllm --range-baseline clean-v2
#   deploy/agent/run.sh doctor
#   deploy/agent/run.sh setup
#
# Arguments are passed to `docker-audit` in the container.
#
# The agent container mounts no Mac folder (harness h4), so files move with
# Docker's own copy commands, which do not need Docker Desktop file sharing:
#
#   1. before the run: the range baselines' baseline.json files (small, read
#      by --range-baseline) are copied INTO the container's data volume. The
#      originals, with the volume archives a reset restores from, stay on the
#      Mac where the agent cannot reach them.
#   2. the run itself, in a container named docker-audit-agent-run-<time>
#      (that name keeps it out of the assessment and of the range fingerprint).
#   3. after the run: outputs/<RUN_ID>/ is copied to the repository's outputs/,
#      and the container's SQLite databases to data/container/.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
COMPOSE=(docker compose -f "$REPO_ROOT/deploy/agent/compose.yml")
NAME="docker-audit-agent-run-$(date -u +%Y%m%d-%H%M%S)"

log() { echo "[run] $*" >&2; }

# 1. baselines in (baseline.json only)
if compgen -G "$REPO_ROOT/data/range-baselines/*/baseline.json" >/dev/null; then
  log "Copying range baselines into the agent's data volume"
  (cd "$REPO_ROOT/data" && tar -c range-baselines/*/baseline.json) \
    | "${COMPOSE[@]}" run --rm -T --entrypoint sh agent -c 'tar -x -C /app/data'
fi

# 2. the run (the container is kept until its results are copied out)
status=0
"${COMPOSE[@]}" run --name "$NAME" agent "$@" || status=$?

# 3. results out
mkdir -p "$REPO_ROOT/outputs" "$REPO_ROOT/data/container"
docker cp "$NAME:/app/outputs/." "$REPO_ROOT/outputs/"
docker cp "$NAME:/app/data/." "$REPO_ROOT/data/container/"
docker rm "$NAME" >/dev/null
log "Reports: outputs/<RUN_ID>/ · databases: data/container/ (exit status $status)"
exit "$status"
