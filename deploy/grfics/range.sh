#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# GRFICSv3 range reset: restore the lab to a named baseline between runs.
#
# Reference: experiment framework section 3 ("a range-reset mechanism should
# restore the environment to a known snapshot between experimental runs") and
# coding guide section 25 ("reset the range to the same snapshot before each
# run").
#
#   range.sh save  NAME   stop the lab, archive its volumes, restart it, and
#                         record the inventory fingerprint as baseline NAME
#   range.sh reset NAME   remove containers + volumes, restore the volumes
#                         from NAME's archives, start the lab, then verify the
#                         inventory matches NAME and everything was recreated
#   range.sh list         list baselines and their latest verified reset
#
# THIS SCRIPT CHANGES THE LAB. It is an operator tool and deliberately lives
# outside docker-audit: the assessment agent and its MCP servers only ever
# reach Docker through the read-only socket proxy, which refuses every write.
# This script uses YOUR Docker access instead (DOCKER_HOST is ignored, so it
# never talks to the proxy). Verification is read-only: it runs
# `docker-audit range verify`, which inspects the lab through the proxy.
#
# What a reset restores: container filesystems (containers are recreated from
# the same local images; nothing is pulled or built), the contents of every
# named volume of the compose project (PLC program/state, HMI database, ...)
# and the networks. Images are not re-pulled: if a tag now points to a
# different image, verification reports the changed image ID.
#
# Environment:
#   GRFICS_DIR              GRFICSv3 checkout            (default: $HOME/GRFICSv3)
#   GRFICS_PROJECT          compose project name         (default: lower-cased dir name)
#   GRFICS_COMPOSE_OVERRIDE extra compose file; empty = none
#                           (default on macOS: deploy/grfics/docker-compose.macos.yml)
#   GRFICS_DOCKER_HOST      Docker endpoint WITH write access (default: docker context)
#   RANGE_DATA_DIR          must match experiment.yaml data_dir (default: <repo>/data)
#   RANGE_HELPER_IMAGE      image used to tar/untar volumes (default: alpine:3.20)
#   RANGE_HEALTH_TIMEOUT    seconds to wait for healthy containers (default: 600)
#   DOCKER_AUDIT            how to run docker-audit (default: uv run docker-audit)
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
GRFICS_DIR=${GRFICS_DIR:-$HOME/GRFICSv3}
PROJECT=${GRFICS_PROJECT:-$(basename "$GRFICS_DIR" | tr '[:upper:]' '[:lower:]')}
DATA_DIR=${RANGE_DATA_DIR:-$REPO_ROOT/data}
BASELINES="$DATA_DIR/range-baselines"
HELPER_IMAGE=${RANGE_HELPER_IMAGE:-alpine:3.20}
HEALTH_TIMEOUT=${RANGE_HEALTH_TIMEOUT:-600}
read -r -a AUDIT <<<"${DOCKER_AUDIT:-uv run --project $REPO_ROOT docker-audit}"

COMPOSE_ARGS=(-p "$PROJECT" -f "$GRFICS_DIR/docker-compose.yml")
if [[ -n "${GRFICS_COMPOSE_OVERRIDE+set}" ]]; then
  [[ -n "$GRFICS_COMPOSE_OVERRIDE" ]] && COMPOSE_ARGS+=(-f "$GRFICS_COMPOSE_OVERRIDE")
elif [[ "$(uname -s)" == "Darwin" ]]; then
  COMPOSE_ARGS+=(-f "$SCRIPT_DIR/docker-compose.macos.yml")
fi

log() { printf '\033[1m[range]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[range] %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  sed -n '/^#   range.sh/,/^#   range.sh list/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

# Docker with write access: never the read-only proxy from DOCKER_HOST.
dkr() {
  if [[ -n "${GRFICS_DOCKER_HOST:-}" ]]; then
    DOCKER_HOST="$GRFICS_DOCKER_HOST" docker "$@"
  else
    env -u DOCKER_HOST docker "$@"
  fi
}
compose() { dkr compose "${COMPOSE_ARGS[@]}" "$@"; }

check_name() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "Invalid baseline name '$1'"
}

project_volumes() {
  dkr volume ls -q --filter "label=com.docker.compose.project=$PROJECT"
}

wait_healthy() {
  local deadline=$((SECONDS + HEALTH_TIMEOUT)) states bad
  log "Waiting for all services to be running and healthy (timeout ${HEALTH_TIMEOUT}s)"
  while :; do
    states=$(compose ps -a --format '{{.Service}} {{.State}} {{.Health}}')
    bad=$(awk '$2 != "running" || ($3 != "" && $3 != "healthy")' <<<"$states")
    if [[ -n "$states" && -z "$bad" ]]; then
      return 0
    fi
    if ((SECONDS > deadline)); then
      die "Lab not healthy after ${HEALTH_TIMEOUT}s:"$'\n'"${bad:-no containers}"
    fi
    sleep 5
  done
}

cmd_save() {
  local name=$1 dir vol
  check_name "$name"
  dir="$BASELINES/$name"
  [[ -e "$dir" ]] && die "Baseline '$name' already exists ($dir). Baselines are write-once; use a new name."
  [[ -f "$GRFICS_DIR/docker-compose.yml" ]] || die "No docker-compose.yml in GRFICS_DIR=$GRFICS_DIR"
  [[ -n "$(compose ps -q --status running)" ]] || die "Start the lab first (no running services in project '$PROJECT')"

  mkdir -p "$dir/volumes"
  trap 'log "save failed: the lab may be stopped (start it: docker compose ... start) and $dir is incomplete (delete it before retrying)"' ERR

  log "Stopping project '$PROJECT' so volumes are archived in a consistent state"
  compose stop
  while read -r vol; do
    [[ -n "$vol" ]] || continue
    log "Archiving volume $vol"
    dkr volume inspect --format '{{range $k, $v := .Labels}}{{$k}}={{$v}}{{"\n"}}{{end}}' "$vol" \
      >"$dir/volumes/$vol.labels"
    dkr run --rm --network none -v "$vol:/from:ro" -v "$dir/volumes:/to" "$HELPER_IMAGE" \
      tar -C /from -czf "/to/$vol.tar.gz" .
  done < <(project_volumes)
  (cd "$dir/volumes" && shasum -a 256 -- *.tar.gz >SHA256SUMS)

  log "Restarting the lab"
  compose start
  wait_healthy
  trap - ERR
  log "Recording the inventory fingerprint (read-only, via the proxy)"
  "${AUDIT[@]}" range record "$name"
}

cmd_reset() {
  local name=$1 dir start labels_file vol label
  check_name "$name"
  dir="$BASELINES/$name"
  [[ -f "$dir/baseline.json" && -f "$dir/volumes/SHA256SUMS" ]] \
    || die "No complete baseline '$name' in $BASELINES (create one with: range.sh save $name)"
  [[ -f "$GRFICS_DIR/docker-compose.yml" ]] || die "No docker-compose.yml in GRFICS_DIR=$GRFICS_DIR"
  log "Checking archive integrity"
  (cd "$dir/volumes" && shasum -a 256 -c SHA256SUMS >/dev/null) || die "Volume archives of '$name' are corrupt or altered"

  # The engine's own clock: container/volume creation times come from it, and
  # a Docker Desktop VM clock can differ from the host's.
  start=$(dkr run --rm --network none "$HELPER_IMAGE" date -u +%Y-%m-%dT%H:%M:%SZ)
  log "Reset started at $start (engine clock)"

  log "Removing containers, networks and volumes of project '$PROJECT'"
  compose down --volumes --remove-orphans

  for labels_file in "$dir"/volumes/*.labels; do
    [[ -e "$labels_file" ]] || continue
    vol=$(basename "$labels_file" .labels)
    local args=()
    while IFS= read -r label; do
      [[ -n "$label" ]] && args+=(--label "$label")
    done <"$labels_file"
    log "Restoring volume $vol"
    # ${args[@]+...}: bash 3.2 (macOS) treats an empty array as unbound under set -u
    dkr volume create ${args[@]+"${args[@]}"} "$vol" >/dev/null
    dkr run --rm --network none -v "$vol:/to" -v "$dir/volumes:/from:ro" "$HELPER_IMAGE" \
      tar -C /to -xzf "/from/$vol.tar.gz"
  done

  log "Starting the lab from local images (no pull, no build)"
  compose up -d --no-build --pull never
  wait_healthy

  log "Verifying the range against baseline '$name' (read-only, via the proxy)"
  "${AUDIT[@]}" range verify "$name" --since "$start" --project "$PROJECT"
}

case "${1:-}" in
  save) [[ $# -eq 2 ]] || usage; cmd_save "$2" ;;
  reset) [[ $# -eq 2 ]] || usage; cmd_reset "$2" ;;
  list) [[ $# -eq 1 ]] || usage; "${AUDIT[@]}" range list ;;
  *) usage ;;
esac
