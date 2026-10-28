"""deploy/grfics/range.sh against a fake ``docker`` (no real lab is touched).

The script is run with macOS's /bin/bash when present (bash 3.2) so
compatibility problems surface here. The fake records every docker call; the
tests check the command sequence, that the read-only proxy (DOCKER_HOST) is
never used, and that a broken baseline stops before anything is removed.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "grfics" / "range.sh"
BASH = "/bin/bash" if Path("/bin/bash").exists() else shutil.which("bash")

FAKE_DOCKER = r"""#!/bin/sh
echo "DOCKER_HOST=${DOCKER_HOST-<unset>} $*" >> "$FAKE_LOG"
case "$*" in
  *"compose"*" ps -q"*) echo abc123 ;;
  *"compose"*" ps -a"*) printf 'plc running healthy\nhmi running \n' ;;
  "volume ls"*) printf 'grficsv3_plc_volume\ngrficsv3_scadalts_db\n' ;;
  "volume inspect"*) printf 'com.docker.compose.project=grficsv3\ncom.docker.compose.volume=x\n' ;;
  "run "*" date "*) echo 2026-10-16T10:00:00Z ;;
  "run "*"-czf"*)
    host=""; prev=""
    for a in "$@"; do
      case "$prev:$a" in -v:*:/to) host=${a%:/to} ;; esac
      case "$prev" in -czf) echo "archive" > "$host/${a#/to/}" ;; esac
      prev=$a
    done ;;
esac
exit 0
"""


@pytest.fixture
def env(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(FAKE_DOCKER)
    docker.chmod(0o755)
    audit = bin_dir / "fake-audit"
    audit.write_text('#!/bin/sh\necho "AUDIT $*" >> "$FAKE_LOG"\n')
    audit.chmod(0o755)
    grfics = tmp_path / "GRFICSv3"
    grfics.mkdir()
    (grfics / "docker-compose.yml").write_text("services: {}\n")
    data = tmp_path / "data"
    log = tmp_path / "calls.log"
    e = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "FAKE_LOG": str(log),
        "GRFICS_DIR": str(grfics),
        "GRFICS_COMPOSE_OVERRIDE": "",
        "RANGE_DATA_DIR": str(data),
        "RANGE_HEALTH_TIMEOUT": "5",
        "DOCKER_AUDIT": str(audit),
        "DOCKER_HOST": "tcp://127.0.0.1:2375",  # the read-only proxy: must be ignored
    }
    return e, data, log


def run(e, *args):
    return subprocess.run([BASH, str(SCRIPT), *args], env=e, capture_output=True, text=True)


def calls(log: Path) -> list[str]:
    return log.read_text().splitlines() if log.exists() else []


def test_save_then_reset(env):
    e, data, log = env
    r = run(e, "save", "base1")
    assert r.returncode == 0, r.stderr
    vols = data / "range-baselines" / "base1" / "volumes"
    assert sorted(p.name for p in vols.iterdir()) == [
        "SHA256SUMS",
        "grficsv3_plc_volume.labels",
        "grficsv3_plc_volume.tar.gz",
        "grficsv3_scadalts_db.labels",
        "grficsv3_scadalts_db.tar.gz",
    ]
    save_calls = calls(log)
    # stop before archiving, start after; then record via docker-audit (read-only)
    order = [c for c in save_calls if " stop" in c or "-czf" in c or " start" in c]
    assert " stop" in order[0] and " start" in order[-1]
    assert save_calls[-1] == "AUDIT range record base1"

    (data / "range-baselines" / "base1" / "baseline.json").write_text("{}")  # by `range record`
    log.unlink()
    r = run(e, "reset", "base1")
    assert r.returncode == 0, r.stderr
    c = calls(log)
    docker_calls = [x for x in c if not x.startswith("AUDIT")]
    assert all(x.startswith("DOCKER_HOST=<unset> ") for x in docker_calls)
    steps = [
        next(i for i, x in enumerate(c) if " date " in x),
        next(
            i for i, x in enumerate(c) if "compose" in x and "down --volumes --remove-orphans" in x
        ),
        next(
            i
            for i, x in enumerate(c)
            if "volume create --label com.docker.compose.project=grficsv3" in x
        ),
        next(i for i, x in enumerate(c) if "-xzf /from/grficsv3_plc_volume.tar.gz" in x),
        next(i for i, x in enumerate(c) if "up -d --no-build --pull never" in x),
        c.index("AUDIT range verify base1 --since 2026-10-16T10:00:00Z --project grficsv3"),
    ]
    assert steps == sorted(steps)
    assert all(" -p grficsv3 " in x for x in c if " compose " in x)


def test_refusals_happen_before_anything_is_removed(env):
    e, data, log = env
    assert run(e, "reset", "nope").returncode == 1  # no such baseline
    assert run(e, "save", "../evil").returncode == 1  # invalid name
    assert run(e, "save", "base1").returncode == 0
    assert run(e, "save", "base1").returncode == 1  # write-once
    (data / "range-baselines" / "base1" / "baseline.json").write_text("{}")
    archive = data / "range-baselines" / "base1" / "volumes" / "grficsv3_plc_volume.tar.gz"
    archive.write_text("tampered")
    log.unlink()
    r = run(e, "reset", "base1")
    assert r.returncode == 1 and "corrupt or altered" in r.stderr
    assert not any("down" in x for x in calls(log))


def test_reset_fails_when_lab_never_gets_healthy(env, tmp_path):
    e, data, log = env
    assert run(e, "save", "base1").returncode == 0
    (data / "range-baselines" / "base1" / "baseline.json").write_text("{}")
    docker = Path(e["PATH"].split(":")[0]) / "docker"
    docker.write_text(docker.read_text().replace("hmi running ", "hmi running unhealthy"))
    e["RANGE_HEALTH_TIMEOUT"] = "0"
    r = run(e, "reset", "base1")
    assert r.returncode == 1 and "not healthy" in r.stderr
    assert not any(x.startswith("AUDIT range verify") for x in calls(log))
