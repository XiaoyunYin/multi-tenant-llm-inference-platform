#!/bin/sh
# Uploaded only after source-bundle verification; run literally in sh rehearsals.
set -eu
bootstrap_start_epoch=$(date +%s)
BOOTSTRAP_DEADLINE_EPOCH=$((bootstrap_start_epoch + 900))
export BOOTSTRAP_DEADLINE_EPOCH
# The agent supplies host_environment(), also used by descriptive phase commands.
runtime=$1
output=$2
repo=$(pwd)
test -f /sys/fs/cgroup/cgroup.controllers
mkdir -p "$output" /opt/dec077/tools /opt/dec077/downloads
. "$repo/scripts/package_a_bootstrap_retry.sh"
# Install only host prerequisites. Docker is the separately pinned static binary.
export DEBIAN_FRONTEND=noninteractive
timed_step apt_update 300 "$BOOTSTRAP_DEADLINE_EPOCH" apt-get -o DPkg::Lock::Timeout=120 update
timed_step apt_install 300 "$BOOTSTRAP_DEADLINE_EPOCH" apt-get -o DPkg::Lock::Timeout=120 install -y git curl ca-certificates gcc libc6-dev iptables procps xz-utils
timed_step tool_pins to_deadline "$BOOTSTRAP_DEADLINE_EPOCH" python3 "$repo/scripts/package_a_bootstrap_pins.py" "$repo/deploy/package-a/pins.json" /opt/dec077/tools /opt/dec077/downloads --deadline-epoch "$BOOTSTRAP_DEADLINE_EPOCH"
python3 - <<'PY'
import subprocess
from pathlib import Path
tools=Path('/opt/dec077/tools')
for name,argv in [('python',['/opt/dec077/tools/python/bin/python3.12','--version']),('go',['/opt/dec077/tools/go/bin/go','version']),('uv',['/opt/dec077/tools/uv-x86_64-unknown-linux-gnu/uv','--version']),('docker',['/opt/dec077/tools/docker/docker','--version']),('kind',[str(tools/'kind'),'version']),('kubectl',[str(tools/'kubectl'),'version','--client=true'])]:
    print(name,subprocess.check_output(argv,timeout=30).decode(),flush=True)
PY
export PATH=/opt/dec077/tools/go/bin:/opt/dec077/tools/uv-x86_64-unknown-linux-gnu:/opt/dec077/tools/docker:$PATH
export UV_PYTHON=/opt/dec077/tools/python/bin/python3.12
export UV_PYTHON_DOWNLOADS=never PYTHONDONTWRITEBYTECODE=1 GOTOOLCHAIN=local
export UV_HTTP_TIMEOUT=20 UV_HTTP_RETRIES=0
export PYTHONPATH="$repo/python/src"
mkdir -p .tools /root/.docker/cli-plugins
cp /opt/dec077/tools/kind .tools/kind
cp /opt/dec077/tools/kubectl .tools/kubectl
cp /opt/dec077/tools/buildx /root/.docker/cli-plugins/docker-buildx
cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
After=network-online.target
[Service]
ExecStart=/opt/dec077/tools/docker/dockerd
Environment=PATH=/opt/dec077/tools/docker:/usr/sbin:/usr/bin:/sbin:/bin
Restart=no
Delegate=yes
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
# Deliberately do not start Docker: native sizing comes first.
bootstrap_rate_bytes_per_s=1000000
bootstrap_download_overhead_s=30
uv_sync_cap_s=$(((95000000 + bootstrap_rate_bytes_per_s - 1) / bootstrap_rate_bytes_per_s + bootstrap_download_overhead_s))
go_mod_download_cap_s=$(((152000000 + bootstrap_rate_bytes_per_s - 1) / bootstrap_rate_bytes_per_s + bootstrap_download_overhead_s))
retry_step uv_sync 3 "$uv_sync_cap_s" 2 "$BOOTSTRAP_DEADLINE_EPOCH" uv sync --project python --locked --python "$UV_PYTHON"
retry_step go_mod_download 3 "$go_mod_download_cap_s" 2 "$BOOTSTRAP_DEADLINE_EPOCH" go mod download
mkdir -p .cache/kind-build
timed_step gateway_build to_deadline "$BOOTSTRAP_DEADLINE_EPOCH" env GOMEMLIMIT=256MiB go build -p 1 -o .cache/kind-build/gateway ./cmd/gateway
exec "$UV_PYTHON" -m inference_platform.package_a_cloud --repo "$repo" --manifest "$runtime" --output "$output/runner"
