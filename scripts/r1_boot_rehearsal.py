"""Run real R1 user data in Ubuntu 24.04 while dpkg's frontend lock is held 60s."""

import argparse
import json
import subprocess
import time
from pathlib import Path

CONTAINER = r'''set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update >/tmp/setup.log 2>&1
apt-get install -y python3 >>/tmp/setup.log 2>&1
mkdir -p /test-bin /etc/systemd/system
printf '#!/bin/sh\nexit 0\n' >/test-bin/systemctl
cp /test-bin/systemctl /test-bin/docker
cp /test-bin/systemctl /test-bin/shutdown
cat >/test-bin/curl <<'SH'
#!/bin/sh
case "$*" in
  *instance-identity*) python3 -c 'import datetime,json; print(json.dumps({"pendingTime":datetime.datetime.now(datetime.UTC).isoformat()}))' ;;
  *) printf fixture-token ;;
esac
SH
chmod +x /test-bin/*
export PATH=/test-bin:$PATH
python3 - <<'PY' &
import fcntl,time,pathlib
with open('/var/lib/dpkg/lock-frontend','w') as lock:
    fcntl.lockf(lock,fcntl.LOCK_EX)
    pathlib.Path('/tmp/lock-held').touch()
    time.sleep(60)
PY
holder=$!
while [ ! -f /tmp/lock-held ]; do sleep 0.1; done
start=$(date +%s)
bash /source/infra/terraform/r1/user-data.sh >/tmp/user-data.log 2>&1
elapsed=$(( $(date +%s) - start ))
wait "$holder"
test -f /opt/r1/user-data.done
command -v chronyc
test "$elapsed" -ge 55
grep -q 'Waiting for cache lock' /tmp/user-data.log
printf '#!/bin/sh\nexit 201\n' >/test-bin/apt-get
chmod +x /test-bin/apt-get
bash /source/infra/terraform/r1/user-data.sh
printf '{"dpkg_lock_seconds":60,"user_data_elapsed_s":%s,"lock_wait_observed":true,"marker_present":true,"second_boot_no_apt":true}\n' "$elapsed"
cat /tmp/user-data.log
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    started = time.time()
    command = ["docker", "run", "--rm", "--name", "r1-round89-boot", "-v",
               str(Path.cwd()) + ":/source:ro", "ubuntu:24.04", "bash", "-c", CONTAINER]
    result = subprocess.run(command, capture_output=True, timeout=900)
    (args.output / "stdout.log").write_bytes(result.stdout)
    (args.output / "stderr.log").write_bytes(result.stderr)
    rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b'{"dpkg')]
    receipt = {"command": command[:8], "image": "ubuntu:24.04", "exit": result.returncode,
               "elapsed_s": time.time() - started, "result": rows,
               "stubs": ["IMDS curl", "systemctl", "shutdown", "already baked docker"],
               "real": ["user-data.sh", "apt-get", "dpkg lock", "chrony install"],
               "source_sha256": __import__("hashlib").sha256(Path("infra/terraform/r1/user-data.sh").read_bytes()).hexdigest()}
    (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
