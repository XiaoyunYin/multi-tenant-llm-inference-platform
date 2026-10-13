#!/usr/bin/env bash
set -euo pipefail
install -d -m 0700 /opt/r1 /etc/r1
# IMDS pendingTime anchors the fallback to launch, not completion of bootstrap.
# Persist once: reboot never extends this failsafe. Operator tightens it to the
# earlier wrapper deadline over SSM; Terraform does not regenerate the plan.
token=$(curl -fsS --retry 3 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 300' http://169.254.169.254/latest/api/token)
pending=$(curl -fsS --retry 3 -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/dynamic/instance-identity/document)
if [ ! -s /etc/r1/deadline_epoch ]; then
  printf '%s' "$pending" | python3 -c 'import json,sys,datetime; t=datetime.datetime.fromisoformat(json.load(sys.stdin)["pendingTime"].replace("Z","+00:00")); print(int(t.timestamp())+16080)' > /etc/r1/deadline_epoch
fi
deadline=$(cat /etc/r1/deadline_epoch)
cat > /etc/systemd/system/r1-terminate.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/sbin/shutdown -h now
UNIT
cat > /etc/systemd/system/r1-terminate.timer <<UNIT
[Timer]
OnCalendar=@$deadline
Persistent=true
AccuracySec=1s
Unit=r1-terminate.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now r1-terminate.timer
systemctl is-active --quiet r1-terminate.timer || { shutdown -h now; exit 1; }
missing=()
command -v chronyc >/dev/null || missing+=(chrony)
command -v docker >/dev/null || missing+=(docker.io)
# uv supplies Python; avoid touching already baked packages. Both the lock wait
# and retries fit inside the original 2400-second ready budget.
apt_retry() {
  for attempt in 1 2 3; do
    remaining=$((deadline - 13680 - $(date +%s)))
    [ "$remaining" -gt 0 ] || return 1
    [ "$remaining" -le 650 ] || remaining=650
    if timeout "$remaining" apt-get -o DPkg::Lock::Timeout=600 "$@"; then return 0; fi
    [ "$attempt" -lt 3 ] || return 1
    sleep 5
  done
}
if [ "${#missing[@]}" -gt 0 ]; then
  apt_retry update
  apt_retry install -y "${missing[@]}"
fi
systemctl enable --now docker.service chrony.service
python3 -c 'import json,shutil; print(json.dumps(dict(zip(("total","used","free"),shutil.disk_usage("/")))))' >/opt/r1/disk-before-pull.json
touch /opt/r1/user-data.done
