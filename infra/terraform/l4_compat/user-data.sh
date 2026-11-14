#!/bin/sh
# Arm termination before installation or network downloads. Never launch Docker.
set -eu
trap 'shutdown -h now' 0
install -d -m 0700 /etc/dec077 /opt/dec077
token=$(curl -fsS --max-time 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)
document=$(curl -fsS --max-time 5 -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/dynamic/instance-identity/document)
if [ ! -s /etc/dec077/deadline ]; then
  printf %s "$document" | python3 -c 'import datetime,json,sys; print(int(datetime.datetime.fromisoformat(json.load(sys.stdin)["pendingTime"].replace("Z","+00:00")).timestamp())+${host_timer_seconds})' > /etc/dec077/deadline
fi
cat > /etc/systemd/system/dec077-terminate.service <<'UNIT'
[Service]
Type=oneshot
ExecStart=/sbin/shutdown -h now
UNIT
cat > /etc/systemd/system/dec077-terminate.timer <<UNIT
[Timer]
OnCalendar=@$(cat /etc/dec077/deadline)
Persistent=true
AccuracySec=1s
Unit=dec077-terminate.service
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now dec077-terminate.timer
systemctl is-active --quiet dec077-terminate.timer || { shutdown -h now; exit 1; }
test -f /sys/fs/cgroup/cgroup.controllers || { shutdown -h now; exit 1; }
touch /opt/dec077/user-data.done
trap - 0
