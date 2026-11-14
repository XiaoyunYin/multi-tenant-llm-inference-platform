#!/bin/bash
set -eu
exec > >(tee -a /var/log/gate-a-user-data.log | logger -t gate-a-user-data -s 2>/dev/console) 2>&1
systemctl enable --now amazon-ssm-agent || true
systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true
mkdir -p /var/lib/gate-a
printf '%s\n' '${role}' > /var/lib/gate-a/role
if [ '${role}' = receiver ]; then
  volume_id='${recovery_volume_id}'
  device="/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_$${volume_id//-/}"
  for _ in $(seq 1 300); do [ -b "$device" ] && break; sleep 1; done
  [ -b "$device" ] || { echo 'recovery volume did not attach' >&2; exit 1; }
  if [ -z "$(blkid -o value -s TYPE "$device" || true)" ]; then
    [ -z "$(wipefs -n "$device")" ] || { echo 'unexpected recovery volume signatures' >&2; exit 1; }
    mkfs.ext4 -F "$device"
  fi
  mkdir -p /recovery
  mount -o noatime "$device" /recovery
  printf '%s %s ext4 defaults,noatime,nofail 0 2\n' "$device" /recovery >> /etc/fstab
  systemctl daemon-reload
fi
systemd-run --unit=gate-a-maximum-lifetime --on-active=${host_timer_seconds}s --timer-property=AccuracySec=1s /sbin/shutdown -h now
mkdir -p /opt/dec077
touch /opt/dec077/user-data.done
