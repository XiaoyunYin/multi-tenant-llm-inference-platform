#!/bin/sh
# Invoke only after the separate exact-hash approvals. No cloud resource API.
set -eu
packet=$1
output=$2
origin=$3
systemctl is-active --quiet dec077-terminate.timer
cd "$packet"
# Every subprocess shares the first-action deadline; no readiness reset.
left=$(python3 -c 'import sys,time; print(max(0,int(float(sys.argv[1])+2700-time.time())))' "$origin")
test "$left" -gt 0
timeout "$left" python3 - "$packet" <<'PY'
import hashlib,json,subprocess,sys,tarfile,urllib.request
from pathlib import Path
root=Path(sys.argv[1]); tools=root/'.tools'; tools.mkdir(exist_ok=False)
for name,pin in json.loads((root/'tools.json').read_bytes()).items():
    path=tools/(name+'.tar.gz')
    with urllib.request.urlopen(pin['url'],timeout=30) as source,path.open('xb') as target:
        while data:=source.read(1024**2): target.write(data)
    if path.stat().st_size!=pin['bytes'] or hashlib.sha256(path.read_bytes()).hexdigest()!=pin['sha256']:
        raise ValueError('tool_pin:'+name)
    with tarfile.open(path) as archive: archive.extractall(tools,filter='data')
subprocess.run(['systemctl','start','docker'],check=True,timeout=60)
PY
export PATH="$packet/.tools/go/bin:$PATH"
export PYTHONPATH="$packet/python/src"
export PYTHONDONTWRITEBYTECODE=1 GOTOOLCHAIN=local
left=$(python3 -c 'import sys,time; print(max(0,int(float(sys.argv[1])+2700+210+240+196-time.time())))' "$origin")
test "$left" -gt 0
exec timeout --signal=TERM --kill-after=10 "$left" "$packet/.tools/python/bin/python3.12" \
  scripts/l4_compat_host.py --packet "$packet" --output "$output" --t0-epoch "$origin"
