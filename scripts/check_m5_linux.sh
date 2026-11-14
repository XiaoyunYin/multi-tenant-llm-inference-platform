#!/bin/sh
# Inside the constrained, network-disabled Docker invocation in the EKS README.
# /src and /mirror are read-only; /work is disposable. No real backend or AWS.
set -eu
mkdir -p /work/src /work/bin
tar -C /src --exclude=.terraform --exclude=__pycache__ -cf - \
    infra/terraform/eks python/src/inference_platform/m5_infra_safety.py \
    python/tests/test_m5_infra_safety.py python/tests/fixtures/m5_plan_configuration.json \
    scripts/check_m5_offline.py |
    tar -C /work/src -xf -
PYTHON=/opt/r87-probe-venv/bin/python
"$PYTHON" - <<'PY'
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile
archive = Path('/terraform.zip')
assert sha256(archive.read_bytes()).hexdigest() == '0d17011f0c4664539b164b044903d04e296c86c13cb9f28040076c65cfb3985a'
with ZipFile(archive) as source:
    source.extract('terraform', '/work/bin')
Path('/work/bin/terraform').chmod(0o755)
PY
cat > /work/terraform.rc <<'EOF'
provider_installation {
  filesystem_mirror { path = "/mirror" }
}
EOF
export TF_CLI_CONFIG_FILE=/work/terraform.rc
export PYTHONPATH=/work/src/python/src
cd /work/src
exec "$PYTHON" scripts/check_m5_offline.py --terraform /work/bin/terraform --inside-sealed-container
