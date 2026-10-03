param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    & uv run --project python --locked python -m inference_platform.kind_rollout --output $OutputDirectory
    if ($LASTEXITCODE -ne 0) { throw "M5 stage 1 campaign failed with exit code $LASTEXITCODE." }
}
finally { Pop-Location }
