param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$MatchedDispatchCheck
)
$ErrorActionPreference = "Stop"
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $benchmarkArguments = @('--output', $OutputDirectory)
    if ($MatchedDispatchCheck) {
        $benchmarkArguments += @('--precise-dispatch', '--rates', '400', '800', '1600', '3200', '--no-profiles')
    }
    & uv run --project python --locked python -m inference_platform.cpu_benchmark @benchmarkArguments
    if ($LASTEXITCODE -ne 0) { throw "INF-036 benchmark failed with exit code $LASTEXITCODE." }
}
finally { Pop-Location }
