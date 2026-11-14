param([switch]$PythonTestsOnly, [switch]$ChecksOnly, [int]$Shard = -1, [int]$ShardCount = 32)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not $env:UV_CACHE_DIR) { $env:UV_CACHE_DIR = Join-Path $root ".cache/uv" }
if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $root ".cache/go-build" }
if (-not $env:GOMODCACHE) { $env:GOMODCACHE = Join-Path $root ".cache/go-mod" }
$env:GOTOOLCHAIN = "local"
function Invoke-PublicCheck {
    param([string]$Name, [scriptblock]$Command)
    Write-Output "==> $Name"
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Name failed ($LASTEXITCODE)." }
}
Push-Location $root
try {
    if (-not $PythonTestsOnly) {
        $checksClock = [Diagnostics.Stopwatch]::StartNew()
        Invoke-PublicCheck "Locked dependency bootstrap" { & (Join-Path $root 'scripts/bootstrap.ps1') }
        $unformatted = & gofmt -l cmd internal
        if ($LASTEXITCODE -ne 0 -or $unformatted) { throw "Go formatting failed." }
        Invoke-PublicCheck "Go vet" { go vet ./... }
        Invoke-PublicCheck "Go build" { go build ./... }
        Invoke-PublicCheck "Go unit and configured Redis integration" { go test ./... }
        Invoke-PublicCheck "Go race" { go test -race ./... }
        Invoke-PublicCheck "Python format" { uv run --project python --locked ruff format --check python }
        Invoke-PublicCheck "Python lint" { uv run --project python --locked ruff check python }
        Invoke-PublicCheck "Committed evidence" { uv run --project python --locked python scripts/check_experiment_evidence.py }
        Invoke-PublicCheck "Scanner wrapper tests (not a release scan)" { uv run --project python --locked python -m unittest discover -s scripts/tests -p test_secret_scan.py -v }
        $checks = @{ exit_code = 0; elapsed_s = $checksClock.Elapsed.TotalSeconds }
        $checks | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $root '.cache/public-checks.json')
        if ($checks.elapsed_s -ge 900) { throw 'Public checks job exceeded 15 minutes.' }
    }
    if ($ChecksOnly) { return }
    if ($Shard -lt 0) {
        $jobs = @()
        for ($index = 0; $index -lt $ShardCount; $index++) {
            $jobClock = [Diagnostics.Stopwatch]::StartNew()
            & pwsh -NoProfile -File $PSCommandPath -PythonTestsOnly -Shard $index -ShardCount $ShardCount
            $jobs += @{ shard = $index; exit_code = $LASTEXITCODE; elapsed_s = $jobClock.Elapsed.TotalSeconds }
        }
        $jobs | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $root '.cache/public-jobs.json')
        Invoke-PublicCheck "Public shard union and timing" { uv run --project python --locked python scripts/verify_public_shards.py --directory .cache/public-shards --jobs .cache/public-jobs.json --checks .cache/public-checks.json }
        return
    }
    # Same locked dependency step as a fresh matrix job; measured inside the
    # host job bracket rather than amortized across the entire test selection.
    Invoke-PublicCheck "Locked dependency bootstrap" { & (Join-Path $root 'scripts/bootstrap.ps1') }
    Invoke-PublicCheck "Public gateway fixture" { go build -o .cache/kind-build/gateway ./cmd/gateway }
    $env:M5_PACKAGE_A_BIN = Join-Path $root ".cache/kind-build/gateway"
    Invoke-PublicCheck "Pinned tokenizer prerequisite" { uv run --project python --locked python -m inference_platform.stage_c_tokenizer --fetch --fetch-only }
    Invoke-PublicCheck "Public test selection regressions" { uv run --project python --locked python -m unittest discover -s scripts/tests -p test_public_python_selection.py -v }
    Invoke-PublicCheck "R1 chart provenance regressions" { uv run --project python --locked python -m unittest discover -s scripts/tests -p test_render_r1_packet.py -v }
    Invoke-PublicCheck "Pinned kind/kubectl test prerequisites (no cluster)" { uv run --project python --locked python -c "from pathlib import Path; from inference_platform.kind_rollout import Campaign; Campaign(Path('.cache/public-test-tools')).install_tools()" }
    if ($Shard -ge 0) {
        Invoke-PublicCheck "Public Python shard $Shard/$ShardCount" { uv run --project python --locked python scripts/run_public_python_tests.py --index $Shard --count $ShardCount --report ".cache/public-shards/shard-$Shard.json" }
    } else {
        Invoke-PublicCheck "All public Python shards (no selected cases omitted)" { uv run --project python --locked python scripts/run_public_python_tests.py --all-shards --count $ShardCount --report .cache/public-shards }
    }
    Write-Output "Redis integration needs REDIS_TEST_ADDR; report skips. Private PLAN/approval/preflight/builder checks are not part of this snapshot command."
}
finally { Pop-Location }
