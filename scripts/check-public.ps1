param([switch]$PythonTestsOnly)
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
    }
    Invoke-PublicCheck "Pinned tokenizer prerequisite" { uv run --project python --locked python -m inference_platform.stage_c_tokenizer --fetch --fetch-only }
    $excluded = @("test_remote_source_fitness", "test_stage_c_fitness", "test_stage_c_preflight", "test_stage_c_protocol", "test_stage_c_session", "test_stage_c_sizing")
    Write-Output "Excluded private-record-dependent Python modules: $($excluded -join ', ')"
    $modules = @(Get-ChildItem -LiteralPath python/tests -Filter 'test_*.py' | ForEach-Object { $_.BaseName } | Where-Object { $_ -notin $excluded } | Sort-Object)
    Write-Output "Public-context Python modules: $($modules -join ', ')"
    $env:PYTHONPATH = Join-Path $root "python/tests"
    Invoke-PublicCheck "Public-context Python tests" { uv run --project python --locked python -m unittest -v @modules }
    Write-Output "Redis integration needs REDIS_TEST_ADDR; report skips. Private PLAN/approval/preflight/builder checks are not part of this snapshot command."
}
finally { Pop-Location }
