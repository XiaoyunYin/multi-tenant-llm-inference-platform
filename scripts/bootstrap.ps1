$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$env:UV_CACHE_DIR = Join-Path $projectRoot ".cache\uv"
$env:GOCACHE = Join-Path $projectRoot ".cache\go-build"
$env:GOMODCACHE = Join-Path $projectRoot ".cache\go-mod"
$env:GOTOOLCHAIN = "local"

function Require-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found on PATH."
    }
}

Require-Command "go"
Require-Command "uv"

$actualGo = (go version)
if ($actualGo -notmatch "\bgo1\.26\.6\b") {
    throw "Go 1.26.6 is required; found: $actualGo"
}

$actualUv = (uv --version)
if ($actualUv -notmatch "\b0\.9\.5\b") {
    throw "uv 0.9.5 is required; found: $actualUv"
}

Push-Location $projectRoot
try {
    go mod download
    if ($LASTEXITCODE -ne 0) {
        throw "go mod download failed with exit code $LASTEXITCODE."
    }

    uv sync --project python --locked
    if ($LASTEXITCODE -ne 0) {
        throw "uv sync failed with exit code $LASTEXITCODE."
    }

    go build ./...
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE."
    }

    uv run --project python --locked python -c "import inference_platform"
    if ($LASTEXITCODE -ne 0) {
        throw "Python import smoke check failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}

Write-Output "Foundation bootstrap completed successfully."
