param(
    [ValidateSet("all", "format", "lint", "build", "test", "race", "benchmark", "gpu", "cloud", "plan")]
    [string]$Suite = "all",
    [string]$PlanPath = (Join-Path (Split-Path -Parent $PSScriptRoot) "PLAN.md")
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$PowerShellExecutable = (Get-Process -Id $PID).Path
if (-not $env:UV_CACHE_DIR) { $env:UV_CACHE_DIR = Join-Path $projectRoot ".cache\uv" }
if (-not $env:GOCACHE) { $env:GOCACHE = Join-Path $projectRoot ".cache\go-build" }
if (-not $env:GOMODCACHE) { $env:GOMODCACHE = Join-Path $projectRoot ".cache\go-mod" }
$env:GOTOOLCHAIN = "local"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    Write-Output "==> $Description"
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-GoTestPackageCount {
    $testFiles = & go list -f '{{len .TestGoFiles}} {{len .XTestGoFiles}}' ./...
    if ($LASTEXITCODE -ne 0) {
        throw "Go test discovery failed with exit code $LASTEXITCODE."
    }

    $count = 0
    foreach ($line in $testFiles) {
        $parts = $line -split '\s+'
        $count += [int]$parts[0] + [int]$parts[1]
    }
    return $count
}

function Invoke-PlanStructureChecks {
    Write-Output "==> PLAN task headings and contiguous numbered sections"
    $plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8
    $appendix = [regex]::Match($plan, '(?ms)^## Appendix B: Task index\r?\n(.*?)(?=^## |\z)')
    if (-not $appendix.Success) { throw "PLAN Appendix B task index is missing." }
    $ids = @{}
    foreach ($match in [regex]::Matches($appendix.Groups[1].Value, 'INF-\d{3}[ab]?')) {
        $ids[$match.Value] = $true
    }
    foreach ($range in [regex]::Matches($appendix.Groups[1].Value, 'INF-(\d{3}) to INF-(\d{3})')) {
        for ($id = [int]$range.Groups[1].Value; $id -le [int]$range.Groups[2].Value; $id++) {
            $ids[('INF-{0:D3}' -f $id)] = $true
        }
    }
    if ($ids.Count -eq 0) { throw "PLAN task index contains no task IDs." }
    foreach ($id in ($ids.Keys | Sort-Object)) {
        $count = [regex]::Matches($plan, ('(?m)^### ' + [regex]::Escape($id) + '(?![0-9a-z])')).Count
        if ($count -ne 1) { throw "PLAN task $id requires exactly one heading; found $count." }
    }
    $sections = [regex]::Matches($plan, '(?m)^## (\d+)\. ')
    if ($sections.Count -eq 0) { throw "PLAN numbered sections are missing." }
    for ($index = 0; $index -lt $sections.Count; $index++) {
        $number = [int]$sections[$index].Groups[1].Value
        if ($number -ne ($index + 1)) {
            throw "PLAN numbered sections must be contiguous from 1; expected $($index + 1), found $number."
        }
    }
}

function Invoke-FormatChecks {
    Write-Output "==> Go formatting"
    $unformatted = & gofmt -l cmd internal
    if ($LASTEXITCODE -ne 0) {
        throw "gofmt discovery failed with exit code $LASTEXITCODE."
    }
    if ($unformatted) {
        throw "Go formatting drift detected: $($unformatted -join ', ')"
    }

    Invoke-Checked "Python formatting" {
        uv run --project python --locked ruff format --check python
    }
}

function Invoke-LintChecks {
    Invoke-Checked "Go vet" { go vet ./... }
    Invoke-Checked "Python lint" {
        uv run --project python --locked ruff check python
    }
}

function Invoke-BuildChecks {
    Invoke-Checked "Go build" { go build ./... }
    Invoke-Checked "Python package import" {
        uv run --project python --locked python -c "import inference_platform"
    }
}

function Invoke-TestChecks {
    Invoke-Checked "Public hash-pinned chat tokenizer prerequisite (no model weights)" {
        uv run --project python --locked python -m inference_platform.stage_c_tokenizer --fetch --fetch-only
    }
    $goTestCount = Get-GoTestPackageCount
    if ($goTestCount -eq 0) {
        Write-Output "==> Go unit tests: NOT IMPLEMENTED (no *_test.go files); running go test only as a package compile check"
    }
    if ($env:REDIS_TEST_ADDR) {
        Write-Output "==> Redis integration tests: ENABLED at REDIS_TEST_ADDR"
    }
    else {
        Write-Output "==> Redis integration tests: SKIPPED (set REDIS_TEST_ADDR to a disposable Redis endpoint)"
    }
    Invoke-Checked "Go package test command" { go test ./... }
    Invoke-Checked "Python unit tests" {
        uv run --project python --locked python -m unittest discover -s python/tests -v
    }
}

function Invoke-BenchmarkSmoke {
    Invoke-Checked "Deterministic workload generator smoke" {
        uv run --project python --locked python -m inference_platform.workload `
            --config experiments/examples/workload-config.json `
            --validate-only
    }
}

function Invoke-RaceChecks {
    param([switch]$AllowNoTests)

    if ((Get-GoTestPackageCount) -eq 0) {
        if ($AllowNoTests) {
            Write-Output "==> Go race tests: NOT APPLICABLE (no Go tests exist)"
            return
        }
        Stop-UnavailableSuite "Race" "no Go tests exist"
    }
    Invoke-Checked "Go race tests" { go test -race ./... }
}

function Invoke-TerraformChecks {
    Invoke-Checked "Terraform INF-011 offline validation" {
        & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "inf011-pilot.ps1") -Action Validate
    }
    Invoke-Checked "Terraform INF-011 zero-resource plan" {
        & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "inf011-pilot.ps1") -Action PlanOffline
    }
    Invoke-PilotRegionMockChecks
}

function Invoke-PilotRegionMockChecks {
    Invoke-Checked "INF-011 wrapper region wiring with mocked AWS calls" {
        & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "tests\inf011-pilot-region.ps1")
    }
}

function Stop-UnavailableSuite {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Reason
    )

    throw "$Name suite is unavailable: $Reason"
}

Push-Location $projectRoot
try {
    Invoke-PlanStructureChecks
    Invoke-Checked "Committed experiment evidence checksums and strict JSON" {
        uv run --project python --locked python scripts/check_experiment_evidence.py
    }
    Invoke-Checked "New binary evidence <=5 MB (5000000 bytes) or exact allowlist" {
        uv run --project python --locked python scripts/evidence_binary_guard.py
    }
    switch ($Suite) {
        "plan" { }
        "format" { Invoke-FormatChecks }
        "lint" { Invoke-LintChecks }
        "build" { Invoke-BuildChecks }
        "test" { Invoke-TestChecks }
        "race" { Invoke-RaceChecks }
        "benchmark" {
            Invoke-BenchmarkSmoke
        }
        "gpu" {
            Stop-UnavailableSuite "GPU" "paid GPU checks are opt-in and not implemented or authorized"
        }
        "cloud" {
            Invoke-TerraformChecks
            Write-Output "==> Paid cloud apply: NOT AUTHORIZED (only the zero-resource offline plan ran)"
        }
        "all" {
            Invoke-Checked "Large binary evidence guard regressions" {
                uv run --project python --locked python -m unittest discover -s scripts/tests -p test_evidence_binary_guard.py -v
            }
            Invoke-Checked "PLAN structural guard regression" {
                & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "tests\plan-structure.ps1")
            }
            Invoke-Checked "Committed evidence rejected-copy regressions" {
                uv run --project python --locked python -m unittest discover -s scripts/tests -p test_experiment_evidence.py -v
            }
            Invoke-Checked "Release-gate secret scanner regressions (pinned image or recorded transport mock)" {
                uv run --project python --locked python -m unittest discover -s scripts/tests -p test_secret_scan.py -v
            }
            Invoke-Checked "Private public-snapshot gate regressions (no publication)" {
                uv run --project python --locked python -m unittest discover -s scripts/tests -p test_public_snapshot.py -v
            }
            Invoke-Checked "Private push and snapshot publication refusals (no network push)" {
                uv run --project python --locked python -m unittest discover -s scripts/tests -p test_publication_guard.py -v
            }
            Invoke-FormatChecks
            Invoke-LintChecks
            Invoke-BuildChecks
            Invoke-TestChecks
            Invoke-RaceChecks -AllowNoTests
            Invoke-PilotRegionMockChecks
            Invoke-BenchmarkSmoke
            Write-Output "==> GPU/cloud checks: OPT-IN (excluded from default suite; cloud performs only offline Terraform validation)"
        }
    }
}
finally {
    Pop-Location
}

Write-Output "Check suite '$Suite' completed successfully."
