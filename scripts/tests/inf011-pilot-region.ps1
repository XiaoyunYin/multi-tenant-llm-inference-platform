$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$PowerShellExecutable = (Get-Process -Id $PID).Path
$wrapperPath = Join-Path $projectRoot "scripts\inf011-pilot.ps1"
$temporaryPath = [Environment]::GetEnvironmentVariable("TEMP")
if ([string]::IsNullOrWhiteSpace($temporaryPath)) {
    $temporaryPath = [IO.Path]::GetTempPath()
}
$temporaryRoot = [IO.Path]::GetFullPath($temporaryPath)
$temporaryDirectory = Join-Path $temporaryRoot ("inf011-region-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null

function ConvertTo-NormalizedProcessOutput {
    param([object[]]$Output)

    $text = ($Output | ForEach-Object { [string]$_ }) -join " "
    $text = [regex]::Replace($text, '\x1B\[[0-?]*[ -/]*[@-~]', '')
    # PowerShell 7 inserts source-gutter bars when wrapped error text is redirected.
    $text = [regex]::Replace($text, '\s+\|\s+', ' ')
    return ([regex]::Replace($text, '\s+', ' ')).Trim()
}

function Assert-PlanRegionMockLog {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$PlanRegion)

    $calls = @(Get-Content -LiteralPath $Path | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    if ($calls.Count -ne 21) {
        throw "Expected 21 mocked AWS calls for cleanup under $PlanRegion; saw $($calls.Count)."
    }
    $teardownCallsByRegion = @{ "us-east-1" = 0; "us-west-2" = 0 }
    foreach ($call in $calls) {
        $arguments = @($call.arguments)
        $regionIndex = [Array]::IndexOf($arguments, "--region")
        if ($regionIndex -lt 0 -or $regionIndex + 1 -ge $arguments.Count -or $arguments[$regionIndex + 1] -cne $call.aws_region) {
            throw "Mocked AWS_REGION '$($call.aws_region)' differs from the explicit query region: $($arguments -join ' ')"
        }
        $isTeardown = ($arguments[0] -eq "ec2" -and $arguments[1] -like "describe-*" -and -not ($arguments -contains "--image-ids")) -or
            ($arguments[0] -eq "iam" -and $arguments[1] -like "list-*")
        if ($isTeardown) {
            if (-not $teardownCallsByRegion.ContainsKey($call.aws_region)) {
                throw "Teardown query targeted an unapproved region '$($call.aws_region)'."
            }
            $teardownCallsByRegion[$call.aws_region]++
        }
        elseif ($call.aws_region -cne $PlanRegion) {
            throw "Cleanup preflight ran in '$($call.aws_region)' instead of hash-bound plan region '$PlanRegion'."
        }
    }
    foreach ($region in @("us-east-1", "us-west-2")) {
        if ($teardownCallsByRegion[$region] -ne 9) {
            throw "Expected nine teardown queries in $region; saw $($teardownCallsByRegion[$region])."
        }
    }
}

$originalTerraformRegion = $env:TF_VAR_aws_region
$originalDryRunLog = $env:INF011_REGION_DRY_RUN_LOG
try {
    $env:TF_VAR_aws_region = "us-east-1"

    $stateLog = Join-Path $temporaryDirectory "non-empty-state.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $stateLog
    $originalErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $stateOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
            -Action RegionDryRun -PlanRegion us-east-1 -AmiId ami-0123456789abcdef0 `
            -MockTerraformStateEntries "aws_instance.inf011_pilot" 2>&1
    }
    finally {
        $ErrorActionPreference = $originalErrorActionPreference
    }
    if ($LASTEXITCODE -eq 0) {
        throw "Wrapper accepted a non-empty Terraform state before paid planning."
    }
    if (Test-Path -LiteralPath $stateLog) {
        $stateCalls = @(Get-Content -LiteralPath $stateLog)
        if ($stateCalls.Count -ne 0) {
            throw "Wrapper issued mocked AWS calls before rejecting a non-empty Terraform state."
        }
    }

    $successLog = Join-Path $temporaryDirectory "matching-region.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $successLog
    $successOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
        -Action RegionDryRun -PlanRegion us-east-1 -AmiId ami-0123456789abcdef0 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Wrapper region dry run failed: $($successOutput -join [Environment]::NewLine)"
    }
    $successDiagnostic = ConvertTo-NormalizedProcessOutput -Output $successOutput
    if (-not (Select-String -InputObject $successDiagnostic -Pattern "hash-bound plan metadata uses us-east-1" -Quiet)) {
        throw "Wrapper did not confirm that plan metadata and preflight use us-east-1: $successDiagnostic"
    }

    $calls = @(Get-Content -LiteralPath $successLog | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    if ($calls.Count -ne 21) {
        throw "Expected 21 mocked AWS calls (three preflight calls and nine teardown queries in each of two approved regions); saw $($calls.Count)."
    }
    $teardownCallsByRegion = @{"us-east-1" = 0; "us-west-2" = 0}
    foreach ($call in $calls) {
        $arguments = @($call.arguments)
        $regionIndex = [Array]::IndexOf($arguments, "--region")
        if ($regionIndex -lt 0 -or $regionIndex + 1 -ge $arguments.Count -or $arguments[$regionIndex + 1] -cne $call.aws_region) {
            throw "Mocked AWS_REGION '$($call.aws_region)' differs from the explicit query region: $($arguments -join ' ')"
        }
        $isTeardown = ($arguments[0] -eq "ec2" -and $arguments[1] -like "describe-*" -and -not ($arguments -contains "--image-ids")) -or
            ($arguments[0] -eq "iam" -and $arguments[1] -like "list-*")
        if ($isTeardown) {
            if (-not $teardownCallsByRegion.ContainsKey($call.aws_region)) {
                throw "Teardown query targeted an unapproved region '$($call.aws_region)'."
            }
            $teardownCallsByRegion[$call.aws_region]++
            if ($arguments[0] -eq "ec2") {
                if (-not ($arguments -contains "--filters") -or
                    -not ($arguments -contains "Name=tag:Project,Values=multi-tenant-llm-inference-platform") -or
                    -not ($arguments -contains "Name=tag:Milestone,Values=INF-011")) {
                    throw "EC2 teardown query was missing the INF-011 project and milestone tag filters: $($arguments -join ' ')"
                }
            }
        }
        elseif ($call.aws_region -cne "us-east-1") {
            throw "Mocked identity/quota/AMI preflight ran in '$($call.aws_region)' instead of the plan region us-east-1."
        }
    }
    foreach ($region in @("us-east-1", "us-west-2")) {
        if ($teardownCallsByRegion[$region] -ne 9) {
            throw "Expected nine teardown queries in $region; saw $($teardownCallsByRegion[$region])."
        }
    }

    # Destroy uses the hash-bound region when TF_VAR_aws_region is unset (Terraform's default is us-east-1).
    Remove-Item Env:TF_VAR_aws_region -ErrorAction SilentlyContinue
    $destroyLog = Join-Path $temporaryDirectory "destroy-unset-region.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $destroyLog
    $destroyOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
        -Action RegionDryRun -MockOperation Destroy -PlanRegion us-east-1 -AmiId ami-0123456789abcdef0 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Destroy mock refused when TF_VAR_aws_region was unset: $($destroyOutput -join ' ')"
    }
    $destroyDiagnostic = ConvertTo-NormalizedProcessOutput -Output $destroyOutput
    if (-not (Select-String -InputObject $destroyDiagnostic -Pattern "hash-bound plan metadata uses us-east-1" -Quiet)) {
        throw "Destroy mock did not report that the plan metadata region controls cleanup: $destroyDiagnostic"
    }
    Assert-PlanRegionMockLog -Path $destroyLog -PlanRegion us-east-1

    # VerifyTeardown warns on a configured mismatch but still queries using the saved plan region.
    $env:TF_VAR_aws_region = "us-west-1"
    $verifyLog = Join-Path $temporaryDirectory "verify-mismatched-region.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $verifyLog
    $verifyOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
        -Action RegionDryRun -MockOperation VerifyTeardown -PlanRegion us-east-1 -AmiId ami-0123456789abcdef0 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "VerifyTeardown mock refused a configured-region mismatch: $($verifyOutput -join ' ')"
    }
    $verifyDiagnostic = ConvertTo-NormalizedProcessOutput -Output $verifyOutput
    if (-not (Select-String -InputObject $verifyDiagnostic -Pattern "differs from the hash-bound paid plan region 'us-east-1'; teardown will use the plan region" -Quiet)) {
        throw "VerifyTeardown mock did not warn that metadata controls cleanup: $verifyDiagnostic"
    }
    Assert-PlanRegionMockLog -Path $verifyLog -PlanRegion us-east-1

    # Apply retains the fail-closed behavior for the same plan/configured-region mismatch.
    $applyLog = Join-Path $temporaryDirectory "apply-mismatched-region.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $applyLog
    $originalErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $applyOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
            -Action RegionDryRun -MockOperation Apply -PlanRegion us-east-1 -AmiId ami-0123456789abcdef0 2>&1
    }
    finally {
        $ErrorActionPreference = $originalErrorActionPreference
    }
    if ($LASTEXITCODE -eq 0) {
        throw "Apply mock accepted a us-east-1 plan with TF_VAR_aws_region set to us-west-1."
    }
    $applyDiagnostic = ConvertTo-NormalizedProcessOutput -Output $applyOutput
    if (-not (Select-String -InputObject $applyDiagnostic -Pattern "differs from the reviewed plan region" -Quiet)) {
        throw "Apply region mismatch failed without the expected refusal: $applyDiagnostic"
    }
    if (Test-Path -LiteralPath $applyLog) {
        $applyCalls = @(Get-Content -LiteralPath $applyLog)
        if ($applyCalls.Count -ne 0) {
            throw "Apply mock issued AWS calls before refusing a mismatched region."
        }
    }

    # A mismatched configured region remains a refusal for planning, where it selects provider resources.
    $env:TF_VAR_aws_region = "us-east-1"
    $mismatchLog = Join-Path $temporaryDirectory "mismatched-region.jsonl"
    $env:INF011_REGION_DRY_RUN_LOG = $mismatchLog
    $originalErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $mismatchOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
            -Action RegionDryRun -PlanRegion us-west-1 -AmiId ami-0123456789abcdef0 2>&1
    }
    finally {
        $ErrorActionPreference = $originalErrorActionPreference
    }
    if ($LASTEXITCODE -eq 0) {
        throw "Wrapper accepted plan region us-west-1 while Terraform aws_region was us-east-1."
    }
    $mismatchDiagnostic = ConvertTo-NormalizedProcessOutput -Output $mismatchOutput
    if (-not (Select-String -InputObject $mismatchDiagnostic -Pattern "differs from the reviewed plan region" -Quiet)) {
        throw "Region mismatch failed without the expected fail-closed diagnostic: $mismatchDiagnostic"
    }
    if (Test-Path -LiteralPath $mismatchLog) {
        $mismatchCalls = @(Get-Content -LiteralPath $mismatchLog)
        if ($mismatchCalls.Count -ne 0) {
            throw "Wrapper issued mocked AWS calls before rejecting the mismatched plan region."
        }
    }

    # Capacity errors use the same evidence/abort function as Apply, with no AWS.
    $capacityDirectory = Join-Path $temporaryDirectory "capacity-evidence"
    $originalErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $capacityOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
            -Action CapacityDryRun -EvidenceDirectory $capacityDirectory 2>&1
        $capacityExit = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $originalErrorActionPreference }
    $capacityDiagnostic = ConvertTo-NormalizedProcessOutput -Output $capacityOutput
    if ($capacityExit -eq 0 -or -not $capacityDiagnostic.Contains("infrastructure abort: capacity") -or
        -not $capacityDiagnostic.Contains("Destroy") -or -not $capacityDiagnostic.Contains("VerifyTeardown")) {
        throw "Capacity mock did not return a nonzero abort with cleanup instructions: $capacityDiagnostic"
    }
    $capacityLog = Join-Path $capacityDirectory "terraform-apply.log"
    $capacityBytes = [IO.File]::ReadAllBytes($capacityLog)
    $capacityText = [Text.UTF8Encoding]::new($false, $true).GetString($capacityBytes)
    if ($capacityText.StartsWith([string][char]0xFEFF, [StringComparison]::Ordinal) -or $capacityText.Contains("`r") -or
        -not $capacityText.Contains("mock supporting resources created") -or
        -not $capacityText.Contains("InsufficientInstanceCapacity")) {
        throw "Capacity Terraform stdout/stderr was not recorded as BOM-free UTF-8/LF."
    }
    $capacityOutcomePath = Join-Path $capacityDirectory "terraform-apply-outcome.json"
    $capacityOutcomeBytes = [IO.File]::ReadAllBytes($capacityOutcomePath)
    $capacityOutcomeText = [Text.UTF8Encoding]::new($false, $true).GetString($capacityOutcomeBytes)
    if ($capacityOutcomeText.StartsWith([string][char]0xFEFF, [StringComparison]::Ordinal) -or $capacityOutcomeText.Contains("`r")) {
        throw "Capacity outcome JSON contains a BOM or CR."
    }
    $capacityOutcome = ConvertFrom-Json -InputObject $capacityOutcomeText
    if (-not $capacityOutcome.capacity_error -or $capacityOutcome.terraform_exit_code -ne 1 -or
        $capacityOutcome.log_sha256 -ne (Get-FileHash -LiteralPath $capacityLog -Algorithm SHA256).Hash.ToLower()) {
        throw "Capacity outcome did not preserve Terraform's error and exact log hash."
    }
    Write-Output "PASS: capacity mock exited nonzero, captured stdout/stderr as UTF-8/LF, and requested Destroy/VerifyTeardown."

    $timeoutDirectory = Join-Path $temporaryDirectory "capacity-timeout"
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $ErrorActionPreference = "Continue"
        $timeoutOutput = & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $wrapperPath `
            -Action CapacityTimeoutDryRun -EvidenceDirectory $timeoutDirectory 2>&1
        $timeoutExit = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $originalErrorActionPreference }
    $timeoutDiagnostic = ConvertTo-NormalizedProcessOutput -Output $timeoutOutput
    $timeoutOutcome = Get-Content -LiteralPath (Join-Path $timeoutDirectory "terraform-apply-outcome.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    $watchdog = Get-Content -LiteralPath (Join-Path $timeoutDirectory "terraform-apply-watchdog.json") -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($timeoutExit -eq 0 -or $timer.Elapsed.TotalSeconds -gt 15 -or
        $timeoutOutcome.terraform_exit_code -ne 124 -or -not $timeoutOutcome.deadline_exceeded -or
        $timeoutOutcome.abort_reason -ne "capacity" -or -not $timeoutOutcome.destroy_requested -or
        -not $watchdog.capacity_error_observed -or -not $watchdog.verify_teardown_requested -or
        -not $timeoutDiagnostic.Contains("Destroy") -or -not $timeoutDiagnostic.Contains("VerifyTeardown")) {
        throw "Capacity retry child exceeded its mock bound or failed to request cleanup: $timeoutDiagnostic"
    }
    Write-Output "PASS: sustained capacity retry interrupted within mock wall-clock bound; capacity classified and Destroy/VerifyTeardown requested."

    Write-Output "INF-011 wrapper mock passed: Destroy with an unset region and VerifyTeardown with us-west-1 used us-east-1 plan metadata; Apply and PlanPaid refused mismatches; teardown scans cover only us-east-1 and historical us-west-2."
}
finally {
    $env:TF_VAR_aws_region = $originalTerraformRegion
    $env:INF011_REGION_DRY_RUN_LOG = $originalDryRunLog
    $resolvedTemporaryDirectory = [IO.Path]::GetFullPath($temporaryDirectory)
    if (-not $resolvedTemporaryDirectory.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Split-Path -Leaf $resolvedTemporaryDirectory).StartsWith("inf011-region-test-", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing cleanup outside the dedicated INF-011 region test directory."
    }
    Remove-Item -LiteralPath $resolvedTemporaryDirectory -Recurse -Force
}
