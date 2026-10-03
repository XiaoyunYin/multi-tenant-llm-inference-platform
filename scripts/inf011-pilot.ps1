param(
    [ValidateSet("Validate", "PlanOffline", "PlanPaid", "Apply", "Destroy", "VerifyTeardown", "RegionDryRun", "CapacityDryRun", "CapacityTimeoutDryRun", "PreflightDryRun")]
    [string]$Action = "Validate",
    [decimal]$ApprovedSpendCapUsd = 0,
    [decimal]$EstimatedMaxSessionCostUsd = 0,
    [string]$BudgetAuthorizationId = "",
    [string]$AmiId = "",
    [decimal]$MaxSessionHours = 4,
    [string]$AvailabilityZone = "",
    [string]$EvidenceDirectory = "",
    [string]$PlanRegion = "",
    [string]$PreflightRepo = "",
    [string]$PreflightPlanHash = "",
    [string]$PreflightBindingTarget = "",
    [ValidateSet("PlanPaid", "Apply", "Destroy", "VerifyTeardown")]
    [string]$MockOperation = "PlanPaid",
    [string[]]$MockTerraformStateEntries = @(),
    [switch]$ConfirmPaidResources,
    [string]$ConfirmationText = ""
)

$ErrorActionPreference = "Stop"
if ($PreflightBindingTarget -and $Action -ne "PreflightDryRun") {
    throw "PreflightBindingTarget is restricted to no-AWS PreflightDryRun; it cannot authorize Apply."
}

$projectRoot = Split-Path -Parent $PSScriptRoot
$PowerShellExecutable = (Get-Process -Id $PID).Path
$stackPath = Join-Path $projectRoot "infra\terraform\pilot"
$workspaceTerraform = Join-Path $projectRoot ".tools\terraform\1.16.2\terraform.exe"
$terraform = if (Test-Path -LiteralPath $workspaceTerraform) {
    $workspaceTerraform
}
else {
    $command = Get-Command terraform -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        throw "Terraform 1.16.2 is required. Install it on PATH or under .tools\terraform\1.16.2."
    }
    $command.Source
}

$env:TF_CLI_CONFIG_FILE = Join-Path $projectRoot "infra\terraform\terraform.rc"
$env:TF_PLUGIN_CACHE_DIR = Join-Path $projectRoot ".cache\terraform-plugins"
New-Item -ItemType Directory -Force -Path $env:TF_PLUGIN_CACHE_DIR | Out-Null
$script:AwsDryRun = $false
$script:AwsDryRunLogPath = ""
$script:ApprovedTeardownRegions = @("us-east-1", "us-west-2")

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

function Invoke-TerraformWithEvidence {
    param(
        [Parameter(Mandatory = $true)][ValidateSet("plan", "apply", "destroy")][string]$Operation,
        [Parameter(Mandatory = $true)][scriptblock]$Command
    )

    if ([string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
        $sessionId = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") + "-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
        $destination = Join-Path $projectRoot ".cache\inf011-session-evidence\$sessionId"
    }
    else {
        $destination = [IO.Path]::GetFullPath($EvidenceDirectory)
    }
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $logPath = Join-Path $destination "terraform-$Operation.log"
    $writer = [IO.StreamWriter]::new($logPath, $false, [Text.UTF8Encoding]::new($false))
    $writer.NewLine = "`n"
    $writer.AutoFlush = $true
    $capacityError = $false
    $script:OperationEvidenceDirectory = $destination
    $watchdogPath = Join-Path $destination "terraform-apply-watchdog.json"
    if ($Operation -eq "apply" -and (Test-Path -LiteralPath $watchdogPath)) {
        Remove-Item -LiteralPath $watchdogPath
    }
    $originalPreference = $ErrorActionPreference
    Write-Output "Terraform $Operation evidence: $logPath"
    try {
        # PS 5.1 converts native stderr to ErrorRecord. Continue lets us retain
        # both streams and Terraform's exit code rather than throw on its first line.
        $ErrorActionPreference = "Continue"
        & $Command 2>&1 | ForEach-Object {
            $line = $_.ToString() -replace "`r`n", "`n"
            $writer.WriteLine($line)
            if ($line -match '(?i)InsufficientInstanceCapacity|InsufficientHostCapacity|insufficient capacity') {
                $capacityError = $true
            }
            Write-Output $line
        }
        $terraformExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $originalPreference
        $writer.Dispose()
    }
    $outcome = [ordered]@{
        schema = "inf011-terraform-operation.v1"
        operation = $Operation
        terraform_exit_code = $terraformExit
        capacity_error = ($terraformExit -ne 0 -and $capacityError)
        log_file = "terraform-$Operation.log"
        log_sha256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLower()
        observed_at_utc = [DateTime]::UtcNow.ToString("o")
    }
    if ($Operation -eq "apply" -and (Test-Path -LiteralPath $watchdogPath)) {
        $watchdog = Get-Content -LiteralPath $watchdogPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $outcome.abort_reason = $watchdog.abort_reason
        $outcome.deadline_exceeded = $watchdog.deadline_exceeded
        $outcome.destroy_requested = $watchdog.destroy_requested
        $outcome.watchdog_receipt = "terraform-apply-watchdog.json"
    }
    $outcomeText = (ConvertTo-Json -InputObject $outcome -Depth 4) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $destination "terraform-$Operation-outcome.json"), $outcomeText + "`n", [Text.UTF8Encoding]::new($false))
    if ($terraformExit -ne 0) {
        if ($capacityError) {
            throw "infrastructure abort: capacity. Terraform exited $terraformExit; evidence: $logPath. Run scripts/inf011-pilot.ps1 -Action Destroy -EvidenceDirectory `"$destination`" -ConfirmationText `"DESTROY INF-011 PILOT`", then -Action VerifyTeardown. Do not retry Apply or change zones without a new authorization and reviewed plan."
        }
        throw "Terraform $Operation failed with exit code $terraformExit; evidence: $logPath. Inspect partial state and run Destroy/VerifyTeardown for any created resources."
    }
}

function Invoke-StageCPreflight {
    param([string]$Repo, [string]$PlanHash, [string]$BindingRehearsalTarget = "")
    if ($BindingRehearsalTarget -and $Action -ne "PreflightDryRun") {
        throw "Binding rehearsal is restricted to PreflightDryRun; it cannot authorize Apply."
    }
    $rehearsalArguments = @()
    if ($BindingRehearsalTarget) { $rehearsalArguments = @("--preflight-rehearsal-target", $BindingRehearsalTarget) }
    $receipt = Join-Path $Repo ".cache\stage-c-preflight\receipt.json"
    Invoke-Checked "No-cost Stage C pre-Apply preflight" {
        & uv run --project (Join-Path $projectRoot "python") --locked python -B -m inference_platform.stage_c_session --preflight --repo $Repo --plan-sha256 $PlanHash --receipt $receipt @rehearsalArguments
    }
}

function Assert-EmptyTerraformState {
    param([AllowEmptyCollection()][string[]]$Entries = @())

    if ($Entries.Count -ne 0) {
        throw "Terraform state is not empty: $($Entries -join ', ')"
    }
}

function Assert-CurrentTerraformStateEmpty {
    $stateEntries = @(& $terraform state list)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to inspect Terraform state before planning or teardown verification."
    }
    Assert-EmptyTerraformState -Entries $stateEntries
}

function Assert-TerraformVersion {
    $version = & $terraform version -json | ConvertFrom-Json
    if ($version.terraform_version -ne "1.16.2") {
        throw "Terraform 1.16.2 is required; found $($version.terraform_version)."
    }
}

function Assert-ValidAwsRegion {
    param([Parameter(Mandatory = $true)][string]$Region)

    if ($Region -notmatch '^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$') {
        throw "Terraform aws_region is not a valid AWS region name: '$Region'."
    }
}

function Get-TerraformAwsRegion {
    $expression = "var.aws_region"
    $consoleOutput = @($expression | & $terraform console -no-color)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to resolve Terraform variable aws_region."
    }
    try {
        $consoleJson = $consoleOutput -join "`n"
        $region = [string](ConvertFrom-Json -InputObject $consoleJson)
    }
    catch {
        throw "Terraform console returned invalid aws_region JSON: $($consoleOutput -join ' ')"
    }
    Assert-ValidAwsRegion -Region $region
    return $region
}

function Assert-RegionMatchesPlan {
    param(
        [Parameter(Mandatory = $true)][string]$ConfiguredRegion,
        [Parameter(Mandatory = $true)][string]$PlanRegion
    )

    Assert-ValidAwsRegion -Region $ConfiguredRegion
    Assert-ValidAwsRegion -Region $PlanRegion
    if ($ConfiguredRegion -cne $PlanRegion) {
        throw "Configured Terraform aws_region '$ConfiguredRegion' differs from the reviewed plan region '$PlanRegion'; refusing AWS queries."
    }
}

function Warn-ConfiguredRegionDiffersFromPlan {
    param([Parameter(Mandatory = $true)][string]$PlanRegion)

    Assert-ValidAwsRegion -Region $PlanRegion
    try {
        $configuredRegion = Get-TerraformAwsRegion
    }
    catch {
        Write-Warning "Unable to resolve configured Terraform aws_region; teardown will use the hash-bound paid plan region '$PlanRegion'."
        return
    }
    if ($configuredRegion -cne $PlanRegion) {
        Write-Warning "Configured Terraform aws_region '$configuredRegion' differs from the hash-bound paid plan region '$PlanRegion'; teardown will use the plan region."
    }
}

function Set-AwsRegionEnvironment {
    param([Parameter(Mandatory = $true)][string]$Region)

    Assert-ValidAwsRegion -Region $Region
    $env:AWS_REGION = $Region
}

function Initialize-Stack {
    $providerDirectory = Join-Path (Get-Location) ".terraform\providers"
    $lockFile = Join-Path (Get-Location) ".terraform.lock.hcl"
    if ((Test-Path -LiteralPath $providerDirectory) -and (Test-Path -LiteralPath $lockFile)) {
        Write-Output "==> Terraform initialization: REUSING LOCKED LOCAL PROVIDER"
        return
    }
    Invoke-Checked "Terraform initialization without a remote backend" {
        & $terraform init -backend=false -input=false
    }
}

function Get-PaidArguments {
    if ($ApprovedSpendCapUsd -le 0) {
        throw "A positive user-approved spend cap is required."
    }
    if ($EstimatedMaxSessionCostUsd -le 0) {
        throw "A positive maximum session cost estimate is required."
    }
    if ($EstimatedMaxSessionCostUsd -gt $ApprovedSpendCapUsd) {
        throw "The maximum session estimate exceeds the approved spend cap."
    }
    if ([string]::IsNullOrWhiteSpace($BudgetAuthorizationId)) {
        throw "BudgetAuthorizationId must identify the recorded user approval."
    }
    if ($AmiId -notmatch '^ami-[0-9a-f]+$') {
        throw "A lowercase AMI ID resolved from the reviewed DLAMI parameter in Terraform aws_region is required."
    }
    if ($MaxSessionHours -le 0 -or $MaxSessionHours -gt 4 -or $MaxSessionHours -ne [math]::Floor($MaxSessionHours)) {
        throw "MaxSessionHours must be a whole number between one and four."
    }

    # PowerShell 5.1's native-command argument splatting can split strings that
    # contain an equals sign after a leading dash (Terraform then reports
    # "Too many command line arguments"). Pass Terraform's repeatable -var
    # option and its name=value operand as separate array entries instead.
    $arguments = @(
        "-var", "enable_paid_gpu=true",
        "-var", "offline_validation=false",
        "-var", "approved_phase_cap_usd=$ApprovedSpendCapUsd",
        "-var", "estimated_max_session_cost_usd=$EstimatedMaxSessionCostUsd",
        "-var", "budget_authorization_id=$BudgetAuthorizationId",
        "-var", "ami_id=$AmiId",
        "-var", "max_session_hours=$MaxSessionHours"
    )
    if (-not [string]::IsNullOrWhiteSpace($AvailabilityZone)) {
        $arguments += @("-var", "availability_zone=$AvailabilityZone")
    }
    return $arguments
}

function Invoke-AwsCli {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    if ($script:AwsDryRun) {
        $entry = [ordered]@{
            aws_region = $env:AWS_REGION
            arguments  = @($Arguments)
        }
        $jsonLine = ConvertTo-Json -InputObject $entry -Compress
        [System.IO.File]::AppendAllText($script:AwsDryRunLogPath, $jsonLine + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        $global:LASTEXITCODE = 0

        if ($Arguments[0] -eq "sts") { return "{}" }
        if ($Arguments[0] -eq "service-quotas") { return "8.0" }
        if ($Arguments[0] -eq "ec2" -and $Arguments[1] -eq "describe-images") {
            $imageIndex = [Array]::IndexOf($Arguments, "--image-ids")
            if ($imageIndex -lt 0 -or $imageIndex + 1 -ge $Arguments.Count) { return "None" }
            return $Arguments[$imageIndex + 1]
        }
        return "0"
    }

    $output = & aws @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI command failed with exit code ${LASTEXITCODE}: aws $($Arguments -join ' ')"
    }
    return $output
}

function Assert-AwsIdentity {
    param([Parameter(Mandatory = $true)][string]$Region)

    if (-not $script:AwsDryRun -and $null -eq (Get-Command aws -ErrorAction SilentlyContinue)) {
        throw "AWS CLI is required for paid plans, applies, and teardown verification."
    }
    Invoke-Checked "AWS caller identity in $Region" {
        Invoke-AwsCli -Arguments @("sts", "get-caller-identity", "--region", $Region) | Out-Null
    }
}

function Assert-PilotQuota {
    param([Parameter(Mandatory = $true)][string]$Region)

    $quotaCode = "L-DB2E81BA"
    $requiredVcpu = 4
    $quotaValue = Invoke-AwsCli -Arguments @(
        "service-quotas", "get-service-quota",
        "--service-code", "ec2",
        "--quota-code", $quotaCode,
        "--region", $Region,
        "--query", "Quota.Value",
        "--output", "text"
    )
    $quota = 0.0
    if (-not [double]::TryParse(([string]$quotaValue).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$quota)) {
        throw "EC2 service quota $quotaCode returned a non-numeric value: $quotaValue"
    }
    Write-Output "Verified EC2 quota $quotaCode in $Region at $quota vCPUs; g6.xlarge requires at least $requiredVcpu."
    if ($quota -lt $requiredVcpu) {
        throw "EC2 service quota $quotaCode in $Region is $quota vCPUs; request at least $requiredVcpu before planning or applying the paid pilot."
    }
}

function Assert-AmiInRegion {
    param(
        [Parameter(Mandatory = $true)][string]$Region,
        [Parameter(Mandatory = $true)][string]$ImageId
    )

    if ($ImageId -notmatch '^ami-[0-9a-f]+$') {
        throw "A lowercase AMI ID is required."
    }
    $resolvedImage = [string](Invoke-AwsCli -Arguments @(
        "ec2", "describe-images",
        "--region", $Region,
        "--image-ids", $ImageId,
        "--query", "Images[0].ImageId",
        "--output", "text"
    )).Trim()
    if ($resolvedImage -cne $ImageId) {
        throw "AMI '$ImageId' is not available in Terraform aws_region '$Region'."
    }
    Write-Output "Verified AMI $ImageId in $Region."
}

function Get-PaidPlanHash {
    if (-not (Test-Path -LiteralPath "inf011-paid.tfplan")) {
        throw "The reviewed paid plan file is missing."
    }
    return (Get-FileHash -LiteralPath "inf011-paid.tfplan" -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-PaidPlanDocument {
    if (-not (Test-Path -LiteralPath "inf011-paid.tfplan")) {
        throw "The reviewed paid plan file is missing."
    }
    $planJson = & $terraform show -json "inf011-paid.tfplan"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the saved Terraform plan metadata."
    }
    try {
        return ($planJson | Out-String | ConvertFrom-Json)
    }
    catch {
        throw "Terraform returned invalid saved-plan JSON: $($_.Exception.Message)"
    }
}

function Get-RegionFromPaidPlan {
    $document = Get-PaidPlanDocument
    $variableRegion = [string]$document.variables.aws_region.value
    $outputRegion = [string]$document.planned_values.outputs.pilot_region.value
    if ([string]::IsNullOrWhiteSpace($variableRegion) -or [string]::IsNullOrWhiteSpace($outputRegion)) {
        throw "The saved Terraform plan does not contain aws_region and pilot_region metadata."
    }
    Assert-ValidAwsRegion -Region $variableRegion
    if ($variableRegion -cne $outputRegion) {
        throw "Saved Terraform plan aws_region '$variableRegion' differs from its pilot_region output '$outputRegion'."
    }
    return $variableRegion
}

function Write-PaidPlanMetadata {
    param([Parameter(Mandatory = $true)][string]$ExpectedRegion)

    $planHash = Get-PaidPlanHash
    $planRegion = Get-RegionFromPaidPlan
    Assert-RegionMatchesPlan -ConfiguredRegion $ExpectedRegion -PlanRegion $planRegion
    $metadata = [ordered]@{
        schema_version = 1
        plan_sha256    = $planHash
        aws_region     = $planRegion
    }
    $temporaryPath = "inf011-paid.plan-metadata.json.tmp"
    $metadataText = (ConvertTo-Json -InputObject $metadata -Depth 4) -replace "`r`n", "`n"
    [IO.File]::WriteAllText((Join-Path $PWD $temporaryPath), $metadataText + "`n", [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination "inf011-paid.plan-metadata.json" -Force
    return $metadata
}

function Get-PaidPlanMetadata {
    $metadataPath = "inf011-paid.plan-metadata.json"
    if (-not (Test-Path -LiteralPath $metadataPath)) {
        throw "The paid plan region metadata is missing; refusing AWS queries."
    }
    try {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "The paid plan region metadata is invalid: $($_.Exception.Message)"
    }
    if ($metadata.schema_version -ne 1) {
        throw "Unsupported paid plan metadata schema version '$($metadata.schema_version)'."
    }
    $planHash = Get-PaidPlanHash
    if ([string]$metadata.plan_sha256 -cne $planHash) {
        throw "Paid plan metadata hash does not match inf011-paid.tfplan; refusing AWS queries."
    }
    $planRegion = Get-RegionFromPaidPlan
    if ([string]$metadata.aws_region -cne $planRegion) {
        throw "Paid plan metadata region '$($metadata.aws_region)' differs from the saved plan region '$planRegion'; refusing AWS queries."
    }
    $planDocument = Get-PaidPlanDocument
    $imageId = [string]$planDocument.variables.ami_id.value
    if ($imageId -notmatch '^ami-[0-9a-f]+$') {
        throw "The saved Terraform plan does not contain a valid AMI ID."
    }
    return [pscustomobject]@{
        plan_sha256 = $planHash
        aws_region  = $planRegion
        ami_id      = $imageId
    }
}

function Assert-PaidPlanReview {
    if ($null -eq (Get-Command git -ErrorAction SilentlyContinue)) {
        throw "Apply requires Git to verify the committed Claude review gate."
    }
    & git -C $projectRoot ls-files --error-unmatch -- REVIEW.md *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Apply requires a tracked REVIEW.md containing the Claude paid-plan approval marker."
    }
    & git -C $projectRoot diff --quiet -- REVIEW.md
    if ($LASTEXITCODE -ne 0) {
        throw "Apply requires REVIEW.md to be clean; commit the Claude review before applying."
    }
    & git -C $projectRoot diff --cached --quiet -- REVIEW.md
    if ($LASTEXITCODE -ne 0) {
        throw "Apply requires the Claude review marker to be committed, not staged."
    }
    $committedReview = (& git -C $projectRoot show "HEAD:REVIEW.md" 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the committed REVIEW.md review gate."
    }
    $planMetadata = Get-PaidPlanMetadata
    $planHash = $planMetadata.plan_sha256
    $reviewSectionMatch = [regex]::Match($committedReview, '(?ms)^## Claude review rounds\s*(.*?)^## Findings\s*$')
    if (-not $reviewSectionMatch.Success) {
        throw "Apply requires a Claude review-round section in the committed REVIEW.md."
    }
    $rounds = [regex]::Matches($reviewSectionMatch.Groups[1].Value, '(?ms)^### Round ([1-9][0-9]*)\b[^\r\n]*\r?\n(.*?)(?=^### Round [1-9][0-9]*\b|\z)')
    if ($rounds.Count -eq 0) {
        throw "Apply requires at least one Claude review round in the committed REVIEW.md."
    }
    $latestRound = $rounds[$rounds.Count - 1]
    $approvalPattern = '(?m)^- INF-011 PAID PLAN APPROVED: plan_sha256=([0-9a-f]{64}); target=([0-9a-f]{40}); review_round=([1-9][0-9]*)\s*$'
    $approvals = [regex]::Matches($latestRound.Groups[2].Value, $approvalPattern)
    if ($approvals.Count -ne 1) {
        throw "Apply requires exactly one Claude approval marker in the latest Claude review round ($($latestRound.Groups[1].Value))."
    }
    $approval = $approvals[0]
    if ($approval.Groups[3].Value -ne $latestRound.Groups[1].Value) {
        throw "The Claude approval marker review_round must match the latest Claude review round ($($latestRound.Groups[1].Value))."
    }
    if ($approval.Groups[1].Value -ne $planHash) {
        throw "The committed Claude review marker does not match inf011-paid.tfplan SHA-256 $planHash. Regenerate and review the exact plan."
    }
    $targetCommit = $approval.Groups[2].Value
    & git -C $projectRoot merge-base --is-ancestor $targetCommit HEAD *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "The Claude approval target $targetCommit is not an ancestor of the current HEAD."
    }
    Write-Output "Verified committed Claude review round $($approval.Groups[3].Value) for paid plan $planHash at target $targetCommit."
}

function Set-OfflineAwsEnvironment {
    param([string]$Region = "")

    # Deliberately shadow any real ambient identity. With offline_validation=true,
    # the provider accepts these inert values and the zero-count graph makes no API calls.
    $env:AWS_ACCESS_KEY_ID = "offline-validation"
    $env:AWS_SECRET_ACCESS_KEY = "offline-validation"
    $env:AWS_SESSION_TOKEN = ""
    $env:AWS_EC2_METADATA_DISABLED = "true"
    if (-not [string]::IsNullOrWhiteSpace($Region)) {
        Set-AwsRegionEnvironment -Region $Region
    }
}

function Assert-AwsQueryZero {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $result = Invoke-AwsCli -Arguments $Arguments
    $count = 0
    if (-not [int]::TryParse(([string]$result).Trim(), [ref]$count)) {
        throw "AWS query for $Description returned a non-integer result: $result"
    }
    if ($count -ne 0) {
        throw "Teardown verification found $count $Description."
    }
    Write-Output "Verified zero $Description."
}

function Invoke-TeardownAwsQueries {
    param([Parameter(Mandatory = $true)][string]$Region)

    if ($Region -notin $script:ApprovedTeardownRegions) {
        throw "Plan region '$Region' is outside the approved teardown region set."
    }
    $projectTag = "Name=tag:Project,Values=multi-tenant-llm-inference-platform"
    $milestoneTag = "Name=tag:Milestone,Values=INF-011"
    $activeStates = "Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down"
    $volumeStates = "Name=status,Values=creating,available,in-use,error"
    foreach ($queryRegion in $script:ApprovedTeardownRegions) {
        Set-AwsRegionEnvironment -Region $queryRegion
        Assert-AwsQueryZero "active INF-011 instances in $queryRegion" @(
            "ec2", "describe-instances", "--region", $queryRegion,
            "--filters", $projectTag, $milestoneTag, $activeStates,
            "--query", "length(Reservations[].Instances[])", "--output", "text"
        )

        Assert-AwsQueryZero "retained INF-011 volumes in $queryRegion" @(
            "ec2", "describe-volumes", "--region", $queryRegion,
            "--filters", $projectTag, $milestoneTag, $volumeStates,
            "--query", "length(Volumes[])", "--output", "text"
        )

        Assert-AwsQueryZero "INF-011 VPCs in $queryRegion" @(
            "ec2", "describe-vpcs", "--region", $queryRegion, "--filters", $projectTag, $milestoneTag,
            "--query", "length(Vpcs[])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 subnets in $queryRegion" @(
            "ec2", "describe-subnets", "--region", $queryRegion, "--filters", $projectTag, $milestoneTag,
            "--query", "length(Subnets[])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 security groups in $queryRegion" @(
            "ec2", "describe-security-groups", "--region", $queryRegion, "--filters", $projectTag, $milestoneTag,
            "--query", "length(SecurityGroups[])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 route tables in $queryRegion" @(
            "ec2", "describe-route-tables", "--region", $queryRegion, "--filters", $projectTag, $milestoneTag,
            "--query", "length(RouteTables[])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 internet gateways in $queryRegion" @(
            "ec2", "describe-internet-gateways", "--region", $queryRegion, "--filters", $projectTag, $milestoneTag,
            "--query", "length(InternetGateways[])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 IAM roles in $queryRegion" @(
            "iam", "list-roles", "--region", $queryRegion,
            "--query", "length(Roles[?starts_with(RoleName, 'inf011-pilot-')])", "--output", "text"
        )
        Assert-AwsQueryZero "INF-011 IAM instance profiles in $queryRegion" @(
            "iam", "list-instance-profiles", "--region", $queryRegion,
            "--query", "length(InstanceProfiles[?starts_with(InstanceProfileName, 'inf011-pilot-')])", "--output", "text"
        )
    }
}

function Confirm-PaidApply {
    if (-not $ConfirmPaidResources) {
        throw "Apply requires -ConfirmPaidResources."
    }
    if ($ConfirmationText -cne "CREATE INF-011 PAID GPU") {
        throw 'Apply requires -ConfirmationText "CREATE INF-011 PAID GPU".'
    }
}

Push-Location $stackPath
try {
    Assert-TerraformVersion

    switch ($Action) {
        "Validate" {
            Set-OfflineAwsEnvironment
            Initialize-Stack
            $region = Get-TerraformAwsRegion
            Set-OfflineAwsEnvironment -Region $region
            Invoke-Checked "Terraform formatting" {
                & $terraform fmt -check -recursive
            }
            Invoke-Checked "Terraform static validation" {
                & $terraform validate
            }
            Invoke-Checked "Terraform offline gate tests" {
                & $terraform test
            }
        }
        "PlanOffline" {
            Set-OfflineAwsEnvironment
            Initialize-Stack
            $region = Get-TerraformAwsRegion
            Set-OfflineAwsEnvironment -Region $region
            Invoke-Checked "Zero-resource offline plan" {
                & $terraform plan -input=false -refresh=false -lock=false
            }
        }
        "PlanPaid" {
            $paidArguments = Get-PaidArguments
            Initialize-Stack
            Assert-CurrentTerraformStateEmpty
            $fitnessDirectory = Join-Path $projectRoot ".cache\stage-c-fitness"
            New-Item -ItemType Directory -Force -Path $fitnessDirectory | Out-Null
            # console prints multiline strings as heredocs; jsonencode makes the output parseable.
            $rendered = 'jsonencode(templatefile("user-data.sh.tftpl", {max_session_hours=' + $MaxSessionHours + '}))' | & $terraform console
            if ($LASTEXITCODE -ne 0) { throw "Stage C launcher rendering failed." }
            $renderedPath = Join-Path $fitnessDirectory "rendered.json"
            [IO.File]::WriteAllText($renderedPath, ($rendered -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
            Invoke-Checked "Stage C pre-plan prerequisite fitness (rendered launcher and staged providers)" {
                $sessionInputs = Get-Content -LiteralPath (Join-Path $projectRoot "docs\INF011_STAGE_C_SESSION_INPUTS.json") -Raw -Encoding UTF8 | ConvertFrom-Json
                $stagedSources = Join-Path $projectRoot $sessionInputs.staging.payload_directory
                & uv run --project (Join-Path $projectRoot "python") --locked python -m inference_platform.stage_c_fitness --rendered-json $renderedPath --inputs (Join-Path $projectRoot "docs\INF011_STAGE_C_SESSION_INPUTS.json") --root $projectRoot --payload-root $stagedSources --output (Join-Path $fitnessDirectory "fitness.json")
            }
            Invoke-Checked "Stage C pre-plan KV pressure and corpus sizing" {
                & uv run --project (Join-Path $projectRoot "python") --locked python -m inference_platform.stage_c_sizing --rendered-json $renderedPath --inputs (Join-Path $projectRoot "docs\INF011_STAGE_C_SESSION_INPUTS.json") --output (Join-Path $fitnessDirectory "sizing.json")
            }
            $region = Get-TerraformAwsRegion
            Set-AwsRegionEnvironment -Region $region
            Assert-AwsIdentity -Region $region
            Assert-PilotQuota -Region $region
            Assert-AmiInRegion -Region $region -ImageId $AmiId
            Invoke-TerraformWithEvidence -Operation plan -Command {
                $planArguments = @("-input=false", "-no-color", "-out=inf011-paid.tfplan") + $paidArguments
                & $terraform plan @planArguments
            }
            $metadata = Write-PaidPlanMetadata -ExpectedRegion $region
            Write-Output "Paid plan SHA-256: $($metadata.plan_sha256); Terraform aws_region: $($metadata.aws_region)."
        }
        "Apply" {
            Confirm-PaidApply
            $metadata = Get-PaidPlanMetadata
            # Always rerun in this shell. Old receipts cannot authorize Apply.
            Invoke-StageCPreflight -Repo $projectRoot -PlanHash $metadata.plan_sha256
            Initialize-Stack
            $configuredRegion = Get-TerraformAwsRegion
            Assert-RegionMatchesPlan -ConfiguredRegion $configuredRegion -PlanRegion $metadata.aws_region
            Set-AwsRegionEnvironment -Region $metadata.aws_region
            Assert-AwsIdentity -Region $metadata.aws_region
            Assert-PilotQuota -Region $metadata.aws_region
            Assert-AmiInRegion -Region $metadata.aws_region -ImageId $metadata.ami_id
            Assert-PaidPlanReview
            # Read-only initialization/AWS checks may take time: revalidate at
            # the mutation boundary too, before creating the apply child.
            Invoke-StageCPreflight -Repo $projectRoot -PlanHash $metadata.plan_sha256
            Invoke-TerraformWithEvidence -Operation apply -Command {
                & uv run --project (Join-Path $projectRoot "python") --locked python -B -m inference_platform.terraform_apply_watchdog --receipt (Join-Path $script:OperationEvidenceDirectory "terraform-apply-watchdog.json") -- $terraform apply -input=false -no-color inf011-paid.tfplan
            }
        }
        "Destroy" {
            if ($ConfirmationText -cne "DESTROY INF-011 PILOT") {
                throw 'Destroy requires -ConfirmationText "DESTROY INF-011 PILOT".'
            }
            $metadata = Get-PaidPlanMetadata
            Initialize-Stack
            Warn-ConfiguredRegionDiffersFromPlan -PlanRegion $metadata.aws_region
            Set-AwsRegionEnvironment -Region $metadata.aws_region
            Assert-AwsIdentity -Region $metadata.aws_region
            Invoke-TerraformWithEvidence -Operation destroy -Command {
                & $terraform destroy -input=false -no-color -auto-approve -var "aws_region=$($metadata.aws_region)" -var=offline_validation=false
            }
            Invoke-Checked "Verify teardown after destroy" {
                & $PowerShellExecutable -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Action VerifyTeardown
            }
        }
        "VerifyTeardown" {
            $metadata = Get-PaidPlanMetadata
            Initialize-Stack
            Warn-ConfiguredRegionDiffersFromPlan -PlanRegion $metadata.aws_region
            Set-AwsRegionEnvironment -Region $metadata.aws_region
            Assert-AwsIdentity -Region $metadata.aws_region
            Assert-CurrentTerraformStateEmpty
            Invoke-TeardownAwsQueries -Region $metadata.aws_region

            Write-Output "Teardown verified: Terraform state is empty and every pilot resource class is empty in $($script:ApprovedTeardownRegions -join ', ')."
        }
        "CapacityDryRun" {
            # This isolated seam never initializes Terraform or invokes AWS/Apply.
            Invoke-TerraformWithEvidence -Operation apply -Command {
                & $PowerShellExecutable -NoProfile -Command "[Console]::Out.WriteLine('mock supporting resources created'); [Console]::Error.WriteLine('Error: creating EC2 Instance: InsufficientInstanceCapacity'); exit 1"
            }
        }
        "CapacityTimeoutDryRun" {
            # The production watchdog with a shortened mock deadline, no AWS.
            Invoke-TerraformWithEvidence -Operation apply -Command {
                & uv run --project (Join-Path $projectRoot "python") --locked python -B -m inference_platform.terraform_apply_watchdog --seconds 1 --grace 1 --receipt (Join-Path $script:OperationEvidenceDirectory "terraform-apply-watchdog.json") -- $PowerShellExecutable -NoProfile -Command "while (`$true) { [Console]::Error.WriteLine('InsufficientInstanceCapacity'); Start-Sleep -Milliseconds 100 }"
            }
        }
        "PreflightDryRun" {
            if ([string]::IsNullOrWhiteSpace($PreflightRepo) -or [string]::IsNullOrWhiteSpace($PreflightPlanHash)) {
                throw "PreflightDryRun requires mock repo and plan hash; no AWS/Apply."
            }
            Invoke-StageCPreflight -Repo $PreflightRepo -PlanHash $PreflightPlanHash -BindingRehearsalTarget $PreflightBindingTarget
            Write-Output "Apply preflight seam passed; no AWS/Apply."
        }
        "RegionDryRun" {
            if ([string]::IsNullOrWhiteSpace($PlanRegion)) {
                throw "RegionDryRun requires -PlanRegion to represent saved plan metadata."
            }
            if ([string]::IsNullOrWhiteSpace($env:INF011_REGION_DRY_RUN_LOG)) {
                throw "RegionDryRun requires INF011_REGION_DRY_RUN_LOG to record mock AWS calls."
            }
            if ([string]::IsNullOrWhiteSpace($AmiId)) {
                $AmiId = "ami-0123456789abcdef0"
            }
            Set-OfflineAwsEnvironment
            Initialize-Stack
            $configuredRegion = Get-TerraformAwsRegion
            if ($MockOperation -in @("PlanPaid", "Apply")) {
                Assert-RegionMatchesPlan -ConfiguredRegion $configuredRegion -PlanRegion $PlanRegion
            }
            else {
                Warn-ConfiguredRegionDiffersFromPlan -PlanRegion $PlanRegion
            }
            $region = $PlanRegion
            Set-OfflineAwsEnvironment -Region $region
            Assert-EmptyTerraformState -Entries $MockTerraformStateEntries
            $script:AwsDryRun = $true
            $script:AwsDryRunLogPath = $env:INF011_REGION_DRY_RUN_LOG
            Assert-AwsIdentity -Region $region
            Assert-PilotQuota -Region $region
            Assert-AmiInRegion -Region $region -ImageId $AmiId
            Invoke-TeardownAwsQueries -Region $region
            Write-Output "Region mock passed for ${MockOperation}: configured Terraform aws_region '$configuredRegion'; hash-bound plan metadata uses $region; teardown checks $($script:ApprovedTeardownRegions -join ', ')."
        }
    }
}
finally {
    Pop-Location
}
