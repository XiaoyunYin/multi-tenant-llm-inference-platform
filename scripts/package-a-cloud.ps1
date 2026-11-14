param(
    [ValidateSet('prepare', 'rehearse', 'apply', 'recover')][string]$Mode = 'rehearse',
    [Parameter(Mandatory = $true)][string]$Directory,
    [string]$Refresh,
    [string]$Preflight,
    [string]$Profile = 'admin-learning'
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    $taskArgs = @('run', '--project', 'python', '--locked', 'python', '-m',
        'inference_platform.package_a_operator', $Mode, '--directory', $Directory, '--profile', $Profile)
    if ($Refresh) { $taskArgs += @('--refresh', $Refresh) }
    if ($Preflight) { $taskArgs += @('--preflight', $Preflight) }
    & uv @taskArgs
    if ($LASTEXITCODE -ne 0) { throw "DEC-077 $Mode failed (exit $LASTEXITCODE)" }
}
finally { Pop-Location }
