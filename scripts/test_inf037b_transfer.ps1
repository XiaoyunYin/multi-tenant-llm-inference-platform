param([switch]$TransferOnly)

$ErrorActionPreference = 'Stop'

$sourceRepoPath = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$suffix = [guid]::NewGuid().ToString('N').Substring(0, 12)
$preferredScratchRoot = 'D:\coding agent files\multi-tenant-llm-inference-platform\codex'
$scratchRoot = if (Test-Path -LiteralPath $preferredScratchRoot -PathType Container) {
    $preferredScratchRoot
} else {
    Join-Path $sourceRepoPath '.cache'
}
New-Item -ItemType Directory -Path $scratchRoot -Force | Out-Null
$checkoutPath = Join-Path $scratchRoot "inf037b-test-checkout-$suffix"
$repoPath = $checkoutPath
$network = "inf037b-transfer-$suffix"
$minioName = "inf037b-minio-$suffix"
$runnerName = "inf037b-transfer-runner-$suffix"
$minioVolume = "inf037b-minio-data-$suffix"
$recoveryVolume = "inf037b-transfer-recovery-$suffix"
$minioImage = 'ghcr.io/coollabsio/minio@sha256:69b55a1c1c5dc285ce04db96689f5b2102317fc77a50680a1874ca6efd1c87f9'
$pythonImage = 'python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d'
$accessKey = 'transfer-test-access'
$secretKey = 'transfer-test-secret-123456'
function Invoke-TransferRunner([string]$phase, [string[]]$testNames) {
    $arguments = @(
        'run', '--network', $network,
        '--name', $runnerName,
        '--memory', '4096m', '--memory-swap', '4096m', '--cpus', '2', '--pids-limit', '128',
        '--mount', "type=bind,source=$repoPath,target=/repo,readonly",
        '--mount', "type=volume,source=$recoveryVolume,target=/recovery",
        '--env', 'S3_ENDPOINT_URL=http://row5-minio:9000',
        '--env', 'MINIO_TEST_ENDPOINT=http://row5-minio:9000',
        '--env', 'S3_TEST_BUCKET=inf037b-transfer-tests',
        '--env', "AWS_ACCESS_KEY_ID=$accessKey",
        '--env', "AWS_SECRET_ACCESS_KEY=$secretKey",
        '--env', "MINIO_TEST_ACCESS_KEY=$accessKey",
        '--env', "MINIO_TEST_SECRET_KEY=$secretKey",
        '--env', 'AWS_DEFAULT_REGION=us-east-1',
        '--env', "TRANSFER_RESTART_PHASE=$phase",
        '--env', 'RECOVERY_ROOT=/recovery',
        '--workdir', '/repo',
        $pythonImage, 'python', '/repo/scripts/run_inf037b_transfer_runner.py'
    )
    $arguments += $testNames
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $runnerOutput = & docker @arguments 2>&1
    $runnerExit = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorAction
    $runnerOutput | ForEach-Object { Write-Output $_ }
    try { & docker rm $runnerName 2>&1 | Out-Null } catch { }
    if ($runnerExit -ne 0) {
        throw "Pinned Linux transfer runner failed in phase '$phase' with exit $runnerExit."
    }
}

try {
    & git clone --no-hardlinks $sourceRepoPath $checkoutPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the clean pinned-test checkout.' }
    & docker network create $network
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated test network.' }
    & docker volume create $minioVolume
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the disposable MinIO volume.' }
    & docker volume create $recoveryVolume
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the disposable recovery volume.' }
    & docker run --detach --name $minioName --network $network --network-alias row5-minio `
        --env "MINIO_ROOT_USER=$accessKey" --env "MINIO_ROOT_PASSWORD=$secretKey" `
        --mount "type=volume,source=$minioVolume,target=/data" `
        $minioImage server /data --console-address ':9001'
    if ($LASTEXITCODE -ne 0) { throw 'Could not start digest-pinned MinIO.' }

    Invoke-TransferRunner 'before' @('-m', 'unittest', '-v', 'test_inf037b_transfer')
    if (-not $TransferOnly) {
        Invoke-TransferRunner 'affected-modules' @(
            '-m', 'unittest', '-v',
            'test_inf037b_command',
            'test_inf037b_engine',
            'test_inf037b_fitness',
            'test_inf037b_maximum',
            'test_inf037b_observations',
            'test_inf037b_preparation',
            'test_inf037b_preparation_adapter',
            'test_inf037b_setup',
            'test_inf037b_export_runtime',
            'test_inf037b_gate_a',
            'test_inf037b_gate_a_spool',
            'test_inf037b_gate_a_socket',
            'test_package_a_gate_a_host',
            'test_package_a_gate_a_operator',
            'test_package_a_sealed',
            'test_build_inf037b_gate_a_fixture',
            'test_package_a_cloud'
        )
    }
    & docker restart $minioName
    if ($LASTEXITCODE -ne 0) { throw 'MinIO container restart failed.' }
    Invoke-TransferRunner 'after' @('-m', 'unittest', '-v', 'test_inf037b_transfer.MinioRestartReadTests')
}
finally {
    foreach ($resource in @($runnerName, $minioName)) {
        try { & docker rm --force --volumes $resource 2>&1 | Out-Null } catch { }
    }
    foreach ($resource in @($recoveryVolume, $minioVolume)) {
        try { & docker volume rm $resource 2>&1 | Out-Null } catch { }
    }
    try { & docker network rm $network 2>&1 | Out-Null } catch { }
    $resolvedScratchRoot = [IO.Path]::GetFullPath($scratchRoot).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $resolvedCheckout = [IO.Path]::GetFullPath($checkoutPath)
    if ($resolvedCheckout.StartsWith($resolvedScratchRoot, [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $resolvedCheckout -Recurse -Force -ErrorAction SilentlyContinue
    }
}
