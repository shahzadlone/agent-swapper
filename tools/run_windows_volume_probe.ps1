param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('empty', 'filesystem', 'root')]
    [string]$Kind
)

# Each fixture is a separate process: privilege and root-Job changes must not
# affect any other test. Rust enforces the corresponding hosted-runner opt-ins.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$prefix = 'ffi::identity_tests::volume::'
switch ($Kind) {
    'empty' {
        $testName = $prefix + 'owned_empty_virtual_disk_attaches_and_cleans_up_without_formatting'
        $notices = @('::notice title=Windows disposable disk ownership::')
    }
    'filesystem' {
        $testName = $prefix + 'formatted::newly_owned_ntfs_volume_has_verified_identity_and_removal'
        $notices = @('::notice title=Windows owned NTFS identity::')
    }
    'root' {
        $testName = $prefix + 'formatted::root_probe::owned_volume_root_directory_tag_behavior_has_matched_other_user_controls'
        $notices = @(
            '::notice title=Owned volume root reparse measurement::basic:',
            '::notice title=Owned volume root reparse measurement::extended:'
        )
    }
}
$cargoArguments = @(
    '+1.98.0', 'test', '--locked', '-p', 'agentswapper-windows-security',
    '--lib', $testName, '--', '--ignored', '--exact', '--test-threads=1',
    '--nocapture', '--color', 'never'
)
$report = @(& cargo @cargoArguments 2>&1 | ForEach-Object { $_.ToString() })
$code = $LASTEXITCODE
$report | Write-Output

function Fail-Fixture([string]$Reason) {
    $diagnostic = $report -join "`n"
    if ($diagnostic.Length -gt 6000) {
        $diagnostic = $diagnostic.Substring($diagnostic.Length - 6000)
    }
    $message = "$Kind fixture: $Reason`n$diagnostic"
    $message = $message.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Output "::error title=Windows owned-volume fixture::$message"
    exit 1
}

if ($code -ne 0) { Fail-Fixture "cargo exit $code" }
if (-not ($report -match '^test result: ok\. 1 passed; 0 failed;')) {
    Fail-Fixture 'exactly one passing test required'
}
foreach ($notice in $notices) {
    $matching = @($report | Where-Object { $_.Contains($notice) })
    if ($matching.Count -ne 1) { Fail-Fixture 'unique result/cleanup notice required' }
    # libtest can prefix a no-capture notice with "test NAME ... ". Re-emit
    # the known fixture notice at column zero so GitHub records the evidence.
    Write-Output $matching[0].Substring($matching[0].IndexOf($notice))
}
