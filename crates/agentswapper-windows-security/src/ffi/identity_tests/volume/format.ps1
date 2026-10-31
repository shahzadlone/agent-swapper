# Private test implementation, embedded in the Rust fixture. Input is produced
# only by a live OwnedDisk that exclusively created this image in this process.
# This is not a command-line tool for selecting or formatting existing disks.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
foreach ($pair in @(
    @('GITHUB_ACTIONS', 'true'),
    @('RUNNER_ENVIRONMENT', 'github-hosted'),
    @('RUNNER_OS', 'Windows'),
    @('GITHUB_REPOSITORY', 'shahzadlone/agent-swapper'),
    @('ASWP_CI_IDENTITY_FIXTURE', '1'),
    @('ASWP_CI_VOLUME_FIXTURE', '1'),
    @('ASWP_CI_FORMAT_OWNED_VOLUME', '1')
)) {
    if ([Environment]::GetEnvironmentVariable($pair[0]) -cne $pair[1]) {
        throw 'Owned-volume fixture opt-in missing'
    }
}
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ($request.image -notmatch '^[A-Za-z]:\\.+\\new-empty\.vhd$' -or
    $request.physical -notmatch '^\\\\\.\\PhysicalDrive[0-9]+$') {
    throw 'Unexpected owned image/device spelling'
}
$expectedNumber = [uint32]$request.physical.Substring(17)
$expectedSize = [uint64](64 * 1024 * 1024)

function Get-OwnedDisk {
    $images = @(Get-DiskImage -ImagePath $request.image -ErrorAction Stop)
    if ($images.Count -ne 1 -or !$images[0].Attached -or
        $images[0].DevicePath -ine $request.physical) {
        throw 'Owned image attachment identity changed'
    }
    $disks = @($images[0] | Get-Disk -ErrorAction Stop)
    if ($disks.Count -ne 1) { throw 'Ambiguous image-to-disk association' }
    $disk = $disks[0]
    if ($disk.Number -ne $expectedNumber -or $disk.Size -ne $expectedSize -or
        [uint16]$disk.BusType -ne 15 -or $disk.IsBoot -or
        $disk.IsSystem -or $disk.IsClustered -or $disk.IsOffline -or $disk.IsReadOnly) {
        throw 'Owned disk failed type/size/system-state checks'
    }
    return $disk
}

$disk = Get-OwnedDisk
if ($disk.PartitionStyle -ne 'RAW' -or $disk.NumberOfPartitions -ne 0) {
    throw 'Owned disk is not new and empty'
}
$identity = $disk.ObjectId
Initialize-Disk -InputObject $disk -PartitionStyle GPT -Confirm:$false -ErrorAction Stop
$disk = Get-OwnedDisk
if ($disk.ObjectId -cne $identity -or $disk.PartitionStyle -ne 'GPT') {
    throw 'Disk identity changed during initialization'
}
$partitions = @(New-Partition -InputObject $disk -UseMaximumSize -ErrorAction Stop)
if ($partitions.Count -ne 1) { throw 'Unexpected new partition count' }
$partition = $partitions[0]
if ($partition.DiskNumber -ne $expectedNumber -or $partition.IsBoot -or
    $partition.IsSystem -or $partition.Size -le 0 -or $partition.Size -gt $expectedSize) {
    throw 'Unexpected owned partition'
}
# Recheck both associations immediately before the only formatting operation.
$disk = Get-OwnedDisk
$associated = @($partition | Get-Disk -ErrorAction Stop)
if ($disk.ObjectId -cne $identity -or $associated.Count -ne 1 -or
    $associated[0].ObjectId -cne $identity) {
    throw 'Partition is not on the retained owned disk'
}
$volumes = @(Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel 'aswp-fixture' -Confirm:$false -ErrorAction Stop)
if ($volumes.Count -ne 1) { throw 'Unexpected formatted volume count' }
$disk = Get-OwnedDisk
$verified = @(Get-Volume -Partition $partition -ErrorAction Stop)
if ($disk.ObjectId -cne $identity -or $verified.Count -ne 1 -or
    $verified[0].ObjectId -cne $volumes[0].ObjectId -or
    $verified[0].FileSystemType -ne 'NTFS' -or
    $verified[0].Path -notmatch '^\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\$') {
    throw 'Formatted volume identity/type failed verification'
}
[Console]::Out.Write($verified[0].Path)
