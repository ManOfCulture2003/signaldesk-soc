param(
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateRange(1, 10000)][int]$MaxEvents = 200
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $OutputPath) { throw 'Output already exists; choose a new file.' }
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688,1102} -MaxEvents $MaxEvents -ErrorAction Stop)
if ($events.Count -eq 0) { throw 'No matching events found. No export was written.' }
$fullPath = [IO.Path]::GetFullPath($OutputPath)
$parentPath = [IO.Path]::GetDirectoryName($fullPath)
[IO.Directory]::CreateDirectory($parentPath) | Out-Null
$xml = '<Events>' + (($events | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
$bytes = [Text.UTF8Encoding]::new($false).GetBytes($xml)
$stream = [IO.File]::Open($fullPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
Write-Output "Exported $($events.Count) events to the local file. Keep this evidence private."
