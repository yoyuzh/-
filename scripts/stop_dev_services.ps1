$ErrorActionPreference = "Stop"

$Ports = 8000..8020
$ProcessIds = @()

$Connections = Get-NetTCPConnection -LocalPort $Ports -State Listen -ErrorAction SilentlyContinue
if ($Connections) {
    $ProcessIds += $Connections | Select-Object -ExpandProperty OwningProcess -Unique
}

$NetstatLines = netstat -ano | Select-String "LISTENING"
foreach ($Line in $NetstatLines) {
    $Text = $Line.ToString()
    if ($Text -match "^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING\s+(\d+)\s*$") {
        $Port = [int]$Matches[1]
        $ProcessId = [int]$Matches[2]
        if ($Ports -contains $Port) {
            $ProcessIds += $ProcessId
        }
    }
}

$ProcessIds = $ProcessIds | Sort-Object -Unique

if (-not $ProcessIds) {
    Write-Host "No development service is listening on ports 8000-8020."
    exit 0
}

foreach ($ProcessId in $ProcessIds) {
    $Process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($Process) {
        Write-Host "Stopping $($Process.ProcessName) (PID $ProcessId)."
        Stop-Process -Id $ProcessId -Force -ErrorAction Continue
    }
}
