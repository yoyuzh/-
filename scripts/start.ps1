param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$StrictPort
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$Arguments = @("start.py", "--host", $HostAddress, "--port", $Port)
if ($StrictPort) {
    $Arguments += "--strict-port"
}

python @Arguments
