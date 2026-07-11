#!/usr/bin/env pwsh
# Thin wrapper so day-to-day usage is `./pwnlibc.ps1 <args>` with no Go
# toolchain and no docker-compose boilerplate to remember.
#
# `build` and `run` shell out to a nested `docker run`, so they're routed to
# the build-src service (the only one with the Docker socket mounted).
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

Set-Location $PSScriptRoot
New-Item -ItemType Directory -Force -Path "libs", "workdir" | Out-Null

$service = "cli"
$profileArgs = @()
if ($Args.Length -gt 0 -and ($Args[0] -eq "build" -or $Args[0] -eq "run")) {
    $service = "build-src"
    $profileArgs = @("--profile", "build-src")
}

& docker compose @profileArgs run --rm $service @Args
exit $LASTEXITCODE
