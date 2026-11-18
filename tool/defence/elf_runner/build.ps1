$ErrorActionPreference = 'Stop'
$toolDir = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$output = Join-Path $toolDir 'build/elf-runner'
New-Item -ItemType Directory -Path $output -Force | Out-Null
$previousOS = $env:GOOS
$previousArch = $env:GOARCH
$previousCgo = $env:CGO_ENABLED
$previousCache = $env:GOCACHE
try {
    $env:GOOS = 'linux'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'
    $env:GOCACHE = Join-Path $output 'cache'
    $source = Join-Path $PSScriptRoot 'main_linux_amd64.go'
    & go build -trimpath -buildvcs=false -ldflags '-s -w' -o (Join-Path $output 'run-hardened') $source
    if ($LASTEXITCODE -ne 0) { throw 'Linux ELF runner build failed.' }
} finally {
    $env:GOOS = $previousOS
    $env:GOARCH = $previousArch
    $env:CGO_ENABLED = $previousCgo
    $env:GOCACHE = $previousCache
}
