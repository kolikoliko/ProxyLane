[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneMitm'
$output = Join-Path $repositoryRoot 'bin'
$toolOutput = Join-Path $repositoryRoot 'build\tools'
New-Item -ItemType Directory -Path $output -Force | Out-Null
New-Item -ItemType Directory -Path $toolOutput -Force | Out-Null
$target = 'x86_64-pc-windows-msvc'
& rustup target add $target --toolchain '1.88.0-x86_64-pc-windows-msvc'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& cargo +1.88.0-x86_64-pc-windows-msvc build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $target
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$release = Join-Path $project ('target\' + $target + '\release')
Copy-Item -LiteralPath (Join-Path $release 'proxylane_mitm.dll') -Destination (Join-Path $output 'ProxyLaneMitm64.dll') -Force
Copy-Item -LiteralPath (Join-Path $release 'proxylane-mitm-ca.exe') -Destination (Join-Path $toolOutput 'ProxyLaneMitm64.exe') -Force
