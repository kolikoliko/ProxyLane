[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repositoryRoot 'src\ProxyLaneMitm'
$output = Join-Path $repositoryRoot 'bin'
New-Item -ItemType Directory -Path $output -Force | Out-Null
foreach ($arch in @(@('i686-pc-windows-msvc', '32'), @('x86_64-pc-windows-msvc', '64'))) {
    & rustup target add $arch[0]
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & cargo build --manifest-path (Join-Path $project 'Cargo.toml') --release --locked --target $arch[0]
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $release = Join-Path $project ('target\' + $arch[0] + '\release')
    Copy-Item -LiteralPath (Join-Path $release 'proxylane_mitm.dll') -Destination (Join-Path $output ('ProxyLaneMitm' + $arch[1] + '.dll')) -Force
    Copy-Item -LiteralPath (Join-Path $release 'proxylane-mitm-ca.exe') -Destination (Join-Path $output ('ProxyLaneMitm' + $arch[1] + '.exe')) -Force
}
