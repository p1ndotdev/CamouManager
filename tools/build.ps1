$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $VsWhere)) { throw 'Install Visual Studio Build Tools with Desktop development with C++ and Windows SDK.' }
$VisualStudio = & $VsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$VisualStudio) { throw 'The MSVC x64 C++ toolchain is missing.' }
$VcVars = Join-Path $VisualStudio 'VC\Auxiliary\Build\vcvars64.bat'
Push-Location $Root
try {
    $Version = (Get-Content 'src-tauri\tauri.conf.json' -Raw | ConvertFrom-Json).version
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency sync failed.' }
    & cmd.exe /d /c "`"$VcVars`" && npm.cmd run desktop:build"
    if ($LASTEXITCODE -ne 0) { throw 'Tauri build failed.' }
    $Installer = Get-Item "src-tauri\target\release\bundle\nsis\CamouManager_${Version}_x64-setup.exe"
    $Setup = Join-Path $Root "dist\CamouManager-Setup-$Version.exe"
    Copy-Item $Installer.FullName $Setup -Force
    $Portable = Join-Path $Root 'dist\CamouManager'
    if (Test-Path $Portable) { Remove-Item $Portable -Recurse -Force }
    New-Item -ItemType Directory -Force $Portable | Out-Null
    Copy-Item @(
        'src-tauri\target\release\CamouManager.exe',
        'LICENSE',
        'src-tauri\data\NOTICE',
        'src-tauri\data\LICENSE-CAMOUFOX',
        'src-tauri\data\LICENSE-FPGEN'
    ) $Portable -Force
    Write-Output "Installer: $Setup"
    Write-Output "Portable: $Portable"
    Write-Output "SHA256: $((Get-FileHash $Setup -Algorithm SHA256).Hash)"
} finally { Pop-Location }
