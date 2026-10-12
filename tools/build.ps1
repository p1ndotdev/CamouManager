$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$VsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (!(Test-Path $VsWhere)) { throw 'Install Visual Studio Build Tools with Desktop development with C++ and Windows SDK.' }
$VisualStudio = & $VsWhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$VisualStudio) { throw 'The MSVC x64 C++ toolchain is missing.' }
$VcVars = Join-Path $VisualStudio 'VC\Auxiliary\Build\vcvars64.bat'
Push-Location $Root
try {
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency sync failed.' }
    & cmd.exe /d /c "`"$VcVars`" && npm.cmd run desktop:build"
    if ($LASTEXITCODE -ne 0) { throw 'Tauri build failed.' }
    $Installer = Get-Item 'src-tauri\target\release\bundle\nsis\CamouManager_1.0.0_x64-setup.exe'
    Copy-Item $Installer.FullName 'dist\CamouManager-Setup-1.0.0.exe' -Force
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
    Write-Output "Installer: $(Join-Path $Root 'dist\CamouManager-Setup-1.0.0.exe')"
    Write-Output "Portable: $Portable"
    Write-Output "SHA256: $((Get-FileHash 'dist\CamouManager-Setup-1.0.0.exe' -Algorithm SHA256).Hash)"
} finally { Pop-Location }
