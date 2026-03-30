<#
.SYNOPSIS
Build script for the secamo-ingress Lambda Layer (Windows/PowerShell)

.DESCRIPTION
Downloads and extracts the required Python packages (temporalio, pydantic) for the
AWS Lambda Linux/ARM64 runtime directly to the layer directory, without
requiring Docker. Also copies shared runtime subpackages into the layer.

.EXAMPLE
.\build.ps1
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LayerDir = Join-Path $ScriptDir "python"
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..\..\..\..\")).Path

Write-Host "── Installing dependencies into $LayerDir ──" -ForegroundColor Cyan

# Use pip to download the Linux/ARM64 pre-built wheels directly
# without attempting to compile or install them to the local system.
pip install `
    temporalio `
    pydantic `
    PyJWT `
    --target "$LayerDir" `
    --platform manylinux2014_aarch64 `
    --implementation cp `
    --python-version 3.11 `
    --only-binary=:all: `
    --upgrade `
    --quiet

# Copy shared package into the layer so the proxy Lambda can import it
Write-Host "Copying shared package into layer..." -ForegroundColor Gray
$SharedDst = Join-Path $LayerDir "shared"
if (Test-Path $SharedDst) { Remove-Item -Recurse -Force $SharedDst }
New-Item -ItemType Directory -Path $SharedDst | Out-Null

# Keep explicit subpackage list so newly added shared modules are not missed.
$SharedSubdirs = @(
    "approval",
    "auth",
    "ingress",
    "models",
    "normalization",
    "providers",
    "routing",
    "temporal"
)

Get-ChildItem -Path (Join-Path $RepoRoot "shared") -Filter "*.py" -File |
    Copy-Item -Destination $SharedDst

foreach ($Subdir in $SharedSubdirs) {
    $Src = Join-Path $RepoRoot (Join-Path "shared" $Subdir)
    $Dst = Join-Path $SharedDst $Subdir
    if (Test-Path $Src) {
        Copy-Item -Recurse -Path $Src -Destination $Dst
    } else {
        Write-Warning "shared/$Subdir not found in repository"
    }
}

# Validate that key shared files are synced byte-for-byte from repository source.
$SyncFiles = @(
    "config.py",
    "models/canonical.py",
    "models/mappers.py",
    "routing/defaults.py",
    "routing/registry.py"
)

foreach ($RelPath in $SyncFiles) {
    $SrcFile = Join-Path (Join-Path $RepoRoot "shared") $RelPath
    $DstFile = Join-Path $SharedDst $RelPath

    if (!(Test-Path $SrcFile) -or !(Test-Path $DstFile)) {
        throw "Shared sync verification failed (missing file): $RelPath"
    }

    $SrcHash = (Get-FileHash -Path $SrcFile -Algorithm SHA256).Hash
    $DstHash = (Get-FileHash -Path $DstFile -Algorithm SHA256).Hash
    if ($SrcHash -ne $DstHash) {
        throw "Shared sync verification failed (drift detected): $RelPath"
    }
}

# Clean up unnecessary files to reduce layer size
Write-Host "Cleaning up unnecessary files..." -ForegroundColor Gray
Get-ChildItem -Path $LayerDir -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem -Path $LayerDir -Filter "*.dist-info" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem -Path $LayerDir -Filter "tests" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

Write-Host "── Layer build complete ──" -ForegroundColor Green
