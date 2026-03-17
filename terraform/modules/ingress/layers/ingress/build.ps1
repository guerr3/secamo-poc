<#
.SYNOPSIS
Build script for the secamo-ingress Lambda Layer (Windows/PowerShell)

.DESCRIPTION
Downloads and extracts the required Python packages (temporalio, pydantic) for the 
AWS Lambda Linux/ARM64 runtime directly to the layer directory, without 
requiring Docker. Also copies the shared models package into the layer.

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
$SharedSrc = Join-Path $RepoRoot "shared"
$SharedDst = Join-Path $LayerDir "shared"
if (Test-Path $SharedDst) { Remove-Item -Recurse -Force $SharedDst }
Copy-Item -Recurse -Path $SharedSrc -Destination $SharedDst

# Clean up unnecessary files to reduce layer size
Write-Host "Cleaning up unnecessary files..." -ForegroundColor Gray
Get-ChildItem -Path $LayerDir -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem -Path $LayerDir -Filter "*.dist-info" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Get-ChildItem -Path $LayerDir -Filter "tests" -Recurse -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

Write-Host "── Layer build complete ──" -ForegroundColor Green
