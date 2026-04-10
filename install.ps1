# FMTool — One-line installer for Windows PowerShell
#
# Usage (from PowerShell):
#   irm https://raw.githubusercontent.com/404-developer-AI/FMTool/master/install.ps1 | iex
#
# What this script does:
#   1. Checks prerequisites (git, python 3.10+)
#   2. Clones the FMTool repository into a target folder
#   3. Creates a Python virtual environment
#   4. Installs requirements
#   5. Seeds config.local.py from the example
#   6. Optionally starts FMTool

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$RepoUrl     = "https://github.com/404-developer-AI/FMTool.git"
$DefaultDir  = Join-Path $HOME "FMTool"
$MinPyMajor  = 3
$MinPyMinor  = 10

function Write-Step   { param($Msg) Write-Host "==> $Msg" -ForegroundColor Cyan }
function Write-Ok     { param($Msg) Write-Host "    $Msg" -ForegroundColor Green }
function Write-Warn2  { param($Msg) Write-Host "    $Msg" -ForegroundColor Yellow }
function Write-Err2   { param($Msg) Write-Host "    $Msg" -ForegroundColor Red }

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "py -3", "python3")) {
        $parts = $candidate -split " "
        $exe = $parts[0]
        if (Test-Command $exe) {
            try {
                $extraArgs = if ($parts.Length -gt 1) { $parts[1..($parts.Length-1)] } else { @() }
                $versionOutput = & $exe @extraArgs --version 2>&1
                if ($versionOutput -match "Python\s+(\d+)\.(\d+)\.(\d+)") {
                    $major = [int]$Matches[1]
                    $minor = [int]$Matches[2]
                    if ($major -gt $MinPyMajor -or ($major -eq $MinPyMajor -and $minor -ge $MinPyMinor)) {
                        return @{ Command = $candidate; Version = "$major.$minor.$($Matches[3])" }
                    }
                }
            } catch { }
        }
    }
    return $null
}

Write-Host ""
Write-Host "  FMTool installer" -ForegroundColor White
Write-Host "  pfSense -> Sophos XGS migration tool" -ForegroundColor DarkGray
Write-Host ""

# --- 1. Prerequisites -------------------------------------------------------
Write-Step "Checking prerequisites"

if (-not (Test-Command "git")) {
    Write-Err2 "git not found. Install Git for Windows: https://git-scm.com/download/win"
    throw "git is required but was not found in PATH"
}
Write-Ok "git found"

$py = Get-PythonCommand
if (-not $py) {
    Write-Err2 "Python $MinPyMajor.$MinPyMinor+ not found. Install from https://www.python.org/downloads/windows/"
    Write-Err2 "Make sure to tick 'Add Python to PATH' during installation."
    throw "Python $MinPyMajor.$MinPyMinor+ is required but was not found"
}
Write-Ok "Python $($py.Version) found ($($py.Command))"

# --- 2. Target directory ----------------------------------------------------
Write-Step "Choose install location"
$targetDir = Read-Host "Install path [$DefaultDir]"
if ([string]::IsNullOrWhiteSpace($targetDir)) { $targetDir = $DefaultDir }
$targetDir = [System.IO.Path]::GetFullPath($targetDir)

if (Test-Path $targetDir) {
    if (Test-Path (Join-Path $targetDir ".git")) {
        Write-Warn2 "Existing FMTool checkout found at $targetDir"
        $answer = Read-Host "Pull latest changes? [Y/n]"
        if ($answer -eq "" -or $answer -match "^[yY]") {
            Push-Location $targetDir
            try { git pull --ff-only } finally { Pop-Location }
        }
    } else {
        Write-Err2 "Directory exists and is not an FMTool checkout: $targetDir"
        throw "Target directory already exists and is not an FMTool checkout"
    }
} else {
    Write-Step "Cloning repository"
    git clone $RepoUrl $targetDir
    Write-Ok "Cloned to $targetDir"
}

Set-Location $targetDir

# --- 3. Virtual environment -------------------------------------------------
Write-Step "Creating virtual environment"
if (-not (Test-Path "venv")) {
    $pyParts = $py.Command -split " "
    $pyExtra = if ($pyParts.Length -gt 1) { $pyParts[1..($pyParts.Length-1)] } else { @() }
    & $pyParts[0] @pyExtra -m venv venv
    Write-Ok "venv created"
} else {
    Write-Ok "venv already present"
}

$venvPython = Join-Path $targetDir "venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    Write-Err2 "venv python not found at $venvPython"
    throw "virtualenv creation failed"
}

# --- 4. Install dependencies ------------------------------------------------
Write-Step "Installing dependencies"
& $venvPython -m pip install --upgrade pip | Out-Null
& $venvPython -m pip install -r requirements.txt
Write-Ok "Dependencies installed"

# --- 5. Seed config ---------------------------------------------------------
Write-Step "Configuring Sophos credentials"
$configFile  = Join-Path $targetDir "config.local.py"
$exampleFile = Join-Path $targetDir "config.local.example.py"

if (-not (Test-Path $configFile)) {
    if (Test-Path $exampleFile) {
        Copy-Item $exampleFile $configFile
        Write-Ok "Created config.local.py from example"
        Write-Warn2 "Edit $configFile and fill in SOPHOS_HOST, SOPHOS_USERNAME, SOPHOS_PASSWORD before first run."
    } else {
        Write-Warn2 "config.local.example.py missing — skipped config seed."
    }
} else {
    Write-Ok "config.local.py already exists — left untouched"
}

# --- 6. Done ----------------------------------------------------------------
Write-Host ""
Write-Host "  Install complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  To start FMTool later:" -ForegroundColor White
Write-Host "    cd `"$targetDir`"" -ForegroundColor DarkGray
Write-Host "    .\venv\Scripts\Activate.ps1" -ForegroundColor DarkGray
Write-Host "    python run.py" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Then open http://127.0.0.1:5000 in your browser." -ForegroundColor White
Write-Host ""

$runNow = Read-Host "Start FMTool now? [Y/n]"
if ($runNow -eq "" -or $runNow -match "^[yY]") {
    Write-Step "Starting FMTool (Ctrl+C to stop)"
    & $venvPython run.py
}
