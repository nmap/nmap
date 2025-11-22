# R-Map Windows Installer (PowerShell)
# Installs R-Map standalone binary + MCP server + Web UI on Windows

#Requires -RunAsAdministrator

param(
    [switch]$SkipWebUI = $false,
    [string]$InstallPath = "$env:ProgramFiles\R-Map"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" -ForegroundColor Cyan
Write-Host "┃  R-Map Windows Installer v1.0.0        ┃" -ForegroundColor Cyan
Write-Host "┃  Rust + redb + Svelte Network Scanner  ┃" -ForegroundColor Cyan
Write-Host "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" -ForegroundColor Cyan
Write-Host ""

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor Yellow
}

# Check prerequisites
Write-Info "Checking prerequisites..."

# Check Rust
if (Get-Command cargo -ErrorAction SilentlyContinue) {
    $rustVersion = (cargo --version).Split()[1]
    Write-Success "Rust installed: $rustVersion"
    $hasRust = $true
} else {
    Write-Warning "Rust not installed"
    Write-Info "Download from: https://rustup.rs"
    $hasRust = $false
    exit 1
}

# Check Node.js
if (Get-Command node -ErrorAction SilentlyContinue) {
    $nodeVersion = node --version
    Write-Success "Node.js installed: $nodeVersion"
    $hasNode = $true
} else {
    Write-Warning "Node.js not installed - web UI will not be available"
    $hasNode = $false
}

# Build binaries
Write-Info "Building R-Map from source..."

Write-Info "Building rmap.exe..."
cargo build --release --bin rmap
if ($LASTEXITCODE -eq 0) {
    Write-Success "Built rmap.exe"
} else {
    Write-Error "Failed to build rmap.exe"
    exit 1
}

Write-Info "Building rmap-mcp-server.exe..."
cargo build --release --bin rmap-mcp-server
if ($LASTEXITCODE -eq 0) {
    Write-Success "Built rmap-mcp-server.exe"
} else {
    Write-Error "Failed to build rmap-mcp-server.exe"
    exit 1
}

# Create installation directory
Write-Info "Creating installation directory: $InstallPath"
New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallPath\bin" -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallPath\data" -ItemType Directory -Force | Out-Null
New-Item -Path "$InstallPath\config" -ItemType Directory -Force | Out-Null

# Copy binaries
Write-Info "Installing binaries..."
Copy-Item "target\release\rmap.exe" "$InstallPath\bin\"
Copy-Item "target\release\rmap-mcp-server.exe" "$InstallPath\bin\"
Write-Success "Binaries installed"

# Add to PATH
Write-Info "Adding to PATH..."
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallPath\bin*") {
    [Environment]::SetEnvironmentVariable(
        "Path",
        "$currentPath;$InstallPath\bin",
        "Machine"
    )
    Write-Success "Added to PATH (restart terminal to use)"
} else {
    Write-Info "Already in PATH"
}

# Create configuration
Write-Info "Creating configuration..."
$configContent = @"
# R-Map Configuration

[database]
path = "$($InstallPath -replace '\\', '\\')\data\scans.db"

[logging]
level = "info"

[scanner]
default_timing = "normal"
max_concurrent = 100
timeout = 300

[mcp_server]
bind = "stdio"
"@

Set-Content -Path "$InstallPath\config\config.toml" -Value $configContent
Write-Success "Configuration created"

# Install web UI
if (-not $SkipWebUI -and $hasNode) {
    Write-Info "Installing web UI..."
    Set-Location frontend-svelte
    npm install
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Web UI dependencies installed"
        npm run build
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Web UI built"
        }
    }
    Set-Location ..
} elseif ($SkipWebUI) {
    Write-Info "Skipping web UI (-SkipWebUI flag)"
} else {
    Write-Warning "Skipping web UI (Node.js not installed)"
}

# Create start scripts
Write-Info "Creating start scripts..."

# rmap.bat
@"
@echo off
"$InstallPath\bin\rmap.exe" %*
"@ | Set-Content "$InstallPath\rmap.bat"

# rmap-mcp-server.bat
@"
@echo off
set RMAP_DB_PATH=$InstallPath\data\scans.db
set RUST_LOG=info
"$InstallPath\bin\rmap-mcp-server.exe" %*
"@ | Set-Content "$InstallPath\rmap-mcp-server.bat"

# web-ui.bat (if Node.js available)
if ($hasNode -and -not $SkipWebUI) {
    @"
@echo off
cd /d "$PSScriptRoot\frontend-svelte"
npm run dev
"@ | Set-Content "$InstallPath\web-ui.bat"
}

Write-Success "Start scripts created"

# Create desktop shortcuts (optional)
Write-Info "Creating desktop shortcuts..."
$WshShell = New-Object -comObject WScript.Shell

# R-Map shortcut
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\R-Map.lnk")
$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-NoExit -Command `"cd '$InstallPath'; .\rmap.bat --help`""
$Shortcut.Description = "R-Map Network Scanner"
$Shortcut.WorkingDirectory = $InstallPath
$Shortcut.Save()

Write-Success "Desktop shortcuts created"

# Print summary
Write-Host ""
Write-Host "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓" -ForegroundColor Green
Write-Host "┃  Installation Complete! 🎉              ┃" -ForegroundColor Green
Write-Host "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛" -ForegroundColor Green
Write-Host ""

Write-Success "R-Map is now installed!"
Write-Host ""

Write-Host "📦 Installed Components:" -ForegroundColor Cyan
Write-Host "  • rmap.exe (standalone binary)"
Write-Host "  • rmap-mcp-server.exe (MCP protocol server)"
if ($hasNode -and -not $SkipWebUI) {
    Write-Host "  • Web UI (Svelte frontend)"
}
Write-Host ""

Write-Host "🚀 Quick Start:" -ForegroundColor Cyan
Write-Host "  # Standalone scanner (open new terminal)"
Write-Host "  rmap example.com -p 80,443"
Write-Host ""
Write-Host "  # Or use batch files"
Write-Host "  cd $InstallPath"
Write-Host "  .\rmap.bat example.com -p 80,443"
Write-Host ""
Write-Host "  # MCP server"
Write-Host "  .\rmap-mcp-server.bat"
Write-Host ""
if ($hasNode -and -not $SkipWebUI) {
    Write-Host "  # Web UI"
    Write-Host "  .\web-ui.bat"
    Write-Host "  # Open http://localhost:5173"
    Write-Host ""
}

Write-Host "📁 Installation Location:" -ForegroundColor Cyan
Write-Host "  $InstallPath"
Write-Host ""

Write-Host "📚 Documentation:" -ForegroundColor Cyan
Write-Host "  • GitHub: https://github.com/Ununp3ntium115/R-map"
Write-Host "  • PYRO Integration: PYRO_INTEGRATION.md"
Write-Host ""

Write-Host "⚠️  Note: Restart your terminal for PATH changes to take effect" -ForegroundColor Yellow
Write-Host ""
