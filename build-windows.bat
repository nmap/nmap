@echo off
REM R-Map Windows Build Script
REM Builds Windows executable (.exe) for distribution

echo.
echo ========================================
echo   R-Map Windows Build System
echo ========================================
echo.

REM Version info
set VERSION=1.0.0
set BUILD_DATE=%DATE%

echo Version: %VERSION%
echo Build Date: %BUILD_DATE%
echo.

REM Clean previous builds
echo Cleaning previous builds...
if exist dist\ rmdir /s /q dist
if exist target\release\rmap.exe del /q target\release\rmap.exe
if exist target\release\rmap-mcp-server.exe del /q target\release\rmap-mcp-server.exe
echo.

REM Build standalone R-Map binary
echo Building R-Map standalone executable...
cargo build --release --bin rmap
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build rmap
    exit /b 1
)
echo   SUCCESS: Built rmap.exe
echo.

REM Build MCP Server
echo Building R-Map MCP Server...
cargo build --release --bin rmap-mcp-server
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Failed to build rmap-mcp-server
    exit /b 1
)
echo   SUCCESS: Built rmap-mcp-server.exe
echo.

REM Create distribution directory
echo Creating distribution package...
mkdir dist\rmap-windows-%VERSION%
mkdir dist\rmap-windows-%VERSION%\bin
mkdir dist\rmap-windows-%VERSION%\docs
mkdir dist\rmap-windows-%VERSION%\examples

REM Copy binaries
copy target\release\rmap.exe dist\rmap-windows-%VERSION%\bin\
copy target\release\rmap-mcp-server.exe dist\rmap-windows-%VERSION%\bin\

REM Generate checksums
certutil -hashfile target\release\rmap.exe SHA256 > dist\rmap-windows-%VERSION%\bin\rmap.exe.sha256
certutil -hashfile target\release\rmap-mcp-server.exe SHA256 > dist\rmap-windows-%VERSION%\bin\rmap-mcp-server.exe.sha256

REM Copy documentation
copy README.md dist\rmap-windows-%VERSION%\docs\
copy LICENSE dist\rmap-windows-%VERSION%\ 2>nul || echo.

REM Create quick start batch file
echo @echo off > dist\rmap-windows-%VERSION%\rmap.bat
echo bin\rmap.exe %%* >> dist\rmap-windows-%VERSION%\rmap.bat

echo @echo off > dist\rmap-windows-%VERSION%\rmap-mcp-server.bat
echo bin\rmap-mcp-server.exe %%* >> dist\rmap-windows-%VERSION%\rmap-mcp-server.bat

REM Create README for Windows package
(
echo # R-Map for Windows v%VERSION%
echo.
echo ## Quick Start
echo.
echo 1. Extract this package to your desired location
echo 2. Run `rmap.bat` from the command line
echo 3. Example: `rmap.bat scanme.nmap.org -p 80,443`
echo.
echo ## Included Binaries
echo.
echo - **rmap.exe**: Standalone network scanner
echo - **rmap-mcp-server.exe**: MCP server for AI integration
echo.
echo ## Usage
echo.
echo ### Standalone Scanner
echo ```
echo rmap.bat ^<target^> -p ^<ports^>
echo rmap.bat example.com -p 80,443,8080
echo rmap.bat 192.168.1.0/24 --top-ports 100
echo ```
echo.
echo ### MCP Server
echo ```
echo rmap-mcp-server.bat
echo ```
echo.
echo ## System Requirements
echo.
echo - Windows 10/11 ^(64-bit^)
echo - No additional dependencies required
echo.
echo ## Support
echo.
echo - GitHub: https://github.com/Ununp3ntium115/R-map
echo - Documentation: See docs/ folder
echo.
) > dist\rmap-windows-%VERSION%\README.txt

echo.
echo Build Complete!
echo.
echo Distribution: dist\rmap-windows-%VERSION%\
dir /b dist\rmap-windows-%VERSION%
echo.
echo Binaries:
dir /b dist\rmap-windows-%VERSION%\bin
echo.

REM Create ZIP archive if 7-Zip is available
where 7z >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Creating ZIP archive...
    cd dist
    7z a -tzip rmap-windows-%VERSION%.zip rmap-windows-%VERSION%
    cd ..
    echo   Created: dist\rmap-windows-%VERSION%.zip
    echo.
) else (
    echo 7-Zip not found - skipping ZIP creation
    echo Manual: Compress dist\rmap-windows-%VERSION% to create distribution ZIP
    echo.
)

echo.
echo ========================================
echo   Build Complete!
echo ========================================
echo.
pause
