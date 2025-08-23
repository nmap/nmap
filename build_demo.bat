@echo off
echo Building Nmap Rust Demo...
rustc demo.rs -o nmap-demo.exe
if %errorlevel% == 0 (
    echo Build successful!
    echo.
    echo Testing basic functionality:
    echo.
    echo === Help Output ===
    nmap-demo.exe
    echo.
    echo === Scan Example ===
    nmap-demo.exe -sS -v 127.0.0.1
    echo.
    echo === Running Tests ===
    rustc --test demo.rs -o demo-test.exe
    demo-test.exe
) else (
    echo Build failed!
)