@echo off
echo Building Advanced Nmap Rust Demo...
echo.

echo Installing required dependencies...
cargo add tokio --features full
cargo add futures
cargo add chrono

echo.
echo Compiling advanced demo...
rustc advanced_demo.rs --extern tokio --extern futures --extern chrono -o nmap-advanced.exe

if %errorlevel% == 0 (
    echo Build successful!
    echo.
    echo === Testing Advanced Scanner ===
    echo.
    echo Testing localhost scan:
    nmap-advanced.exe -sT -v -p22,80,135,443,3389 127.0.0.1
    echo.
    echo Testing external host (if available):
    nmap-advanced.exe -sT -p80,443 google.com
) else (
    echo Build failed! 
    echo Note: This demo requires tokio, futures, and chrono crates
    echo Try: cargo new temp_project && cd temp_project
    echo Then copy advanced_demo.rs and run: cargo run
)