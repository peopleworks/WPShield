@echo off
REM ==========================================================================
REM  WPShield - build the release to carry to the server.
REM
REM  Produces a self-contained win-x64 build of BOTH executables - the gateway
REM  (the service) and wpshield.exe (the operator tool) - in one directory
REM  under artifacts\, plus a .zip and its .sha256.
REM
REM  This is the thin house-style wrapper. The work is done by 'wpshield
REM  publish', so the packaging rules live in the tool and are tested: it
REM  refuses to ship appsettings.Local.json, checks the binary version, and
REM  asserts the two executables share one runtime rather than doubling it.
REM
REM  Run this on a BUILD MACHINE with the .NET SDK. Never on the server - a web
REM  server has no SDK and should not get one.
REM
REM  Pass-through options (optional):
REM    publish.cmd --output D:\drops      put the artifact somewhere else
REM    publish.cmd --skip-archive         directory only, no .zip
REM ==========================================================================

setlocal
cd /d "%~dp0"

echo Building WPShield release (self-contained win-x64, gateway + CLI)...
echo.

dotnet run -c Release --project "src\WPShield.Cli\WPShield.Cli.csproj" -- publish %*
set EXITCODE=%ERRORLEVEL%

echo.
if %EXITCODE% NEQ 0 (
    echo Publish FAILED with exit code %EXITCODE%. Nothing was produced.
) else (
    echo Publish complete. The artifact and its .sha256 are under artifacts\.
    echo Copy it across, verify the SHA-256, then run 'wpshield preflight' on the server.
)

pause
exit /b %EXITCODE%
