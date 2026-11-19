@echo off
setlocal
chcp 65001 >nul
title IP 端口测速 · 局域网模式（需要口令）
set "NO_PROXY=127.0.0.1,localhost"
set "no_proxy=127.0.0.1,localhost"

rem ── 优先用打包好的单文件 exe：不需要 runtime，也不需要装 Python ──
set "EXE=%~dp0一键测速IP.exe"
if exist "%EXE%" goto :runexe

rem ── 没有 exe 时退回 Python 脚本 ──
set "APP=%~dp0ip_tester_v4.py"

rem 优先用随包附带的嵌入式 Python
set "PY=%~dp0runtime\pythonw.exe"
if exist "%PY%" goto :run

echo   提示：未找到随包运行时 runtime\pythonw.exe，尝试使用系统 Python...
set "PY="
if exist "%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe" set "PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\pythonw.exe"
if defined PY goto :run
for /f "delims=" %%i in ('where pythonw 2^>nul') do set "PY=%%i"
if defined PY goto :run
for /f "delims=" %%i in ('where python 2^>nul') do set "PY=%%i"
if defined PY goto :run
echo.
echo   [错误] 既没有 一键测速IP.exe，也没找到 Python 3.9+。
echo   请保留完整的 runtime 文件夹，或安装 Python 并勾选 Add Python to PATH。
echo.
pause
exit /b 1

:runexe
cd /d "%~dp0"
rem 结束上次可能残留的实例
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -eq '一键测速IP.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
ping -n 2 127.0.0.1 >nul
echo   局域网访问用本机 IP 加端口 8765，口令见同目录 token.txt
start "" "%EXE%" --host 0.0.0.0 --idle-exit 10
exit /b 0

:run
cd /d "%~dp0"

rem 结束本目录残留的旧实例
set "IPT_TARGET=%APP%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -and $_.CommandLine.Contains($env:IPT_TARGET) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
ping -n 2 127.0.0.1 >nul

rem 关掉网页约 120 秒无请求后进程自动退出
start "" "%PY%" "%APP%" --host 0.0.0.0 --idle-exit 10
