@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM 一键运行Windows应急响应数据收集器
REM 支持多种脚本格式，自动选择最佳方案

echo.
echo 🛡️ Windows应急响应数据收集器 - 一键运行
echo ================================================
echo 版本: 2.0 Enhanced
echo 支持: PowerShell, Python, 批处理, VBScript
echo ================================================
echo.

REM 检查管理员权限
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ 检测到管理员权限，可获取完整系统信息
) else (
    echo ⚠️ 未检测到管理员权限，部分信息可能无法获取
    echo    建议右键选择"以管理员身份运行"
)
echo.

REM 显示菜单
echo 请选择要使用的数据收集器:
echo.
echo 1. PowerShell版本 (推荐) - 功能最全面
echo 2. Python版本 - 跨平台兼容性好
echo 3. 批处理版本 - 兼容性最佳
echo 4. VBScript版本 - 轻量级选择
echo 5. 自动选择最佳方案
echo 0. 退出
echo.

set /p choice="请输入选择 (1-5, 0退出): "

if "%choice%"=="0" goto :exit
if "%choice%"=="1" goto :powershell
if "%choice%"=="2" goto :python
if "%choice%"=="3" goto :batch
if "%choice%"=="4" goto :vbscript
if "%choice%"=="5" goto :auto
goto :invalid

:powershell
echo.
echo 🚀 启动PowerShell版本数据收集器...
echo.
if exist "windows_emergency_collector.ps1" (
    powershell -ExecutionPolicy Bypass -File "windows_emergency_collector.ps1" -Verbose
    if %errorlevel% equ 0 (
        echo ✅ PowerShell版本执行成功
    ) else (
        echo ❌ PowerShell版本执行失败，尝试其他方案...
        goto :batch
    )
) else (
    echo ❌ 找不到PowerShell脚本文件
    goto :batch
)
goto :complete

:python
echo.
echo 🐍 启动Python版本数据收集器...
echo.
REM 检查Python是否安装
python --version >nul 2>&1
if %errorlevel% equ 0 (
    if exist "windows_emergency_collector.py" (
        echo 检测到Python环境，正在安装依赖...
        pip install psutil >nul 2>&1
        python windows_emergency_collector.py --verbose
        if %errorlevel% equ 0 (
            echo ✅ Python版本执行成功
        ) else (
            echo ❌ Python版本执行失败，尝试其他方案...
            goto :batch
        )
    ) else (
        echo ❌ 找不到Python脚本文件
        goto :batch
    )
) else (
    echo ❌ 未检测到Python环境，尝试其他方案...
    goto :batch
)
goto :complete

:batch
echo.
echo 📝 启动批处理版本数据收集器...
echo.
if exist "windows_emergency_collector.bat" (
    call windows_emergency_collector.bat
    if %errorlevel% equ 0 (
        echo ✅ 批处理版本执行成功
    ) else (
        echo ❌ 批处理版本执行失败，尝试VBScript...
        goto :vbscript
    )
) else (
    echo ❌ 找不到批处理脚本文件
    goto :vbscript
)
goto :complete

:vbscript
echo.
echo 📜 启动VBScript版本数据收集器...
echo.
if exist "windows_emergency_collector.vbs" (
    cscript //nologo windows_emergency_collector.vbs
    if %errorlevel% equ 0 (
        echo ✅ VBScript版本执行成功
    ) else (
        echo ❌ VBScript版本执行失败
    )
) else (
    echo ❌ 找不到VBScript脚本文件
)
goto :complete

:auto
echo.
echo 🤖 自动选择最佳数据收集方案...
echo.

REM 优先级: PowerShell > Python > 批处理 > VBScript
echo 检查PowerShell环境...
powershell -Command "Get-Host" >nul 2>&1
if %errorlevel% equ 0 (
    if exist "windows_emergency_collector.ps1" (
        echo ✅ 选择PowerShell版本 (最佳选择)
        goto :powershell
    )
)

echo 检查Python环境...
python --version >nul 2>&1
if %errorlevel% equ 0 (
    if exist "windows_emergency_collector.py" (
        echo ✅ 选择Python版本
        goto :python
    )
)

echo 检查批处理脚本...
if exist "windows_emergency_collector.bat" (
    echo ✅ 选择批处理版本
    goto :batch
)

echo 检查VBScript...
if exist "windows_emergency_collector.vbs" (
    echo ✅ 选择VBScript版本
    goto :vbscript
)

echo ❌ 未找到任何可用的数据收集脚本
goto :exit

:complete
echo.
echo ================================================================
echo 🎉 数据收集完成!
echo ================================================================
echo.

REM 检查生成的报告文件
if exist "windows_emergency_report.txt" (
    echo 📄 报告文件: windows_emergency_report.txt
    for %%A in ("windows_emergency_report.txt") do set "FILE_SIZE=%%~zA"
    set /a FILE_SIZE_KB=!FILE_SIZE!/1024
    echo 📊 文件大小: !FILE_SIZE_KB! KB
    echo.
    echo 🔍 下一步操作:
    echo    1. 将报告文件上传到 /viewer 界面进行分析
    echo    2. 或者发送给安全团队进行人工分析
    echo.
    
    set /p open="是否要打开报告文件查看? (y/n): "
    if /i "!open!"=="y" (
        notepad "windows_emergency_report.txt"
    )
) else (
    echo ❌ 未找到生成的报告文件
    echo    请检查脚本执行过程中是否有错误
)

echo.
echo 💡 提示:
echo    - 如需重新收集，请再次运行此脚本
echo    - 建议定期进行安全检查
echo    - 如发现异常，请立即联系安全团队
echo.
goto :exit

:invalid
echo.
echo ❌ 无效选择，请重新运行脚本
goto :exit

:exit
echo.
echo 感谢使用Windows应急响应数据收集器!
echo.
pause