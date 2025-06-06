@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM 一键运行Windows应急响应数据收集器 (增强版)
REM 优先使用Python版本，避免PowerShell依赖

echo.
echo 🛡️ Windows应急响应数据收集器 - 一键运行 (v3.0)
echo ========================================================
echo 版本: 3.0 Enhanced - 解决闪退和数据不足问题
echo 支持: Python增强版, 修复版批处理, 手动CMD指南
echo 特点: 避免PowerShell依赖，确保数据完整性
echo ========================================================
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
echo 请选择要使用的数据收集方案:
echo.
echo 1. Python增强版 (推荐) - 功能最全面，数据最丰富
echo 2. 修复版批处理 - 解决闪退问题，兼容性最佳
echo 3. 手动CMD指南 - 学习应急响应命令
echo 4. 自动选择最佳方案
echo 0. 退出
echo.

set /p choice="请输入选择 (1-4, 0退出): "

if "%choice%"=="0" goto :exit
if "%choice%"=="1" goto :python_enhanced
if "%choice%"=="2" goto :batch_fixed
if "%choice%"=="3" goto :manual_guide
if "%choice%"=="4" goto :auto_select
goto :invalid

:python_enhanced
echo.
echo 🐍 启动Python增强版数据收集器...
echo ================================================
echo 特点: 
echo - ✅ 避免PowerShell依赖
echo - ✅ 收集13大类详细信息
echo - ✅ 自动标记可疑活动
echo - ✅ 生成标准化报告
echo ================================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo ✅ 检测到Python环境
    python --version
    echo.
    
    if exist "windows_emergency_enhanced.py" (
        echo 📦 检查并安装Python依赖...
        pip install psutil >nul 2>&1
        if %errorlevel% equ 0 (
            echo ✅ 依赖安装成功
        ) else (
            echo ⚠️ 依赖安装失败，但脚本仍可运行 (功能可能受限)
        )
        echo.
        
        echo 🚀 开始数据收集...
        python windows_emergency_enhanced.py --verbose
        if %errorlevel% equ 0 (
            echo ✅ Python增强版执行成功
        ) else (
            echo ❌ Python增强版执行失败，尝试修复版批处理...
            goto :batch_fixed
        )
    ) else (
        echo ❌ 找不到Python增强版脚本文件
        goto :batch_fixed
    )
) else (
    echo ❌ 未检测到Python环境
    echo.
    echo 💡 Python安装建议:
    echo    1. 访问 https://www.python.org/downloads/
    echo    2. 下载并安装最新版本的Python
    echo    3. 安装时勾选 "Add Python to PATH"
    echo.
    echo 🔄 自动切换到修复版批处理...
    goto :batch_fixed
)
goto :complete

:batch_fixed
echo.
echo 📝 启动修复版批处理数据收集器...
echo ================================================
echo 特点:
echo - ✅ 解决闪退问题
echo - ✅ 纯CMD命令实现
echo - ✅ 兼容所有Windows版本
echo - ✅ 收集12大类安全信息
echo ================================================
echo.

if exist "windows_emergency_fixed.bat" (
    echo 🚀 开始数据收集...
    call windows_emergency_fixed.bat
    if %errorlevel% equ 0 (
        echo ✅ 修复版批处理执行成功
    ) else (
        echo ❌ 修复版批处理执行失败
        echo 💡 建议查看手动CMD指南进行人工检查
    )
) else (
    echo ❌ 找不到修复版批处理脚本文件
    echo 💡 建议查看手动CMD指南进行人工检查
)
goto :complete

:manual_guide
echo.
echo 📖 打开手动CMD指南...
echo ================================================
echo 内容包括:
echo - 🚀 5分钟快速检查命令
echo - 🔍 30分钟详细检查流程
echo - 🛡️ Windows Defender检查
echo - 📊 补丁和更新检查
echo - 🚨 应急响应检查清单
echo ================================================
echo.

if exist "CMD_MANUAL_GUIDE.md" (
    echo 📋 手动检查指南已准备就绪
    echo.
    echo 💡 快速检查命令示例:
    echo.
    echo 1. 检查用户账户:
    echo    net localgroup administrators
    echo.
    echo 2. 检查可疑进程:
    echo    tasklist ^| findstr /i "powershell cmd wscript"
    echo.
    echo 3. 检查网络连接:
    echo    netstat -ano ^| findstr "ESTABLISHED"
    echo.
    echo 4. 检查启动项:
    echo    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    echo.
    
    set /p open_guide="是否要打开完整的CMD手动指南? (y/n): "
    if /i "!open_guide!"=="y" (
        if exist "notepad.exe" (
            notepad "CMD_MANUAL_GUIDE.md"
        ) else (
            type "CMD_MANUAL_GUIDE.md"
        )
    )
) else (
    echo ❌ 找不到手动CMD指南文件
)
goto :complete

:auto_select
echo.
echo 🤖 自动选择最佳数据收集方案...
echo ================================================
echo 检查顺序: Python增强版 → 修复版批处理 → 手动指南
echo ================================================
echo.

echo 🔍 检查Python环境...
python --version >nul 2>&1
if %errorlevel% equ 0 (
    if exist "windows_emergency_enhanced.py" (
        echo ✅ 选择Python增强版 (最佳选择)
        goto :python_enhanced
    )
)

echo 🔍 检查修复版批处理...
if exist "windows_emergency_fixed.bat" (
    echo ✅ 选择修复版批处理
    goto :batch_fixed
)

echo 🔍 检查手动指南...
if exist "CMD_MANUAL_GUIDE.md" (
    echo ✅ 提供手动CMD指南
    goto :manual_guide
)

echo ❌ 未找到任何可用的数据收集方案
echo 💡 请确保脚本文件完整
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
    echo    1. 将报告文件上传到 /viewer 界面进行自动分析
    echo    2. 查看报告中的 ⚠️ 标记项目
    echo    3. 根据告警级别制定处置方案
    echo.
    
    echo 📋 报告内容预览:
    echo ----------------------------------------
    findstr /i "⚠️" "windows_emergency_report.txt" | head -10
    echo ----------------------------------------
    echo.
    
    set /p open="是否要打开报告文件查看详情? (y/n): "
    if /i "!open!"=="y" (
        if exist "notepad.exe" (
            notepad "windows_emergency_report.txt"
        ) else (
            type "windows_emergency_report.txt" | more
        )
    )
) else (
    echo ❌ 未找到生成的报告文件
    echo    请检查脚本执行过程中是否有错误
    echo.
    echo 💡 替代方案:
    echo    1. 使用手动CMD指南进行检查
    echo    2. 检查脚本文件是否完整
    echo    3. 确认管理员权限
)

echo.
echo 💡 安全建议:
echo    - 🔄 定期进行安全检查 (建议每周一次)
echo    - 📊 对比历史报告，发现异常变化
echo    - 🚨 发现高危告警时立即隔离系统
echo    - 👥 与安全团队分享检查结果
echo    - 📚 学习应急响应最佳实践
echo.
goto :exit

:invalid
echo.
echo ❌ 无效选择，请重新运行脚本
goto :exit

:exit
echo.
echo 🛡️ 感谢使用Windows应急响应数据收集器!
echo.
echo 📞 技术支持:
echo    - 遇到问题请查看CMD手动指南
echo    - 确保以管理员权限运行
echo    - 检查Python环境和依赖
echo.
echo 🔗 相关资源:
echo    - NIST网络安全框架
echo    - SANS应急响应指南
echo    - Microsoft安全最佳实践
echo.
pause