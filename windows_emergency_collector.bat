@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM Windows应急响应数据收集脚本 (批处理版)
REM 版本: 2.0 Enhanced
REM 作者: Windows Emergency Response Team
REM 用途: 收集Windows系统应急响应所需的详细信息

set "REPORT_FILE=windows_emergency_report.txt"
set "START_TIME=%date% %time%"

echo.
echo 🛡️ Windows应急响应数据收集器 (批处理版)
echo ================================================
echo 版本: 2.0 Enhanced
echo 功能: 全面收集Windows系统安全信息
echo 用途: 应急响应、安全评估、威胁检测
echo ================================================
echo.
echo 📁 输出文件: %REPORT_FILE%
echo ⏰ 开始时间: %START_TIME%
echo.

REM 初始化报告文件
echo ================================================================ > "%REPORT_FILE%"
echo Windows 应急响应报告 (批处理版) >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 生成时间: %START_TIME% >> "%REPORT_FILE%"
echo 计算机名: %COMPUTERNAME% >> "%REPORT_FILE%"
echo 用户名: %USERNAME% >> "%REPORT_FILE%"
echo 域名: %USERDOMAIN% >> "%REPORT_FILE%"
echo 系统目录: %SystemRoot% >> "%REPORT_FILE%"
echo 临时目录: %TEMP% >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

REM 1. 系统基本信息
echo 📊 收集系统基本信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统基本信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统信息概览: >> "%REPORT_FILE%"
echo - 计算机名: %COMPUTERNAME% >> "%REPORT_FILE%"
echo - 用户名: %USERNAME% >> "%REPORT_FILE%"
echo - 域名: %USERDOMAIN% >> "%REPORT_FILE%"
echo - 系统目录: %SystemRoot% >> "%REPORT_FILE%"
echo - 临时目录: %TEMP% >> "%REPORT_FILE%"
echo - 当前时间: %date% %time% >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory" >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

REM 2. 用户账户信息 (重点检查)
echo 👥 收集用户账户信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 用户账户信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 本地用户账户详情: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

net user >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 管理员组成员: >> "%REPORT_FILE%"
net localgroup administrators >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 检查每个用户的详细信息
for /f "tokens=1" %%u in ('net user ^| findstr /v "命令成功完成" ^| findstr /v "User accounts for" ^| findstr /v "The command completed" ^| findstr /v "^-"') do (
    if not "%%u"=="" (
        echo 用户详情: %%u >> "%REPORT_FILE%"
        net user "%%u" >> "%REPORT_FILE%" 2>&1
        echo. >> "%REPORT_FILE%"
        
        REM 检查可疑管理员账户
        echo %%u | findstr /i "test temp hack admin guest" >nul
        if !errorlevel! equ 0 (
            echo ⚠️ 管理员: %COMPUTERNAME%\%%u [可疑账户] >> "%REPORT_FILE%"
        )
    )
)

REM 3. 进程信息 (重点检查)
echo ⚙️ 收集进程信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 进程信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 当前运行进程详情: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

tasklist /v >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑进程检查: >> "%REPORT_FILE%"
tasklist | findstr /i "powershell cmd wscript cscript" >> "%REPORT_FILE%" 2>&1
for /f "tokens=1,2" %%a in ('tasklist ^| findstr /i "powershell cmd wscript cscript"') do (
    echo ⚠️ 可疑进程: %%a ^| PID: %%b ^| 路径: 需要进一步检查 >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 4. 网络连接信息 (重点检查)
echo 🌐 收集网络连接信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 网络连接信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 活动网络连接详情: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

netstat -an >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 网络连接进程信息: >> "%REPORT_FILE%"
netstat -ano >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑网络连接检查: >> "%REPORT_FILE%"
REM 检查常见后门端口
netstat -an | findstr ":4444 :1234 :31337 :12345 :54321" >> "%REPORT_FILE%" 2>&1
for /f "tokens=2,3" %%a in ('netstat -an ^| findstr ":4444 :1234 :31337 :12345 :54321"') do (
    echo ⚠️ 可疑连接: %%a -> %%b [可疑端口] >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 5. 文件系统检查 (重点检查)
echo 📁 检查文件系统...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 文件系统检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 文件系统安全检查: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo 临时目录可疑文件检查: >> "%REPORT_FILE%"
if exist "%TEMP%" (
    echo 检查目录: %TEMP% >> "%REPORT_FILE%"
    dir "%TEMP%\*.exe" "%TEMP%\*.bat" "%TEMP%\*.cmd" "%TEMP%\*.ps1" "%TEMP%\*.vbs" "%TEMP%\*.js" /s /b 2>nul >> "%REPORT_FILE%"
    for %%f in ("%TEMP%\*.exe" "%TEMP%\*.bat" "%TEMP%\*.cmd" "%TEMP%\*.ps1" "%TEMP%\*.vbs" "%TEMP%\*.js") do (
        if exist "%%f" (
            echo ⚠️ 可疑文件: %%f >> "%REPORT_FILE%"
        )
    )
)
echo. >> "%REPORT_FILE%"

if exist "%SystemRoot%\Temp" (
    echo 检查目录: %SystemRoot%\Temp >> "%REPORT_FILE%"
    dir "%SystemRoot%\Temp\*.exe" "%SystemRoot%\Temp\*.bat" "%SystemRoot%\Temp\*.cmd" "%SystemRoot%\Temp\*.ps1" "%SystemRoot%\Temp\*.vbs" "%SystemRoot%\Temp\*.js" /s /b 2>nul >> "%REPORT_FILE%"
    for %%f in ("%SystemRoot%\Temp\*.exe" "%SystemRoot%\Temp\*.bat" "%SystemRoot%\Temp\*.cmd" "%SystemRoot%\Temp\*.ps1" "%SystemRoot%\Temp\*.vbs" "%SystemRoot%\Temp\*.js") do (
        if exist "%%f" (
            echo ⚠️ 可疑文件: %%f >> "%REPORT_FILE%"
        )
    )
)
echo. >> "%REPORT_FILE%"

REM 6. 系统服务检查
echo 🔧 检查系统服务...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统服务检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统服务状态检查: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

sc query type= service state= all >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑服务检查: >> "%REPORT_FILE%"
sc query type= service state= all | findstr /i "temp tmp test hack backdoor" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 7. 计划任务检查
echo ⏰ 检查计划任务...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 计划任务检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 计划任务列表: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

schtasks /query /fo table /v >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑计划任务检查: >> "%REPORT_FILE%"
schtasks /query /fo table /v | findstr /i "powershell cmd wscript cscript" >> "%REPORT_FILE%" 2>&1
for /f "tokens=1,2" %%a in ('schtasks /query /fo table /v ^| findstr /i "powershell cmd wscript cscript"') do (
    echo ⚠️ 可疑任务: %%a ^| 操作: %%b >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 8. Windows Defender状态
echo 🛡️ 检查Windows Defender状态...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo Windows Defender状态 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"

powershell -Command "try { Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, AntispywareEnabled, FirewallEnabled, QuickScanStartTime, AntivirusSignatureVersion | Format-List } catch { 'Windows Defender信息获取失败' }" >> "%REPORT_FILE%" 2>&1

REM 检查实时保护状态
powershell -Command "try { $status = Get-MpComputerStatus; if (-not $status.RealTimeProtectionEnabled) { '实时保护: False' } else { '实时保护: True' } } catch { '无法检查实时保护状态' }" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 9. 注册表启动项检查
echo 📋 检查注册表启动项...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 注册表启动项检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 注册表启动项: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run: >> "%REPORT_FILE%"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce: >> "%REPORT_FILE%"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑注册表项检查: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack" >> "%REPORT_FILE%" 2>&1
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 10. 系统日志摘要
echo 📊 收集系统日志摘要...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统日志摘要 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统日志摘要 (最近24小时): >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo 安全事件日志: >> "%REPORT_FILE%"
powershell -Command "try { Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 | Group-Object Id | Select-Object Name, Count | Format-Table -AutoSize } catch { '无法获取安全日志' }" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 系统事件日志: >> "%REPORT_FILE%"
powershell -Command "try { Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 | Group-Object LevelDisplayName | Select-Object Name, Count | Format-Table -AutoSize } catch { '无法获取系统日志' }" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 登录失败检查: >> "%REPORT_FILE%"
powershell -Command "try { $failures = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue; if ($failures.Count -ge 5) { '⚠️ 登录失败: 失败次数: ' + $failures.Count + ' [可能的暴力破解攻击]' } else { '登录失败次数: ' + $failures.Count } } catch { '无法检查登录失败记录' }" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 完成报告
set "END_TIME=%date% %time%"
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 报告生成完成 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 开始时间: %START_TIME% >> "%REPORT_FILE%"
echo 结束时间: %END_TIME% >> "%REPORT_FILE%"
echo 报告文件: %REPORT_FILE% >> "%REPORT_FILE%"

for %%A in ("%REPORT_FILE%") do set "FILE_SIZE=%%~zA"
set /a FILE_SIZE_KB=%FILE_SIZE%/1024
echo 文件大小: %FILE_SIZE_KB% KB >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"
echo 建议: 请将此报告文件上传到 /viewer 界面进行详细分析 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"

echo.
echo 🎉 数据收集完成!
echo 📄 报告文件: %REPORT_FILE%
echo 📊 文件大小: %FILE_SIZE_KB% KB
echo 🔍 请将报告文件上传到 /viewer 界面进行分析
echo.
pause