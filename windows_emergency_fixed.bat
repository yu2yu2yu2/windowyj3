@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

REM Windows应急响应数据收集脚本 (修复版)
REM 版本: 3.0 Fixed
REM 解决闪退问题，增强数据收集

set "REPORT_FILE=windows_emergency_report.txt"
set "START_TIME=%date% %time%"

echo.
echo 🛡️ Windows应急响应数据收集器 (修复版 v3.0)
echo ================================================
echo 版本: 3.0 Fixed - 解决闪退问题
echo 功能: 全面收集Windows系统安全信息
echo 特点: 避免PowerShell，使用原生CMD命令
echo ================================================
echo.
echo 📁 输出文件: %REPORT_FILE%
echo ⏰ 开始时间: %START_TIME%
echo.

REM 检查管理员权限
net session >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ 检测到管理员权限，可获取完整系统信息
) else (
    echo ⚠️ 未检测到管理员权限，部分信息可能无法获取
)
echo.

REM 初始化报告文件
echo ================================================================ > "%REPORT_FILE%"
echo Windows 应急响应报告 (修复版 v3.0) >> "%REPORT_FILE%"
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

echo 详细系统信息: >> "%REPORT_FILE%"
systeminfo >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 2. 已安装补丁信息
echo 🔧 收集已安装补丁信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 已安装补丁信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统补丁列表: >> "%REPORT_FILE%"
wmic qfe list full /format:csv >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 3. 重要环境变量
echo 🌍 收集重要环境变量...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 重要环境变量 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 环境变量列表: >> "%REPORT_FILE%"
set >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 4. 用户账户信息 (重点检查)
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

echo 用户详细信息: >> "%REPORT_FILE%"
for /f "tokens=1" %%u in ('net user ^| findstr /v "命令成功完成" ^| findstr /v "User accounts for" ^| findstr /v "The command completed" ^| findstr /v "^-"') do (
    if not "%%u"=="" (
        echo. >> "%REPORT_FILE%"
        echo 用户详情: %%u >> "%REPORT_FILE%"
        net user "%%u" >> "%REPORT_FILE%" 2>&1
        
        REM 检查可疑管理员账户
        echo %%u | findstr /i "test temp hack admin guest" >nul
        if !errorlevel! equ 0 (
            echo ⚠️ 管理员: %COMPUTERNAME%\%%u [可疑账户] >> "%REPORT_FILE%"
        )
    )
)

REM 5. 进程信息 (重点检查)
echo ⚙️ 收集进程信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 进程信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 当前运行进程详情: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

tasklist /v /fo csv >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 高CPU占用进程检查: >> "%REPORT_FILE%"
wmic process get Name,ProcessId,PageFileUsage,WorkingSetSize /format:csv >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑进程检查: >> "%REPORT_FILE%"
tasklist | findstr /i "powershell cmd wscript cscript mshta rundll32" >> "%REPORT_FILE%" 2>&1
for /f "tokens=1,2" %%a in ('tasklist ^| findstr /i "powershell cmd wscript cscript mshta rundll32"') do (
    echo ⚠️ 可疑进程: %%a ^| PID: %%b >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 6. 网络连接信息 (重点检查)
echo 🌐 收集网络连接信息...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 网络连接信息 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 活动网络连接详情: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

netstat -ano >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 监听端口: >> "%REPORT_FILE%"
netstat -an | findstr "LISTENING" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 网络配置: >> "%REPORT_FILE%"
ipconfig /all >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo DNS配置: >> "%REPORT_FILE%"
nslookup >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑网络连接检查: >> "%REPORT_FILE%"
netstat -an | findstr ":4444 :1234 :31337 :12345 :54321" >> "%REPORT_FILE%" 2>&1
for /f "tokens=2,3" %%a in ('netstat -an ^| findstr ":4444 :1234 :31337 :12345 :54321"') do (
    echo ⚠️ 可疑连接: %%a -^> %%b [可疑端口] >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 7. 文件系统检查 (重点检查)
echo 📁 检查文件系统...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 文件系统检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 文件系统安全检查: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo 最近修改的系统文件: >> "%REPORT_FILE%"
forfiles /p %SystemRoot%\System32 /m *.exe /d -7 /c "cmd /c echo @path @fdate @ftime" >> "%REPORT_FILE%" 2>&1
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

echo 下载目录最近文件: >> "%REPORT_FILE%"
if exist "%USERPROFILE%\Downloads" (
    echo 检查目录: %USERPROFILE%\Downloads >> "%REPORT_FILE%"
    forfiles /p "%USERPROFILE%\Downloads" /d -7 /c "cmd /c echo @path @fdate @ftime" >> "%REPORT_FILE%" 2>&1
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

REM 8. 系统服务检查
echo 🔧 检查系统服务...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统服务检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 运行中的系统服务: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

sc query type= service state= all >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 服务详细信息: >> "%REPORT_FILE%"
wmic service get Name,DisplayName,State,StartMode,PathName /format:csv >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑服务检查: >> "%REPORT_FILE%"
sc query type= service state= all | findstr /i "temp tmp test hack backdoor malware" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

REM 9. 启动项检查
echo 🚀 检查启动项...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 启动项检查 >> "%REPORT_FILE%"
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

echo WOW6432Node启动项: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo WMIC启动项: >> "%REPORT_FILE%"
wmic startup get Caption,Command,Location /format:csv >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑启动项检查: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack backdoor malware" >> "%REPORT_FILE%" 2>&1
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack backdoor malware" >> "%REPORT_FILE%" 2>&1
for /f "tokens=*" %%a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" ^| findstr /i "temp tmp test hack backdoor malware"') do (
    echo ⚠️ 注册表项: %%a [可疑启动项] >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 10. 计划任务检查
echo ⏰ 检查计划任务...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 计划任务检查 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 活动计划任务: >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

schtasks /query /fo table /v >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 可疑计划任务检查: >> "%REPORT_FILE%"
schtasks /query /fo table /v | findstr /i "powershell cmd wscript cscript mshta" >> "%REPORT_FILE%" 2>&1
for /f "tokens=1,2" %%a in ('schtasks /query /fo table /v ^| findstr /i "powershell cmd wscript cscript mshta"') do (
    echo ⚠️ 可疑任务: %%a ^| 操作: %%b >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 11. Windows Defender状态
echo 🛡️ 检查Windows Defender状态...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo Windows Defender状态 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"

echo Windows Defender服务状态: >> "%REPORT_FILE%"
sc query WinDefend >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo Windows Defender配置: >> "%REPORT_FILE%"
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 实时保护状态检查: >> "%REPORT_FILE%"
sc query WinDefend | findstr "STATE" >> "%REPORT_FILE%" 2>&1
for /f "tokens=*" %%a in ('sc query WinDefend ^| findstr "STATE"') do (
    echo %%a | findstr "RUNNING" >nul
    if !errorlevel! equ 0 (
        echo 实时保护: True >> "%REPORT_FILE%"
    ) else (
        echo 实时保护: False >> "%REPORT_FILE%"
    )
)
echo. >> "%REPORT_FILE%"

REM 12. 最近访问的文件记录
echo 📋 检查最近访问的文件记录...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 最近访问的文件记录 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 最近文档: >> "%REPORT_FILE%"

if exist "%USERPROFILE%\Recent" (
    dir "%USERPROFILE%\Recent" /od >> "%REPORT_FILE%" 2>&1
)
echo. >> "%REPORT_FILE%"

echo 浏览器历史记录路径检查: >> "%REPORT_FILE%"
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\History" (
    echo 发现Chrome历史记录: %LOCALAPPDATA%\Google\Chrome\User Data\Default\History >> "%REPORT_FILE%"
)
if exist "%APPDATA%\Mozilla\Firefox\Profiles" (
    echo 发现Firefox配置文件: %APPDATA%\Mozilla\Firefox\Profiles >> "%REPORT_FILE%"
)
if exist "%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History" (
    echo 发现Edge历史记录: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

REM 13. 系统日志摘要
echo 📊 收集系统日志摘要...
echo. >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统日志摘要 >> "%REPORT_FILE%"
echo ================================================================ >> "%REPORT_FILE%"
echo 系统日志摘要 (最近事件): >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo 安全事件日志: >> "%REPORT_FILE%"
wevtutil qe Security /c:100 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 系统事件日志: >> "%REPORT_FILE%"
wevtutil qe System /c:50 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 应用程序事件日志: >> "%REPORT_FILE%"
wevtutil qe Application /c:50 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 登录失败记录检查: >> "%REPORT_FILE%"
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 系统错误事件: >> "%REPORT_FILE%"
wevtutil qe System /q:"*[System[Level=2]]" /c:20 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
echo. >> "%REPORT_FILE%"

echo 应用程序错误事件: >> "%REPORT_FILE%"
wevtutil qe Application /q:"*[System[Level=2]]" /c:20 /rd:true /f:text >> "%REPORT_FILE%" 2>&1
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
echo 💡 提示: 
echo    - 报告包含详细的系统安全信息
echo    - 可疑项目已用 ⚠️ 标记
echo    - 建议定期进行安全检查
echo.
echo 按任意键退出...
pause >nul