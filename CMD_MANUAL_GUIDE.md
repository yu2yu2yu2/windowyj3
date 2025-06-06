# Windows应急响应手动检查指南 (CMD命令版)

## 🎯 概述

本指南提供纯CMD命令的Windows应急响应检查方法，避免PowerShell依赖，适用于所有Windows版本。

## 🚀 快速检查命令 (5分钟内完成)

### 1. 系统基本信息
```cmd
# 查看系统信息
systeminfo

# 查看计算机名和用户
echo 计算机名: %COMPUTERNAME%
echo 用户名: %USERNAME%
echo 域名: %USERDOMAIN%

# 查看系统版本
ver

# 查看环境变量
set
```

### 2. 用户账户检查 ⚠️ 重点
```cmd
# 查看所有用户
net user

# 查看管理员组成员
net localgroup administrators

# 查看特定用户详情 (替换username为实际用户名)
net user username

# 检查可疑用户 (包含test、temp、hack等关键词的用户)
net user | findstr /i "test temp hack admin guest"
```

### 3. 进程检查 ⚠️ 重点
```cmd
# 查看所有进程
tasklist

# 查看详细进程信息
tasklist /v

# 查看进程和服务关系
tasklist /svc

# 检查可疑进程
tasklist | findstr /i "powershell cmd wscript cscript mshta rundll32"

# 查看高CPU/内存占用进程
wmic process get Name,ProcessId,PageFileUsage,WorkingSetSize /format:table
```

### 4. 网络连接检查 ⚠️ 重点
```cmd
# 查看所有网络连接
netstat -ano

# 查看监听端口
netstat -an | findstr "LISTENING"

# 查看已建立的连接
netstat -an | findstr "ESTABLISHED"

# 检查可疑端口连接
netstat -an | findstr ":4444 :1234 :31337 :12345 :54321"

# 查看网络配置
ipconfig /all

# 查看路由表
route print

# 查看ARP表
arp -a
```

### 5. 服务检查
```cmd
# 查看所有服务状态
sc query type= service state= all

# 查看运行中的服务
sc query type= service state= running

# 查看服务详细信息
wmic service get Name,DisplayName,State,StartMode,PathName /format:table

# 检查可疑服务
sc query type= service state= all | findstr /i "temp tmp test hack backdoor"
```

## 🔍 详细检查命令 (30分钟内完成)

### 6. 启动项检查 ⚠️ 重点
```cmd
# 查看注册表启动项
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

# 查看64位系统的32位启动项
reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

# 使用WMIC查看启动项
wmic startup get Caption,Command,Location /format:table

# 检查启动文件夹
dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
dir "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup"
```

### 7. 计划任务检查
```cmd
# 查看所有计划任务
schtasks /query

# 查看详细任务信息
schtasks /query /fo table /v

# 查看特定任务详情 (替换taskname为实际任务名)
schtasks /query /tn "taskname" /v

# 检查可疑计划任务
schtasks /query /fo table /v | findstr /i "powershell cmd wscript cscript"
```

### 8. 文件系统检查 ⚠️ 重点
```cmd
# 检查临时目录可疑文件
dir "%TEMP%\*.exe" "%TEMP%\*.bat" "%TEMP%\*.cmd" "%TEMP%\*.ps1" "%TEMP%\*.vbs" /s
dir "%SystemRoot%\Temp\*.exe" "%SystemRoot%\Temp\*.bat" "%SystemRoot%\Temp\*.cmd" /s

# 检查下载目录最近文件
forfiles /p "%USERPROFILE%\Downloads" /d -7 /c "cmd /c echo @path @fdate @ftime"

# 检查最近修改的系统文件
forfiles /p %SystemRoot%\System32 /m *.exe /d -7 /c "cmd /c echo @path @fdate @ftime"

# 检查系统文件完整性
sfc /verifyonly

# 查看磁盘使用情况
wmic logicaldisk get Size,FreeSpace,Caption /format:table
```

### 9. 注册表检查
```cmd
# 检查常见恶意软件注册表位置
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | findstr /i "temp tmp test hack"

# 检查系统策略
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"

# 检查Windows Defender配置
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender"

# 检查防火墙配置
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
```

### 10. 系统日志检查
```cmd
# 查看安全日志 (最近100条)
wevtutil qe Security /c:100 /rd:true /f:text

# 查看系统日志 (最近50条)
wevtutil qe System /c:50 /rd:true /f:text

# 查看应用程序日志 (最近50条)
wevtutil qe Application /c:50 /rd:true /f:text

# 查看登录失败记录
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:20 /rd:true /f:text

# 查看系统错误事件
wevtutil qe System /q:"*[System[Level=2]]" /c:20 /rd:true /f:text

# 查看应用程序错误事件
wevtutil qe Application /q:"*[System[Level=2]]" /c:20 /rd:true /f:text
```

## 🛡️ Windows Defender检查

### 11. Defender状态检查
```cmd
# 查看Windows Defender服务状态
sc query WinDefend

# 查看Windows Defender配置
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender" /s

# 查看实时保护状态
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

# 查看排除项配置
reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions" /s

# 查看威胁检测历史
dir "%ProgramData%\Microsoft\Windows Defender\Scans\History" /s
```

## 📊 补丁和更新检查

### 12. 系统补丁检查
```cmd
# 查看已安装的补丁
wmic qfe list full /format:table

# 查看最近安装的补丁
wmic qfe list full /format:csv | findstr "2024"

# 查看Windows Update服务状态
sc query wuauserv

# 查看Windows Update配置
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
```

## 🔍 高级检查技巧

### 13. 内存和性能分析
```cmd
# 查看内存使用情况
wmic OS get TotalVisibleMemorySize,FreePhysicalMemory /format:table

# 查看CPU信息
wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors /format:table

# 查看系统性能计数器
typeperf "\Processor(_Total)\% Processor Time" -sc 5

# 查看进程内存使用
wmic process get Name,WorkingSetSize,PageFileUsage /format:table | sort /r /+2
```

### 14. 网络深度分析
```cmd
# 查看网络适配器信息
wmic path win32_networkadapter get Name,MACAddress,Speed /format:table

# 查看IP配置详情
wmic path win32_networkadapterconfiguration get IPAddress,SubnetMask,DefaultIPGateway /format:table

# 查看DNS缓存
ipconfig /displaydns

# 清除DNS缓存 (如需要)
ipconfig /flushdns

# 查看网络统计
netstat -s
```

### 15. 用户活动分析
```cmd
# 查看当前登录用户
query user

# 查看用户会话
query session

# 查看最近访问的文件
dir "%USERPROFILE%\Recent" /od

# 查看用户配置文件
wmic useraccount get Name,SID,LocalAccount /format:table

# 查看用户组信息
net localgroup
```

## 🚨 应急响应检查清单

### 快速威胁评估 (按优先级)

#### 🔴 高优先级 (立即检查)
1. **可疑进程**: `tasklist | findstr /i "powershell cmd wscript cscript"`
2. **异常网络连接**: `netstat -ano | findstr ":4444 :1234 :31337"`
3. **可疑用户**: `net localgroup administrators`
4. **异常服务**: `sc query type= service state= running`

#### 🟡 中优先级 (30分钟内)
1. **启动项检查**: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"`
2. **计划任务**: `schtasks /query /fo table`
3. **临时文件**: `dir "%TEMP%\*.exe" /s`
4. **系统日志**: `wevtutil qe Security /c:50`

#### 🟢 低优先级 (1小时内)
1. **补丁状态**: `wmic qfe list`
2. **系统配置**: `systeminfo`
3. **网络配置**: `ipconfig /all`
4. **文件完整性**: `sfc /verifyonly`

## 💡 实用技巧

### 输出重定向和日志记录
```cmd
# 将结果保存到文件
systeminfo > system_info.txt
tasklist > process_list.txt
netstat -ano > network_connections.txt

# 追加到现有文件
net user >> user_info.txt

# 同时显示和保存
tasklist | tee process_list.txt

# 保存错误信息
systeminfo > system_info.txt 2>&1
```

### 批量检查脚本示例
```cmd
@echo off
echo 开始应急响应检查...
echo.

echo 1. 检查用户账户
net localgroup administrators
echo.

echo 2. 检查可疑进程
tasklist | findstr /i "powershell cmd wscript"
echo.

echo 3. 检查网络连接
netstat -ano | findstr "ESTABLISHED"
echo.

echo 4. 检查启动项
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
echo.

echo 检查完成！
pause
```

## ⚠️ 注意事项

1. **权限要求**: 某些命令需要管理员权限
2. **系统版本**: 部分命令在不同Windows版本中可能有差异
3. **性能影响**: 大量查询可能影响系统性能
4. **数据保护**: 检查结果可能包含敏感信息，请妥善保管
5. **及时性**: 恶意软件可能会清理痕迹，应尽快进行检查

## 🔗 相关资源

- [Microsoft Windows Commands Reference](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Incident Response Guide](https://www.sans.org/white-papers/incident-response/)

---

**🛡️ 通过系统化的CMD命令检查，快速识别Windows系统安全威胁！**