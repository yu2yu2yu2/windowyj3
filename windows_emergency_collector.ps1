# Windows应急响应数据收集脚本 (PowerShell版)
# 版本: 2.0 Enhanced
# 作者: Windows Emergency Response Team
# 用途: 收集Windows系统应急响应所需的详细信息

param(
    [string]$OutputPath = "windows_emergency_report.txt",
    [switch]$Verbose = $false
)

# 设置输出编码为UTF-8
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 创建输出文件
$ReportFile = $OutputPath
$StartTime = Get-Date

Write-Host "🛡️ Windows应急响应数据收集开始..." -ForegroundColor Green
Write-Host "📁 输出文件: $ReportFile" -ForegroundColor Yellow
Write-Host "⏰ 开始时间: $StartTime" -ForegroundColor Yellow

# 初始化报告文件
@"
================================================================
Windows 应急响应报告
================================================================
生成时间: $StartTime
计算机名: $env:COMPUTERNAME
用户名: $env:USERNAME
操作系统: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
================================================================

"@ | Out-File -FilePath $ReportFile -Encoding UTF8

function Write-Section {
    param([string]$Title, [string]$Content)
    
    $SectionHeader = @"

================================================================
$Title
================================================================
$Content

"@
    Add-Content -Path $ReportFile -Value $SectionHeader -Encoding UTF8
    if ($Verbose) { Write-Host "✅ 完成: $Title" -ForegroundColor Green }
}

function Get-SafeWMIObject {
    param([string]$Class, [string]$Property = "*")
    try {
        return Get-WmiObject -Class $Class -ErrorAction SilentlyContinue | Select-Object $Property
    } catch {
        return "无法获取 $Class 信息: $($_.Exception.Message)"
    }
}

# 1. 系统基本信息
Write-Host "📊 收集系统基本信息..." -ForegroundColor Cyan
$SystemInfo = @"
系统信息概览:
- 计算机名: $env:COMPUTERNAME
- 用户名: $env:USERNAME  
- 域名: $env:USERDOMAIN
- 操作系统: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
- 系统版本: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version)
- 系统架构: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)
- 安装日期: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty InstallDate)
- 最后启动: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
- 系统目录: $env:SystemRoot
- 临时目录: $env:TEMP
- 当前时间: $(Get-Date)

硬件信息:
- 处理器: $(Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name)
- 内存总量: $([math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory/1GB, 2)) GB
- 磁盘信息: $(Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | ForEach-Object {"$($_.DeviceID) $([math]::Round($_.Size/1GB, 2))GB"} | Join-String -Separator ", ")
"@
Write-Section "系统基本信息" $SystemInfo

# 2. 用户账户信息 (重点检查)
Write-Host "👥 收集用户账户信息..." -ForegroundColor Cyan
try {
    $Users = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
    $AdminUsers = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    
    $UserInfo = @"
本地用户账户详情:
"@
    
    $AdminCount = 0
    $NeverLoginCount = 0
    
    foreach ($User in $Users) {
        $LastLogin = "从未登录"
        $IsAdmin = $false
        
        # 检查是否为管理员
        if ($AdminUsers | Where-Object {$_.Name -like "*$($User.Name)"}) {
            $IsAdmin = $true
            $AdminCount++
        }
        
        # 检查最后登录时间
        try {
            $UserProfile = Get-WmiObject -Class Win32_UserProfile | Where-Object {$_.LocalPath -like "*$($User.Name)"}
            if ($UserProfile -and $UserProfile.LastUseTime) {
                $LastLogin = [Management.ManagementDateTimeConverter]::ToDateTime($UserProfile.LastUseTime)
            } else {
                $NeverLoginCount++
            }
        } catch {}
        
        $UserInfo += @"

用户: $($User.Name)
- SID: $($User.SID)
- 描述: $($User.Description)
- 状态: $(if($User.Disabled){"已禁用"}else{"已启用"})
- 管理员权限: $(if($IsAdmin){"是"}else{"否"})
- 最后登录: $LastLogin
- 权限级别: $(if($User.SID -eq "S-1-5-21-*-500"){"超级管理员权限"}elseif($IsAdmin){"管理员权限"}else{"普通用户权限"})
"@
        
        # 添加可疑管理员检测
        if ($IsAdmin -and ($User.Name -match "test|temp|hack|admin|guest")) {
            $UserInfo += "- ⚠️ 管理员: $env:COMPUTERNAME\$($User.Name) [可疑账户]"
        }
    }
    
    $UserInfo += @"

用户统计信息:
- 总用户数: $($Users.Count)
- 管理员用户数: $AdminCount
- 从未登录用户数: $NeverLoginCount
- 已启用用户数: $(($Users | Where-Object {-not $_.Disabled}).Count)
- 已禁用用户数: $(($Users | Where-Object {$_.Disabled}).Count)
"@

} catch {
    $UserInfo = "无法获取用户信息: $($_.Exception.Message)"
}
Write-Section "用户账户信息" $UserInfo

# 3. 进程信息 (重点检查)
Write-Host "⚙️ 收集进程信息..." -ForegroundColor Cyan
try {
    $Processes = Get-Process | Sort-Object CPU -Descending
    $SuspiciousProcessCount = 0
    
    $ProcessInfo = @"
当前运行进程详情:
"@
    
    foreach ($Process in $Processes | Select-Object -First 50) {
        try {
            $ProcessPath = $Process.Path
            if (-not $ProcessPath) { $ProcessPath = "路径未知" }
            
            $IsSuspicious = $false
            $SuspiciousReason = ""
            
            # 检查可疑进程
            if ($Process.ProcessName -match "powershell|cmd|wscript|cscript") {
                $IsSuspicious = $true
                $SuspiciousReason = "脚本执行进程"
                $SuspiciousProcessCount++
            }
            
            # 检查异常路径
            if ($ProcessPath -match "temp|tmp|appdata|downloads") {
                $IsSuspicious = $true
                $SuspiciousReason += " 异常路径"
            }
            
            $ProcessInfo += @"

进程: $($Process.ProcessName)
- PID: $($Process.Id)
- 路径: $ProcessPath
- CPU使用: $([math]::Round($Process.CPU, 2))
- 内存使用: $([math]::Round($Process.WorkingSet64/1MB, 2)) MB
- 启动时间: $($Process.StartTime)
"@
            
            if ($IsSuspicious) {
                $ProcessInfo += "- ⚠️ 可疑进程: $($Process.ProcessName) | PID: $($Process.Id) | 路径: $ProcessPath [$SuspiciousReason]"
            }
            
        } catch {
            $ProcessInfo += "- 进程信息获取失败: $($Process.ProcessName)"
        }
    }
    
    $ProcessInfo += @"

进程统计信息:
- 总进程数: $($Processes.Count)
- 可疑进程数: $SuspiciousProcessCount
- 高CPU进程数: $(($Processes | Where-Object {$_.CPU -gt 100}).Count)
- 高内存进程数: $(($Processes | Where-Object {$_.WorkingSet64 -gt 100MB}).Count)
"@

} catch {
    $ProcessInfo = "无法获取进程信息: $($_.Exception.Message)"
}
Write-Section "进程信息" $ProcessInfo

# 4. 网络连接信息 (重点检查)
Write-Host "🌐 收集网络连接信息..." -ForegroundColor Cyan
try {
    $NetConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    $SuspiciousConnCount = 0
    
    $NetworkInfo = @"
活动网络连接详情:
"@
    
    foreach ($Conn in $NetConnections | Select-Object -First 30) {
        $IsSuspicious = $false
        $SuspiciousReason = ""
        
        # 检查可疑连接
        if ($Conn.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)" -and 
            $Conn.RemoteAddress -ne "0.0.0.0" -and $Conn.RemoteAddress -ne "::") {
            $IsSuspicious = $true
            $SuspiciousReason = "外网连接"
            $SuspiciousConnCount++
        }
        
        # 检查可疑端口
        if ($Conn.RemotePort -in @(4444, 1234, 31337, 12345, 54321)) {
            $IsSuspicious = $true
            $SuspiciousReason += " 可疑端口"
        }
        
        $NetworkInfo += @"

连接: $($Conn.LocalAddress):$($Conn.LocalPort) -> $($Conn.RemoteAddress):$($Conn.RemotePort)
- 状态: $($Conn.State)
- 进程ID: $($Conn.OwningProcess)
- 创建时间: $($Conn.CreationTime)
"@
        
        if ($IsSuspicious) {
            $NetworkInfo += "- ⚠️ 可疑连接: $($Conn.LocalAddress):$($Conn.LocalPort) -> $($Conn.RemoteAddress):$($Conn.RemotePort) [$SuspiciousReason]"
        }
    }
    
    $NetworkInfo += @"

网络统计信息:
- 活动连接数: $($NetConnections.Count)
- 可疑连接数: $SuspiciousConnCount
- 监听端口数: $((Get-NetTCPConnection -State Listen).Count)
- 外网连接数: $(($NetConnections | Where-Object {$_.RemoteAddress -notmatch "^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)"}).Count)
"@

} catch {
    $NetworkInfo = "无法获取网络连接信息: $($_.Exception.Message)"
}
Write-Section "网络连接信息" $NetworkInfo

# 5. 文件系统检查 (重点检查)
Write-Host "📁 检查文件系统..." -ForegroundColor Cyan
try {
    $SuspiciousFiles = @()
    $TempDirs = @($env:TEMP, "$env:SystemRoot\Temp", "$env:USERPROFILE\Downloads")
    
    $FileInfo = @"
文件系统安全检查:
"@
    
    foreach ($TempDir in $TempDirs) {
        if (Test-Path $TempDir) {
            $Files = Get-ChildItem -Path $TempDir -File -ErrorAction SilentlyContinue | 
                     Where-Object {$_.Extension -match "\.(exe|bat|cmd|ps1|vbs|js)$"} |
                     Select-Object -First 20
            
            foreach ($File in $Files) {
                $SuspiciousFiles += $File
                $FileInfo += @"

可疑文件: $($File.FullName)
- 大小: $([math]::Round($File.Length/1KB, 2)) KB
- 创建时间: $($File.CreationTime)
- 修改时间: $($File.LastWriteTime)
- 扩展名: $($File.Extension)
"@
            }
        }
    }
    
    $FileInfo += @"

文件统计信息:
- 临时目录可疑文件数: $($SuspiciousFiles.Count)
- 检查目录数: $($TempDirs.Count)
- 最近修改文件数: $(($SuspiciousFiles | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}).Count)
"@

} catch {
    $FileInfo = "无法检查文件系统: $($_.Exception.Message)"
}
Write-Section "文件系统检查" $FileInfo

# 6. 系统服务检查
Write-Host "🔧 检查系统服务..." -ForegroundColor Cyan
try {
    $Services = Get-Service | Where-Object {$_.Status -eq "Running"}
    $SuspiciousServices = @()
    
    $ServiceInfo = @"
系统服务状态检查:
"@
    
    foreach ($Service in $Services) {
        $IsSuspicious = $false
        
        if ($Service.Name -match "temp|tmp|test|hack|backdoor") {
            $IsSuspicious = $true
            $SuspiciousServices += $Service
        }
        
        if ($IsSuspicious) {
            $ServiceInfo += @"

可疑服务: $($Service.Name)
- 显示名: $($Service.DisplayName)
- 状态: $($Service.Status)
- 启动类型: $(Get-WmiObject -Class Win32_Service | Where-Object {$_.Name -eq $Service.Name} | Select-Object -ExpandProperty StartMode)
"@
        }
    }
    
    $ServiceInfo += @"

服务统计信息:
- 运行中服务数: $($Services.Count)
- 可疑服务数: $($SuspiciousServices.Count)
- 已停止服务数: $((Get-Service | Where-Object {$_.Status -eq "Stopped"}).Count)
- 自动启动服务数: $((Get-WmiObject -Class Win32_Service | Where-Object {$_.StartMode -eq "Auto"}).Count)
"@

} catch {
    $ServiceInfo = "无法获取服务信息: $($_.Exception.Message)"
}
Write-Section "系统服务检查" $ServiceInfo

# 7. 计划任务检查
Write-Host "⏰ 检查计划任务..." -ForegroundColor Cyan
try {
    $ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
    $SuspiciousTasks = @()
    
    $TaskInfo = @"
计划任务检查:
"@
    
    foreach ($Task in $ScheduledTasks | Select-Object -First 30) {
        $IsSuspicious = $false
        $TaskAction = ""
        
        try {
            $TaskDetail = Get-ScheduledTask -TaskName $Task.TaskName -ErrorAction SilentlyContinue
            if ($TaskDetail.Actions) {
                $TaskAction = $TaskDetail.Actions[0].Execute
                if ($TaskAction -match "powershell|cmd|wscript|cscript") {
                    $IsSuspicious = $true
                    $SuspiciousTasks += $Task
                }
            }
        } catch {}
        
        if ($IsSuspicious) {
            $TaskInfo += @"

可疑任务: $($Task.TaskName)
- 状态: $($Task.State)
- 操作: $TaskAction
- 路径: $($Task.TaskPath)
- 描述: $($Task.Description)
"@
        }
    }
    
    $TaskInfo += @"

计划任务统计:
- 活动任务数: $($ScheduledTasks.Count)
- 可疑任务数: $($SuspiciousTasks.Count)
- 已禁用任务数: $((Get-ScheduledTask | Where-Object {$_.State -eq "Disabled"}).Count)
"@

} catch {
    $TaskInfo = "无法获取计划任务信息: $($_.Exception.Message)"
}
Write-Section "计划任务检查" $TaskInfo

# 8. Windows Defender状态
Write-Host "🛡️ 检查Windows Defender状态..." -ForegroundColor Cyan
try {
    $DefenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    
    $DefenderInfo = @"
Windows Defender状态:
- 实时保护: $($DefenderStatus.RealTimeProtectionEnabled)
- 反恶意软件: $($DefenderStatus.AntivirusEnabled)
- 反间谍软件: $($DefenderStatus.AntispywareEnabled)
- 防火墙: $($DefenderStatus.FirewallEnabled)
- 最后扫描: $($DefenderStatus.QuickScanStartTime)
- 签名版本: $($DefenderStatus.AntivirusSignatureVersion)
- 引擎版本: $($DefenderStatus.AMEngineVersion)
"@

} catch {
    $DefenderInfo = "无法获取Windows Defender状态信息"
}
Write-Section "Windows Defender状态" $DefenderInfo

# 9. 注册表启动项检查
Write-Host "📋 检查注册表启动项..." -ForegroundColor Cyan
try {
    $StartupKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $RegistryInfo = @"
注册表启动项检查:
"@
    
    foreach ($Key in $StartupKeys) {
        if (Test-Path $Key) {
            $Items = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
            if ($Items) {
                $Items.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                    $IsSuspicious = $false
                    if ($_.Name -match "temp|tmp|test|hack" -or $_.Value -match "temp|tmp|test|hack") {
                        $IsSuspicious = $true
                    }
                    
                    $RegistryInfo += @"

启动项: $($_.Name)
- 路径: $Key
- 命令: $($_.Value)
$(if($IsSuspicious){"- ⚠️ 注册表项: $($_.Name) [可疑启动项]"})
"@
                }
            }
        }
    }

} catch {
    $RegistryInfo = "无法检查注册表启动项: $($_.Exception.Message)"
}
Write-Section "注册表启动项检查" $RegistryInfo

# 10. 系统日志摘要
Write-Host "📊 收集系统日志摘要..." -ForegroundColor Cyan
try {
    $LogInfo = @"
系统日志摘要 (最近24小时):
"@
    
    # 安全日志
    $SecurityEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 -ErrorAction SilentlyContinue
    $LoginFailures = $SecurityEvents | Where-Object {$_.Id -eq 4625}
    $LoginSuccess = $SecurityEvents | Where-Object {$_.Id -eq 4624}
    
    $LogInfo += @"

安全事件统计:
- 登录成功: $($LoginSuccess.Count)
- 登录失败: $($LoginFailures.Count)
- 权限提升: $(($SecurityEvents | Where-Object {$_.Id -eq 4672}).Count)
- 账户创建: $(($SecurityEvents | Where-Object {$_.Id -eq 4720}).Count)
- 账户删除: $(($SecurityEvents | Where-Object {$_.Id -eq 4726}).Count)
"@
    
    if ($LoginFailures.Count -ge 5) {
        $LogInfo += "- ⚠️ 登录失败: 失败次数: $($LoginFailures.Count) [可能的暴力破解攻击]"
    }
    
    # 系统日志
    $SystemEvents = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50 -ErrorAction SilentlyContinue
    $ErrorEvents = $SystemEvents | Where-Object {$_.LevelDisplayName -eq "Error"}
    
    $LogInfo += @"

系统事件统计:
- 系统错误: $($ErrorEvents.Count)
- 警告事件: $(($SystemEvents | Where-Object {$_.LevelDisplayName -eq "Warning"}).Count)
- 信息事件: $(($SystemEvents | Where-Object {$_.LevelDisplayName -eq "Information"}).Count)
"@

} catch {
    $LogInfo = "无法获取系统日志信息: $($_.Exception.Message)"
}
Write-Section "系统日志摘要" $LogInfo

# 完成报告
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

$Summary = @"
================================================================
报告生成完成
================================================================
开始时间: $StartTime
结束时间: $EndTime
耗时: $($Duration.TotalSeconds) 秒
报告文件: $ReportFile
文件大小: $([math]::Round((Get-Item $ReportFile).Length/1KB, 2)) KB

建议: 请将此报告文件上传到 /viewer 界面进行详细分析
================================================================
"@

Add-Content -Path $ReportFile -Value $Summary -Encoding UTF8

Write-Host "🎉 数据收集完成!" -ForegroundColor Green
Write-Host "📄 报告文件: $ReportFile" -ForegroundColor Yellow
Write-Host "📊 文件大小: $([math]::Round((Get-Item $ReportFile).Length/1KB, 2)) KB" -ForegroundColor Yellow
Write-Host "⏱️ 耗时: $($Duration.TotalSeconds) 秒" -ForegroundColor Yellow
Write-Host "🔍 请将报告文件上传到 /viewer 界面进行分析" -ForegroundColor Cyan