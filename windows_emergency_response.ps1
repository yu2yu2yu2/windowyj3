# Windows应急响应工具
# 作者: Security Team
# 版本: 1.0
# 描述: 全面的Windows系统安全检查和应急响应工具

param(
    [string]$OutputPath = "emergency_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [switch]$Detailed = $false,
    [switch]$JsonOutput = $false
)

# 全局变量
$Global:ReportData = @{}
$Global:StartTime = Get-Date
$Global:SecurityStats = @{
    'TotalUsers' = 0
    'AdminUsers' = 0
    'EnabledUsers' = 0
    'DisabledUsers' = 0
    'NeverLoggedInUsers' = 0
    'RecentlyLoggedInUsers' = 0
    'TotalProcesses' = 0
    'SuspiciousProcesses' = 0
    'HighCpuProcesses' = 0
    'NetworkConnections' = 0
    'SuspiciousConnections' = 0
    'ListeningPorts' = 0
    'SuspiciousFiles' = 0
    'RegistryStartupItems' = 0
    'SuspiciousRegistryItems' = 0
    'ScheduledTasks' = 0
    'SuspiciousScheduledTasks' = 0
    'SecurityEvents' = 0
    'FailedLogins' = 0
    'SystemErrors' = 0
    'DefenderEnabled' = $false
    'FirewallEnabled' = $false
    'UACEnabled' = $false
}

# 写入分隔符和标题的函数
function Write-Section {
    param([string]$Title)
    $separator = "=" * 60
    $output = @"

$separator
$Title
$separator

"@
    Write-Host $output -ForegroundColor Cyan
    return $output
}

function Write-SubSection {
    param([string]$Title)
    $separator = "-" * 40
    $output = @"

$separator
$Title
$separator

"@
    Write-Host $output -ForegroundColor Yellow
    return $output
}

# 1. 系统信息收集
function Get-SystemInfo {
    Write-Host "正在收集系统信息..." -ForegroundColor Green
    
    $output = Write-Section "系统信息"
    
    # 基本系统信息
    $output += Write-SubSection "基本系统信息"
    $computerInfo = Get-ComputerInfo
    $output += "计算机名: $($computerInfo.CsName)`n"
    $output += "操作系统: $($computerInfo.WindowsProductName)`n"
    $output += "版本: $($computerInfo.WindowsVersion)`n"
    $output += "构建号: $($computerInfo.WindowsBuildLabEx)`n"
    $output += "系统类型: $($computerInfo.CsSystemType)`n"
    $output += "处理器: $($computerInfo.CsProcessors[0].Name)`n"
    $output += "总内存: $([math]::Round($computerInfo.TotalPhysicalMemory/1GB, 2)) GB`n"
    $output += "系统启动时间: $($computerInfo.CsBootupState)`n"
    $output += "最后启动时间: $(Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)`n"
    
    # 补丁信息
    $output += Write-SubSection "已安装补丁信息"
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
    foreach ($hotfix in $hotfixes) {
        $output += "补丁: $($hotfix.HotFixID) | 安装时间: $($hotfix.InstalledOn) | 描述: $($hotfix.Description)`n"
    }
    
    # 环境变量
    $output += Write-SubSection "重要环境变量"
    $envVars = @('PATH', 'TEMP', 'TMP', 'USERPROFILE', 'PROGRAMFILES', 'SYSTEMROOT')
    foreach ($var in $envVars) {
        $value = [Environment]::GetEnvironmentVariable($var)
        $output += "$var = $value`n"
    }
    
    $Global:ReportData['system'] = @{
        '基本系统信息' = $computerInfo
        '已安装补丁信息' = $hotfixes
        '重要环境变量' = $envVars
    }
    
    return $output
}

# 2. 用户和权限检查
function Get-UserInfo {
    Write-Host "正在检查用户和权限..." -ForegroundColor Green
    
    $output = Write-Section "用户和权限检查"
    
    # 本地用户账户统计
    $output += Write-SubSection "用户账户统计分析"
    $localUsers = Get-LocalUser
    $Global:SecurityStats['TotalUsers'] = $localUsers.Count
    $Global:SecurityStats['EnabledUsers'] = ($localUsers | Where-Object {$_.Enabled -eq $true}).Count
    $Global:SecurityStats['DisabledUsers'] = ($localUsers | Where-Object {$_.Enabled -eq $false}).Count
    $Global:SecurityStats['NeverLoggedInUsers'] = ($localUsers | Where-Object {$_.LastLogon -eq $null}).Count
    
    $recentDate = (Get-Date).AddDays(-30)
    $Global:SecurityStats['RecentlyLoggedInUsers'] = ($localUsers | Where-Object {$_.LastLogon -gt $recentDate}).Count
    
    $output += "用户账户总数: $($Global:SecurityStats['TotalUsers'])`n"
    $output += "启用用户数: $($Global:SecurityStats['EnabledUsers'])`n"
    $output += "禁用用户数: $($Global:SecurityStats['DisabledUsers'])`n"
    $output += "从未登录用户数: $($Global:SecurityStats['NeverLoggedInUsers'])`n"
    $output += "近30天登录用户数: $($Global:SecurityStats['RecentlyLoggedInUsers'])`n"
    
    # 本地用户账户详细信息
    $output += Write-SubSection "本地用户账户详细信息"
    foreach ($user in $localUsers) {
        $userSID = $user.SID.Value
        $isBuiltIn = $userSID.StartsWith("S-1-5-21") -eq $false
        $userType = if ($isBuiltIn) { "内置账户" } else { "本地账户" }
        
        # 检查用户ID为0的情况（类似Unix的root用户概念）
        $isHighPrivilege = $user.Name -eq "Administrator" -or $userSID.EndsWith("-500")
        $privilegeLevel = if ($isHighPrivilege) { "超级管理员权限" } else { "普通用户权限" }
        
        $output += "用户: $($user.Name) | 启用: $($user.Enabled) | 类型: $userType | 权限级别: $privilegeLevel | SID: $userSID | 最后登录: $($user.LastLogon) | 描述: $($user.Description)`n"
    }
    
    # 管理员组成员分析
    $output += Write-SubSection "管理员组成员分析"
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        $Global:SecurityStats['AdminUsers'] = $adminGroup.Count
        
        $output += "管理员组成员总数: $($adminGroup.Count)`n"
        $output += "安全建议: 除了内置Administrator账户外，建议限制管理员权限用户数量`n`n"
        
        foreach ($member in $adminGroup) {
            $memberType = if ($member.Name -match "Administrator|管理员") { "内置管理员" } else { "自定义管理员" }
            $securityRisk = if ($memberType -eq "自定义管理员") { "需要验证" } else { "正常" }
            $output += "管理员: $($member.Name) | 类型: $($member.ObjectClass) | 分类: $memberType | 安全风险: $securityRisk | 来源: $($member.PrincipalSource)`n"
        }
        
        # 安全分析建议
        $output += "`n权限分析结论:`n"
        if ($adminGroup.Count -eq 1 -and $adminGroup[0].Name -match "Administrator") {
            $output += "✓ 安全状况良好: 仅有内置Administrator账户具有管理员权限`n"
        } elseif ($adminGroup.Count -le 3) {
            $output += "⚠ 中等风险: 发现 $($adminGroup.Count) 个管理员账户，建议与运维开发人员确认其必要性`n"
        } else {
            $output += "⚠ 高风险: 发现 $($adminGroup.Count) 个管理员账户，存在权限过度分配风险，强烈建议审查`n"
        }
        
    } catch {
        $output += "无法获取管理员组信息: $($_.Exception.Message)`n"
    }
    
    # 当前登录用户
    $output += Write-SubSection "当前登录用户"
    $loggedUsers = Get-CimInstance -ClassName Win32_LoggedOnUser
    $uniqueUsers = $loggedUsers | Select-Object -ExpandProperty Antecedent | Sort-Object -Unique
    foreach ($user in $uniqueUsers) {
        if ($user -match 'Name="([^"]+)"') {
            $output += "登录用户: $($matches[1])`n"
        }
    }
    
    # 最近登录记录
    $output += Write-SubSection "最近登录记录"
    try {
        $loginEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($event in $loginEvents) {
            $xml = [xml]$event.ToXml()
            $username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $logonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'} | Select-Object -ExpandProperty '#text'
            $output += "时间: $($event.TimeCreated) | 用户: $username | 登录类型: $logonType`n"
        }
    } catch {
        $output += "无法获取登录记录: $($_.Exception.Message)`n"
    }
    
    $Global:ReportData['user'] = @{
        '本地用户账户' = $localUsers
        '管理员组成员' = $adminGroup
        '当前登录用户' = $uniqueUsers
        '最近登录记录' = $loginEvents
    }
    
    return $output
}

# 3. 进程和服务分析
function Get-ProcessInfo {
    Write-Host "正在分析进程和服务..." -ForegroundColor Green
    
    $output = Write-Section "进程和服务分析"
    
    # 进程统计分析
    $output += Write-SubSection "进程统计分析"
    $allProcesses = Get-Process
    $Global:SecurityStats['TotalProcesses'] = $allProcesses.Count
    
    # 高CPU占用进程统计
    $highCpuProcesses = $allProcesses | Where-Object {$_.CPU -gt 100} | Sort-Object CPU -Descending
    $Global:SecurityStats['HighCpuProcesses'] = $highCpuProcesses.Count
    
    $output += "系统进程总数: $($Global:SecurityStats['TotalProcesses'])`n"
    $output += "高CPU占用进程数(>100): $($Global:SecurityStats['HighCpuProcesses'])`n"
    
    # 高CPU占用进程详情
    $output += Write-SubSection "高CPU占用进程详情"
    $topProcesses = $allProcesses | Sort-Object CPU -Descending | Select-Object -First 15
    foreach ($proc in $topProcesses) {
        $cpuUsage = if ($proc.CPU) { [math]::Round($proc.CPU, 2) } else { "N/A" }
        $memoryMB = [math]::Round($proc.WorkingSet/1MB, 2)
        $processPath = if ($proc.Path) { $proc.Path } else { "系统进程" }
        $output += "进程: $($proc.ProcessName) | PID: $($proc.Id) | CPU: $cpuUsage | 内存: $memoryMB MB | 路径: $processPath`n"
    }
    
    # 可疑进程检查
    $output += Write-SubSection "可疑进程安全检查"
    $suspiciousProcesses = $allProcesses | Where-Object {
        $_.ProcessName -match "(cmd|powershell|wscript|cscript|mshta|rundll32|regsvr32)" -or
        ($_.Path -and $_.Path -match "(temp|tmp|appdata|downloads)") -or
        $_.ProcessName -match "^[a-f0-9]{8,}$" -or
        ($_.Path -and $_.Path -match "\.(tmp|temp)\.exe$")
    }
    
    $Global:SecurityStats['SuspiciousProcesses'] = $suspiciousProcesses.Count
    $output += "可疑进程总数: $($Global:SecurityStats['SuspiciousProcesses'])`n"
    
    if ($suspiciousProcesses.Count -eq 0) {
        $output += "✓ 未发现明显可疑进程`n"
    } else {
        $output += "⚠ 发现 $($suspiciousProcesses.Count) 个可疑进程，建议进一步分析`n"
        foreach ($proc in $suspiciousProcesses) {
            $riskLevel = "中等"
            if ($proc.ProcessName -match "(powershell|cmd)" -and $proc.Path -match "(temp|tmp)") {
                $riskLevel = "高"
            }
            $processPath = if ($proc.Path) { $proc.Path } else { "未知路径" }
            $output += "可疑进程: $($proc.ProcessName) | PID: $($proc.Id) | 风险级别: $riskLevel | 路径: $processPath`n"
        }
    }
    
    # 系统服务
    $output += Write-SubSection "运行中的系统服务"
    $services = Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object Name
    foreach ($service in $services) {
        $serviceInfo = Get-CimInstance -ClassName Win32_Service | Where-Object {$_.Name -eq $service.Name}
        $output += "服务: $($service.Name) | 显示名: $($service.DisplayName) | 状态: $($service.Status) | 路径: $($serviceInfo.PathName)`n"
    }
    
    # 启动项
    $output += Write-SubSection "启动项"
    $startupItems = Get-CimInstance -ClassName Win32_StartupCommand
    foreach ($item in $startupItems) {
        $output += "启动项: $($item.Name) | 命令: $($item.Command) | 位置: $($item.Location) | 用户: $($item.User)`n"
    }
    
    $Global:ReportData['process'] = @{
        '高CPU占用进程' = $processes
        '可疑进程检查' = $suspiciousProcesses
        '运行中的系统服务' = $services
        '启动项' = $startupItems
    }
    
    return $output
}

# 4. 网络连接检查
function Get-NetworkInfo {
    Write-Host "正在检查网络连接..." -ForegroundColor Green
    
    $output = Write-Section "网络连接检查"
    
    # 网络连接统计
    $output += Write-SubSection "网络连接统计"
    $allConnections = Get-NetTCPConnection
    $connections = $allConnections | Where-Object {$_.State -eq "Established"} | Sort-Object RemoteAddress
    $listeners = $allConnections | Where-Object {$_.State -eq "Listen"} | Sort-Object LocalPort
    
    $Global:SecurityStats['NetworkConnections'] = $connections.Count
    $Global:SecurityStats['ListeningPorts'] = $listeners.Count
    
    # 可疑网络连接检查
    $suspiciousConnections = $connections | Where-Object {
        $_.RemoteAddress -notmatch "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" -and
        $_.RemoteAddress -ne "0.0.0.0" -and
        $_.RemoteAddress -ne "::" -and
        $_.RemotePort -in @(4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337)
    }
    
    $Global:SecurityStats['SuspiciousConnections'] = $suspiciousConnections.Count
    
    $output += "网络连接总数: $($Global:SecurityStats['NetworkConnections'])`n"
    $output += "监听端口数: $($Global:SecurityStats['ListeningPorts'])`n"
    $output += "可疑连接数: $($Global:SecurityStats['SuspiciousConnections'])`n"
    
    # 活动网络连接详情
    $output += Write-SubSection "活动网络连接详情"
    foreach ($conn in $connections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $processName = if ($process) { $process.ProcessName } else { "未知进程" }
        $connectionType = if ($conn.RemoteAddress -match "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)") { "内网连接" } else { "外网连接" }
        $output += "连接: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | 类型: $connectionType | 进程: $processName (PID: $($conn.OwningProcess))`n"
    }
    
    # 可疑网络连接分析
    if ($suspiciousConnections.Count -gt 0) {
        $output += Write-SubSection "可疑网络连接分析"
        $output += "⚠ 发现 $($suspiciousConnections.Count) 个可疑网络连接`n"
        foreach ($conn in $suspiciousConnections) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.ProcessName } else { "未知进程" }
            $output += "可疑连接: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | 进程: $processName | 风险: 高`n"
        }
    }
    
    # 监听端口详情
    $output += Write-SubSection "监听端口详情"
    foreach ($listener in $listeners) {
        $process = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue
        $processName = if ($process) { $process.ProcessName } else { "未知进程" }
        $portType = switch ($listener.LocalPort) {
            80 { "HTTP" }
            443 { "HTTPS" }
            22 { "SSH" }
            3389 { "RDP" }
            135 { "RPC" }
            445 { "SMB" }
            default { "其他" }
        }
        $output += "监听: $($listener.LocalAddress):$($listener.LocalPort) | 服务类型: $portType | 进程: $processName (PID: $($listener.OwningProcess))`n"
    }
    
    # 网络配置
    $output += Write-SubSection "网络配置"
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    foreach ($adapter in $adapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue
        $output += "网卡: $($adapter.Name) | 状态: $($adapter.Status) | MAC: $($adapter.MacAddress)`n"
        foreach ($ip in $ipConfig) {
            $output += "  IP: $($ip.IPAddress)/$($ip.PrefixLength) | 类型: $($ip.AddressFamily)`n"
        }
    }
    
    # DNS配置
    $output += Write-SubSection "DNS配置"
    $dnsServers = Get-DnsClientServerAddress
    foreach ($dns in $dnsServers) {
        if ($dns.ServerAddresses) {
            $output += "接口: $($dns.InterfaceAlias) | DNS服务器: $($dns.ServerAddresses -join ', ')`n"
        }
    }
    
    $Global:ReportData['network'] = @{
        '活动网络连接' = $connections
        '监听端口' = $listeners
        '网络配置' = $adapters
        'DNS配置' = $dnsServers
    }
    
    return $output
}

# 5. 文件系统检查
function Get-FileSystemInfo {
    Write-Host "正在检查文件系统..." -ForegroundColor Green
    
    $output = Write-Section "文件系统检查"
    
    # 最近修改的文件
    $output += Write-SubSection "最近修改的系统文件"
    $systemPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Program Files", "C:\Program Files (x86)")
    foreach ($path in $systemPaths) {
        if (Test-Path $path) {
            $recentFiles = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                          Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)} | 
                          Sort-Object LastWriteTime -Descending | 
                          Select-Object -First 10
            foreach ($file in $recentFiles) {
                $output += "文件: $($file.FullName) | 修改时间: $($file.LastWriteTime) | 大小: $($file.Length) bytes`n"
            }
        }
    }
    
    # 临时目录检查
    $output += Write-SubSection "临时目录可疑文件"
    $tempPaths = @($env:TEMP, $env:TMP, "C:\Windows\Temp", "$env:USERPROFILE\AppData\Local\Temp")
    foreach ($tempPath in $tempPaths) {
        if (Test-Path $tempPath) {
            $suspiciousFiles = Get-ChildItem -Path $tempPath -File -ErrorAction SilentlyContinue | 
                              Where-Object {$_.Extension -match "\.(exe|bat|cmd|ps1|vbs|js)$"} | 
                              Sort-Object LastWriteTime -Descending | 
                              Select-Object -First 20
            foreach ($file in $suspiciousFiles) {
                $output += "可疑文件: $($file.FullName) | 创建时间: $($file.CreationTime) | 修改时间: $($file.LastWriteTime)`n"
            }
        }
    }
    
    # 下载目录检查
    $output += Write-SubSection "下载目录最近文件"
    $downloadPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $downloadPath) {
        $recentDownloads = Get-ChildItem -Path $downloadPath -File -ErrorAction SilentlyContinue | 
                          Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-7)} | 
                          Sort-Object CreationTime -Descending | 
                          Select-Object -First 20
        foreach ($file in $recentDownloads) {
            $output += "下载文件: $($file.Name) | 创建时间: $($file.CreationTime) | 大小: $($file.Length) bytes`n"
        }
    }
    
    $Global:ReportData['filesystem'] = @{
        '最近修改的系统文件' = $recentFiles
        '临时目录可疑文件' = $suspiciousFiles
        '下载目录最近文件' = $recentDownloads
    }
    
    return $output
}

# 6. 注册表分析
function Get-RegistryInfo {
    Write-Host "正在分析注册表..." -ForegroundColor Green
    
    $output = Write-Section "注册表分析"
    
    # 启动项注册表
    $output += Write-SubSection "注册表启动项"
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $output += "注册表项: $key`n"
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $items.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                $output += "  $($_.Name) = $($_.Value)`n"
            }
        }
    }
    
    # 服务注册表
    $output += Write-SubSection "可疑服务注册表"
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services"
    if (Test-Path $serviceKey) {
        $services = Get-ChildItem -Path $serviceKey -ErrorAction SilentlyContinue | 
                   Where-Object {$_.Name -match "(temp|tmp|test|hack|backdoor)"} | 
                   Select-Object -First 10
        foreach ($service in $services) {
            $serviceProps = Get-ItemProperty -Path $service.PSPath -ErrorAction SilentlyContinue
            $output += "可疑服务: $($service.PSChildName) | 路径: $($serviceProps.ImagePath)`n"
        }
    }
    
    # 最近访问的文件
    $output += Write-SubSection "最近访问的文件记录"
    $recentDocsKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    if (Test-Path $recentDocsKey) {
        $recentDocs = Get-ChildItem -Path $recentDocsKey -ErrorAction SilentlyContinue | Select-Object -First 10
        foreach ($doc in $recentDocs) {
            $output += "最近文档类型: $($doc.PSChildName)`n"
        }
    }
    
    $Global:ReportData['registry'] = @{
        '注册表启动项' = $runKeys
        '可疑服务注册表' = $services
        '最近访问的文件记录' = $recentDocs
    }
    
    return $output
}

# 7. 日志分析
function Get-LogAnalysis {
    Write-Host "正在分析系统日志..." -ForegroundColor Green
    
    $output = Write-Section "系统日志分析"
    
    # 安全日志 - 登录失败
    $output += Write-SubSection "登录失败记录"
    try {
        $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue
        $loginStats = @{}
        foreach ($event in $failedLogins) {
            $xml = [xml]$event.ToXml()
            $username = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
            $ipAddress = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
            
            if ($username -and $username -ne "-") {
                if ($loginStats[$username]) {
                    $loginStats[$username]++
                } else {
                    $loginStats[$username] = 1
                }
                $output += "时间: $($event.TimeCreated) | 用户: $username | IP: $ipAddress`n"
            }
        }
        
        $output += "`n登录失败统计:`n"
        $loginStats.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            $output += "用户: $($_.Key) | 失败次数: $($_.Value)`n"
        }
    } catch {
        $output += "无法获取安全日志: $($_.Exception.Message)`n"
    }
    
    # 系统日志 - 错误事件
    $output += Write-SubSection "系统错误事件"
    try {
        $systemErrors = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($event in $systemErrors) {
            $output += "时间: $($event.TimeCreated) | 事件ID: $($event.Id) | 来源: $($event.ProviderName) | 描述: $($event.LevelDisplayName)`n"
        }
    } catch {
        $output += "无法获取系统日志: $($_.Exception.Message)`n"
    }
    
    # 应用程序日志 - 错误事件
    $output += Write-SubSection "应用程序错误事件"
    try {
        $appErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2} -MaxEvents 20 -ErrorAction SilentlyContinue
        foreach ($event in $appErrors) {
            $output += "时间: $($event.TimeCreated) | 事件ID: $($event.Id) | 来源: $($event.ProviderName) | 描述: $($event.LevelDisplayName)`n"
        }
    } catch {
        $output += "无法获取应用程序日志: $($_.Exception.Message)`n"
    }
    
    $Global:ReportData['logs'] = @{
        '登录失败记录' = $failedLogins
        '系统错误事件' = $systemErrors
        '应用程序错误事件' = $appErrors
    }
    
    return $output
}

# 8. 计划任务检查
function Get-ScheduledTaskInfo {
    Write-Host "正在检查计划任务..." -ForegroundColor Green
    
    $output = Write-Section "计划任务检查"
    
    # 获取所有计划任务
    $output += Write-SubSection "活动计划任务"
    try {
        $tasks = Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Sort-Object TaskName
        foreach ($task in $tasks) {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
            $actions = $task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
            $output += "任务: $($task.TaskName) | 状态: $($task.State) | 路径: $($task.TaskPath) | 操作: $($actions -join '; ')`n"
        }
    } catch {
        $output += "无法获取计划任务: $($_.Exception.Message)`n"
    }
    
    # 可疑计划任务
    $output += Write-SubSection "可疑计划任务"
    $suspiciousTasks = $tasks | Where-Object {
        $_.TaskName -match "(temp|tmp|test|update|check)" -or
        $_.Actions.Execute -match "(powershell|cmd|wscript|cscript)" -or
        $_.Actions.Execute -match "(temp|tmp|appdata)"
    }
    foreach ($task in $suspiciousTasks) {
        $actions = $task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }
        $output += "可疑任务: $($task.TaskName) | 操作: $($actions -join '; ') | 路径: $($task.TaskPath)`n"
    }
    
    $Global:ReportData['tasks'] = @{
        '活动计划任务' = $tasks
        '可疑计划任务' = $suspiciousTasks
    }
    
    return $output
}

# 9. 恶意软件检测
function Get-MalwareDetection {
    Write-Host "正在进行恶意软件检测..." -ForegroundColor Green
    
    $output = Write-Section "恶意软件检测"
    
    # Windows Defender状态
    $output += Write-SubSection "Windows Defender状态"
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $output += "实时保护: $($defenderStatus.RealTimeProtectionEnabled)`n"
            $output += "反恶意软件启用: $($defenderStatus.AntivirusEnabled)`n"
            $output += "最后快速扫描: $($defenderStatus.QuickScanStartTime)`n"
            $output += "最后完整扫描: $($defenderStatus.FullScanStartTime)`n"
            $output += "病毒定义版本: $($defenderStatus.AntivirusSignatureVersion)`n"
        }
    } catch {
        $output += "无法获取Windows Defender状态: $($_.Exception.Message)`n"
    }
    
    # 可疑网络连接
    $output += Write-SubSection "可疑网络连接"
    $suspiciousConnections = Get-NetTCPConnection | Where-Object {
        $_.RemoteAddress -notmatch "^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)" -and
        $_.RemoteAddress -ne "0.0.0.0" -and
        $_.RemoteAddress -ne "::" -and
        $_.State -eq "Established"
    } | Sort-Object RemoteAddress
    
    foreach ($conn in $suspiciousConnections) {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $output += "可疑连接: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | 进程: $($process.ProcessName) (PID: $($conn.OwningProcess))`n"
    }
    
    # 异常进程检查
    $output += Write-SubSection "异常进程检查"
    $processes = Get-Process
    $anomalousProcesses = $processes | Where-Object {
        ($_.ProcessName -match "^[a-f0-9]{8,}$") -or
        ($_.Path -and $_.Path -match "(temp|tmp|appdata|downloads)") -or
        ($_.ProcessName -match "(svchost|explorer|winlogon)" -and $_.Path -notmatch "C:\\Windows")
    }
    
    foreach ($proc in $anomalousProcesses) {
        $output += "异常进程: $($proc.ProcessName) | PID: $($proc.Id) | 路径: $($proc.Path) | CPU: $($proc.CPU)`n"
    }
    
    $Global:ReportData['malware'] = @{
        'Windows Defender状态' = $defenderStatus
        '可疑网络连接' = $suspiciousConnections
        '异常进程检查' = $anomalousProcesses
    }
    
    return $output
}

# 10. 生成报告摘要
function Get-ReportSummary {
    $output = Write-Section "应急响应报告摘要"
    
    $endTime = Get-Date
    $duration = $endTime - $Global:StartTime
    
    $output += "报告生成时间: $endTime`n"
    $output += "扫描耗时: $($duration.TotalSeconds) 秒`n"
    $output += "扫描的主要模块:`n"
    $output += "- 系统信息收集`n"
    $output += "- 用户和权限检查`n"
    $output += "- 进程和服务分析`n"
    $output += "- 网络连接检查`n"
    $output += "- 文件系统检查`n"
    $output += "- 注册表分析`n"
    $output += "- 系统日志分析`n"
    $output += "- 计划任务检查`n"
    $output += "- 恶意软件检测`n"
    
    # 统计信息
    $output += "`n统计信息:`n"
    $output += "- 运行进程数: $(Get-Process | Measure-Object | Select-Object -ExpandProperty Count)`n"
    $output += "- 活动网络连接数: $(Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Measure-Object | Select-Object -ExpandProperty Count)`n"
    $output += "- 监听端口数: $(Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Measure-Object | Select-Object -ExpandProperty Count)`n"
    $output += "- 本地用户数: $(Get-LocalUser | Measure-Object | Select-Object -ExpandProperty Count)`n"
    $output += "- 运行服务数: $(Get-Service | Where-Object {$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count)`n"
    
    return $output
}

# 安全统计汇总函数
function Get-SecurityStatsSummary {
    Write-Host "正在生成安全统计汇总..." -ForegroundColor Green
    
    $output = Write-Section "安全统计汇总"
    
    # 用户安全统计
    $output += Write-SubSection "用户安全统计"
    $output += "用户账户总数: $($Global:SecurityStats['TotalUsers'])`n"
    $output += "启用用户数: $($Global:SecurityStats['EnabledUsers'])`n"
    $output += "禁用用户数: $($Global:SecurityStats['DisabledUsers'])`n"
    $output += "管理员用户数: $($Global:SecurityStats['AdminUsers'])`n"
    $output += "从未登录用户数: $($Global:SecurityStats['NeverLoggedInUsers'])`n"
    $output += "近30天活跃用户数: $($Global:SecurityStats['RecentlyLoggedInUsers'])`n"
    
    # 进程安全统计
    $output += Write-SubSection "进程安全统计"
    $output += "系统进程总数: $($Global:SecurityStats['TotalProcesses'])`n"
    $output += "可疑进程数: $($Global:SecurityStats['SuspiciousProcesses'])`n"
    $output += "高CPU占用进程数: $($Global:SecurityStats['HighCpuProcesses'])`n"
    
    # 网络安全统计
    $output += Write-SubSection "网络安全统计"
    $output += "网络连接总数: $($Global:SecurityStats['NetworkConnections'])`n"
    $output += "可疑网络连接数: $($Global:SecurityStats['SuspiciousConnections'])`n"
    $output += "监听端口数: $($Global:SecurityStats['ListeningPorts'])`n"
    
    # 文件系统统计
    $output += Write-SubSection "文件系统统计"
    $output += "可疑文件数: $($Global:SecurityStats['SuspiciousFiles'])`n"
    
    # 注册表统计
    $output += Write-SubSection "注册表统计"
    $output += "注册表启动项数: $($Global:SecurityStats['RegistryStartupItems'])`n"
    $output += "可疑注册表项数: $($Global:SecurityStats['SuspiciousRegistryItems'])`n"
    
    # 计划任务统计
    $output += Write-SubSection "计划任务统计"
    $output += "计划任务总数: $($Global:SecurityStats['ScheduledTasks'])`n"
    $output += "可疑计划任务数: $($Global:SecurityStats['SuspiciousScheduledTasks'])`n"
    
    # 日志统计
    $output += Write-SubSection "日志统计"
    $output += "安全事件数: $($Global:SecurityStats['SecurityEvents'])`n"
    $output += "登录失败次数: $($Global:SecurityStats['FailedLogins'])`n"
    $output += "系统错误数: $($Global:SecurityStats['SystemErrors'])`n"
    
    # 安全防护状态
    $output += Write-SubSection "安全防护状态"
    $defenderStatus = if ($Global:SecurityStats['DefenderEnabled']) { "✓ 已启用" } else { "✗ 已禁用" }
    $firewallStatus = if ($Global:SecurityStats['FirewallEnabled']) { "✓ 已启用" } else { "✗ 已禁用" }
    $uacStatus = if ($Global:SecurityStats['UACEnabled']) { "✓ 已启用" } else { "✗ 已禁用" }
    
    $output += "Windows Defender: $defenderStatus`n"
    $output += "Windows防火墙: $firewallStatus`n"
    $output += "用户账户控制(UAC): $uacStatus`n"
    
    # 安全风险评估
    $output += Write-SubSection "安全风险评估"
    $riskScore = 0
    $riskFactors = @()
    
    if ($Global:SecurityStats['AdminUsers'] -gt 3) {
        $riskScore += 20
        $riskFactors += "管理员账户过多"
    }
    
    if ($Global:SecurityStats['SuspiciousProcesses'] -gt 0) {
        $riskScore += 30
        $riskFactors += "存在可疑进程"
    }
    
    if ($Global:SecurityStats['SuspiciousConnections'] -gt 0) {
        $riskScore += 25
        $riskFactors += "存在可疑网络连接"
    }
    
    if (-not $Global:SecurityStats['DefenderEnabled']) {
        $riskScore += 15
        $riskFactors += "Windows Defender未启用"
    }
    
    if ($Global:SecurityStats['FailedLogins'] -gt 10) {
        $riskScore += 10
        $riskFactors += "登录失败次数较多"
    }
    
    $riskLevel = switch ($riskScore) {
        {$_ -le 20} { "低风险" }
        {$_ -le 50} { "中等风险" }
        {$_ -le 80} { "高风险" }
        default { "极高风险" }
    }
    
    $output += "风险评分: $riskScore/100`n"
    $output += "风险等级: $riskLevel`n"
    
    if ($riskFactors.Count -gt 0) {
        $output += "风险因素:`n"
        foreach ($factor in $riskFactors) {
            $output += "  - $factor`n"
        }
    }
    
    # 专业建议
    $output += Write-SubSection "专业安全建议"
    
    # 基于具体发现的问题给出针对性建议
    if ($Global:SecurityStats['AdminUsers'] -gt 1) {
        $output += "👥 用户权限管理建议：`n"
        $output += "  • 发现 $($Global:SecurityStats['AdminUsers']) 个管理员账户，建议与运维开发人员确认其必要性`n"
        $output += "  • 除内置Administrator外，其他管理员账户应遵循最小权限原则`n"
        $output += "  • 建议启用账户审计，记录权限变更操作`n"
        $output += "  • 定期审查用户权限分配，清理不必要的高权限账户`n`n"
    }
    
    if ($Global:SecurityStats['SuspiciousProcesses'] -gt 0) {
        $output += "⚙️ 进程安全处置建议：`n"
        $output += "  • 发现 $($Global:SecurityStats['SuspiciousProcesses']) 个可疑进程，建议立即分析其合法性`n"
        $output += "  • 检查可疑进程的数字签名和文件路径`n"
        $output += "  • 分析进程的网络连接和文件访问行为`n"
        $output += "  • 如确认为恶意进程，立即终止并清理相关文件`n`n"
    }
    
    if ($Global:SecurityStats['SuspiciousConnections'] -gt 0) {
        $output += "🌐 网络安全处置建议：`n"
        $output += "  • 发现 $($Global:SecurityStats['SuspiciousConnections']) 个可疑网络连接，建议立即断开`n"
        $output += "  • 分析连接的目标IP地址和端口，确认是否为已知威胁`n"
        $output += "  • 检查防火墙规则，阻断可疑IP地址`n"
        $output += "  • 监控网络流量，识别异常数据传输`n`n"
    }
    
    if ($Global:SecurityStats['NeverLoggedInUsers'] -gt 2) {
        $output += "👤 僵尸账户处置建议：`n"
        $output += "  • 发现 $($Global:SecurityStats['NeverLoggedInUsers']) 个从未登录的账户，建议审查其必要性`n"
        $output += "  • 对于确认不需要的账户，建议禁用或删除`n"
        $output += "  • 对于业务需要的服务账户，确保密码强度和权限最小化`n`n"
    }
    
    if (-not $Global:SecurityStats['DefenderEnabled']) {
        $output += "🛡️ 安全防护加固建议：`n"
        $output += "  • Windows Defender未启用，建议立即启用实时保护`n"
        $output += "  • 更新病毒定义库到最新版本`n"
        $output += "  • 配置定期全盘扫描计划`n`n"
    }
    
    # 应急响应流程建议
    $output += "📋 应急响应流程建议：`n"
    if ($riskScore -le 20) {
        $output += "  ✓ 系统安全状况良好，当前风险等级：$riskLevel`n"
        $output += "  ✓ 建议继续保持当前安全配置和监控`n"
        $output += "  ✓ 定期进行安全检查和系统更新`n"
        $output += "  ✓ 建立基线配置，便于后续对比分析`n"
    } elseif ($riskScore -le 50) {
        $output += "  ⚠️ 系统存在中等安全风险，当前风险等级：$riskLevel`n"
        $output += "  1. 立即处置上述发现的安全问题`n"
        $output += "  2. 加强系统监控，特别关注异常行为`n"
        $output += "  3. 更新所有安全补丁和防护软件`n"
        $output += "  4. 制定详细的安全加固计划`n"
        $output += "  5. 考虑进行专业安全评估`n"
    } else {
        $output += "  🚨 系统存在较高安全风险，当前风险等级：$riskLevel`n"
        $output += "  紧急处置措施（建议在30分钟内完成）：`n"
        $output += "  1. 立即隔离可疑进程和网络连接`n"
        $output += "  2. 断开网络连接（保持系统运行以保护证据）`n"
        $output += "  3. 通知安全团队和管理层`n"
        $output += "  4. 保护现场，避免破坏数字证据`n"
        $output += "  5. 启动应急响应预案`n"
        $output += "  后续处置措施：`n"
        $output += "  6. 进行全面的恶意软件扫描`n"
        $output += "  7. 分析系统日志，确定攻击时间线`n"
        $output += "  8. 评估数据泄露风险`n"
        $output += "  9. 制定系统恢复计划`n"
        $output += "  10. 联系专业安全团队进行深度分析`n"
    }
    
    # 预防措施建议
    $output += "`n🔒 预防措施建议：`n"
    $output += "  • 建立完善的安全监控体系，实时检测异常行为`n"
    $output += "  • 定期进行安全培训，提高员工安全意识`n"
    $output += "  • 制定详细的应急响应预案并定期演练`n"
    $output += "  • 建立威胁情报收集机制，及时了解最新威胁`n"
    $output += "  • 实施多层防护策略，包括网络、主机、应用层防护`n"
    $output += "  • 定期进行渗透测试和安全评估`n"
    
    return $output
}

# 主函数
function Main {
    Write-Host "开始Windows应急响应检查..." -ForegroundColor Green
    Write-Host "报告将保存到: $OutputPath" -ForegroundColor Yellow
    
    $fullReport = ""
    
    # 执行所有检查模块
    $fullReport += Get-SystemInfo
    $fullReport += Get-UserInfo
    $fullReport += Get-ProcessInfo
    $fullReport += Get-NetworkInfo
    $fullReport += Get-FileSystemInfo
    $fullReport += Get-RegistryInfo
    $fullReport += Get-LogAnalysis
    $fullReport += Get-ScheduledTaskInfo
    $fullReport += Get-MalwareDetection
    $fullReport += Get-SecurityStatsSummary
    $fullReport += Get-ReportSummary
    
    # 保存报告
    if ($JsonOutput) {
        $Global:ReportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath.Replace('.txt', '.json') -Encoding UTF8
        Write-Host "JSON报告已保存到: $($OutputPath.Replace('.txt', '.json'))" -ForegroundColor Green
    } else {
        $fullReport | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "报告已保存到: $OutputPath" -ForegroundColor Green
    }
    
    Write-Host "Windows应急响应检查完成!" -ForegroundColor Green
}

# 执行主函数
Main