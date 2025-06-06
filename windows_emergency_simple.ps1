# Windows应急响应数据收集脚本 (简化版)
# 解决兼容性问题，适用于所有Windows版本

param(
    [string]$OutputPath = "windows_emergency_report.txt"
)

Write-Host "🛡️ Windows应急响应数据收集开始..." -ForegroundColor Green

# 初始化报告文件
$StartTime = Get-Date
$ReportContent = @"
================================================================
Windows 应急响应报告 (简化版)
================================================================
生成时间: $StartTime
计算机名: $env:COMPUTERNAME
用户名: $env:USERNAME
操作系统: $((Get-WmiObject Win32_OperatingSystem).Caption)
================================================================

"@

# 1. 系统基本信息
Write-Host "📊 收集系统基本信息..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
系统基本信息
================================================================
系统信息概览:
- 计算机名: $env:COMPUTERNAME
- 用户名: $env:USERNAME
- 域名: $env:USERDOMAIN
- 操作系统: $((Get-WmiObject Win32_OperatingSystem).Caption)
- 系统版本: $((Get-WmiObject Win32_OperatingSystem).Version)
- 系统目录: $env:SystemRoot
- 临时目录: $env:TEMP
- 当前时间: $(Get-Date)

"@

# 2. 用户账户信息
Write-Host "👥 收集用户账户信息..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
用户账户信息
================================================================
本地用户账户详情:

"@

try {
    $Users = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True"
    $AdminCount = 0
    
    foreach ($User in $Users) {
        $ReportContent += @"
用户: $($User.Name)
- SID: $($User.SID)
- 描述: $($User.Description)
- 状态: $(if($User.Disabled){"已禁用"}else{"已启用"})

"@
        
        # 检查可疑管理员账户
        if ($User.Name -match "test|temp|hack|admin|guest") {
            $ReportContent += "⚠️ 管理员: $env:COMPUTERNAME\$($User.Name) [可疑账户]`n"
            $AdminCount++
        }
    }
    
    $ReportContent += @"

用户统计信息:
- 总用户数: $($Users.Count)
- 管理员用户数: $AdminCount

"@
} catch {
    $ReportContent += "无法获取用户信息: $($_.Exception.Message)`n"
}

# 3. 进程信息
Write-Host "⚙️ 收集进程信息..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
进程信息
================================================================
当前运行进程详情:

"@

try {
    $Processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 30
    $SuspiciousCount = 0
    
    foreach ($Process in $Processes) {
        $ProcessPath = if ($Process.Path) { $Process.Path } else { "路径未知" }
        
        $ReportContent += @"
进程: $($Process.ProcessName)
- PID: $($Process.Id)
- 路径: $ProcessPath

"@
        
        # 检查可疑进程
        if ($Process.ProcessName -match "powershell|cmd|wscript|cscript") {
            $ReportContent += "⚠️ 可疑进程: $($Process.ProcessName) | PID: $($Process.Id) | 路径: $ProcessPath`n"
            $SuspiciousCount++
        }
        
        # 检查异常路径
        if ($ProcessPath -match "temp|tmp|appdata|downloads") {
            $ReportContent += "路径: $ProcessPath [异常路径]`n"
        }
    }
    
    $ReportContent += @"

进程统计信息:
- 总进程数: $($Processes.Count)
- 可疑进程数: $SuspiciousCount

"@
} catch {
    $ReportContent += "无法获取进程信息: $($_.Exception.Message)`n"
}

# 4. 网络连接信息
Write-Host "🌐 收集网络连接信息..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
网络连接信息
================================================================
网络连接详情:

"@

try {
    # 使用netstat命令获取网络连接
    $NetstatOutput = netstat -an
    $SuspiciousConnections = 0
    
    foreach ($Line in $NetstatOutput) {
        if ($Line -match "ESTABLISHED") {
            $ReportContent += "$Line`n"
            
            # 检查可疑端口
            if ($Line -match ":4444|:1234|:31337|:12345|:54321") {
                $ReportContent += "⚠️ 可疑连接: $Line [可疑端口]`n"
                $SuspiciousConnections++
            }
        }
    }
    
    $ReportContent += @"

网络统计信息:
- 可疑连接数: $SuspiciousConnections

"@
} catch {
    $ReportContent += "无法获取网络连接信息: $($_.Exception.Message)`n"
}

# 5. 文件系统检查
Write-Host "📁 检查文件系统..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
文件系统检查
================================================================
文件系统安全检查:

"@

try {
    $SuspiciousFiles = @()
    $TempDirs = @($env:TEMP, "$env:SystemRoot\Temp")
    
    foreach ($TempDir in $TempDirs) {
        if (Test-Path $TempDir) {
            $ReportContent += "检查目录: $TempDir`n"
            
            $Files = Get-ChildItem -Path $TempDir -File -ErrorAction SilentlyContinue | 
                     Where-Object {$_.Extension -match "\.(exe|bat|cmd|ps1|vbs|js)$"} |
                     Select-Object -First 10
            
            foreach ($File in $Files) {
                $ReportContent += @"
⚠️ 可疑文件: $($File.FullName)
- 大小: $([math]::Round($File.Length/1KB, 2)) KB
- 创建时间: $($File.CreationTime)
- 修改时间: $($File.LastWriteTime)

"@
                $SuspiciousFiles += $File
            }
        }
    }
    
    $ReportContent += @"

文件统计信息:
- 可疑文件数: $($SuspiciousFiles.Count)

"@
} catch {
    $ReportContent += "无法检查文件系统: $($_.Exception.Message)`n"
}

# 6. 系统服务检查
Write-Host "🔧 检查系统服务..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
系统服务检查
================================================================
系统服务状态检查:

"@

try {
    $Services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 20
    $SuspiciousServices = 0
    
    foreach ($Service in $Services) {
        if ($Service.Name -match "temp|tmp|test|hack|backdoor") {
            $ReportContent += @"
⚠️ 可疑服务: $($Service.Name)
- 显示名: $($Service.DisplayName)
- 状态: $($Service.Status)

"@
            $SuspiciousServices++
        }
    }
    
    $ReportContent += @"

服务统计信息:
- 运行中服务数: $($Services.Count)
- 可疑服务数: $SuspiciousServices

"@
} catch {
    $ReportContent += "无法获取服务信息: $($_.Exception.Message)`n"
}

# 7. Windows Defender状态
Write-Host "🛡️ 检查Windows Defender状态..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
Windows Defender状态
================================================================

"@

try {
    # 尝试获取Windows Defender状态
    $DefenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($DefenderService) {
        $ReportContent += @"
Windows Defender服务状态:
- 服务状态: $($DefenderService.Status)
- 启动类型: $($DefenderService.StartType)

"@
        
        if ($DefenderService.Status -ne "Running") {
            $ReportContent += "实时保护: False`n"
        } else {
            $ReportContent += "实时保护: True`n"
        }
    } else {
        $ReportContent += "Windows Defender服务未找到`n"
    }
} catch {
    $ReportContent += "无法获取Windows Defender状态: $($_.Exception.Message)`n"
}

# 8. 注册表启动项检查
Write-Host "📋 检查注册表启动项..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
注册表启动项检查
================================================================
注册表启动项:

"@

try {
    $StartupKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($Key in $StartupKeys) {
        if (Test-Path $Key) {
            $ReportContent += "`n$Key :`n"
            $Items = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue
            if ($Items) {
                $Items.PSObject.Properties | Where-Object {$_.Name -notmatch "^PS"} | ForEach-Object {
                    $ReportContent += "启动项: $($_.Name) = $($_.Value)`n"
                    
                    # 检查可疑启动项
                    if ($_.Name -match "temp|tmp|test|hack" -or $_.Value -match "temp|tmp|test|hack") {
                        $ReportContent += "⚠️ 注册表项: $($_.Name) [可疑启动项]`n"
                    }
                }
            }
        }
    }
} catch {
    $ReportContent += "无法检查注册表启动项: $($_.Exception.Message)`n"
}

# 9. 系统日志摘要
Write-Host "📊 收集系统日志摘要..." -ForegroundColor Cyan
$ReportContent += @"

================================================================
系统日志摘要
================================================================
系统日志摘要 (最近24小时):

"@

try {
    # 简化的日志检查
    $ReportContent += "注意: 简化版本的日志分析功能有限`n"
    $ReportContent += "建议使用完整版PowerShell脚本获取详细日志信息`n"
} catch {
    $ReportContent += "无法获取系统日志信息: $($_.Exception.Message)`n"
}

# 完成报告
$EndTime = Get-Date
$Duration = $EndTime - $StartTime

$ReportContent += @"

================================================================
报告生成完成
================================================================
开始时间: $StartTime
结束时间: $EndTime
耗时: $($Duration.TotalSeconds) 秒
报告文件: $OutputPath

建议: 请将此报告文件上传到 /viewer 界面进行详细分析
================================================================
"@

# 写入文件
$ReportContent | Out-File -FilePath $OutputPath -Encoding UTF8

Write-Host "🎉 数据收集完成!" -ForegroundColor Green
Write-Host "📄 报告文件: $OutputPath" -ForegroundColor Yellow
Write-Host "📊 文件大小: $([math]::Round((Get-Item $OutputPath).Length/1KB, 2)) KB" -ForegroundColor Yellow
Write-Host "⏱️ 耗时: $($Duration.TotalSeconds) 秒" -ForegroundColor Yellow
Write-Host "🔍 请将报告文件上传到 /viewer 界面进行分析" -ForegroundColor Cyan