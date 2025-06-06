' Windows应急响应数据收集脚本 (VBScript版)
' 版本: 2.0 Enhanced
' 作者: Windows Emergency Response Team
' 用途: 收集Windows系统应急响应所需的详细信息

Option Explicit

Dim objFSO, objShell, objWMI, objNetwork
Dim reportFile, startTime, endTime
Dim suspiciousCount

' 初始化对象
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
Set objWMI = GetObject("winmgmts:\\.\root\cimv2")
Set objNetwork = CreateObject("WScript.Network")

reportFile = "windows_emergency_report.txt"
startTime = Now()
suspiciousCount = 0

' 显示横幅
WScript.Echo ""
WScript.Echo "🛡️ Windows应急响应数据收集器 (VBScript版)"
WScript.Echo "================================================"
WScript.Echo "版本: 2.0 Enhanced"
WScript.Echo "功能: 全面收集Windows系统安全信息"
WScript.Echo "用途: 应急响应、安全评估、威胁检测"
WScript.Echo "================================================"
WScript.Echo ""
WScript.Echo "📁 输出文件: " & reportFile
WScript.Echo "⏰ 开始时间: " & startTime
WScript.Echo ""

' 初始化报告文件
Call InitializeReport()

' 收集各类信息
WScript.Echo "📊 收集系统基本信息..."
Call CollectSystemInfo()

WScript.Echo "👥 收集用户账户信息..."
Call CollectUserInfo()

WScript.Echo "⚙️ 收集进程信息..."
Call CollectProcessInfo()

WScript.Echo "🌐 收集网络连接信息..."
Call CollectNetworkInfo()

WScript.Echo "📁 检查文件系统..."
Call CollectFileSystemInfo()

WScript.Echo "🔧 检查系统服务..."
Call CollectServiceInfo()

WScript.Echo "⏰ 检查计划任务..."
Call CollectScheduledTasks()

WScript.Echo "🛡️ 检查Windows Defender状态..."
Call CollectDefenderStatus()

WScript.Echo "📋 检查注册表启动项..."
Call CollectRegistryStartup()

WScript.Echo "📊 收集系统日志摘要..."
Call CollectEventLogs()

' 完成报告
Call FinalizeReport()

WScript.Echo ""
WScript.Echo "🎉 数据收集完成!"
WScript.Echo "📄 报告文件: " & reportFile
WScript.Echo "📊 文件大小: " & FormatNumber(objFSO.GetFile(reportFile).Size / 1024, 2) & " KB"
WScript.Echo "🔍 请将报告文件上传到 /viewer 界面进行分析"

' 清理对象
Set objFSO = Nothing
Set objShell = Nothing
Set objWMI = Nothing
Set objNetwork = Nothing

' ==================== 函数定义 ====================

Sub InitializeReport()
    Dim objFile
    Set objFile = objFSO.CreateTextFile(reportFile, True)
    
    objFile.WriteLine "================================================================"
    objFile.WriteLine "Windows 应急响应报告 (VBScript版)"
    objFile.WriteLine "================================================================"
    objFile.WriteLine "生成时间: " & startTime
    objFile.WriteLine "计算机名: " & objNetwork.ComputerName
    objFile.WriteLine "用户名: " & objNetwork.UserName
    objFile.WriteLine "域名: " & objNetwork.UserDomain
    objFile.WriteLine "系统目录: " & objShell.ExpandEnvironmentStrings("%SystemRoot%")
    objFile.WriteLine "临时目录: " & objShell.ExpandEnvironmentStrings("%TEMP%")
    objFile.WriteLine "================================================================"
    objFile.WriteLine ""
    
    objFile.Close
    Set objFile = Nothing
End Sub

Sub WriteSection(sectionTitle, content)
    Dim objFile
    Set objFile = objFSO.OpenTextFile(reportFile, 8) ' 8 = ForAppending
    
    objFile.WriteLine ""
    objFile.WriteLine "================================================================"
    objFile.WriteLine sectionTitle
    objFile.WriteLine "================================================================"
    objFile.WriteLine content
    objFile.WriteLine ""
    
    objFile.Close
    Set objFile = Nothing
End Sub

Function SafeExecute(command)
    On Error Resume Next
    Dim result
    result = objShell.Run(command, 0, True)
    If Err.Number <> 0 Then
        SafeExecute = "命令执行失败: " & Err.Description
        Err.Clear
    Else
        SafeExecute = "命令执行成功"
    End If
    On Error GoTo 0
End Function

Sub CollectSystemInfo()
    Dim content, objOS, objCS, objProcessor
    
    On Error Resume Next
    Set objOS = objWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem").ItemIndex(0)
    Set objCS = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem").ItemIndex(0)
    Set objProcessor = objWMI.ExecQuery("SELECT * FROM Win32_Processor").ItemIndex(0)
    
    content = "系统信息概览:" & vbCrLf
    content = content & "- 计算机名: " & objNetwork.ComputerName & vbCrLf
    content = content & "- 用户名: " & objNetwork.UserName & vbCrLf
    content = content & "- 域名: " & objNetwork.UserDomain & vbCrLf
    
    If Not objOS Is Nothing Then
        content = content & "- 操作系统: " & objOS.Caption & vbCrLf
        content = content & "- 系统版本: " & objOS.Version & vbCrLf
        content = content & "- 系统架构: " & objOS.OSArchitecture & vbCrLf
        content = content & "- 安装日期: " & objOS.InstallDate & vbCrLf
        content = content & "- 最后启动: " & objOS.LastBootUpTime & vbCrLf
    End If
    
    If Not objCS Is Nothing Then
        content = content & "- 内存总量: " & FormatNumber(objCS.TotalPhysicalMemory / (1024^3), 2) & " GB" & vbCrLf
    End If
    
    If Not objProcessor Is Nothing Then
        content = content & "- 处理器: " & objProcessor.Name & vbCrLf
    End If
    
    content = content & "- 系统目录: " & objShell.ExpandEnvironmentStrings("%SystemRoot%") & vbCrLf
    content = content & "- 临时目录: " & objShell.ExpandEnvironmentStrings("%TEMP%") & vbCrLf
    content = content & "- 当前时间: " & Now() & vbCrLf
    
    On Error GoTo 0
    Call WriteSection("系统基本信息", content)
End Sub

Sub CollectUserInfo()
    Dim content, objUsers, objUser, objGroups, objGroup
    Dim adminCount, userCount
    
    adminCount = 0
    userCount = 0
    content = "本地用户账户详情:" & vbCrLf & vbCrLf
    
    On Error Resume Next
    Set objUsers = objWMI.ExecQuery("SELECT * FROM Win32_UserAccount WHERE LocalAccount = True")
    
    For Each objUser In objUsers
        userCount = userCount + 1
        content = content & "用户: " & objUser.Name & vbCrLf
        content = content & "- SID: " & objUser.SID & vbCrLf
        content = content & "- 描述: " & objUser.Description & vbCrLf
        content = content & "- 状态: "
        If objUser.Disabled Then
            content = content & "已禁用"
        Else
            content = content & "已启用"
        End If
        content = content & vbCrLf
        
        ' 检查权限级别
        If InStr(objUser.SID, "-500") > 0 Then
            content = content & "- 权限级别: 超级管理员权限" & vbCrLf
            adminCount = adminCount + 1
        End If
        
        ' 检查可疑管理员账户
        If InStr(LCase(objUser.Name), "test") > 0 Or _
           InStr(LCase(objUser.Name), "temp") > 0 Or _
           InStr(LCase(objUser.Name), "hack") > 0 Or _
           InStr(LCase(objUser.Name), "admin") > 0 Or _
           InStr(LCase(objUser.Name), "guest") > 0 Then
            content = content & "- ⚠️ 管理员: " & objNetwork.ComputerName & "\" & objUser.Name & " [可疑账户]" & vbCrLf
            suspiciousCount = suspiciousCount + 1
        End If
        
        content = content & vbCrLf
    Next
    
    content = content & "用户统计信息:" & vbCrLf
    content = content & "- 总用户数: " & userCount & vbCrLf
    content = content & "- 管理员用户数: " & adminCount & vbCrLf
    
    On Error GoTo 0
    Call WriteSection("用户账户信息", content)
End Sub

Sub CollectProcessInfo()
    Dim content, objProcesses, objProcess
    Dim processCount, suspiciousProcessCount
    
    processCount = 0
    suspiciousProcessCount = 0
    content = "当前运行进程详情:" & vbCrLf & vbCrLf
    
    On Error Resume Next
    Set objProcesses = objWMI.ExecQuery("SELECT * FROM Win32_Process")
    
    For Each objProcess In objProcesses
        processCount = processCount + 1
        If processCount <= 50 Then ' 限制显示前50个进程
            content = content & "进程: " & objProcess.Name & vbCrLf
            content = content & "- PID: " & objProcess.ProcessId & vbCrLf
            content = content & "- 路径: " & objProcess.ExecutablePath & vbCrLf
            content = content & "- 命令行: " & objProcess.CommandLine & vbCrLf
            
            ' 检查可疑进程
            If InStr(LCase(objProcess.Name), "powershell") > 0 Or _
               InStr(LCase(objProcess.Name), "cmd") > 0 Or _
               InStr(LCase(objProcess.Name), "wscript") > 0 Or _
               InStr(LCase(objProcess.Name), "cscript") > 0 Then
                content = content & "- ⚠️ 可疑进程: " & objProcess.Name & " | PID: " & objProcess.ProcessId & " | 路径: " & objProcess.ExecutablePath & " [脚本执行进程]" & vbCrLf
                suspiciousProcessCount = suspiciousProcessCount + 1
            End If
            
            ' 检查异常路径
            If Not IsNull(objProcess.ExecutablePath) Then
                If InStr(LCase(objProcess.ExecutablePath), "temp") > 0 Or _
                   InStr(LCase(objProcess.ExecutablePath), "tmp") > 0 Or _
                   InStr(LCase(objProcess.ExecutablePath), "appdata") > 0 Or _
                   InStr(LCase(objProcess.ExecutablePath), "downloads") > 0 Then
                    content = content & "- 路径: " & objProcess.ExecutablePath & " [异常路径]" & vbCrLf
                End If
            End If
            
            content = content & vbCrLf
        End If
    Next
    
    content = content & "进程统计信息:" & vbCrLf
    content = content & "- 总进程数: " & processCount & vbCrLf
    content = content & "- 可疑进程数: " & suspiciousProcessCount & vbCrLf
    
    On Error GoTo 0
    Call WriteSection("进程信息", content)
End Sub

Sub CollectNetworkInfo()
    Dim content
    content = "网络连接信息:" & vbCrLf & vbCrLf
    content = content & "注意: VBScript版本网络连接信息收集有限" & vbCrLf
    content = content & "建议使用PowerShell或Python版本获取详细网络信息" & vbCrLf & vbCrLf
    
    ' 获取网络适配器信息
    On Error Resume Next
    Dim objAdapters, objAdapter
    Set objAdapters = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True")
    
    content = content & "网络适配器配置:" & vbCrLf
    For Each objAdapter In objAdapters
        content = content & "- 适配器: " & objAdapter.Description & vbCrLf
        If Not IsNull(objAdapter.IPAddress) Then
            content = content & "  IP地址: " & Join(objAdapter.IPAddress, ", ") & vbCrLf
        End If
        If Not IsNull(objAdapter.DefaultIPGateway) Then
            content = content & "  网关: " & Join(objAdapter.DefaultIPGateway, ", ") & vbCrLf
        End If
        content = content & vbCrLf
    Next
    
    On Error GoTo 0
    Call WriteSection("网络连接信息", content)
End Sub

Sub CollectFileSystemInfo()
    Dim content, tempDir, sysTemp, downloads
    Dim suspiciousFileCount
    
    suspiciousFileCount = 0
    content = "文件系统安全检查:" & vbCrLf & vbCrLf
    
    tempDir = objShell.ExpandEnvironmentStrings("%TEMP%")
    sysTemp = objShell.ExpandEnvironmentStrings("%SystemRoot%\Temp")
    downloads = objShell.ExpandEnvironmentStrings("%USERPROFILE%\Downloads")
    
    content = content & "临时目录可疑文件检查:" & vbCrLf
    
    ' 检查用户临时目录
    content = content & "检查目录: " & tempDir & vbCrLf
    content = content & CheckSuspiciousFiles(tempDir) & vbCrLf
    
    ' 检查系统临时目录
    content = content & "检查目录: " & sysTemp & vbCrLf
    content = content & CheckSuspiciousFiles(sysTemp) & vbCrLf
    
    ' 检查下载目录
    content = content & "检查目录: " & downloads & vbCrLf
    content = content & CheckSuspiciousFiles(downloads) & vbCrLf
    
    content = content & "文件统计信息:" & vbCrLf
    content = content & "- 检查目录数: 3" & vbCrLf
    content = content & "- 可疑文件数: " & suspiciousFileCount & vbCrLf
    
    Call WriteSection("文件系统检查", content)
End Sub

Function CheckSuspiciousFiles(folderPath)
    Dim result, objFolder, objFiles, objFile
    Dim extensions, ext
    
    result = ""
    extensions = Array(".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js")
    
    On Error Resume Next
    If objFSO.FolderExists(folderPath) Then
        Set objFolder = objFSO.GetFolder(folderPath)
        Set objFiles = objFolder.Files
        
        For Each objFile In objFiles
            For Each ext In extensions
                If LCase(Right(objFile.Name, Len(ext))) = LCase(ext) Then
                    result = result & "⚠️ 可疑文件: " & objFile.Path & vbCrLf
                    result = result & "- 大小: " & FormatNumber(objFile.Size / 1024, 2) & " KB" & vbCrLf
                    result = result & "- 创建时间: " & objFile.DateCreated & vbCrLf
                    result = result & "- 修改时间: " & objFile.DateLastModified & vbCrLf
                    result = result & vbCrLf
                    suspiciousFileCount = suspiciousFileCount + 1
                    Exit For
                End If
            Next
        Next
    Else
        result = "目录不存在或无法访问" & vbCrLf
    End If
    On Error GoTo 0
    
    CheckSuspiciousFiles = result
End Function

Sub CollectServiceInfo()
    Dim content, objServices, objService
    Dim serviceCount, suspiciousServiceCount
    
    serviceCount = 0
    suspiciousServiceCount = 0
    content = "系统服务状态检查:" & vbCrLf & vbCrLf
    
    On Error Resume Next
    Set objServices = objWMI.ExecQuery("SELECT * FROM Win32_Service")
    
    For Each objService In objServices
        serviceCount = serviceCount + 1
        If serviceCount <= 50 Then ' 限制显示前50个服务
            content = content & "服务: " & objService.Name & vbCrLf
            content = content & "- 显示名: " & objService.DisplayName & vbCrLf
            content = content & "- 状态: " & objService.State & vbCrLf
            content = content & "- 启动类型: " & objService.StartMode & vbCrLf
            content = content & "- 路径: " & objService.PathName & vbCrLf
            
            ' 检查可疑服务
            If InStr(LCase(objService.Name), "temp") > 0 Or _
               InStr(LCase(objService.Name), "tmp") > 0 Or _
               InStr(LCase(objService.Name), "test") > 0 Or _
               InStr(LCase(objService.Name), "hack") > 0 Or _
               InStr(LCase(objService.Name), "backdoor") > 0 Then
                content = content & "- ⚠️ 可疑服务: " & objService.Name & " [可疑服务名]" & vbCrLf
                suspiciousServiceCount = suspiciousServiceCount + 1
            End If
            
            content = content & vbCrLf
        End If
    Next
    
    content = content & "服务统计信息:" & vbCrLf
    content = content & "- 总服务数: " & serviceCount & vbCrLf
    content = content & "- 可疑服务数: " & suspiciousServiceCount & vbCrLf
    
    On Error GoTo 0
    Call WriteSection("系统服务检查", content)
End Sub

Sub CollectScheduledTasks()
    Dim content
    content = "计划任务检查:" & vbCrLf & vbCrLf
    content = content & "注意: VBScript版本计划任务信息收集有限" & vbCrLf
    content = content & "建议使用PowerShell或批处理版本获取详细任务信息" & vbCrLf & vbCrLf
    
    ' 尝试通过注册表检查一些计划任务
    On Error Resume Next
    Dim objReg, strKeyPath, arrSubKeys, strSubKey
    Const HKEY_LOCAL_MACHINE = &H80000002
    
    Set objReg = GetObject("winmgmts:\\.\root\default:StdRegProv")
    strKeyPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"
    
    objReg.EnumKey HKEY_LOCAL_MACHINE, strKeyPath, arrSubKeys
    
    If IsArray(arrSubKeys) Then
        content = content & "发现计划任务数量: " & UBound(arrSubKeys) + 1 & vbCrLf
    Else
        content = content & "无法枚举计划任务" & vbCrLf
    End If
    
    On Error GoTo 0
    Call WriteSection("计划任务检查", content)
End Sub

Sub CollectDefenderStatus()
    Dim content
    content = "Windows Defender状态:" & vbCrLf & vbCrLf
    content = content & "注意: VBScript版本Defender状态检查有限" & vbCrLf
    content = content & "建议使用PowerShell版本获取详细Defender信息" & vbCrLf & vbCrLf
    
    ' 尝试检查Windows Defender服务状态
    On Error Resume Next
    Dim objDefenderService
    Set objDefenderService = objWMI.ExecQuery("SELECT * FROM Win32_Service WHERE Name = 'WinDefend'").ItemIndex(0)
    
    If Not objDefenderService Is Nothing Then
        content = content & "Windows Defender服务状态:" & vbCrLf
        content = content & "- 服务名: " & objDefenderService.Name & vbCrLf
        content = content & "- 显示名: " & objDefenderService.DisplayName & vbCrLf
        content = content & "- 状态: " & objDefenderService.State & vbCrLf
        content = content & "- 启动类型: " & objDefenderService.StartMode & vbCrLf
        
        If objDefenderService.State <> "Running" Then
            content = content & "- ⚠️ 实时保护: False [Windows Defender未运行]" & vbCrLf
        Else
            content = content & "- 实时保护: True" & vbCrLf
        End If
    Else
        content = content & "无法找到Windows Defender服务" & vbCrLf
    End If
    
    On Error GoTo 0
    Call WriteSection("Windows Defender状态", content)
End Sub

Sub CollectRegistryStartup()
    Dim content
    content = "注册表启动项检查:" & vbCrLf & vbCrLf
    
    ' 检查常见的启动项注册表位置
    content = content & CheckRegistryKey("HKEY_LOCAL_MACHINE", "SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    content = content & CheckRegistryKey("HKEY_LOCAL_MACHINE", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    content = content & CheckRegistryKey("HKEY_CURRENT_USER", "SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    content = content & CheckRegistryKey("HKEY_CURRENT_USER", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    
    Call WriteSection("注册表启动项检查", content)
End Sub

Function CheckRegistryKey(hive, keyPath)
    Dim result, objReg, arrValueNames, arrValueTypes, strValueName, strValue
    Dim hiveConst
    
    result = hive & "\" & keyPath & ":" & vbCrLf
    
    ' 设置注册表常量
    If hive = "HKEY_LOCAL_MACHINE" Then
        hiveConst = &H80000002
    ElseIf hive = "HKEY_CURRENT_USER" Then
        hiveConst = &H80000001
    Else
        result = result & "不支持的注册表根键" & vbCrLf & vbCrLf
        CheckRegistryKey = result
        Exit Function
    End If
    
    On Error Resume Next
    Set objReg = GetObject("winmgmts:\\.\root\default:StdRegProv")
    
    objReg.EnumValues hiveConst, keyPath, arrValueNames, arrValueTypes
    
    If IsArray(arrValueNames) Then
        Dim i
        For i = 0 To UBound(arrValueNames)
            strValueName = arrValueNames(i)
            objReg.GetStringValue hiveConst, keyPath, strValueName, strValue
            
            result = result & "启动项: " & strValueName & vbCrLf
            result = result & "- 命令: " & strValue & vbCrLf
            
            ' 检查可疑启动项
            If InStr(LCase(strValueName), "temp") > 0 Or _
               InStr(LCase(strValueName), "tmp") > 0 Or _
               InStr(LCase(strValueName), "test") > 0 Or _
               InStr(LCase(strValueName), "hack") > 0 Or _
               InStr(LCase(strValue), "temp") > 0 Or _
               InStr(LCase(strValue), "tmp") > 0 Or _
               InStr(LCase(strValue), "test") > 0 Or _
               InStr(LCase(strValue), "hack") > 0 Then
                result = result & "- ⚠️ 注册表项: " & strValueName & " [可疑启动项]" & vbCrLf
            End If
            
            result = result & vbCrLf
        Next
    Else
        result = result & "无启动项或无法访问" & vbCrLf
    End If
    
    result = result & vbCrLf
    On Error GoTo 0
    
    CheckRegistryKey = result
End Function

Sub CollectEventLogs()
    Dim content
    content = "系统日志摘要 (最近24小时):" & vbCrLf & vbCrLf
    content = content & "注意: VBScript版本事件日志分析有限" & vbCrLf
    content = content & "建议使用PowerShell版本获取详细日志分析" & vbCrLf & vbCrLf
    
    ' 尝试获取一些基本的事件日志信息
    On Error Resume Next
    Dim objEvents, objEvent, eventCount
    eventCount = 0
    
    Set objEvents = objWMI.ExecQuery("SELECT * FROM Win32_NTLogEvent WHERE LogFile = 'Security' AND TimeGenerated > '" & DateAdd("d", -1, Now()) & "'")
    
    For Each objEvent In objEvents
        eventCount = eventCount + 1
        If eventCount > 100 Then Exit For ' 限制处理的事件数量
    Next
    
    content = content & "安全事件统计:" & vbCrLf
    content = content & "- 最近24小时安全事件数: " & eventCount & vbCrLf
    
    If eventCount > 1000 Then
        content = content & "- ⚠️ 安全事件数量异常: " & eventCount & " [可能存在异常活动]" & vbCrLf
    End If
    
    On Error GoTo 0
    Call WriteSection("系统日志摘要", content)
End Sub

Sub FinalizeReport()
    endTime = Now()
    Dim duration, fileSize
    duration = DateDiff("s", startTime, endTime)
    fileSize = objFSO.GetFile(reportFile).Size
    
    Dim content
    content = "报告生成完成" & vbCrLf
    content = content & "================================================================" & vbCrLf
    content = content & "开始时间: " & startTime & vbCrLf
    content = content & "结束时间: " & endTime & vbCrLf
    content = content & "耗时: " & duration & " 秒" & vbCrLf
    content = content & "报告文件: " & reportFile & vbCrLf
    content = content & "文件大小: " & FormatNumber(fileSize / 1024, 2) & " KB" & vbCrLf
    content = content & vbCrLf
    content = content & "建议: 请将此报告文件上传到 /viewer 界面进行详细分析" & vbCrLf
    content = content & "================================================================"
    
    Call WriteSection("", content)
End Sub