#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows应急响应数据收集脚本 (增强版)
版本: 3.0 Enhanced
作者: Windows Emergency Response Team
用途: 全面收集Windows系统应急响应所需的详细信息
特点: 避免PowerShell依赖，使用原生Windows命令和Python库
"""

import os
import sys
import json
import time
import socket
import subprocess
import platform
import winreg
import glob
import hashlib
from datetime import datetime, timedelta
import argparse
import threading
import re

def print_banner():
    """打印横幅"""
    banner = """
🛡️  Windows应急响应数据收集器 (增强版 v3.0)
========================================================
版本: 3.0 Enhanced
功能: 全面收集Windows系统安全信息
特点: 纯Python实现，避免PowerShell依赖
用途: 应急响应、安全评估、威胁检测
========================================================
    """
    print(banner)

def safe_execute_cmd(command, timeout=30):
    """安全执行命令行命令"""
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            encoding='gbk',
            timeout=timeout,
            errors='ignore'
        )
        return result.stdout if result.returncode == 0 else f"命令执行失败: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "命令执行超时"
    except Exception as e:
        return f"命令执行异常: {str(e)}"

def safe_execute(func, default="无法获取信息"):
    """安全执行函数，捕获异常"""
    try:
        return func()
    except Exception as e:
        return f"{default}: {str(e)}"

def get_system_info():
    """获取系统基本信息"""
    print("📊 收集系统基本信息...")
    
    info = {
        "计算机名": os.getenv('COMPUTERNAME', 'Unknown'),
        "用户名": os.getenv('USERNAME', 'Unknown'),
        "域名": os.getenv('USERDOMAIN', 'Unknown'),
        "操作系统": platform.system(),
        "系统版本": platform.version(),
        "系统架构": platform.architecture()[0],
        "处理器": platform.processor(),
        "Python版本": platform.python_version(),
        "当前时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "系统目录": os.getenv('SystemRoot', 'Unknown'),
        "临时目录": os.getenv('TEMP', 'Unknown'),
        "用户配置目录": os.getenv('USERPROFILE', 'Unknown'),
        "程序文件目录": os.getenv('ProgramFiles', 'Unknown')
    }
    
    # 获取详细系统信息
    systeminfo = safe_execute_cmd("systeminfo")
    if "命令执行失败" not in systeminfo:
        lines = systeminfo.split('\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if key and value:
                    info[f"系统_{key}"] = value
    
    # 获取内存信息
    try:
        import psutil
        memory = psutil.virtual_memory()
        info["内存总量"] = f"{memory.total / (1024**3):.2f} GB"
        info["内存使用率"] = f"{memory.percent}%"
        info["可用内存"] = f"{memory.available / (1024**3):.2f} GB"
        
        # 获取磁盘信息
        disks = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append(f"{partition.device} 总计:{usage.total / (1024**3):.2f}GB 已用:{usage.used / (1024**3):.2f}GB 可用:{usage.free / (1024**3):.2f}GB")
            except:
                continue
        info["磁盘信息"] = "; ".join(disks)
        
        # 获取CPU信息
        info["CPU核心数"] = psutil.cpu_count(logical=False)
        info["CPU逻辑核心数"] = psutil.cpu_count(logical=True)
        info["CPU使用率"] = f"{psutil.cpu_percent(interval=1)}%"
        
    except ImportError:
        # 如果没有psutil，使用wmic命令
        wmic_memory = safe_execute_cmd('wmic computersystem get TotalPhysicalMemory /value')
        if "TotalPhysicalMemory=" in wmic_memory:
            try:
                memory_bytes = int(wmic_memory.split('TotalPhysicalMemory=')[1].split()[0])
                info["内存总量"] = f"{memory_bytes / (1024**3):.2f} GB"
            except:
                pass
    
    return info

def get_installed_patches():
    """获取已安装补丁信息"""
    print("🔧 收集已安装补丁信息...")
    
    patches = []
    
    # 使用wmic获取补丁信息
    wmic_output = safe_execute_cmd('wmic qfe list full /format:csv')
    if "命令执行失败" not in wmic_output:
        lines = wmic_output.split('\n')
        for line in lines[1:]:  # 跳过标题行
            if line.strip() and ',' in line:
                fields = line.split(',')
                if len(fields) > 5:
                    patch_info = {
                        "补丁ID": fields[1] if len(fields) > 1 else "",
                        "描述": fields[2] if len(fields) > 2 else "",
                        "安装日期": fields[4] if len(fields) > 4 else "",
                        "安装者": fields[5] if len(fields) > 5 else ""
                    }
                    if patch_info["补丁ID"]:
                        patches.append(patch_info)
    
    return {
        "补丁列表": patches[:50],  # 限制显示前50个补丁
        "统计信息": {
            "已安装补丁数": len(patches),
            "最近30天补丁数": len([p for p in patches if p.get("安装日期") and "2024" in p.get("安装日期", "")])
        }
    }

def get_environment_variables():
    """获取重要环境变量"""
    print("🌍 收集重要环境变量...")
    
    important_vars = [
        'PATH', 'PATHEXT', 'TEMP', 'TMP', 'SystemRoot', 'ProgramFiles', 
        'ProgramFiles(x86)', 'CommonProgramFiles', 'USERPROFILE', 'APPDATA',
        'LOCALAPPDATA', 'ALLUSERSPROFILE', 'PUBLIC', 'PROCESSOR_ARCHITECTURE',
        'PROCESSOR_IDENTIFIER', 'NUMBER_OF_PROCESSORS', 'COMPUTERNAME',
        'USERNAME', 'USERDOMAIN', 'LOGONSERVER', 'SESSIONNAME'
    ]
    
    env_vars = {}
    for var in important_vars:
        value = os.getenv(var)
        if value:
            env_vars[var] = value
    
    # 检查可疑环境变量
    suspicious_vars = []
    for key, value in os.environ.items():
        if any(keyword in key.lower() or keyword in value.lower() 
               for keyword in ['temp', 'tmp', 'hack', 'backdoor', 'malware']):
            suspicious_vars.append(f"{key}={value}")
    
    return {
        "重要环境变量": env_vars,
        "可疑环境变量": suspicious_vars,
        "统计信息": {
            "环境变量总数": len(os.environ),
            "可疑变量数": len(suspicious_vars)
        }
    }

def get_user_accounts():
    """获取用户账户信息"""
    print("👥 收集用户账户信息...")
    
    users_info = []
    admin_count = 0
    never_login_count = 0
    
    # 获取用户列表
    net_user_output = safe_execute_cmd('net user')
    if "命令执行失败" not in net_user_output:
        lines = net_user_output.split('\n')
        users = []
        for line in lines:
            if line.strip() and not line.startswith('-') and not line.startswith('用户') and not line.startswith('User') and not line.startswith('命令'):
                words = line.split()
                users.extend([word for word in words if word.strip()])
        
        # 获取管理员组成员
        admin_output = safe_execute_cmd('net localgroup administrators')
        admin_users = []
        if "命令执行失败" not in admin_output:
            admin_lines = admin_output.split('\n')
            for line in admin_lines:
                if line.strip() and not line.startswith('-') and not line.startswith('别名') and not line.startswith('Alias') and not line.startswith('命令'):
                    admin_users.extend(line.split())
        
        # 获取每个用户的详细信息
        for user in users[:20]:  # 限制处理前20个用户
            if user.strip():
                user_detail = safe_execute_cmd(f'net user "{user}"')
                if "命令执行失败" not in user_detail:
                    user_info = {
                        "用户名": user,
                        "详细信息": user_detail[:500],  # 限制长度
                        "管理员权限": "是" if user in admin_users else "否"
                    }
                    
                    if user in admin_users:
                        admin_count += 1
                        # 检查可疑管理员账户
                        if any(keyword in user.lower() for keyword in ['test', 'temp', 'hack', 'admin', 'guest']):
                            user_info["可疑标记"] = f"⚠️ 管理员: {os.getenv('COMPUTERNAME')}\\{user} [可疑账户]"
                    
                    # 检查登录状态
                    if "从不" in user_detail or "Never" in user_detail:
                        user_info["登录状态"] = "从未登录"
                        never_login_count += 1
                    
                    users_info.append(user_info)
    
    return {
        "用户详情": users_info,
        "管理员列表": admin_users,
        "统计信息": {
            "总用户数": len(users_info),
            "管理员用户数": admin_count,
            "从未登录用户数": never_login_count
        }
    }

def get_process_info():
    """获取进程信息"""
    print("⚙️ 收集进程信息...")
    
    processes = []
    high_cpu_processes = []
    suspicious_processes = []
    
    try:
        import psutil
        
        # 获取所有进程
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'create_time', 'cmdline']):
            try:
                proc_info = proc.info
                
                # 获取CPU使用率
                cpu_percent = proc.cpu_percent(interval=0.1)
                
                process_data = {
                    "进程名": proc_info['name'],
                    "PID": proc_info['pid'],
                    "路径": proc_info['exe'] or "路径未知",
                    "CPU使用": f"{cpu_percent:.2f}%",
                    "内存使用": f"{proc_info['memory_info'].rss / (1024*1024):.2f} MB" if proc_info['memory_info'] else "未知",
                    "启动时间": datetime.fromtimestamp(proc_info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc_info['create_time'] else "未知",
                    "命令行": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else "未知"
                }
                
                # 检查高CPU进程
                if cpu_percent > 10:
                    high_cpu_processes.append(process_data.copy())
                
                # 检查可疑进程
                suspicious_reasons = []
                if proc_info['name'] and any(keyword in proc_info['name'].lower() 
                                           for keyword in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32']):
                    suspicious_reasons.append("脚本执行进程")
                
                if proc_info['exe'] and any(keyword in proc_info['exe'].lower() 
                                          for keyword in ['temp', 'tmp', 'appdata', 'downloads', 'users']):
                    suspicious_reasons.append("异常路径")
                
                if proc_info['cmdline']:
                    cmdline_str = ' '.join(proc_info['cmdline']).lower()
                    if any(keyword in cmdline_str for keyword in ['base64', 'encoded', 'bypass', 'hidden']):
                        suspicious_reasons.append("可疑命令行")
                
                if suspicious_reasons:
                    process_data["可疑标记"] = f"⚠️ 可疑进程: {proc_info['name']} | PID: {proc_info['pid']} | 原因: {', '.join(suspicious_reasons)}"
                    suspicious_processes.append(process_data.copy())
                
                processes.append(process_data)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
    except ImportError:
        # 如果没有psutil，使用tasklist命令
        tasklist_output = safe_execute_cmd('tasklist /v /fo csv')
        if "命令执行失败" not in tasklist_output:
            lines = tasklist_output.split('\n')
            for line in lines[1:]:  # 跳过标题行
                if line.strip() and ',' in line:
                    fields = [field.strip('"') for field in line.split('","')]
                    if len(fields) > 5:
                        process_data = {
                            "进程名": fields[0],
                            "PID": fields[1],
                            "会话名": fields[2],
                            "会话号": fields[3],
                            "内存使用": fields[4],
                            "状态": fields[5] if len(fields) > 5 else "",
                            "用户名": fields[6] if len(fields) > 6 else "",
                            "CPU时间": fields[7] if len(fields) > 7 else "",
                            "窗口标题": fields[8] if len(fields) > 8 else ""
                        }
                        
                        # 检查可疑进程
                        if any(keyword in process_data["进程名"].lower() 
                              for keyword in ['powershell', 'cmd', 'wscript', 'cscript']):
                            process_data["可疑标记"] = f"⚠️ 可疑进程: {process_data['进程名']} | PID: {process_data['PID']}"
                            suspicious_processes.append(process_data.copy())
                        
                        processes.append(process_data)
    
    return {
        "进程详情": processes[:100],  # 限制显示前100个进程
        "高CPU进程": high_cpu_processes[:20],
        "可疑进程": suspicious_processes,
        "统计信息": {
            "总进程数": len(processes),
            "高CPU进程数": len(high_cpu_processes),
            "可疑进程数": len(suspicious_processes)
        }
    }

def get_network_connections():
    """获取网络连接信息"""
    print("🌐 收集网络连接信息...")
    
    connections = []
    listening_ports = []
    suspicious_connections = []
    
    # 获取网络连接
    netstat_output = safe_execute_cmd('netstat -ano')
    if "命令执行失败" not in netstat_output:
        lines = netstat_output.split('\n')
        for line in lines:
            if line.strip() and ('TCP' in line or 'UDP' in line):
                parts = line.split()
                if len(parts) >= 4:
                    protocol = parts[0]
                    local_addr = parts[1]
                    foreign_addr = parts[2] if len(parts) > 2 else ""
                    state = parts[3] if len(parts) > 3 else ""
                    pid = parts[4] if len(parts) > 4 else ""
                    
                    conn_data = {
                        "协议": protocol,
                        "本地地址": local_addr,
                        "远程地址": foreign_addr,
                        "状态": state,
                        "进程ID": pid
                    }
                    
                    # 检查监听端口
                    if state == "LISTENING":
                        listening_ports.append(conn_data.copy())
                    
                    # 检查可疑连接
                    suspicious_reasons = []
                    if foreign_addr and foreign_addr != "*:*":
                        # 检查是否为外网连接
                        if ':' in foreign_addr:
                            ip = foreign_addr.split(':')[0]
                            if not (ip.startswith('10.') or ip.startswith('172.') or 
                                   ip.startswith('192.168.') or ip.startswith('127.') or
                                   ip == '0.0.0.0' or ip == '*'):
                                suspicious_reasons.append("外网连接")
                        
                        # 检查可疑端口
                        if any(port in foreign_addr for port in [':4444', ':1234', ':31337', ':12345', ':54321']):
                            suspicious_reasons.append("可疑端口")
                    
                    if suspicious_reasons:
                        conn_data["可疑标记"] = f"⚠️ 可疑连接: {local_addr} -> {foreign_addr} | 原因: {', '.join(suspicious_reasons)}"
                        suspicious_connections.append(conn_data.copy())
                    
                    connections.append(conn_data)
    
    # 获取网络配置
    ipconfig_output = safe_execute_cmd('ipconfig /all')
    
    # 获取DNS配置
    dns_servers = []
    if "命令执行失败" not in ipconfig_output:
        lines = ipconfig_output.split('\n')
        for line in lines:
            if 'DNS' in line and ':' in line:
                dns_servers.append(line.strip())
    
    return {
        "活动连接": connections[:50],  # 限制显示前50个连接
        "监听端口": listening_ports[:30],
        "可疑连接": suspicious_connections,
        "网络配置": ipconfig_output[:2000] if "命令执行失败" not in ipconfig_output else "无法获取",
        "DNS配置": dns_servers,
        "统计信息": {
            "总连接数": len(connections),
            "监听端口数": len(listening_ports),
            "可疑连接数": len(suspicious_connections)
        }
    }

def get_file_system_info():
    """检查文件系统"""
    print("📁 检查文件系统...")
    
    suspicious_files = []
    recent_modified_files = []
    temp_files = []
    download_files = []
    
    # 检查目录列表
    check_dirs = [
        os.getenv('TEMP', ''),
        os.path.join(os.getenv('SystemRoot', ''), 'Temp'),
        os.path.join(os.getenv('USERPROFILE', ''), 'Downloads'),
        os.path.join(os.getenv('USERPROFILE', ''), 'Desktop'),
        os.path.join(os.getenv('APPDATA', ''), 'Local', 'Temp') if os.getenv('APPDATA') else ''
    ]
    
    # 可疑文件扩展名
    suspicious_extensions = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.com', '.pif']
    
    for check_dir in check_dirs:
        if check_dir and os.path.exists(check_dir):
            try:
                # 检查目录中的文件
                for root, dirs, files in os.walk(check_dir):
                    for file in files[:50]:  # 限制每个目录检查50个文件
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            file_info = {
                                "文件路径": file_path,
                                "文件名": file,
                                "大小": f"{stat.st_size / 1024:.2f} KB",
                                "创建时间": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                                "修改时间": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                "扩展名": os.path.splitext(file)[1].lower()
                            }
                            
                            # 检查可疑文件
                            if file_info["扩展名"] in suspicious_extensions:
                                file_info["可疑标记"] = f"⚠️ 可疑文件: {file_path}"
                                suspicious_files.append(file_info.copy())
                            
                            # 检查最近修改的文件
                            if stat.st_mtime > (time.time() - 7 * 24 * 3600):  # 最近7天
                                recent_modified_files.append(file_info.copy())
                            
                            # 分类存储
                            if 'temp' in check_dir.lower():
                                temp_files.append(file_info.copy())
                            elif 'download' in check_dir.lower():
                                download_files.append(file_info.copy())
                                
                        except (OSError, PermissionError):
                            continue
                    
                    # 只检查第一层目录，避免递归太深
                    if root != check_dir:
                        break
                        
            except (OSError, PermissionError):
                continue
    
    # 检查系统文件完整性
    sfc_output = safe_execute_cmd('sfc /verifyonly')
    
    return {
        "可疑文件": suspicious_files[:50],
        "最近修改文件": recent_modified_files[:30],
        "临时目录文件": temp_files[:20],
        "下载目录文件": download_files[:20],
        "系统文件检查": sfc_output[:1000] if "命令执行失败" not in sfc_output else "无法执行系统文件检查",
        "统计信息": {
            "检查目录数": len([d for d in check_dirs if d and os.path.exists(d)]),
            "可疑文件数": len(suspicious_files),
            "最近修改文件数": len(recent_modified_files),
            "临时文件数": len(temp_files),
            "下载文件数": len(download_files)
        }
    }

def get_services_info():
    """获取系统服务信息"""
    print("🔧 检查系统服务...")
    
    services = []
    running_services = []
    suspicious_services = []
    
    # 使用sc命令获取服务信息
    sc_output = safe_execute_cmd('sc query type= service state= all')
    if "命令执行失败" not in sc_output:
        lines = sc_output.split('\n')
        current_service = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                if current_service:
                    services.append(current_service.copy())
                    if current_service.get('状态') == 'RUNNING':
                        running_services.append(current_service.copy())
                    
                    # 检查可疑服务
                    service_name = current_service.get('服务名', '').lower()
                    if any(keyword in service_name for keyword in ['temp', 'tmp', 'test', 'hack', 'backdoor', 'malware']):
                        current_service["可疑标记"] = f"⚠️ 可疑服务: {current_service.get('服务名', '')}"
                        suspicious_services.append(current_service.copy())
                
                current_service = {"服务名": line.split(':', 1)[1].strip()}
            elif line.startswith('DISPLAY_NAME:'):
                current_service["显示名"] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE'):
                state_info = line.split(':', 1)[1].strip()
                current_service["状态"] = state_info.split()[0] if state_info else ""
        
        # 添加最后一个服务
        if current_service:
            services.append(current_service.copy())
            if current_service.get('状态') == 'RUNNING':
                running_services.append(current_service.copy())
    
    # 获取服务详细信息
    wmic_services = safe_execute_cmd('wmic service get Name,DisplayName,State,StartMode,PathName /format:csv')
    service_details = []
    if "命令执行失败" not in wmic_services:
        lines = wmic_services.split('\n')
        for line in lines[1:]:  # 跳过标题行
            if line.strip() and ',' in line:
                fields = line.split(',')
                if len(fields) >= 5:
                    service_detail = {
                        "显示名": fields[1],
                        "服务名": fields[2],
                        "路径": fields[3],
                        "启动模式": fields[4],
                        "状态": fields[5] if len(fields) > 5 else ""
                    }
                    service_details.append(service_detail)
    
    return {
        "服务详情": services[:100],  # 限制显示前100个服务
        "运行中服务": running_services[:50],
        "可疑服务": suspicious_services,
        "服务详细信息": service_details[:50],
        "统计信息": {
            "总服务数": len(services),
            "运行中服务数": len(running_services),
            "可疑服务数": len(suspicious_services)
        }
    }

def get_startup_items():
    """获取启动项信息"""
    print("🚀 检查启动项...")
    
    startup_items = []
    registry_startup = []
    suspicious_startup = []
    
    # 检查注册表启动项
    registry_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    
    for hkey, subkey in registry_keys:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        item_info = {
                            "启动项名称": name,
                            "注册表路径": f"{hkey}\\{subkey}",
                            "命令": value,
                            "类型": "注册表启动项"
                        }
                        
                        # 检查可疑启动项
                        if any(keyword in name.lower() or keyword in value.lower() 
                              for keyword in ['temp', 'tmp', 'test', 'hack', 'backdoor', 'malware']):
                            item_info["可疑标记"] = f"⚠️ 注册表项: {name} [可疑启动项]"
                            suspicious_startup.append(item_info.copy())
                        
                        registry_startup.append(item_info)
                        startup_items.append(item_info)
                        i += 1
                    except WindowsError:
                        break
        except:
            continue
    
    # 检查启动文件夹
    startup_folders = [
        os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
        os.path.join(os.getenv('ALLUSERSPROFILE', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    ]
    
    for folder in startup_folders:
        if os.path.exists(folder):
            try:
                for file in os.listdir(folder):
                    file_path = os.path.join(folder, file)
                    if os.path.isfile(file_path):
                        item_info = {
                            "启动项名称": file,
                            "文件路径": file_path,
                            "类型": "启动文件夹"
                        }
                        startup_items.append(item_info)
            except:
                continue
    
    # 使用wmic获取启动项
    wmic_startup = safe_execute_cmd('wmic startup get Caption,Command,Location /format:csv')
    wmic_items = []
    if "命令执行失败" not in wmic_startup:
        lines = wmic_startup.split('\n')
        for line in lines[1:]:  # 跳过标题行
            if line.strip() and ',' in line:
                fields = line.split(',')
                if len(fields) >= 3:
                    wmic_item = {
                        "启动项名称": fields[1],
                        "命令": fields[2],
                        "位置": fields[3] if len(fields) > 3 else "",
                        "类型": "WMIC启动项"
                    }
                    wmic_items.append(wmic_item)
                    startup_items.append(wmic_item)
    
    return {
        "所有启动项": startup_items,
        "注册表启动项": registry_startup,
        "可疑启动项": suspicious_startup,
        "WMIC启动项": wmic_items,
        "统计信息": {
            "总启动项数": len(startup_items),
            "注册表启动项数": len(registry_startup),
            "可疑启动项数": len(suspicious_startup)
        }
    }

def get_scheduled_tasks():
    """获取计划任务信息"""
    print("⏰ 检查计划任务...")
    
    tasks = []
    active_tasks = []
    suspicious_tasks = []
    
    # 使用schtasks命令获取计划任务
    schtasks_output = safe_execute_cmd('schtasks /query /fo csv /v')
    if "命令执行失败" not in schtasks_output:
        lines = schtasks_output.split('\n')
        if len(lines) > 1:
            headers = [h.strip('"') for h in lines[0].split(',')]
            for line in lines[1:]:
                if line.strip() and ',' in line:
                    fields = [f.strip('"') for f in line.split(',')]
                    if len(fields) >= len(headers):
                        task_info = dict(zip(headers, fields))
                        
                        # 简化任务信息
                        simplified_task = {
                            "任务名": task_info.get("TaskName", ""),
                            "状态": task_info.get("Status", ""),
                            "下次运行": task_info.get("Next Run Time", ""),
                            "上次运行": task_info.get("Last Run Time", ""),
                            "任务路径": task_info.get("Folder", ""),
                            "执行操作": task_info.get("Task To Run", "")
                        }
                        
                        # 检查活动任务
                        if simplified_task["状态"] in ["Ready", "Running"]:
                            active_tasks.append(simplified_task.copy())
                        
                        # 检查可疑任务
                        task_to_run = simplified_task.get("执行操作", "").lower()
                        if any(keyword in task_to_run for keyword in ['powershell', 'cmd', 'wscript', 'cscript', 'mshta']):
                            simplified_task["可疑标记"] = f"⚠️ 可疑任务: {simplified_task['任务名']} | 操作: {simplified_task['执行操作']}"
                            suspicious_tasks.append(simplified_task.copy())
                        
                        tasks.append(simplified_task)
    
    return {
        "所有任务": tasks[:100],  # 限制显示前100个任务
        "活动任务": active_tasks[:50],
        "可疑任务": suspicious_tasks,
        "统计信息": {
            "总任务数": len(tasks),
            "活动任务数": len(active_tasks),
            "可疑任务数": len(suspicious_tasks)
        }
    }

def get_defender_status():
    """获取Windows Defender状态"""
    print("🛡️ 检查Windows Defender状态...")
    
    defender_info = {}
    
    # 检查Windows Defender服务状态
    sc_defender = safe_execute_cmd('sc query WinDefend')
    if "命令执行失败" not in sc_defender:
        defender_info["服务状态"] = sc_defender
        
        if "RUNNING" in sc_defender:
            defender_info["实时保护"] = "True"
        else:
            defender_info["实时保护"] = "False"
    
    # 尝试获取更多Defender信息
    reg_defender = safe_execute_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender" /s')
    if "命令执行失败" not in reg_defender:
        defender_info["注册表配置"] = reg_defender[:2000]  # 限制长度
    
    # 检查Defender排除项
    exclusions = safe_execute_cmd('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions" /s')
    if "命令执行失败" not in exclusions:
        defender_info["排除项配置"] = exclusions[:1000]
    
    return defender_info

def get_recent_files():
    """获取最近访问的文件记录"""
    print("📋 检查最近访问的文件记录...")
    
    recent_files = []
    
    # 检查最近文档
    recent_docs_path = os.path.join(os.getenv('USERPROFILE', ''), 'Recent')
    if os.path.exists(recent_docs_path):
        try:
            for file in os.listdir(recent_docs_path)[:50]:  # 限制50个文件
                file_path = os.path.join(recent_docs_path, file)
                if os.path.isfile(file_path):
                    try:
                        stat = os.stat(file_path)
                        recent_files.append({
                            "文件名": file,
                            "路径": file_path,
                            "访问时间": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
                            "修改时间": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        })
                    except:
                        continue
        except:
            pass
    
    # 检查浏览器历史记录路径（仅检查是否存在）
    browser_paths = [
        os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'History'),
        os.path.join(os.getenv('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles'),
        os.path.join(os.getenv('LOCALAPPDATA', ''), 'Microsoft', 'Edge', 'User Data', 'Default', 'History')
    ]
    
    browser_info = []
    for path in browser_paths:
        if os.path.exists(path):
            browser_info.append(f"发现浏览器数据: {path}")
    
    return {
        "最近文档": recent_files,
        "浏览器数据": browser_info,
        "统计信息": {
            "最近文档数": len(recent_files),
            "浏览器数据路径数": len(browser_info)
        }
    }

def get_event_logs():
    """获取系统日志摘要"""
    print("📊 收集系统日志摘要...")
    
    log_info = {}
    
    # 使用wevtutil获取事件日志信息
    security_events = safe_execute_cmd('wevtutil qe Security /c:100 /rd:true /f:text')
    if "命令执行失败" not in security_events:
        log_info["安全日志样本"] = security_events[:2000]  # 限制长度
        
        # 统计登录失败
        login_failures = security_events.count("Event ID: 4625")
        if login_failures >= 5:
            log_info["可疑标记"] = f"⚠️ 登录失败: 失败次数: {login_failures} [可能的暴力破解攻击]"
        
        log_info["登录失败次数"] = login_failures
    
    # 获取系统日志
    system_events = safe_execute_cmd('wevtutil qe System /c:50 /rd:true /f:text')
    if "命令执行失败" not in system_events:
        log_info["系统日志样本"] = system_events[:2000]
        
        # 统计错误事件
        error_count = system_events.count("Level: Error")
        log_info["系统错误数"] = error_count
    
    # 获取应用程序日志
    app_events = safe_execute_cmd('wevtutil qe Application /c:50 /rd:true /f:text')
    if "命令执行失败" not in app_events:
        log_info["应用程序日志样本"] = app_events[:2000]
        
        # 统计应用程序错误
        app_error_count = app_events.count("Level: Error")
        log_info["应用程序错误数"] = app_error_count
    
    return log_info

def generate_report(output_file="windows_emergency_report.txt"):
    """生成完整报告"""
    print_banner()
    print("🛡️ 开始收集Windows应急响应数据...")
    start_time = datetime.now()
    
    # 检查是否为Windows系统
    if platform.system() != 'Windows':
        print("❌ 此脚本仅支持Windows系统!")
        return False
    
    # 检查管理员权限
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ 建议以管理员权限运行以获取完整信息")
    except:
        pass
    
    report_data = {
        "报告信息": {
            "生成时间": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "工具版本": "Enhanced Emergency Collector v3.0",
            "收集器": "Python增强版本"
        }
    }
    
    # 收集各类信息
    sections = [
        ("系统基本信息", get_system_info),
        ("已安装补丁信息", get_installed_patches),
        ("重要环境变量", get_environment_variables),
        ("用户账户信息", get_user_accounts),
        ("进程信息", get_process_info),
        ("网络连接信息", get_network_connections),
        ("文件系统检查", get_file_system_info),
        ("系统服务检查", get_services_info),
        ("启动项检查", get_startup_items),
        ("计划任务检查", get_scheduled_tasks),
        ("Windows Defender状态", get_defender_status),
        ("最近访问文件记录", get_recent_files),
        ("系统日志摘要", get_event_logs)
    ]
    
    for section_name, func in sections:
        try:
            print(f"📊 收集{section_name}...")
            report_data[section_name] = func()
        except Exception as e:
            print(f"❌ 收集{section_name}失败: {str(e)}")
            report_data[section_name] = f"收集失败: {str(e)}"
    
    # 生成文本报告
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("================================================================\n")
            f.write("Windows 应急响应报告 (增强版 v3.0)\n")
            f.write("================================================================\n")
            f.write(f"生成时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"计算机名: {os.getenv('COMPUTERNAME', 'Unknown')}\n")
            f.write(f"用户名: {os.getenv('USERNAME', 'Unknown')}\n")
            f.write(f"操作系统: {platform.system()} {platform.version()}\n")
            f.write("================================================================\n\n")
            
            for section_name, data in report_data.items():
                if section_name == "报告信息":
                    continue
                    
                f.write(f"\n================================================================\n")
                f.write(f"{section_name}\n")
                f.write(f"================================================================\n")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(value, list):
                            f.write(f"\n{key}:\n")
                            for item in value:
                                if isinstance(item, dict):
                                    for k, v in item.items():
                                        f.write(f"- {k}: {v}\n")
                                    f.write("\n")
                                else:
                                    f.write(f"- {item}\n")
                        elif isinstance(value, dict):
                            f.write(f"\n{key}:\n")
                            for k, v in value.items():
                                f.write(f"- {k}: {v}\n")
                        else:
                            f.write(f"{key}: {value}\n")
                else:
                    f.write(f"{data}\n")
                
                f.write("\n")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # 添加报告总结
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write("\n================================================================\n")
            f.write("报告生成完成\n")
            f.write("================================================================\n")
            f.write(f"开始时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"耗时: {duration:.2f} 秒\n")
            f.write(f"报告文件: {output_file}\n")
            f.write(f"文件大小: {os.path.getsize(output_file) / 1024:.2f} KB\n")
            f.write("\n建议: 请将此报告文件上传到 /viewer 界面进行详细分析\n")
            f.write("================================================================\n")
        
        print(f"\n🎉 数据收集完成!")
        print(f"📄 报告文件: {output_file}")
        print(f"📊 文件大小: {os.path.getsize(output_file) / 1024:.2f} KB")
        print(f"⏱️ 耗时: {duration:.2f} 秒")
        print(f"🔍 请将报告文件上传到 /viewer 界面进行分析")
        
        return True
        
    except Exception as e:
        print(f"❌ 生成报告失败: {str(e)}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Windows应急响应数据收集器 (增强版 v3.0)')
    parser.add_argument('-o', '--output', default='windows_emergency_report.txt', 
                       help='输出文件路径 (默认: windows_emergency_report.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='显示详细输出')
    
    args = parser.parse_args()
    
    try:
        success = generate_report(args.output)
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ 用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 发生错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()