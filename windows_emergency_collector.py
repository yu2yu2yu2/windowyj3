#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows应急响应数据收集脚本 (Python版)
版本: 2.0 Enhanced
作者: Windows Emergency Response Team
用途: 收集Windows系统应急响应所需的详细信息
"""

import os
import sys
import json
import time
import socket
import psutil
import platform
import subprocess
import winreg
from datetime import datetime, timedelta
import argparse

def print_banner():
    """打印横幅"""
    banner = """
🛡️  Windows应急响应数据收集器 (Python版)
================================================
版本: 2.0 Enhanced
功能: 全面收集Windows系统安全信息
用途: 应急响应、安全评估、威胁检测
================================================
    """
    print(banner)

def safe_execute(func, default="无法获取信息"):
    """安全执行函数，捕获异常"""
    try:
        return func()
    except Exception as e:
        return f"{default}: {str(e)}"

def get_system_info():
    """获取系统基本信息"""
    info = {
        "计算机名": platform.node(),
        "用户名": os.getenv('USERNAME', 'Unknown'),
        "域名": os.getenv('USERDOMAIN', 'Unknown'),
        "操作系统": platform.system(),
        "系统版本": platform.version(),
        "系统架构": platform.architecture()[0],
        "处理器": platform.processor(),
        "Python版本": platform.python_version(),
        "当前时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "系统目录": os.getenv('SystemRoot', 'Unknown'),
        "临时目录": os.getenv('TEMP', 'Unknown')
    }
    
    # 获取内存信息
    try:
        memory = psutil.virtual_memory()
        info["内存总量"] = f"{memory.total / (1024**3):.2f} GB"
        info["内存使用率"] = f"{memory.percent}%"
    except:
        info["内存信息"] = "无法获取"
    
    # 获取磁盘信息
    try:
        disks = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disks.append(f"{partition.device} {usage.total / (1024**3):.2f}GB")
            except:
                continue
        info["磁盘信息"] = ", ".join(disks)
    except:
        info["磁盘信息"] = "无法获取"
    
    return info

def get_user_accounts():
    """获取用户账户信息"""
    users_info = []
    admin_count = 0
    never_login_count = 0
    
    try:
        # 使用net user命令获取用户列表
        result = subprocess.run(['net', 'user'], capture_output=True, text=True, encoding='gbk')
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip() and not line.startswith('-') and not line.startswith('用户') and not line.startswith('命令'):
                    users = line.split()
                    for user in users:
                        if user.strip():
                            # 获取用户详细信息
                            user_detail = subprocess.run(['net', 'user', user], capture_output=True, text=True, encoding='gbk')
                            if user_detail.returncode == 0:
                                user_info = {
                                    "用户名": user,
                                    "详细信息": user_detail.stdout
                                }
                                
                                # 检查是否为管理员
                                admin_check = subprocess.run(['net', 'localgroup', 'administrators'], capture_output=True, text=True, encoding='gbk')
                                if admin_check.returncode == 0 and user in admin_check.stdout:
                                    user_info["管理员权限"] = "是"
                                    admin_count += 1
                                    # 添加可疑管理员检测
                                    if any(keyword in user.lower() for keyword in ['test', 'temp', 'hack', 'admin', 'guest']):
                                        user_info["可疑标记"] = f"⚠️ 管理员: {platform.node()}\\{user} [可疑账户]"
                                else:
                                    user_info["管理员权限"] = "否"
                                
                                # 检查权限级别
                                if "500" in user_detail.stdout:
                                    user_info["权限级别"] = "超级管理员权限"
                                elif user_info["管理员权限"] == "是":
                                    user_info["权限级别"] = "管理员权限"
                                else:
                                    user_info["权限级别"] = "普通用户权限"
                                
                                # 检查登录状态
                                if "从不" in user_detail.stdout or "Never" in user_detail.stdout:
                                    user_info["登录状态"] = "从未登录"
                                    never_login_count += 1
                                
                                users_info.append(user_info)
    except Exception as e:
        users_info.append({"错误": f"无法获取用户信息: {str(e)}"})
    
    return {
        "用户详情": users_info,
        "统计信息": {
            "总用户数": len(users_info),
            "管理员用户数": admin_count,
            "从未登录用户数": never_login_count
        }
    }

def get_process_info():
    """获取进程信息"""
    processes = []
    suspicious_count = 0
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'create_time']):
            try:
                proc_info = proc.info
                process_data = {
                    "进程名": proc_info['name'],
                    "PID": proc_info['pid'],
                    "路径": proc_info['exe'] or "路径未知",
                    "CPU使用": f"{proc_info['cpu_percent']:.2f}%",
                    "内存使用": f"{proc_info['memory_info'].rss / (1024*1024):.2f} MB" if proc_info['memory_info'] else "未知",
                    "启动时间": datetime.fromtimestamp(proc_info['create_time']).strftime("%Y-%m-%d %H:%M:%S") if proc_info['create_time'] else "未知"
                }
                
                # 检查可疑进程
                suspicious_reasons = []
                if proc_info['name'] and any(keyword in proc_info['name'].lower() for keyword in ['powershell', 'cmd', 'wscript', 'cscript']):
                    suspicious_reasons.append("脚本执行进程")
                    suspicious_count += 1
                
                if proc_info['exe'] and any(keyword in proc_info['exe'].lower() for keyword in ['temp', 'tmp', 'appdata', 'downloads']):
                    suspicious_reasons.append("异常路径")
                
                if suspicious_reasons:
                    process_data["可疑标记"] = f"⚠️ 可疑进程: {proc_info['name']} | PID: {proc_info['pid']} | 路径: {proc_info['exe']} [{', '.join(suspicious_reasons)}]"
                
                processes.append(process_data)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        processes.append({"错误": f"无法获取进程信息: {str(e)}"})
    
    return {
        "进程详情": processes[:50],  # 限制前50个进程
        "统计信息": {
            "总进程数": len(processes),
            "可疑进程数": suspicious_count
        }
    }

def get_network_connections():
    """获取网络连接信息"""
    connections = []
    suspicious_count = 0
    
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                conn_data = {
                    "本地地址": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "远程地址": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "未知",
                    "状态": conn.status,
                    "进程ID": conn.pid or "未知"
                }
                
                # 检查可疑连接
                if conn.raddr:
                    suspicious_reasons = []
                    # 检查是否为外网连接
                    if not (conn.raddr.ip.startswith('10.') or 
                           conn.raddr.ip.startswith('172.') or 
                           conn.raddr.ip.startswith('192.168.') or 
                           conn.raddr.ip.startswith('127.')):
                        suspicious_reasons.append("外网连接")
                        suspicious_count += 1
                    
                    # 检查可疑端口
                    if conn.raddr.port in [4444, 1234, 31337, 12345, 54321]:
                        suspicious_reasons.append("可疑端口")
                    
                    if suspicious_reasons:
                        conn_data["可疑标记"] = f"⚠️ 可疑连接: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port} [{', '.join(suspicious_reasons)}]"
                
                connections.append(conn_data)
    except Exception as e:
        connections.append({"错误": f"无法获取网络连接信息: {str(e)}"})
    
    return {
        "连接详情": connections[:30],  # 限制前30个连接
        "统计信息": {
            "活动连接数": len(connections),
            "可疑连接数": suspicious_count
        }
    }

def get_file_system_info():
    """检查文件系统"""
    suspicious_files = []
    temp_dirs = [
        os.getenv('TEMP', ''),
        os.path.join(os.getenv('SystemRoot', ''), 'Temp'),
        os.path.join(os.getenv('USERPROFILE', ''), 'Downloads')
    ]
    
    for temp_dir in temp_dirs:
        if os.path.exists(temp_dir):
            try:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files[:20]:  # 限制每个目录检查20个文件
                        if file.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js')):
                            file_path = os.path.join(root, file)
                            try:
                                stat = os.stat(file_path)
                                file_info = {
                                    "文件路径": file_path,
                                    "大小": f"{stat.st_size / 1024:.2f} KB",
                                    "创建时间": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                                    "修改时间": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                                    "扩展名": os.path.splitext(file)[1],
                                    "可疑标记": f"⚠️ 可疑文件: {file_path}"
                                }
                                suspicious_files.append(file_info)
                            except:
                                continue
                    break  # 只检查第一层目录
            except:
                continue
    
    return {
        "可疑文件": suspicious_files,
        "统计信息": {
            "检查目录数": len(temp_dirs),
            "可疑文件数": len(suspicious_files)
        }
    }

def get_services_info():
    """获取系统服务信息"""
    services = []
    suspicious_count = 0
    
    try:
        result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                              capture_output=True, text=True, encoding='gbk')
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_service = {}
            
            for line in lines:
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    if current_service:
                        # 检查可疑服务
                        service_name = current_service.get('服务名', '').lower()
                        if any(keyword in service_name for keyword in ['temp', 'tmp', 'test', 'hack', 'backdoor']):
                            current_service["可疑标记"] = f"⚠️ 可疑服务: {current_service.get('服务名', '')}"
                            suspicious_count += 1
                        services.append(current_service)
                    
                    current_service = {"服务名": line.split(':', 1)[1].strip()}
                elif line.startswith('DISPLAY_NAME:'):
                    current_service["显示名"] = line.split(':', 1)[1].strip()
                elif line.startswith('STATE'):
                    current_service["状态"] = line.split(':', 1)[1].strip()
            
            # 添加最后一个服务
            if current_service:
                service_name = current_service.get('服务名', '').lower()
                if any(keyword in service_name for keyword in ['temp', 'tmp', 'test', 'hack', 'backdoor']):
                    current_service["可疑标记"] = f"⚠️ 可疑服务: {current_service.get('服务名', '')}"
                    suspicious_count += 1
                services.append(current_service)
                
    except Exception as e:
        services.append({"错误": f"无法获取服务信息: {str(e)}"})
    
    return {
        "服务详情": services[:50],  # 限制前50个服务
        "统计信息": {
            "总服务数": len(services),
            "可疑服务数": suspicious_count
        }
    }

def get_scheduled_tasks():
    """获取计划任务信息"""
    tasks = []
    suspicious_count = 0
    
    try:
        result = subprocess.run(['schtasks', '/query', '/fo', 'csv', '/v'], 
                              capture_output=True, text=True, encoding='gbk')
        if result.returncode == 0:
            lines = result.stdout.split('\n')[1:]  # 跳过标题行
            for line in lines[:30]:  # 限制前30个任务
                if line.strip():
                    fields = line.split(',')
                    if len(fields) > 10:
                        task_name = fields[0].strip('"')
                        task_action = fields[10].strip('"') if len(fields) > 10 else ""
                        
                        task_info = {
                            "任务名": task_name,
                            "状态": fields[3].strip('"') if len(fields) > 3 else "",
                            "操作": task_action,
                            "路径": fields[1].strip('"') if len(fields) > 1 else ""
                        }
                        
                        # 检查可疑任务
                        if any(keyword in task_action.lower() for keyword in ['powershell', 'cmd', 'wscript', 'cscript']):
                            task_info["可疑标记"] = f"⚠️ 可疑任务: {task_name} | 操作: {task_action}"
                            suspicious_count += 1
                        
                        tasks.append(task_info)
    except Exception as e:
        tasks.append({"错误": f"无法获取计划任务信息: {str(e)}"})
    
    return {
        "任务详情": tasks,
        "统计信息": {
            "总任务数": len(tasks),
            "可疑任务数": suspicious_count
        }
    }

def get_defender_status():
    """获取Windows Defender状态"""
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | ConvertTo-Json'], 
                              capture_output=True, text=True, encoding='utf-8')
        if result.returncode == 0:
            defender_data = json.loads(result.stdout)
            return {
                "实时保护": defender_data.get('RealTimeProtectionEnabled', 'Unknown'),
                "反恶意软件": defender_data.get('AntivirusEnabled', 'Unknown'),
                "反间谍软件": defender_data.get('AntispywareEnabled', 'Unknown'),
                "防火墙": defender_data.get('FirewallEnabled', 'Unknown'),
                "最后扫描": defender_data.get('QuickScanStartTime', 'Unknown'),
                "签名版本": defender_data.get('AntivirusSignatureVersion', 'Unknown')
            }
    except:
        pass
    
    return {"状态": "无法获取Windows Defender状态信息"}

def get_registry_startup():
    """获取注册表启动项"""
    startup_items = []
    
    registry_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    ]
    
    for hkey, subkey in registry_keys:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        item_info = {
                            "启动项": name,
                            "路径": subkey,
                            "命令": value
                        }
                        
                        # 检查可疑启动项
                        if any(keyword in name.lower() or keyword in value.lower() 
                              for keyword in ['temp', 'tmp', 'test', 'hack']):
                            item_info["可疑标记"] = f"⚠️ 注册表项: {name} [可疑启动项]"
                        
                        startup_items.append(item_info)
                        i += 1
                    except WindowsError:
                        break
        except:
            continue
    
    return startup_items

def get_event_logs():
    """获取系统日志摘要"""
    try:
        # 获取安全日志
        security_result = subprocess.run([
            'powershell', '-Command', 
            'Get-WinEvent -FilterHashtable @{LogName="Security"; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 100 | Group-Object Id | Select-Object Name, Count | ConvertTo-Json'
        ], capture_output=True, text=True, encoding='utf-8')
        
        login_failures = 0
        if security_result.returncode == 0:
            try:
                events = json.loads(security_result.stdout)
                if isinstance(events, list):
                    for event in events:
                        if event.get('Name') == '4625':  # 登录失败
                            login_failures = event.get('Count', 0)
            except:
                pass
        
        log_info = {
            "安全事件": {
                "登录失败次数": login_failures
            }
        }
        
        if login_failures >= 5:
            log_info["可疑标记"] = f"⚠️ 登录失败: 失败次数: {login_failures} [可能的暴力破解攻击]"
        
        return log_info
    except:
        return {"状态": "无法获取系统日志信息"}

def generate_report(output_file="windows_emergency_report.txt"):
    """生成完整报告"""
    print("🛡️ 开始收集Windows应急响应数据...")
    start_time = datetime.now()
    
    report_data = {
        "报告信息": {
            "生成时间": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "工具版本": "Python Emergency Collector v2.0",
            "收集器": "Python版本"
        }
    }
    
    # 收集各类信息
    sections = [
        ("系统基本信息", get_system_info),
        ("用户账户信息", get_user_accounts),
        ("进程信息", get_process_info),
        ("网络连接信息", get_network_connections),
        ("文件系统检查", get_file_system_info),
        ("系统服务检查", get_services_info),
        ("计划任务检查", get_scheduled_tasks),
        ("Windows Defender状态", get_defender_status),
        ("注册表启动项检查", get_registry_startup),
        ("系统日志摘要", get_event_logs)
    ]
    
    for section_name, func in sections:
        print(f"📊 收集{section_name}...")
        report_data[section_name] = safe_execute(func)
    
    # 生成文本报告
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("================================================================\n")
        f.write("Windows 应急响应报告 (Python版)\n")
        f.write("================================================================\n")
        f.write(f"生成时间: {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"计算机名: {platform.node()}\n")
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
    
    print(f"🎉 数据收集完成!")
    print(f"📄 报告文件: {output_file}")
    print(f"📊 文件大小: {os.path.getsize(output_file) / 1024:.2f} KB")
    print(f"⏱️ 耗时: {duration:.2f} 秒")
    print(f"🔍 请将报告文件上传到 /viewer 界面进行分析")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='Windows应急响应数据收集器 (Python版)')
    parser.add_argument('-o', '--output', default='windows_emergency_report.txt', 
                       help='输出文件路径 (默认: windows_emergency_report.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='显示详细输出')
    
    args = parser.parse_args()
    
    print_banner()
    
    # 检查是否为Windows系统
    if platform.system() != 'Windows':
        print("❌ 此脚本仅支持Windows系统!")
        sys.exit(1)
    
    # 检查管理员权限
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ 建议以管理员权限运行以获取完整信息")
    except:
        pass
    
    try:
        generate_report(args.output)
    except KeyboardInterrupt:
        print("\n❌ 用户中断操作")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 发生错误: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()