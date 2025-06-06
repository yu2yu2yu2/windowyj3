#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Windows应急响应规则引擎和Web服务器
作者: Security Team
版本: 1.0
描述: Windows系统安全检查结果的智能分析和Web展示
"""

import os
import re
import json
import datetime
import logging
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('windows_emergency.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
CORS(app)

# Windows安全规则库
WINDOWS_SECURITY_RULES = [
    {
        "id": "WIN001",
        "name": "管理员账户异常",
        "description": "检测到异常的管理员账户",
        "pattern": r"管理员.*(?:test|temp|hack|admin|guest)",
        "severity": "high",
        "category": "user_security"
    },
    {
        "id": "WIN002", 
        "name": "可疑进程检测",
        "description": "发现可疑的进程活动",
        "pattern": r"可疑进程.*(?:powershell|cmd|wscript|cscript)",
        "severity": "medium",
        "category": "process_security"
    },
    {
        "id": "WIN003",
        "name": "异常网络连接",
        "description": "检测到可疑的网络连接",
        "pattern": r"可疑连接.*(?:\d+\.\d+\.\d+\.\d+)",
        "severity": "high",
        "category": "network_security"
    },
    {
        "id": "WIN004",
        "name": "登录失败攻击",
        "description": "检测到暴力破解攻击",
        "pattern": r"登录失败.*失败次数:\s*([5-9]|\d{2,})",
        "severity": "high",
        "category": "authentication"
    },
    {
        "id": "WIN005",
        "name": "可疑文件发现",
        "description": "在临时目录发现可疑文件",
        "pattern": r"可疑文件.*\.(?:exe|bat|cmd|ps1|vbs|js)",
        "severity": "medium",
        "category": "file_security"
    },
    {
        "id": "WIN006",
        "name": "注册表启动项异常",
        "description": "检测到可疑的注册表启动项",
        "pattern": r"注册表项.*(?:temp|tmp|test|hack)",
        "severity": "medium",
        "category": "persistence"
    },
    {
        "id": "WIN007",
        "name": "系统服务异常",
        "description": "发现异常的系统服务",
        "pattern": r"可疑服务.*(?:temp|tmp|test|hack|backdoor)",
        "severity": "high",
        "category": "service_security"
    },
    {
        "id": "WIN008",
        "name": "计划任务异常",
        "description": "检测到可疑的计划任务",
        "pattern": r"可疑任务.*(?:powershell|cmd|wscript|cscript)",
        "severity": "medium",
        "category": "scheduled_tasks"
    },
    {
        "id": "WIN009",
        "name": "Windows Defender关闭",
        "description": "Windows Defender实时保护已关闭",
        "pattern": r"实时保护:\s*False",
        "severity": "high",
        "category": "antivirus"
    },
    {
        "id": "WIN010",
        "name": "异常进程路径",
        "description": "进程运行在异常路径",
        "pattern": r"路径:.*(?:temp|tmp|appdata|downloads).*\.exe",
        "severity": "medium",
        "category": "process_security"
    },
    {
        "id": "WIN011",
        "name": "管理员账户过多",
        "description": "系统中管理员账户数量异常",
        "pattern": r"管理员用户数:\s*([4-9]|\d{2,})",
        "severity": "medium",
        "category": "user_security"
    },
    {
        "id": "WIN012",
        "name": "高权限用户检测",
        "description": "检测到超级管理员权限用户",
        "pattern": r"权限级别:\s*超级管理员权限",
        "severity": "low",
        "category": "user_security"
    },
    {
        "id": "WIN013",
        "name": "从未登录用户异常",
        "description": "存在大量从未登录的用户账户",
        "pattern": r"从未登录用户数:\s*([3-9]|\d{2,})",
        "severity": "low",
        "category": "user_security"
    },
    {
        "id": "WIN014",
        "name": "可疑进程数量异常",
        "description": "系统中可疑进程数量较多",
        "pattern": r"可疑进程数:\s*([1-9]\d*)",
        "severity": "high",
        "category": "process_security"
    },
    {
        "id": "WIN015",
        "name": "外网连接异常",
        "description": "检测到外网连接",
        "pattern": r"类型:\s*外网连接",
        "severity": "medium",
        "category": "network_security"
    },
    {
        "id": "WIN016",
        "name": "高风险端口监听",
        "description": "检测到高风险端口监听",
        "pattern": r"监听:.*:(4444|5555|6666|7777|8888|9999|1234|31337)",
        "severity": "high",
        "category": "network_security"
    },
    {
        "id": "WIN017",
        "name": "RDP端口开放",
        "description": "检测到RDP端口开放",
        "pattern": r"监听:.*:3389.*RDP",
        "severity": "medium",
        "category": "network_security"
    },
    {
        "id": "WIN018",
        "name": "安全风险评估高",
        "description": "系统安全风险评估为高风险",
        "pattern": r"风险等级:\s*(高风险|极高风险)",
        "severity": "high",
        "category": "risk_assessment"
    },
    {
        "id": "WIN019",
        "name": "安全防护未启用",
        "description": "重要安全防护功能未启用",
        "pattern": r"(Windows Defender|Windows防火墙|用户账户控制):\s*✗\s*已禁用",
        "severity": "high",
        "category": "security_protection"
    },
    {
        "id": "WIN020",
        "name": "登录失败次数过多",
        "description": "系统登录失败次数异常",
        "pattern": r"登录失败次数:\s*([1-9]\d+)",
        "severity": "medium",
        "category": "authentication"
    },
    {
        "id": "WIN021",
        "name": "自定义管理员账户",
        "description": "检测到自定义管理员账户",
        "pattern": r"分类:\s*自定义管理员.*安全风险:\s*需要验证",
        "severity": "medium",
        "category": "user_security"
    },
    {
        "id": "WIN022",
        "name": "权限过度分配",
        "description": "检测到权限过度分配风险",
        "pattern": r"存在权限过度分配风险",
        "severity": "high",
        "category": "user_security"
    },
    {
        "id": "WIN023",
        "name": "高CPU占用进程",
        "description": "检测到高CPU占用进程",
        "pattern": r"高CPU占用进程数.*:\s*([1-9]\d*)",
        "severity": "low",
        "category": "process_security"
    },
    {
        "id": "WIN024",
        "name": "系统进程数量异常",
        "description": "系统进程数量异常",
        "pattern": r"系统进程总数:\s*([2-9]\d{2,})",
        "severity": "low",
        "category": "process_security"
    }
]

def analyze_windows_report(content):
    """分析Windows应急响应报告"""
    alerts = []
    stats = {
        'total_rules_checked': len(WINDOWS_SECURITY_RULES),
        'alerts_by_severity': {'high': 0, 'medium': 0, 'low': 0},
        'alerts_by_category': {},
        'total_alerts': 0
    }
    
    for rule in WINDOWS_SECURITY_RULES:
        matches = re.finditer(rule["pattern"], content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            alert = {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "category": rule["category"],
                "matched_text": match.group(0),
                "line_number": content[:match.start()].count('\n') + 1
            }
            alerts.append(alert)
            
            # 更新统计信息
            stats['alerts_by_severity'][rule["severity"]] += 1
            if rule["category"] not in stats['alerts_by_category']:
                stats['alerts_by_category'][rule["category"]] = 0
            stats['alerts_by_category'][rule["category"]] += 1
    
    stats['total_alerts'] = len(alerts)
    
    # 添加统计信息到结果中
    for alert in alerts:
        alert['stats'] = stats
    
    return alerts

def generate_windows_recommendations(alerts):
    """生成Windows安全建议"""
    recommendations = []
    
    categories = {}
    for alert in alerts:
        category = alert["category"]
        if category not in categories:
            categories[category] = []
        categories[category].append(alert)
    
    if "user_security" in categories:
        user_alerts = categories["user_security"]
        high_privilege_count = len([a for a in user_alerts if "超级管理员权限" in a.get("matched_text", "")])
        admin_count = len([a for a in user_alerts if "管理员账户过多" in a.get("rule_name", "")])
        never_login_count = len([a for a in user_alerts if "从未登录" in a.get("matched_text", "")])
        
        # 生成针对性的用户安全建议
        actions = []
        risk_level = "低"
        
        if high_privilege_count > 0:
            risk_level = "高"
            actions.extend([
                f"🚨 紧急：发现 {high_privilege_count} 个具有超级管理员权限的用户",
                "立即与运维开发人员确认这些账户的业务必要性和合法性",
                "如果是攻击者创建的账户，立即禁用并分析攻击路径",
                "检查这些账户的最近活动记录和登录历史"
            ])
        
        if admin_count > 0:
            if risk_level != "高":
                risk_level = "中等"
            actions.extend([
                f"⚠️ 发现管理员账户数量异常（{admin_count}个），存在权限滥用风险",
                "建议将非必要的管理员账户降级为普通用户",
                "对确需管理员权限的账户，实施严格的审批和监控流程"
            ])
        
        if never_login_count > 2:
            actions.extend([
                f"发现 {never_login_count} 个从未登录的账户，可能存在僵尸账户",
                "审查这些账户的创建目的，禁用或删除不必要的账户",
                "对于服务账户，确保密码强度和权限最小化"
            ])
        
        # 通用用户安全建议
        actions.extend([
            "🔒 用户安全加固措施：",
            "• 启用账户锁定策略（建议：5次失败后锁定30分钟）",
            "• 实施强密码策略（最少12位，包含大小写字母、数字、特殊字符）",
            "• 启用密码历史记录，防止重复使用旧密码",
            "• 配置账户审计策略，记录所有权限变更操作",
            "• 定期（建议每季度）进行用户权限审查",
            "• 考虑实施多因素认证（MFA）"
        ])
        
        recommendations.append({
            "category": "用户安全",
            "priority": "高",
            "risk_level": risk_level,
            "affected_count": len(user_alerts),
            "actions": actions,
            "emergency_actions": [
                "如发现可疑管理员账户，立即禁用并通知安全团队",
                "检查所有管理员账户的最近登录记录",
                "审查用户权限变更日志"
            ] if high_privilege_count > 0 else []
        })
    
    if "process_security" in categories:
        process_alerts = categories["process_security"]
        suspicious_count = len([a for a in process_alerts if "可疑进程" in a.get("rule_name", "")])
        high_cpu_count = len([a for a in process_alerts if "CPU占用" in a.get("rule_name", "")])
        
        actions = []
        risk_level = "中等"
        
        if suspicious_count > 0:
            risk_level = "高"
            actions.extend([
                f"🚨 发现 {suspicious_count} 个可疑进程，需要立即处置",
                "使用任务管理器或Process Explorer查看进程详细信息",
                "检查进程的文件路径、数字签名和版本信息",
                "分析进程的网络连接和文件访问行为",
                "如确认为恶意进程，立即终止并隔离相关文件"
            ])
        
        if high_cpu_count > 0:
            actions.extend([
                f"发现 {high_cpu_count} 个高CPU占用进程，可能影响系统性能",
                "分析这些进程是否为正常业务需要",
                "检查是否存在挖矿木马或其他恶意软件"
            ])
        
        actions.extend([
            "⚙️ 进程安全加固措施：",
            "• 部署应用程序白名单，只允许授权程序运行",
            "• 启用Windows Defender应用程序控制（WDAC）",
            "• 配置进程监控和告警机制",
            "• 定期更新应用程序和系统补丁",
            "• 使用Sysmon等工具增强进程监控能力",
            "• 实施代码签名验证策略"
        ])
        
        recommendations.append({
            "category": "进程安全",
            "priority": "高",
            "risk_level": risk_level,
            "affected_count": len(process_alerts),
            "actions": actions,
            "emergency_actions": [
                "立即终止可疑进程",
                "隔离可疑文件进行分析",
                "检查进程创建的文件和注册表项"
            ] if suspicious_count > 0 else []
        })
    
    if "network_security" in categories:
        network_alerts = categories["network_security"]
        suspicious_connections = len([a for a in network_alerts if "可疑连接" in a.get("rule_name", "")])
        external_connections = len([a for a in network_alerts if "外网连接" in a.get("rule_name", "")])
        
        actions = []
        risk_level = "中等"
        
        if suspicious_connections > 0:
            risk_level = "高"
            actions.extend([
                f"🚨 发现 {suspicious_connections} 个可疑网络连接，可能存在数据泄露风险",
                "立即断开可疑连接，但保持系统运行以保护证据",
                "分析连接的目标IP地址和端口，查询威胁情报",
                "检查连接对应的进程，确认其合法性",
                "监控网络流量，识别异常数据传输"
            ])
        
        if external_connections > 5:
            actions.extend([
                f"发现 {external_connections} 个外网连接，需要审查其必要性",
                "确认所有外网连接都是业务必需的",
                "对于不必要的连接，通过防火墙进行阻断"
            ])
        
        actions.extend([
            "🌐 网络安全加固措施：",
            "• 配置防火墙规则，只允许必要的网络连接",
            "• 部署网络入侵检测系统（IDS/IPS）",
            "• 启用网络流量监控和分析",
            "• 实施网络分段，隔离关键系统",
            "• 配置DNS过滤，阻断恶意域名",
            "• 定期审查网络访问策略",
            "• 监控异常网络行为和数据传输"
        ])
        
        recommendations.append({
            "category": "网络安全",
            "priority": "高",
            "risk_level": risk_level,
            "affected_count": len(network_alerts),
            "actions": actions,
            "emergency_actions": [
                "立即断开可疑网络连接",
                "阻断可疑IP地址",
                "分析网络流量日志"
            ] if suspicious_connections > 0 else []
        })
    
    if "authentication" in categories:
        recommendations.append({
            "category": "身份认证",
            "priority": "高", 
            "actions": [
                "启用账户锁定策略",
                "实施多因素认证",
                "监控登录失败事件",
                "配置登录审计策略",
                "限制远程登录权限"
            ]
        })
    
    if "file_security" in categories:
        recommendations.append({
            "category": "文件安全",
            "priority": "中",
            "actions": [
                "隔离可疑文件进行分析",
                "扫描系统中的恶意软件",
                "检查文件完整性",
                "限制临时目录的执行权限",
                "定期清理临时文件"
            ]
        })
    
    if "persistence" in categories:
        recommendations.append({
            "category": "持久化防护",
            "priority": "高",
            "actions": [
                "清理恶意的注册表项",
                "检查所有启动项的合法性",
                "监控注册表关键位置的变化",
                "使用组策略限制启动项",
                "定期审计系统配置"
            ]
        })
    
    if "service_security" in categories:
        recommendations.append({
            "category": "服务安全",
            "priority": "高",
            "actions": [
                "停止并删除可疑服务",
                "检查服务的数字签名",
                "审查服务权限配置",
                "监控服务状态变化",
                "实施服务白名单策略"
            ]
        })
    
    if "antivirus" in categories:
        recommendations.append({
            "category": "防病毒保护",
            "priority": "高",
            "actions": [
                "立即启用Windows Defender实时保护",
                "更新病毒定义库",
                "执行全盘扫描",
                "检查防病毒软件配置",
                "启用云保护功能"
            ]
        })
    
    return recommendations

@app.route('/')
def index():
    """主页面"""
    return render_template_string("""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows应急响应分析系统</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: "Microsoft YaHei", Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            font-size: 1.1em;
            opacity: 0.9;
        }
        .main-content {
            padding: 40px;
        }
        .upload-section {
            text-align: center;
            margin-bottom: 40px;
            padding: 40px;
            border: 3px dashed #3498db;
            border-radius: 15px;
            background: #f8f9fa;
            transition: all 0.3s ease;
        }
        .upload-section:hover {
            border-color: #2980b9;
            background: #e3f2fd;
        }
        .upload-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
        }
        .file-input {
            margin: 20px 0;
        }
        .file-input input[type="file"] {
            display: none;
        }
        .file-label {
            display: inline-block;
            padding: 15px 30px;
            background: #3498db;
            color: white;
            border-radius: 25px;
            cursor: pointer;
            font-size: 1.1em;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
        }
        .file-label:hover {
            background: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
        }
        .analyze-btn {
            background: #27ae60;
            color: white;
            border: none;
            padding: 15px 40px;
            border-radius: 25px;
            font-size: 1.1em;
            cursor: pointer;
            margin-top: 20px;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(39, 174, 96, 0.3);
        }
        .analyze-btn:hover {
            background: #229954;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(39, 174, 96, 0.4);
        }
        .analyze-btn:disabled {
            background: #bdc3c7;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        .results {
            display: none;
            margin-top: 30px;
        }
        .alert {
            margin: 15px 0;
            padding: 20px;
            border-radius: 10px;
            border-left: 5px solid;
        }
        .alert-high {
            background: #fdf2f2;
            border-color: #e53e3e;
            color: #742a2a;
        }
        .alert-medium {
            background: #fffbf0;
            border-color: #dd6b20;
            color: #7c2d12;
        }
        .alert-low {
            background: #f0fff4;
            border-color: #38a169;
            color: #22543d;
        }
        .recommendations {
            margin-top: 30px;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
        .recommendation {
            margin: 20px 0;
            padding: 20px;
            background: white;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .recommendation h4 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        .recommendation ul {
            list-style: none;
            padding-left: 0;
        }
        .recommendation li {
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
        }
        .recommendation li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #27ae60;
            font-weight: bold;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border: 1px solid #dee2e6;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #3498db;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #7f8c8d;
            font-size: 1.1em;
        }
        .loading {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin: 40px 0;
        }
        .feature-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border: 1px solid #dee2e6;
            text-align: center;
        }
        .feature-icon {
            font-size: 3em;
            margin-bottom: 15px;
        }
        .feature-title {
            font-size: 1.3em;
            color: #2c3e50;
            margin-bottom: 15px;
        }
        .feature-desc {
            color: #7f8c8d;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Windows应急响应分析系统</h1>
            <div class="subtitle">专业化Windows安全威胁检测与分析平台</div>
        </div>
        
        <div class="main-content">
            <div class="upload-section">
                <h2>📁 上传Windows应急响应报告</h2>
                <p style="color: #7f8c8d; margin-bottom: 20px;">
                    支持PowerShell脚本生成的.txt和.json格式报告文件
                </p>
                <div class="file-input">
                    <label for="fileInput" class="file-label">
                        📂 选择报告文件
                    </label>
                    <input type="file" id="fileInput" accept=".txt,.json">
                </div>
                <div id="fileName" style="margin: 15px 0; color: #27ae60; font-weight: bold;"></div>
                <button id="analyzeBtn" class="analyze-btn" onclick="analyzeReport()" disabled>
                    🔍 开始智能分析
                </button>
            </div>
            
            <div class="feature-grid">
                <div class="feature-card">
                    <div class="feature-icon">🔍</div>
                    <div class="feature-title">智能威胁检测</div>
                    <div class="feature-desc">基于专业规则库，自动识别Windows系统中的安全威胁和异常行为</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">📊</div>
                    <div class="feature-title">详细分析报告</div>
                    <div class="feature-desc">提供全面的系统安全状况分析，包括进程、网络、用户等多个维度</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">💡</div>
                    <div class="feature-title">专业处置建议</div>
                    <div class="feature-desc">针对发现的安全问题，提供具体的处置步骤和安全建议</div>
                </div>
                <div class="feature-card">
                    <div class="feature-icon">⚡</div>
                    <div class="feature-title">快速响应</div>
                    <div class="feature-desc">快速分析报告内容，帮助安全人员迅速定位和处理安全事件</div>
                </div>
            </div>
            
            <div id="results" class="results">
                <!-- 分析结果将在这里显示 -->
            </div>
        </div>
    </div>

    <script>
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            const fileName = document.getElementById('fileName');
            const analyzeBtn = document.getElementById('analyzeBtn');
            
            if (file) {
                fileName.textContent = `已选择: ${file.name}`;
                analyzeBtn.disabled = false;
            } else {
                fileName.textContent = '';
                analyzeBtn.disabled = true;
            }
        });

        async function analyzeReport() {
            const fileInput = document.getElementById('fileInput');
            const resultsDiv = document.getElementById('results');
            const analyzeBtn = document.getElementById('analyzeBtn');
            
            if (!fileInput.files[0]) {
                alert('请先选择报告文件');
                return;
            }
            
            analyzeBtn.disabled = true;
            analyzeBtn.textContent = '🔄 分析中...';
            
            resultsDiv.innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    <p>正在分析Windows应急响应报告，请稍候...</p>
                </div>
            `;
            resultsDiv.style.display = 'block';
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    displayResults(result);
                } else {
                    resultsDiv.innerHTML = `
                        <div class="alert alert-high">
                            <h3>❌ 分析失败</h3>
                            <p>${result.error}</p>
                        </div>
                    `;
                }
            } catch (error) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-high">
                        <h3>❌ 网络错误</h3>
                        <p>无法连接到分析服务器，请检查网络连接</p>
                    </div>
                `;
            }
            
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = '🔍 开始智能分析';
        }

        function displayResults(result) {
            const resultsDiv = document.getElementById('results');
            
            let html = `
                <div class="stats">
                    <div class="stat-card">
                        <div class="stat-number">${result.alerts.length}</div>
                        <div class="stat-label">安全告警</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.alerts.filter(a => a.severity === 'high').length}</div>
                        <div class="stat-label">高危告警</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.alerts.filter(a => a.severity === 'medium').length}</div>
                        <div class="stat-label">中危告警</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${result.recommendations.length}</div>
                        <div class="stat-label">处置建议</div>
                    </div>
                </div>
            `;
            
            if (result.alerts.length > 0) {
                html += '<h2 style="color: #2c3e50; margin: 30px 0 20px 0;">🚨 安全告警详情</h2>';
                result.alerts.forEach(alert => {
                    const alertClass = `alert-${alert.severity}`;
                    const severityText = {
                        'high': '🔴 高危',
                        'medium': '🟡 中危', 
                        'low': '🟢 低危'
                    }[alert.severity];
                    
                    html += `
                        <div class="alert ${alertClass}">
                            <h4>${severityText} ${alert.rule_name}</h4>
                            <p><strong>描述:</strong> ${alert.description}</p>
                            <p><strong>匹配内容:</strong> ${alert.matched_text}</p>
                            <p><strong>行号:</strong> ${alert.line_number}</p>
                        </div>
                    `;
                });
            }
            
            if (result.recommendations.length > 0) {
                html += `
                    <div class="recommendations">
                        <h2 style="color: #2c3e50; margin-bottom: 20px;">💡 安全处置建议</h2>
                `;
                result.recommendations.forEach(rec => {
                    html += `
                        <div class="recommendation">
                            <h4>📋 ${rec.category} (优先级: ${rec.priority})</h4>
                            <ul>
                    `;
                    rec.actions.forEach(action => {
                        html += `<li>${action}</li>`;
                    });
                    html += `
                            </ul>
                        </div>
                    `;
                });
                html += '</div>';
            }
            
            // 添加查看详细报告的链接
            html += `
                <div style="text-align: center; margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                    <h3>📋 查看详细报告</h3>
                    <p style="margin: 15px 0; color: #666;">使用详细版查看器查看完整的Windows应急响应报告和专业教程</p>
                    <a href="/viewer" target="_blank" style="display: inline-block; padding: 15px 30px; background: #28a745; color: white; text-decoration: none; border-radius: 25px; font-weight: bold; margin: 10px;">
                        🔍 打开详细版查看器
                    </a>
                </div>
            `;
            resultsDiv.innerHTML = html;
        }
    </script>
</body>
</html>
    """)

@app.route('/analyze', methods=['POST'])
def analyze():
    """分析上传的Windows应急响应报告"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '没有上传文件'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '没有选择文件'})
        
        # 读取文件内容
        content = file.read().decode('utf-8', errors='ignore')
        
        logging.info(f"分析请求来自 {request.remote_addr}")
        
        # 分析报告
        alerts = analyze_windows_report(content)
        recommendations = generate_windows_recommendations(alerts)
        
        logging.info(f"分析完成: 发现 {len(alerts)} 个告警，生成 {len(recommendations)} 条建议")
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'recommendations': recommendations,
            'analysis_time': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"分析过程中出错: {str(e)}")
        return jsonify({'success': False, 'error': f'分析过程中出错: {str(e)}'})

@app.route('/viewer')
def detailed_viewer():
    """详细版报告查看器"""
    try:
        with open('windows_report_viewer.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return """
        <h1>详细版查看器未找到</h1>
        <p>请确保 windows_report_viewer.html 文件存在</p>
        <p><a href="/">返回主页</a></p>
        """

@app.route('/test')
def test_upload():
    """测试上传页面"""
    try:
        with open('test_upload.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return """
        <h1>测试页面未找到</h1>
        <p>请确保 test_upload.html 文件存在</p>
        <p><a href="/">返回主页</a></p>
        """

@app.route('/stats', methods=['POST'])
def get_stats():
    """获取报告统计信息"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '没有上传文件'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '没有选择文件'})
        
        # 读取文件内容
        content = file.read().decode('utf-8', errors='ignore')
        
        # 提取统计信息
        stats = extract_report_statistics(content)
        
        return jsonify({
            'success': True,
            'statistics': stats,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"统计分析过程中出错: {str(e)}")
        return jsonify({'success': False, 'error': f'统计分析过程中出错: {str(e)}'})

def extract_report_statistics(content):
    """从报告中提取统计信息"""
    stats = {
        'user_stats': {},
        'process_stats': {},
        'network_stats': {},
        'security_stats': {},
        'risk_assessment': {}
    }
    
    # 提取用户统计
    user_total_match = re.search(r'用户账户总数:\s*(\d+)', content)
    if user_total_match:
        stats['user_stats']['total_users'] = int(user_total_match.group(1))
    
    admin_count_match = re.search(r'管理员用户数:\s*(\d+)', content)
    if admin_count_match:
        stats['user_stats']['admin_users'] = int(admin_count_match.group(1))
    
    enabled_users_match = re.search(r'启用用户数:\s*(\d+)', content)
    if enabled_users_match:
        stats['user_stats']['enabled_users'] = int(enabled_users_match.group(1))
    
    # 提取进程统计
    process_total_match = re.search(r'系统进程总数:\s*(\d+)', content)
    if process_total_match:
        stats['process_stats']['total_processes'] = int(process_total_match.group(1))
    
    suspicious_process_match = re.search(r'可疑进程数:\s*(\d+)', content)
    if suspicious_process_match:
        stats['process_stats']['suspicious_processes'] = int(suspicious_process_match.group(1))
    
    # 提取网络统计
    network_conn_match = re.search(r'网络连接总数:\s*(\d+)', content)
    if network_conn_match:
        stats['network_stats']['total_connections'] = int(network_conn_match.group(1))
    
    listening_ports_match = re.search(r'监听端口数:\s*(\d+)', content)
    if listening_ports_match:
        stats['network_stats']['listening_ports'] = int(listening_ports_match.group(1))
    
    # 提取风险评估
    risk_score_match = re.search(r'风险评分:\s*(\d+)/100', content)
    if risk_score_match:
        stats['risk_assessment']['risk_score'] = int(risk_score_match.group(1))
    
    risk_level_match = re.search(r'风险等级:\s*([^\n]+)', content)
    if risk_level_match:
        stats['risk_assessment']['risk_level'] = risk_level_match.group(1).strip()
    
    # 提取安全防护状态
    defender_match = re.search(r'Windows Defender:\s*([^\n]+)', content)
    if defender_match:
        stats['security_stats']['defender_status'] = defender_match.group(1).strip()
    
    firewall_match = re.search(r'Windows防火墙:\s*([^\n]+)', content)
    if firewall_match:
        stats['security_stats']['firewall_status'] = firewall_match.group(1).strip()
    
    return stats

@app.route('/health')
def health_check():
    """健康检查接口"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.now().isoformat()})

if __name__ == '__main__':
    import sys
    
    # 支持命令行参数指定端口
    port = 12002  # 默认端口
    if len(sys.argv) > 1:
        for i, arg in enumerate(sys.argv):
            if arg == '--port' and i + 1 < len(sys.argv):
                try:
                    port = int(sys.argv[i + 1])
                except ValueError:
                    print("错误：端口号必须是数字")
                    sys.exit(1)
                break
    
    # 也支持环境变量
    port = int(os.environ.get('PORT', port))
    
    print(f"""
🛡️ Windows应急响应分析系统启动成功!

🌐 访问地址:
   主页: http://localhost:{port}
   详细版查看器: http://localhost:{port}/viewer
   健康检查: http://localhost:{port}/health

📋 功能特性:
   ✅ Windows系统安全检查
   ✅ 智能威胁检测
   ✅ 专业处置建议
   ✅ 详细分析报告
   ✅ Web界面展示

🔧 使用方法:
   1. 运行PowerShell脚本生成报告
   2. 上传报告文件进行分析
   3. 查看安全告警和处置建议

按 Ctrl+C 停止服务器
""")
    
    app.run(
        host='0.0.0.0',
        port=port,
        debug=False,
        threaded=True
    )