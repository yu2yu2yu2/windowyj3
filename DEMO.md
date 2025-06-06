🛡️ Windows应急响应工具演示

📊 主要功能演示:

1. 启动Web服务器:
   python windows_rules_engine.py

2. 访问主页面:
   http://localhost:12002

3. 访问详细版查看器:
   http://localhost:12002/viewer

4. 测试分析功能:
   curl -X POST -F "file=@test_report_enhanced.txt" http://localhost:12002/analyze

5. 测试统计功能:
   curl -X POST -F "file=@test_report_enhanced.txt" http://localhost:12002/stats

📈 增强功能亮点:

✅ 统计分析功能
- 用户账户统计: 总数8个，管理员2个，启用6个
- 进程安全统计: 总进程156个，可疑进程2个
- 网络连接统计: 总连接45个，监听端口12个
- 风险评估: 35/100分，中等风险

✅ 专业检测规则 (24个)
- 管理员权限检测
- 可疑进程分析
- 网络安全监控
- 安全防护状态检查

✅ 真实场景分析
- 检测到超级管理员权限用户，建议与运维开发人员确认
- 发现自定义管理员账户，需要验证安全风险
- 识别可疑进程和网络连接，提供具体处置建议

🔧 使用建议:
1. 在Windows系统上运行PowerShell脚本生成报告
2. 上传报告到Web界面进行分析
3. 查看统计数据和安全建议
4. 根据风险评估结果采取相应措施
