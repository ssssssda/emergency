# 🛡️ 增强版Linux应急响应工具

## 📋 项目概述

这是一个专业的Linux系统安全应急响应工具集，经过安全加固和功能增强，适用于生产环境的安全事件响应。

### 🔍 原项目安全分析结果

**✅ 安全性确认**: 原项目**无后门**，是合法的安全工具  
**❌ 生产环境适用性**: 原项目存在安全配置问题，不适合直接用于生产环境

### 🚀 增强版改进

#### 安全性增强
- ✅ 修复CORS配置安全问题
- ✅ 添加审计日志记录
- ✅ 改进错误处理机制
- ✅ 增强输入验证
- ✅ 支持环境变量配置

#### 功能增强
- ✅ **文件上传功能**: 支持拖拽上传，无需本地文件选择
- ✅ **智能统计分析**: 自动生成系统统计概览
- ✅ **风险评估算法**: 智能计算风险评分
- ✅ **处置建议系统**: 提供具体的安全建议
- ✅ **现代化Web界面**: 响应式设计，用户体验优化

## 🎯 核心功能

### 1. 智能分析引擎
```
风险评分算法:
- UID为0异常用户: +50分 (高危)
- 可疑进程过多: +30分 (中危)  
- SUID文件异常: +20分 (中危)
- 登录失败过多: +25分 (中危)
- 监听端口过多: +15分 (低危)
```

### 2. 统计分析功能
- 📊 系统基本信息统计
- 🔍 安全风险评估
- 📋 应急响应检查清单
- 💡 智能处置建议

### 3. 真实场景应急响应
```
示例分析结果:
[高危] 发现1个非root的UID为0用户，建议立即与运维开发人员确认这些用户的合法性。
[中危] 可疑进程数量较多，建议检查进程合法性。
[低危] 监听端口数量较多，建议关闭不必要的服务。
```

## 🛠️ 安装部署

### 1. 环境要求
```bash
# 操作系统: Linux (Ubuntu/CentOS/Debian)
# Python: 3.6+
# 权限: root (用于系统信息收集)
```

### 2. 依赖安装
```bash
pip3 install flask flask-cors pyyaml
```

### 3. 快速启动
```bash
# 1. 克隆项目
git clone https://github.com/Rabb1tQ/emergency_response.git
cd emergency_response

# 2. 运行增强版应急响应脚本
sudo bash enhanced_emergency_response.sh

# 3. 启动Web分析平台
python3 enhanced_rules_engine.py

# 4. 访问Web界面
# 浏览器打开: http://localhost:12000
```

## 🎮 使用演示

### 1. 生成应急响应报告
```bash
sudo bash enhanced_emergency_response.sh
```

输出示例:
```
[INFO] 开始Linux应急响应检查...
正在执行模块：系统后门排查
正在执行模块：用户与登录检查
正在执行模块：网络检查
...
[SUCCESS] 应急响应检查完成！

报告文件：
  文本格式: emergency_report_20250606_111700.txt
  JSON格式: emergency_report_20250606_111700.json

统计摘要：
  总用户数: 25
  UID为0的非root用户: 1
  监听端口数: 6
  可疑进程数: 4
  SUID文件数: 11

[ERROR] 发现1个异常UID为0用户，建议立即检查！
```

### 2. Web界面分析

#### 上传文件
- 支持拖拽上传
- 自动文件类型检测
- 实时上传进度

#### 智能分析
- 自动规则匹配
- 风险等级评估
- 统计数据生成

#### 分析结果展示
```
📊 分析结果概览
整体风险等级: 高危
高危告警: 3
中危告警: 2  
低危告警: 1

🎯 智能分析建议
[正常] 除root外未发现其他UID为0的高权限用户，权限配置良好。
[中危] 发现4个可疑脚本进程，数量较多，建议检查进程合法性。
[低危] 监听端口数量(6)较多，建议关闭不必要的服务。

🚨 安全告警详情
[高危] 发现非root用户具有UID 0
检测位置: backdoor → UID为0的非root用户
处置建议: 建议立即检查该用户的创建来源，确认是否为恶意账户...
```

## 🔧 生产环境配置

### 1. 安全配置
```bash
# 环境变量配置
export PORT=12000
export DEBUG=False
export SECRET_KEY="your-secret-key-here"
export ALLOWED_ORIGINS="https://your-domain.com"
```

### 2. 反向代理 (Nginx)
```nginx
server {
    listen 443 ssl;
    server_name emergency-response.your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:12000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. 防火墙配置
```bash
# 限制访问来源
iptables -A INPUT -p tcp --dport 12000 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 12000 -j DROP
```

## 📈 功能对比

| 功能特性 | 原版本 | 增强版 |
|---------|--------|--------|
| 后门检测 | ✅ | ✅ |
| 文件上传 | ❌ | ✅ |
| 统计分析 | ❌ | ✅ |
| 风险评估 | ❌ | ✅ |
| 智能建议 | ❌ | ✅ |
| Web界面 | 基础 | 现代化 |
| 安全配置 | 有问题 | 已修复 |
| 审计日志 | ❌ | ✅ |
| 生产就绪 | ❌ | ✅ |

## 🎯 真实场景应用

### 应急响应流程
1. **快速部署**: 一键启动分析平台
2. **数据收集**: 运行增强版脚本收集系统信息
3. **智能分析**: 上传报告进行自动化分析
4. **风险评估**: 查看风险评分和等级
5. **处置建议**: 根据智能建议进行安全处置
6. **跟踪记录**: 审计日志记录所有操作

### 典型使用场景
- 🚨 **安全事件响应**: 快速评估系统安全状态
- 🔍 **定期安全检查**: 周期性系统安全审计
- 📊 **合规性检查**: 满足安全合规要求
- 🛡️ **威胁狩猎**: 主动发现潜在安全威胁

## 📚 API接口

### 健康检查
```bash
curl http://localhost:12000/health
# 响应: {"status":"healthy","timestamp":"2025-06-06T03:17:10.495653"}
```

### 分析报告
```bash
curl -X POST http://localhost:12000/analyze \
  -H "Content-Type: application/json" \
  -d @report.json
```

### 系统统计
```bash
curl http://localhost:12000/stats
# 响应: {"total_analyses":10,"total_alerts":25,"rules_count":40}
```

## 🔒 安全建议

### 部署前检查
- [ ] 修改默认端口
- [ ] 配置HTTPS证书  
- [ ] 设置访问控制
- [ ] 配置防火墙规则
- [ ] 启用审计日志

### 运行时监控
- [ ] 监控访问日志
- [ ] 检查系统资源
- [ ] 验证分析结果
- [ ] 备份重要数据

## 🤝 贡献指南

欢迎提交Issue和Pull Request来帮助改进这个项目。

## 📄 许可证

本项目基于原项目进行增强，保持开源协议。

## ⚠️ 免责声明

本工具仅用于授权的安全应急响应和系统检查，请勿用于非授权的安全测试。使用本工具进行的任何操作均由使用者承担全部责任。

---

**🎉 现在您可以安全地在生产环境中使用这个增强版应急响应工具了！**