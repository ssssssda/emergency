# Linux 应急响应工具 (增强版)

## 🛡️ 项目概述

这是一个专业的Linux应急响应工具增强版，在原有功能基础上添加了：
- **系统安全状况总览面板**
- **智能风险评估系统**
- **详细统计分析功能**
- **专业化安全建议**
- **真实场景应急响应指导**

## ✨ 新增功能特性

### 1. 系统安全状况总览
- 📊 实时统计系统关键安全指标
- 🎯 智能风险评分 (0-100分)
- 📈 可视化数据展示
- ⚡ 一目了然的安全状况

### 2. 智能分析建议
- 🔍 基于统计数据的专业分析
- 💡 针对性安全建议
- 🚨 风险等级自动评估
- 📋 下一步行动指南

### 3. 增强的Web界面
- 🎨 现代化UI设计
- 📱 响应式布局
- 🔄 实时数据更新
- 📁 拖拽文件上传

## 🚀 快速开始

### 1. 运行应急响应脚本
```bash
sudo bash emergency_response.sh
```

### 2. 启动Web查看器
```bash
# 启动HTTP服务器
python3 -m http.server 8080 --bind 0.0.0.0

# 启动规则引擎 (可选)
python3 rules_engine.py
```

### 3. 访问Web界面
打开浏览器访问: `http://localhost:8080/emergency_report_viewer.html`

## 📊 系统安全评估指标

### 统计指标说明
| 指标 | 说明 | 风险权重 |
|------|------|----------|
| 总用户数 | 系统中的用户账户总数 | 低 |
| 异常高权限用户 | UID=0的非root用户 | **高** |
| 监听端口 | 系统监听的网络端口数量 | 中 |
| 可疑进程 | 可能存在风险的进程 | 中 |
| SUID文件 | 具有特殊权限的文件 | 中 |
| 登录失败 | 认证失败次数 | 中 |

### 风险评分算法
```
风险评分 = 异常高权限用户 × 30 + 
          可疑进程数 × 10 + 
          登录失败评分 + 
          SUID文件评分 + 
          监听端口评分
```

### 风险等级划分
- **高危 (70-100分)**: 存在严重安全威胁，需要立即处理
- **中危 (40-69分)**: 需要关注，建议详细排查
- **低危 (20-39分)**: 相对安全，建议定期监控
- **正常 (0-19分)**: 安全状况良好

## 🔍 专业分析示例

### 典型分析结论
```
[正常] UID为0只有root用户，除了root之外没有高权限用户，
       建议与运维开发人员确认其他管理员账户配置。

[中危] 发现3个可疑脚本进程，数量较多，建议检查进程合法性。

[中危] 登录失败次数(100)较多，可能存在暴力破解攻击。

[注意] 监听端口数量(25)较多，建议检查是否有不必要的服务。
```

## 🛠️ 生产环境部署

### 1. 系统要求
- Linux操作系统 (Ubuntu/CentOS/RHEL)
- Python 3.6+
- Root权限 (用于系统检查)
- 网络访问 (用于Web界面)

### 2. 安全配置
```bash
# 1. 创建专用用户
useradd -r -s /bin/false emergency-response

# 2. 设置文件权限
chmod 750 emergency_response.sh
chown root:emergency-response emergency_response.sh

# 3. 配置防火墙 (可选)
ufw allow 8080/tcp
```

### 3. 自动化部署
```bash
# 创建systemd服务
cat > /etc/systemd/system/emergency-response.service << EOF
[Unit]
Description=Emergency Response Web Interface
After=network.target

[Service]
Type=simple
User=emergency-response
WorkingDirectory=/opt/emergency-response
ExecStart=/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 启用服务
systemctl enable emergency-response
systemctl start emergency-response
```

## 📈 使用场景

### 1. 安全事件应急响应
- 快速评估系统安全状况
- 识别潜在的安全威胁
- 生成详细的调查报告

### 2. 定期安全检查
- 建立安全基线
- 监控系统变化
- 趋势分析

### 3. 合规性审计
- 满足安全合规要求
- 生成审计报告
- 证明安全控制有效性

### 4. 威胁狩猎
- 主动寻找威胁指标
- 分析异常行为
- 验证安全假设

## 🔧 高级配置

### 1. 自定义检测规则
编辑 `rules/*.yml` 文件添加自定义检测规则：
```yaml
- id: custom_backdoor_check
  description: 检测自定义后门特征
  level: critical
  target_section: backdoor
  pattern: 'your_custom_pattern'
  case_sensitive: true
```

### 2. 集成SIEM系统
```bash
# 输出JSON格式报告
./emergency_response.sh --format json > report.json

# 发送到SIEM
curl -X POST -H "Content-Type: application/json" \
     -d @report.json \
     https://your-siem-endpoint/api/events
```

### 3. 定时执行
```bash
# 添加到crontab
echo "0 */6 * * * /opt/emergency-response/emergency_response.sh" | crontab -
```

## 🚨 安全注意事项

### 1. 权限管理
- 仅授予必要的最小权限
- 定期审查访问权限
- 使用强密码和多因素认证

### 2. 数据保护
- 报告文件包含敏感信息
- 确保传输和存储加密
- 定期清理历史报告

### 3. 网络安全
- 限制Web界面访问IP
- 使用HTTPS (生产环境)
- 配置适当的防火墙规则

## 📞 技术支持

### 常见问题
1. **Q: 脚本运行缓慢怎么办？**
   A: 可以通过修改脚本中的find命令范围来优化性能

2. **Q: Web界面无法访问？**
   A: 检查防火墙设置和端口占用情况

3. **Q: 如何添加自定义检查项？**
   A: 修改脚本中的相应函数，添加新的检查逻辑

### 联系方式
- 项目地址: https://github.com/Rabb1tQ/emergency_response
- 问题反馈: 通过GitHub Issues提交

## 📄 许可证

本项目基于原项目许可证发布，请查看 LICENSE 文件了解详情。

## 🙏 致谢

感谢原项目作者 Rabb1tQ 提供的优秀基础框架，本增强版在其基础上进行了功能扩展和用户体验优化。

---

**⚠️ 免责声明**: 本工具仅用于合法的安全检查和应急响应，使用者需确保遵守相关法律法规。