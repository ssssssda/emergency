# 🚀 Linux应急响应工具 - 安装指南

## 📋 快速安装

### 方法一：一键安装脚本（推荐）

```bash
# 1. 下载项目
git clone https://github.com/Rabb1tQ/emergency_response.git
cd emergency_response

# 2. 运行一键安装脚本
sudo bash install.sh
```

### 方法二：手动安装

#### 1. 系统要求检查
```bash
# 检查操作系统（支持 Ubuntu/Debian/CentOS/RHEL）
cat /etc/os-release

# 检查Python版本（需要3.6+）
python3 --version
```

#### 2. 安装系统依赖

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev curl wget net-tools psmisc procps lsof
```

**CentOS/RHEL 8+:**
```bash
sudo dnf update
sudo dnf install -y python3 python3-pip python3-devel curl wget net-tools psmisc procps-ng lsof
```

**CentOS/RHEL 7:**
```bash
sudo yum update
sudo yum install -y python3 python3-pip python3-devel curl wget net-tools psmisc procps-ng lsof
```

#### 3. 安装Python依赖
```bash
# 升级pip
python3 -m pip install --upgrade pip

# 安装核心依赖
pip3 install flask==3.1.1
pip3 install flask-cors==6.0.0
pip3 install pyyaml==6.0.2
pip3 install werkzeug==3.1.3
```

#### 4. 设置权限和目录
```bash
# 设置脚本执行权限
chmod +x enhanced_emergency_response.sh
chmod +x enhanced_rules_engine.py

# 创建必要目录
mkdir -p uploads logs
chmod 755 uploads logs
```

## 🔍 验证安装

### 检查Python依赖
```bash
python3 -c "import flask, flask_cors, yaml; print('✅ 所有依赖安装成功')"
```

### 检查系统工具
```bash
# 检查必要的系统命令
which python3 && echo "✅ Python3 已安装"
which pip3 && echo "✅ pip3 已安装"
which curl && echo "✅ curl 已安装"
which netstat && echo "✅ netstat 已安装"
which ps && echo "✅ ps 已安装"
which lsof && echo "✅ lsof 已安装"
```

## 🎮 快速使用

### 1. 生成应急响应报告
```bash
sudo bash enhanced_emergency_response.sh
```

### 2. 启动Web分析平台
```bash
python3 enhanced_rules_engine.py
```

### 3. 访问Web界面
```
浏览器打开: http://localhost:12000
```

## 🛠️ 常见问题解决

### 问题1: Python3未安装
```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip

# CentOS/RHEL
sudo yum install python3 python3-pip  # CentOS 7
sudo dnf install python3 python3-pip  # CentOS 8+
```

### 问题2: pip安装失败
```bash
# 使用国内镜像源
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple flask flask-cors pyyaml
```

### 问题3: 权限不足
```bash
# 确保使用root权限运行应急响应脚本
sudo bash enhanced_emergency_response.sh

# Web平台可以使用普通用户运行
python3 enhanced_rules_engine.py
```

### 问题4: 端口被占用
```bash
# 检查端口占用
netstat -tulnp | grep 12000

# 修改端口
export PORT=12001
python3 enhanced_rules_engine.py
```

### 问题5: 防火墙阻止访问
```bash
# Ubuntu/Debian
sudo ufw allow 12000

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=12000/tcp
sudo firewall-cmd --reload
```

## 🔧 生产环境配置

### 环境变量设置
```bash
# 创建配置文件
cat > .env << EOF
PORT=12000
DEBUG=False
SECRET_KEY=your-secret-key-here
ALLOWED_ORIGINS=https://your-domain.com
EOF

# 加载环境变量
source .env
```

### 使用systemd服务
```bash
# 创建服务文件
sudo tee /etc/systemd/system/emergency-response.service > /dev/null << EOF
[Unit]
Description=Emergency Response Analysis Platform
After=network.target

[Service]
Type=simple
User=emergency
WorkingDirectory=/opt/emergency_response
Environment=PORT=12000
Environment=DEBUG=False
ExecStart=/usr/bin/python3 enhanced_rules_engine.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable emergency-response
sudo systemctl start emergency-response
```

## 📦 依赖包详细说明

| 包名 | 版本 | 用途 |
|------|------|------|
| flask | 3.1.1 | Web框架 |
| flask-cors | 6.0.0 | 跨域请求支持 |
| pyyaml | 6.0.2 | YAML配置文件解析 |
| werkzeug | 3.1.3 | WSGI工具库 |

## 🎯 最小化安装

如果只需要基本功能，可以只安装核心依赖：

```bash
# 最小化安装
pip3 install flask flask-cors pyyaml

# 验证
python3 -c "import flask, flask_cors, yaml; print('最小化安装完成')"
```

## 📞 技术支持

如果遇到安装问题，请检查：

1. **操作系统兼容性**: 支持主流Linux发行版
2. **Python版本**: 需要Python 3.6或更高版本
3. **网络连接**: 确保可以访问PyPI镜像源
4. **权限设置**: 应急响应脚本需要root权限
5. **防火墙配置**: 确保端口12000可访问

---

**🎉 安装完成后，您就可以开始使用增强版Linux应急响应工具了！**