#!/bin/bash
# Linux应急响应工具 - 依赖安装脚本
# 使用方法: bash install.sh

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "    Linux应急响应工具 - 依赖安装脚本"
    echo "=================================================="
    echo -e "${NC}"
}

# 检查操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
    fi
    print_status "检测到操作系统: $OS $VERSION"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "请使用 root 权限运行此脚本"
        print_status "使用方法: sudo bash install.sh"
        exit 1
    fi
}

# 更新系统包管理器
update_system() {
    print_status "更新系统包管理器..."
    
    case $OS in
        ubuntu|debian)
            apt update -y
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf update -y
            else
                yum update -y
            fi
            ;;
        *)
            print_warning "未知操作系统，跳过系统更新"
            ;;
    esac
}

# 安装Python3和pip
install_python() {
    print_status "检查Python3安装状态..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python3 已安装: $PYTHON_VERSION"
    else
        print_status "安装Python3..."
        case $OS in
            ubuntu|debian)
                apt install -y python3 python3-pip python3-dev
                ;;
            centos|rhel|fedora)
                if command -v dnf &> /dev/null; then
                    dnf install -y python3 python3-pip python3-devel
                else
                    yum install -y python3 python3-pip python3-devel
                fi
                ;;
            *)
                print_error "不支持的操作系统，请手动安装Python3"
                exit 1
                ;;
        esac
    fi
    
    # 检查pip3
    if command -v pip3 &> /dev/null; then
        print_success "pip3 已安装"
    else
        print_status "安装pip3..."
        case $OS in
            ubuntu|debian)
                apt install -y python3-pip
                ;;
            centos|rhel|fedora)
                if command -v dnf &> /dev/null; then
                    dnf install -y python3-pip
                else
                    yum install -y python3-pip
                fi
                ;;
        esac
    fi
}

# 安装系统工具
install_system_tools() {
    print_status "安装系统工具..."
    
    case $OS in
        ubuntu|debian)
            apt install -y curl wget net-tools psmisc procps lsof
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y curl wget net-tools psmisc procps-ng lsof
            else
                yum install -y curl wget net-tools psmisc procps-ng lsof
            fi
            ;;
        *)
            print_warning "跳过系统工具安装，请确保已安装: curl, wget, netstat, ps, lsof"
            ;;
    esac
}

# 安装Python依赖
install_python_deps() {
    print_status "安装Python依赖包..."
    
    # 升级pip
    python3 -m pip install --upgrade pip
    
    # 安装核心依赖
    print_status "安装Flask和相关组件..."
    pip3 install flask==3.1.1
    pip3 install flask-cors==6.0.0
    pip3 install pyyaml==6.0.2
    pip3 install werkzeug==3.1.3
    
    # 验证安装
    print_status "验证Python依赖安装..."
    python3 -c "import flask, flask_cors, yaml; print('所有依赖安装成功')" || {
        print_error "Python依赖安装失败"
        exit 1
    }
    
    print_success "Python依赖安装完成"
}

# 创建必要目录
create_directories() {
    print_status "创建必要目录..."
    
    mkdir -p uploads
    mkdir -p logs
    chmod 755 uploads logs
    
    print_success "目录创建完成"
}

# 设置权限
set_permissions() {
    print_status "设置文件权限..."
    
    chmod +x enhanced_emergency_response.sh
    chmod +x enhanced_rules_engine.py
    
    print_success "权限设置完成"
}

# 验证安装
verify_installation() {
    print_status "验证安装..."
    
    # 检查Python模块
    python3 -c "
import sys
try:
    import flask
    import flask_cors
    import yaml
    print('✅ 所有Python依赖正常')
except ImportError as e:
    print(f'❌ 依赖缺失: {e}')
    sys.exit(1)
"
    
    # 检查脚本文件
    if [ -f "enhanced_emergency_response.sh" ] && [ -x "enhanced_emergency_response.sh" ]; then
        print_success "应急响应脚本就绪"
    else
        print_error "应急响应脚本不存在或无执行权限"
    fi
    
    if [ -f "enhanced_rules_engine.py" ] && [ -x "enhanced_rules_engine.py" ]; then
        print_success "规则引擎就绪"
    else
        print_error "规则引擎不存在或无执行权限"
    fi
    
    print_success "安装验证完成"
}

# 显示使用说明
show_usage() {
    echo -e "${GREEN}"
    echo "=================================================="
    echo "           安装完成！使用说明"
    echo "=================================================="
    echo -e "${NC}"
    
    echo -e "${YELLOW}1. 运行应急响应脚本:${NC}"
    echo "   sudo bash enhanced_emergency_response.sh"
    echo ""
    
    echo -e "${YELLOW}2. 启动Web分析平台:${NC}"
    echo "   python3 enhanced_rules_engine.py"
    echo ""
    
    echo -e "${YELLOW}3. 访问Web界面:${NC}"
    echo "   浏览器打开: http://localhost:12000"
    echo ""
    
    echo -e "${YELLOW}4. 生产环境配置:${NC}"
    echo "   export PORT=12000"
    echo "   export DEBUG=False"
    echo "   export ALLOWED_ORIGINS=\"https://your-domain.com\""
    echo ""
    
    echo -e "${BLUE}更多信息请查看: README_ENHANCED.md${NC}"
}

# 主函数
main() {
    print_header
    
    # 检查root权限
    check_root
    
    # 检测操作系统
    detect_os
    
    # 更新系统
    update_system
    
    # 安装Python
    install_python
    
    # 安装系统工具
    install_system_tools
    
    # 安装Python依赖
    install_python_deps
    
    # 创建目录
    create_directories
    
    # 设置权限
    set_permissions
    
    # 验证安装
    verify_installation
    
    # 显示使用说明
    show_usage
    
    print_success "所有依赖安装完成！"
}

# 执行主函数
main "$@"