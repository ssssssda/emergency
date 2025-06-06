#!/bin/bash
# Linux 应急响应一键脚本（分隔符输出版）
# 运行方式：sudo bash emergency_response.sh

NOW=$(date +"%Y%m%d_%H%M%S")
REPORT="emergency_report_${NOW}.txt"
TMPDIR=$(mktemp -d /tmp/emergency.XXXXXX)

# 定义分隔符
SECTION_SEP="=========================================="
SUBSECTION_SEP="------------------------------------------"
MODULE_SEP="##########################################"


if [ "$EUID" -ne 0 ]; then
  echo "请以 root 或 sudo 权限运行本脚本！"
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS=$(uname -s)
fi

declare -A TAB_TITLES=(
  [backdoor]="系统后门排查"
  [user]="用户与登录检查"
  [log]="日志分析"
  [network]="网络检查"
  [process]="进程检查"
  [filesystem]="文件系统检查"
  [package]="软件包检查"
  [persistence]="持久化检查"
  [integrity]="系统完整性"
  [malware]="恶意进程与提权点"
  [summary]="功能总结与使用说明"
)

# 函数：打印当前执行模块
print_module() {
  echo "正在执行模块：$1"
}

# 函数：写入章节标题
write_section() {
  echo "$MODULE_SEP"
  echo "模块: $1"
  echo "$SECTION_SEP"
}

# 函数：写入子章节
write_subsection() {
  echo "$SUBSECTION_SEP"
  echo "子项: $1"
  echo "$SUBSECTION_SEP"
}

# 4. 网络检查
network_check() {
  print_module "${TAB_TITLES[network]}"
  {
    write_section "${TAB_TITLES[network]}"
    
    write_subsection "监听端口"
    ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null
    
    write_subsection "活动连接"
    ss -antp 2>/dev/null || netstat -antp 2>/dev/null
    
    write_subsection "网络配置"
    ip addr 2>/dev/null || ifconfig -a 2>/dev/null
    
    write_subsection "路由表"
    ip route 2>/dev/null || route -n 2>/dev/null
    
    write_subsection "可疑连接"
    ss -antp 2>/dev/null | grep ESTAB | grep -E ':[0-9]+.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '127\.0\.0\.1' || true
  } >> "$REPORT"
}

# 1. 系统后门排查
backdoor_check() {
  print_module "${TAB_TITLES[backdoor]}"
  {
    write_section "${TAB_TITLES[backdoor]}"
    
    write_subsection "UID为0的非root用户"
    awk -F: '($3 == 0 && $1 != "root"){print "可疑UID 0用户: "$1}' /etc/passwd
    
    write_subsection "可疑系统配置"
    echo "检查系统配置文件权限:"
    ls -l /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null
    echo "检查异常的系统配置:"
    find /etc -type f -mtime -7 -ls 2>/dev/null | grep -E 'conf$|cnf$|cfg$'
    
    write_subsection "异常系统文件"
    echo "检查关键目录下的异常文件:"
    find /bin /sbin /usr/bin /usr/sbin -type f -mtime -7 -ls 2>/dev/null
    echo "检查异常的系统库文件:"
    find /lib /lib64 /usr/lib -type f -mtime -7 -ls 2>/dev/null | head -n 20
  } >> "$REPORT"
}

# 2. 用户与登录检查
user_check() {
  print_module "${TAB_TITLES[user]}"
  {
    write_section "${TAB_TITLES[user]}"
    
    write_subsection "当前用户"
    whoami
    
    write_subsection "所有用户"
    awk -F: '{print $1}' /etc/passwd
    
    write_subsection "最近登录记录"
    last -a -n 20 2>/dev/null
    
    write_subsection "登录失败记录"
    lastb -a -n 20 2>/dev/null || echo "lastb 未安装"
  } >> "$REPORT"
}

# 3. 日志分析
log_check() {
  print_module "${TAB_TITLES[log]}"
  {
    write_section "${TAB_TITLES[log]}"
    
    write_subsection "系统日志错误"
    grep -Ei 'error|fail|denied|refused|invalid|segfault|unauthorized|attack|panic' /var/log/syslog /var/log/messages 2>/dev/null | tail -n 50
    
    write_subsection "安全日志错误"
    grep -Ei 'fail|invalid|root|attack|sudo|su:|authentication failure' /var/log/auth.log /var/log/secure 2>/dev/null | tail -n 50
  } >> "$REPORT"
}

# 5. 进程检查
process_check() {
  print_module "${TAB_TITLES[process]}"
  {
    write_section "${TAB_TITLES[process]}"
    
    write_subsection "高CPU占用进程"
    ps aux --sort=-%cpu | head -n 15
    
    write_subsection "可疑脚本进程"
    ps aux | grep -E 'bash|sh|python|perl|php|nc|netcat|socat' | grep -vE 'grep|emergency_response.sh' | awk '{print $2, $11}'
  } >> "$REPORT"
}

# 6. 文件系统检查
filesystem_check() {
  print_module "${TAB_TITLES[filesystem]}"
  {
    write_section "${TAB_TITLES[filesystem]}"
    
    write_subsection "SUID文件"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
    
    write_subsection "最近修改的文件"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -type f -mtime -7 -exec ls -l {} \; 2>/dev/null | head -n 50
  } >> "$REPORT"
}

# 7. 软件包检查
package_check() {
  print_module "${TAB_TITLES[package]}"
  {
    write_section "${TAB_TITLES[package]}"
    
    write_subsection "已安装的软件包"
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
      dpkg -l | grep '^ii' | awk '{print $2, $3}' 2>/dev/null
    elif [[ "$OS" == "centos" || "$OS" == "rhel" ]]; then
      rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null
    else
      echo "未知系统，无法列出软件包"
    fi
  } >> "$REPORT"
}

# 8. 持久化检查
persistence_check() {
  print_module "${TAB_TITLES[persistence]}"
  {
    write_section "${TAB_TITLES[persistence]}"
    
    write_subsection "自启动服务"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null
    
    write_subsection "计划任务"
    echo "系统计划任务:"
    cat /etc/crontab 2>/dev/null
    echo "Cron目录内容:"
    ls -l /etc/cron* /var/spool/cron/* 2>/dev/null
    echo "用户计划任务:"
    for u in $(cut -f1 -d: /etc/passwd); do
      crontab -l -u "$u" 2>/dev/null | grep -v '^#' && echo "用户: $u" || true
    done
    
    write_subsection "SSH公钥"
    for u in $(cut -f1 -d: /etc/passwd); do
      home=$(eval echo ~"$u")
      if [ -f "$home/.ssh/authorized_keys" ]; then
        echo "用户 $u 的SSH密钥:"
        cat "$home/.ssh/authorized_keys" 2>/dev/null
      fi
    done
    
    write_subsection "启动项配置"
    echo "RC启动脚本:"
    ls -l /etc/rc*.d/ 2>/dev/null
    echo "RC Local内容:"
    cat /etc/rc.local 2>/dev/null
    echo "Systemd用户服务:"
    ls -l /etc/systemd/system/*.service /usr/lib/systemd/system/*.service 2>/dev/null
    echo "Init.d脚本:"
    ls -l /etc/init.d/ 2>/dev/null
  } >> "$REPORT"
}

# 9. 系统完整性检查
integrity_check() {
  print_module "${TAB_TITLES[integrity]}"
  {
    write_section "${TAB_TITLES[integrity]}"
    
    write_subsection "关键二进制文件校验"
    for bin in /bin/ls /bin/ps /bin/netstat /usr/bin/ss /bin/bash /usr/bin/sudo; do
      [ -f "$bin" ] && sha256sum "$bin" 2>/dev/null
    done
    
    write_subsection "系统文件完整性"
    if [[ "$OS" == "centos" || "$OS" == "rhel" ]]; then
      rpm -Va --nomtime --nosize --nomd5 | grep -v '^..5......' 2>/dev/null
    elif [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
      debsums -s 2>/dev/null || echo "未安装 debsums"
    fi
  } >> "$REPORT"
}

# 10. 恶意进程与提权点检查
malware_check() {
  print_module "${TAB_TITLES[malware]}"
  {
    write_section "${TAB_TITLES[malware]}"
    
    write_subsection "可疑进程"
    ps aux | grep -E 'kworker|kthreadd|crypto|minerd|\.tmp|\.sh|\.py|\.pl|\.php|/tmp|/dev/shm' | grep -vE 'grep|emergency_response.sh' | awk '{print $2, $11}'
    
    write_subsection "可疑提权点"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | grep -E 'nmap|perl|python|find|awk|vim|nano|less|more|cp|mv|bash|sh'
    
    write_subsection "隐藏文件"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o \( -name ".*" -type f -o -name ".*" -type d \) -exec ls -l {} \; 2>/dev/null
  } >> "$REPORT"
}



# 执行所有检查
{
  echo "Linux 应急响应报告"
  echo "生成时间: $(date)"
  echo "$MODULE_SEP"
  echo
} > "$REPORT"

backdoor_check
user_check
log_check
network_check
process_check
filesystem_check
package_check
persistence_check
integrity_check
malware_check

# 生成统计总结
{
  echo "$MODULE_SEP"
  echo "模块: 安全状况统计总结"
  echo "$SECTION_SEP"
  
  echo "$SUBSECTION_SEP"
  echo "子项: 系统安全评估"
  echo "$SUBSECTION_SEP"
  
  # 统计用户信息
  total_users=$(awk -F: '$3 >= 1000 {print $1}' /etc/passwd | wc -l)
  uid0_users=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | wc -l)
  
  # 统计网络信息
  listening_ports=$(netstat -tuln 2>/dev/null | grep LISTEN | wc -l)
  
  # 统计进程信息
  suspicious_processes=$(ps aux | grep -E '\.(sh|py|pl)$|/tmp/|/dev/shm/' | grep -v grep | wc -l)
  
  # 统计SUID文件
  suid_files=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -print 2>/dev/null | wc -l)
  
  # 统计登录失败
  login_failures=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null || echo "0")
  
  echo "【系统安全状况评估】"
  echo "总用户数: $total_users"
  echo "异常高权限用户(UID=0): $uid0_users"
  echo "监听端口数: $listening_ports"
  echo "可疑进程数: $suspicious_processes"
  echo "SUID文件数: $suid_files"
  echo "登录失败次数: $login_failures"
  echo ""
  
  # 风险评估
  risk_score=0
  
  # 计算风险评分
  risk_score=$((risk_score + uid0_users * 30))
  if [ "$suspicious_processes" -gt 5 ]; then
    risk_score=$((risk_score + 25))
  elif [ "$suspicious_processes" -gt 2 ]; then
    risk_score=$((risk_score + 15))
  fi
  
  if [ "$login_failures" -gt 100 ]; then
    risk_score=$((risk_score + 25))
  elif [ "$login_failures" -gt 50 ]; then
    risk_score=$((risk_score + 15))
  elif [ "$login_failures" -gt 10 ]; then
    risk_score=$((risk_score + 5))
  fi
  
  if [ "$suid_files" -gt 100 ]; then
    risk_score=$((risk_score + 15))
  elif [ "$suid_files" -gt 50 ]; then
    risk_score=$((risk_score + 10))
  fi
  
  if [ "$listening_ports" -gt 20 ]; then
    risk_score=$((risk_score + 10))
  elif [ "$listening_ports" -gt 10 ]; then
    risk_score=$((risk_score + 5))
  fi
  
  # 限制最大评分
  if [ "$risk_score" -gt 100 ]; then
    risk_score=100
  fi
  
  echo "【风险评估结果】"
  if [ "$risk_score" -ge 70 ]; then
    echo "风险等级: 高危 (评分: $risk_score)"
    echo "建议: 立即进行深入安全检查，可能存在严重安全威胁"
  elif [ "$risk_score" -ge 40 ]; then
    echo "风险等级: 中危 (评分: $risk_score)"
    echo "建议: 需要关注安全状况，建议进行详细排查"
  elif [ "$risk_score" -ge 20 ]; then
    echo "风险等级: 低危 (评分: $risk_score)"
    echo "建议: 系统相对安全，建议定期监控"
  else
    echo "风险等级: NORMAL (评分: $risk_score)"
    echo "建议: 系统安全状况良好"
  fi
  echo ""
  
  echo "【专业分析建议】"
  if [ "$uid0_users" -eq 0 ]; then
    echo "[正常] UID为0只有root用户，除了root之外没有高权限用户，建议与运维开发人员确认其他管理员账户配置。"
  else
    echo "[高危] 发现 $uid0_users 个非root的UID=0用户，存在严重安全风险，建议立即检查这些账户的合法性。"
  fi
  
  if [ "$suspicious_processes" -gt 5 ]; then
    echo "[中危] 发现 $suspicious_processes 个可疑脚本进程，数量较多，建议检查进程合法性。"
  elif [ "$suspicious_processes" -gt 0 ]; then
    echo "[低危] 发现 $suspicious_processes 个可疑脚本进程，建议确认进程用途。"
  else
    echo "[正常] 未发现明显可疑进程。"
  fi
  
  if [ "$login_failures" -gt 100 ]; then
    echo "[中危] 登录失败次数($login_failures)较多，可能存在暴力破解攻击。"
  elif [ "$login_failures" -gt 50 ]; then
    echo "[低危] 登录失败次数($login_failures)偏多，建议关注。"
  else
    echo "[正常] 登录失败次数在正常范围内。"
  fi
  
  if [ "$listening_ports" -gt 20 ]; then
    echo "[注意] 监听端口数量($listening_ports)较多，建议检查是否有不必要的服务。"
  else
    echo "[正常] 监听端口数量在合理范围内。"
  fi
  
  echo ""
  echo "【下一步建议】"
  echo "1. 使用增强版报告查看器进行详细分析"
  echo "2. 重点关注高危和中危项目"
  echo "3. 与系统管理员确认可疑发现"
  echo "4. 建议定期执行此脚本进行安全检查"
  
} >> "$REPORT"

rm -rf "$TMPDIR"
echo "应急响应报告已生成：$REPORT"
echo "请使用增强版报告查看器查看详细分析结果。"

