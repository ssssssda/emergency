#!/bin/bash
# 增强版Linux应急响应脚本
# 增加统计分析和智能建议功能
# 运行方式：sudo bash enhanced_emergency_response.sh

NOW=$(date +"%Y%m%d_%H%M%S")
REPORT="emergency_report_${NOW}.txt"
JSON_REPORT="emergency_report_${NOW}.json"
TMPDIR=$(mktemp -d /tmp/emergency.XXXXXX)

# 定义分隔符
SECTION_SEP="=========================================="
SUBSECTION_SEP="------------------------------------------"
MODULE_SEP="##########################################"

# 统计变量
declare -A STATS
STATS[total_users]=0
STATS[uid0_users]=0
STATS[listening_ports]=0
STATS[suspicious_processes]=0
STATS[suid_files]=0
STATS[recent_files]=0
STATS[failed_logins]=0
STATS[cron_jobs]=0

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}请以 root 或 sudo 权限运行本脚本！${NC}"
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS=$(uname -s)
fi

declare -A TAB_TITLES=(
  [summary]="统计分析与建议"
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
)

# 函数：打印彩色输出
print_status() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# 函数：打印当前执行模块
print_module() {
  echo -e "${GREEN}正在执行模块：$1${NC}"
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

# 函数：统计分析
analyze_statistics() {
  local section="$1"
  local content="$2"
  
  case $section in
    "用户与登录检查")
      if [[ "$content" == *"所有用户"* ]]; then
        STATS[total_users]=$(echo "$content" | grep -c "^[a-zA-Z]")
      fi
      if [[ "$content" == *"登录失败记录"* ]]; then
        STATS[failed_logins]=$(echo "$content" | grep -c "Failed password")
      fi
      ;;
    "网络检查")
      if [[ "$content" == *"监听端口"* ]]; then
        STATS[listening_ports]=$(echo "$content" | grep -c "LISTEN\|:.*:")
      fi
      ;;
    "进程检查")
      if [[ "$content" == *"可疑脚本进程"* ]]; then
        STATS[suspicious_processes]=$(echo "$content" | grep -c "bash\|python\|perl\|php")
      fi
      ;;
    "文件系统检查")
      if [[ "$content" == *"SUID文件"* ]]; then
        STATS[suid_files]=$(echo "$content" | grep -c "rws")
      fi
      if [[ "$content" == *"最近修改的文件"* ]]; then
        STATS[recent_files]=$(echo "$content" | wc -l)
      fi
      ;;
    "持久化检查")
      if [[ "$content" == *"计划任务"* ]]; then
        STATS[cron_jobs]=$(echo "$content" | grep -c "crontab\|cron")
      fi
      ;;
  esac
}

# 1. 系统后门排查
backdoor_check() {
  print_module "${TAB_TITLES[backdoor]}"
  local content=""
  {
    write_section "${TAB_TITLES[backdoor]}"
    
    write_subsection "UID为0的非root用户"
    local uid0_output=$(awk -F: '($3 == 0 && $1 != "root"){print "可疑UID 0用户: "$1}' /etc/passwd)
    echo "$uid0_output"
    content+="$uid0_output"
    
    # 统计UID为0的用户
    STATS[uid0_users]=$(echo "$uid0_output" | grep -c "可疑UID 0用户" || echo "0")
    
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
  
  analyze_statistics "${TAB_TITLES[backdoor]}" "$content"
}

# 2. 用户与登录检查
user_check() {
  print_module "${TAB_TITLES[user]}"
  local content=""
  {
    write_section "${TAB_TITLES[user]}"
    
    write_subsection "当前用户"
    whoami
    
    write_subsection "所有用户"
    local users_output=$(awk -F: '{print $1}' /etc/passwd)
    echo "$users_output"
    content+="所有用户: $users_output"
    
    write_subsection "最近登录记录"
    last -a -n 20 2>/dev/null
    
    write_subsection "登录失败记录"
    local failed_logins=$(lastb -a -n 20 2>/dev/null || echo "lastb 未安装")
    echo "$failed_logins"
    content+="登录失败记录: $failed_logins"
  } >> "$REPORT"
  
  analyze_statistics "${TAB_TITLES[user]}" "$content"
}

# 3. 日志分析
log_check() {
  print_module "${TAB_TITLES[log]}"
  {
    write_section "${TAB_TITLES[log]}"
    
    write_subsection "SSH攻击统计分析"
    echo "=== 攻击IP统计与分析 ==="
    
    # 确定日志文件位置
    if [ -f /var/log/secure ]; then
        LOG_FILE="/var/log/secure"
    elif [ -f /var/log/auth.log ]; then
        LOG_FILE="/var/log/auth.log"
    else
        echo "未找到安全日志文件"
        LOG_FILE=""
    fi
    
    if [ -n "$LOG_FILE" ]; then
        echo "【失败登录IP统计 - 前20名攻击者】"
        grep "Failed password" $LOG_FILE 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -20 | while read count ip; do
            echo "攻击次数: $count | IP地址: $ip"
        done
        
        echo ""
        echo "【暴力破解时间分析 - 攻击高峰期】"
        grep "Failed password" $LOG_FILE 2>/dev/null | awk '{print $1" "$2" "$3}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10 | while read count time; do
            echo "攻击次数: $count | 时间段: $time"
        done
        
        echo ""
        echo "【成功登录IP统计 - 常用登录IP】"
        grep -E "Accepted password|Accepted publickey" $LOG_FILE 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | while read count ip; do
            echo "登录次数: $count | IP地址: $ip"
        done
        
        echo ""
        echo "【异常时间登录检测 - 非工作时间(22:00-06:00)】"
        grep -E "Accepted password|Accepted publickey" $LOG_FILE 2>/dev/null | awk '{
            time = $3
            split(time, t, ":")
            hour = t[1]
            if (hour >= 22 || hour <= 6) {
                print "异常时间登录: "$1" "$2" "$3" | 用户: "$(NF-5)" | IP: "$(NF-3)
            }
        }' | head -10
        
        echo ""
        echo "【用户登录行为统计】"
        grep -E "Accepted password|Accepted publickey" $LOG_FILE 2>/dev/null | awk '{
            for(i=1;i<=NF;i++) {
                if($i=="for") {
                    print $(i+1)
                    break
                }
            }
        }' | sort | uniq -c | sort -nr | while read count user; do
            echo "登录次数: $count | 用户: $user"
        done
        
        echo ""
        echo "【攻击成功率分析】"
        failed_count=$(grep "Failed password" $LOG_FILE 2>/dev/null | wc -l)
        success_count=$(grep -E "Accepted password|Accepted publickey" $LOG_FILE 2>/dev/null | wc -l)
        total_count=$((failed_count + success_count))
        if [ $total_count -gt 0 ]; then
            success_rate=$((success_count * 100 / total_count))
            echo "总登录尝试: $total_count"
            echo "失败次数: $failed_count"
            echo "成功次数: $success_count"
            echo "成功率: $success_rate%"
        fi
    fi
    
    write_subsection "登录会话分析"
    echo "【当前活跃会话】"
    who -u 2>/dev/null || who 2>/dev/null
    
    echo ""
    echo "【最近登录记录】"
    last -10 2>/dev/null
    
    echo ""
    echo "【登录失败详细分析 - 最近20次】"
    if [ -n "$LOG_FILE" ]; then
        grep "Failed password" $LOG_FILE 2>/dev/null | tail -20 | while read line; do
            echo "$line" | awk '{
                print "时间: "$1" "$2" "$3" | 用户: "$(NF-5)" | 来源IP: "$(NF-3)
            }'
        done
    fi
    
    write_subsection "系统日志错误"
    grep -Ei 'error|fail|denied|refused|invalid|segfault|unauthorized|attack|panic' /var/log/syslog /var/log/messages 2>/dev/null | tail -n 50
    
    write_subsection "数据传输异常分析"
    echo "【大量数据传输检测 - 可能的数据窃取】"
    if [ -f /var/log/wtmp ]; then
        last -f /var/log/wtmp | grep -v "reboot\|shutdown" | head -20 | while read line; do
            if echo "$line" | grep -q "still logged in"; then
                echo "⚠️ 长时间会话: $line"
            fi
        done
    fi
    
    echo ""
    echo "【文件传输活动检测】"
    if [ -n "$LOG_FILE" ]; then
        grep -E "sftp|scp|rsync|wget|curl" $LOG_FILE 2>/dev/null | tail -10 | while read line; do
            echo "📁 文件传输: $line"
        done
    fi
    
    echo ""
    echo "【频繁登录检测 - 可能的自动化攻击】"
    if [ -n "$LOG_FILE" ]; then
        echo "【5分钟内多次登录的IP】"
        grep -E "Accepted password|Accepted publickey" $LOG_FILE 2>/dev/null | awk '{
            time = $1" "$2" "$3
            ip = $(NF-3)
            print time"|"ip
        }' | sort | uniq | awk -F'|' '{
            ip = $2
            count[ip]++
            times[ip] = times[ip] $1 "\n"
        } END {
            for (ip in count) {
                if (count[ip] > 5) {
                    print "🚨 频繁登录IP: " ip " (次数: " count[ip] ")"
                }
            }
        }'
    fi
    
    write_subsection "攻击模式识别"
    echo "【常见攻击模式检测】"
    if [ -n "$LOG_FILE" ]; then
        echo "🔍 字典攻击检测:"
        grep "Failed password" $LOG_FILE 2>/dev/null | awk '{
            for(i=1;i<=NF;i++) {
                if($i=="for") {
                    user = $(i+1)
                    ip = $(NF-3)
                    key = ip"|"user
                    count[key]++
                    users[ip][user]++
                }
            }
        } END {
            for (key in count) {
                split(key, parts, "|")
                ip = parts[1]
                user = parts[2]
                if (count[key] > 10) {
                    print "  IP: " ip " 对用户 " user " 尝试 " count[key] " 次"
                }
            }
            print ""
            print "🔍 用户名枚举检测:"
            for (ip in users) {
                user_count = 0
                for (user in users[ip]) user_count++
                if (user_count > 5) {
                    print "  IP: " ip " 尝试了 " user_count " 个不同用户名"
                }
            }
        }'
        
        echo ""
        echo "🔍 时间模式分析:"
        grep "Failed password" $LOG_FILE 2>/dev/null | awk '{
            time = $3
            split(time, t, ":")
            hour = t[1]
            minute = t[2]
            time_slot = hour":"int(minute/10)*10
            count[time_slot]++
        } END {
            print "攻击时间分布 (10分钟间隔):"
            for (slot in count) {
                if (count[slot] > 20) {
                    print "  " slot " - " count[slot] " 次攻击 (高频)"
                }
            }
        }'
    fi
    
    write_subsection "IP地理位置分析"
    echo "【攻击来源地理分析】"
    if [ -n "$LOG_FILE" ] && command -v whois >/dev/null 2>&1; then
        echo "正在分析前5个攻击IP的地理位置..."
        grep "Failed password" $LOG_FILE 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -5 | while read count ip; do
            echo "IP: $ip (攻击次数: $count)"
            whois "$ip" 2>/dev/null | grep -E "country|Country|organization|Organization" | head -3
            echo "---"
        done
    else
        echo "whois工具未安装，无法进行地理位置分析"
        echo "建议安装: apt-get install whois 或 yum install whois"
    fi
    
    write_subsection "安全事件时间线"
    echo "【最近50个安全事件时间线】"
    if [ -n "$LOG_FILE" ]; then
        grep -E "Failed password|Accepted|Invalid user|Connection closed|sudo:" $LOG_FILE 2>/dev/null | tail -50 | while read line; do
            echo "$line" | awk '{
                time = $1" "$2" "$3
                if (match($0, /Failed password/)) {
                    print time" [🚨ATTACK] 密码攻击"
                } else if (match($0, /Accepted/)) {
                    print time" [✅LOGIN] 成功登录"
                } else if (match($0, /Invalid user/)) {
                    print time" [🔍SCAN] 用户扫描"
                } else if (match($0, /sudo:/)) {
                    print time" [⚡PRIV] 权限提升"
                } else {
                    print time" [ℹ️OTHER] 其他事件"
                }
            }'
        done
    fi
  } >> "$REPORT"
}

# 4. 网络检查
network_check() {
  print_module "${TAB_TITLES[network]}"
  local content=""
  {
    write_section "${TAB_TITLES[network]}"
    
    write_subsection "监听端口"
    local ports_output=$(ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null)
    echo "$ports_output"
    content+="监听端口: $ports_output"
    
    write_subsection "活动连接"
    ss -antp 2>/dev/null || netstat -antp 2>/dev/null
    
    write_subsection "网络配置"
    ip addr 2>/dev/null || ifconfig -a 2>/dev/null
    
    write_subsection "路由表"
    ip route 2>/dev/null || route -n 2>/dev/null
    
    write_subsection "可疑连接"
    ss -antp 2>/dev/null | grep ESTAB | grep -E ':[0-9]+.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v '127\.0\.0\.1' || true
  } >> "$REPORT"
  
  analyze_statistics "${TAB_TITLES[network]}" "$content"
}

# 5. 进程检查
process_check() {
  print_module "${TAB_TITLES[process]}"
  local content=""
  {
    write_section "${TAB_TITLES[process]}"
    
    write_subsection "高CPU占用进程"
    ps aux --sort=-%cpu | head -n 15
    
    write_subsection "可疑脚本进程"
    local suspicious_proc=$(ps aux | grep -E 'bash|sh|python|perl|php|nc|netcat|socat' | grep -vE 'grep|emergency_response.sh|enhanced_emergency_response.sh' | awk '{print $2, $11}')
    echo "$suspicious_proc"
    content+="可疑脚本进程: $suspicious_proc"
  } >> "$REPORT"
  
  analyze_statistics "${TAB_TITLES[process]}" "$content"
}

# 6. 文件系统检查
filesystem_check() {
  print_module "${TAB_TITLES[filesystem]}"
  local content=""
  {
    write_section "${TAB_TITLES[filesystem]}"
    
    write_subsection "SUID文件"
    local suid_output=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -exec ls -l {} \; 2>/dev/null)
    echo "$suid_output"
    content+="SUID文件: $suid_output"
    
    write_subsection "最近修改的文件"
    local recent_files=$(find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -type f -mtime -7 -exec ls -l {} \; 2>/dev/null | head -n 50)
    echo "$recent_files"
    content+="最近修改的文件: $recent_files"
  } >> "$REPORT"
  
  analyze_statistics "${TAB_TITLES[filesystem]}" "$content"
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
  local content=""
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
    local cron_output=""
    for u in $(cut -f1 -d: /etc/passwd); do
      local user_cron=$(crontab -l -u "$u" 2>/dev/null | grep -v '^#')
      if [ -n "$user_cron" ]; then
        echo "用户: $u"
        echo "$user_cron"
        cron_output+="$user_cron"
      fi
    done
    content+="计划任务: $cron_output"
    
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
  
  analyze_statistics "${TAB_TITLES[persistence]}" "$content"
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
    ps aux | grep -E 'kworker|kthreadd|crypto|minerd|\.tmp|\.sh|\.py|\.pl|\.php|/tmp|/dev/shm' | grep -vE 'grep|emergency_response.sh|enhanced_emergency_response.sh' | awk '{print $2, $11}'
    
    write_subsection "可疑提权点"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o -perm -4000 -type f -exec ls -l {} \; 2>/dev/null | grep -E 'nmap|perl|python|find|awk|vim|nano|less|more|cp|mv|bash|sh'
    
    write_subsection "隐藏文件"
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/lib/docker \) -prune -o \( -name ".*" -type f -o -name ".*" -type d \) -exec ls -l {} \; 2>/dev/null | head -n 50
  } >> "$REPORT"
}

# 11. 统计分析与建议
generate_summary() {
  print_module "${TAB_TITLES[summary]}"
  {
    write_section "${TAB_TITLES[summary]}"
    
    write_subsection "系统统计概览"
    echo "=== 系统基本信息 ==="
    echo "操作系统: $OS"
    echo "检查时间: $(date)"
    echo "总用户数: ${STATS[total_users]}"
    echo "UID为0的非root用户: ${STATS[uid0_users]}"
    echo "监听端口数: ${STATS[listening_ports]}"
    echo "可疑进程数: ${STATS[suspicious_processes]}"
    echo "SUID文件数: ${STATS[suid_files]}"
    echo "最近修改文件数: ${STATS[recent_files]}"
    echo "登录失败次数: ${STATS[failed_logins]}"
    echo "计划任务数: ${STATS[cron_jobs]}"
    
    write_subsection "安全风险评估"
    local risk_score=0
    local recommendations=""
    
    # 风险评分逻辑
    if [ "${STATS[uid0_users]}" -gt 0 ]; then
      risk_score=$((risk_score + 50))
      recommendations+="[高危] 发现${STATS[uid0_users]}个非root的UID为0用户，建议立即与运维开发人员确认这些用户的合法性。\n"
    else
      recommendations+="[正常] 除root外未发现其他UID为0的高权限用户，权限配置良好。\n"
    fi
    
    if [ "${STATS[suspicious_processes]}" -gt 10 ]; then
      risk_score=$((risk_score + 30))
      recommendations+="[中危] 发现${STATS[suspicious_processes]}个可疑脚本进程，数量较多，建议检查进程合法性。\n"
    elif [ "${STATS[suspicious_processes]}" -gt 0 ]; then
      recommendations+="[低危] 发现${STATS[suspicious_processes]}个可疑脚本进程，建议确认业务必要性。\n"
    fi
    
    if [ "${STATS[suid_files]}" -gt 100 ]; then
      risk_score=$((risk_score + 20))
      recommendations+="[中危] SUID文件数量(${STATS[suid_files]})较多，建议审查是否存在异常提权文件。\n"
    fi
    
    if [ "${STATS[failed_logins]}" -gt 50 ]; then
      risk_score=$((risk_score + 25))
      recommendations+="[中危] 登录失败次数(${STATS[failed_logins]})较多，可能存在暴力破解攻击。\n"
    fi
    
    if [ "${STATS[listening_ports]}" -gt 20 ]; then
      risk_score=$((risk_score + 15))
      recommendations+="[低危] 监听端口数量(${STATS[listening_ports]})较多，建议关闭不必要的服务。\n"
    fi
    
    # 风险等级判定
    if [ $risk_score -ge 80 ]; then
      echo "整体风险等级: 高危 (评分: $risk_score)"
    elif [ $risk_score -ge 50 ]; then
      echo "整体风险等级: 中危 (评分: $risk_score)"
    elif [ $risk_score -ge 20 ]; then
      echo "整体风险等级: 低危 (评分: $risk_score)"
    else
      echo "整体风险等级: 正常 (评分: $risk_score)"
    fi
    
    write_subsection "处置建议"
    echo -e "$recommendations"
    
    write_subsection "应急响应检查清单"
    echo "□ 1. 确认所有UID为0的用户合法性"
    echo "□ 2. 检查可疑进程的业务必要性"
    echo "□ 3. 审查SUID文件是否存在异常"
    echo "□ 4. 分析登录失败日志，确认是否存在攻击"
    echo "□ 5. 检查网络服务配置，关闭不必要端口"
    echo "□ 6. 审查计划任务和启动项配置"
    echo "□ 7. 检查最近修改的系统文件"
    echo "□ 8. 确认SSH密钥配置的合法性"
    echo "□ 9. 进行完整的恶意软件扫描"
    echo "□ 10. 更新系统和安全补丁"
    
  } >> "$REPORT"
}

# 生成JSON格式报告
generate_json_report() {
  print_status "生成JSON格式报告..."
  
  # 解析文本报告生成JSON
  python3 -c "
import json
import re
from collections import defaultdict

# 读取文本报告
with open('$REPORT', 'r', encoding='utf-8') as f:
    content = f.read()

# 解析报告
sections = content.split('##########################################')
data = {}

TAB_TITLES = {
    '系统后门排查': 'backdoor',
    '用户与登录检查': 'user', 
    '日志分析': 'log',
    '网络检查': 'network',
    '进程检查': 'process',
    '文件系统检查': 'filesystem',
    '软件包检查': 'package',
    '持久化检查': 'persistence',
    '系统完整性': 'integrity',
    '恶意进程与提权点': 'malware',
    '统计分析与建议': 'summary'
}

for section in sections:
    if not section.strip():
        continue
    
    module_match = re.search(r'模块: (.*?)\n', section)
    if not module_match:
        continue
    
    module_title = module_match.group(1)
    module_key = TAB_TITLES.get(module_title)
    if not module_key:
        continue
    
    sub_sections = section.split('------------------------------------------')
    data[module_key] = {}
    
    for i in range(1, len(sub_sections), 2):
        if i + 1 < len(sub_sections):
            title_match = re.search(r'子项: (.*?)\n', sub_sections[i])
            if title_match:
                title = title_match.group(1)
                content = sub_sections[i + 1].strip() if i + 1 < len(sub_sections) else ''
                data[module_key][title] = content

# 添加统计信息
data['metadata'] = {
    'generated_time': '$(date -Iseconds)',
    'hostname': '$(hostname)',
    'os': '$OS',
    'script_version': 'enhanced_v1.0',
    'statistics': {
        'total_users': ${STATS[total_users]},
        'uid0_users': ${STATS[uid0_users]},
        'listening_ports': ${STATS[listening_ports]},
        'suspicious_processes': ${STATS[suspicious_processes]},
        'suid_files': ${STATS[suid_files]},
        'recent_files': ${STATS[recent_files]},
        'failed_logins': ${STATS[failed_logins]},
        'cron_jobs': ${STATS[cron_jobs]}
    }
}

# 写入JSON文件
with open('$JSON_REPORT', 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print('JSON报告生成完成')
" 2>/dev/null || echo "Python3未安装，跳过JSON报告生成"
}

# 主执行流程
main() {
  print_status "开始Linux应急响应检查..."
  
  # 创建报告文件
  {
    echo "Linux 应急响应报告 (增强版)"
    echo "生成时间: $(date)"
    echo "主机名: $(hostname)"
    echo "操作系统: $OS"
    echo "$MODULE_SEP"
    echo
  } > "$REPORT"
  
  # 执行所有检查模块
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
  generate_summary
  
  # 生成JSON报告
  generate_json_report
  
  # 清理临时目录
  rm -rf "$TMPDIR"
  
  print_success "应急响应检查完成！"
  echo
  print_status "报告文件："
  echo "  文本格式: $REPORT"
  echo "  JSON格式: $JSON_REPORT"
  echo
  print_status "统计摘要："
  echo "  总用户数: ${STATS[total_users]}"
  echo "  UID为0的非root用户: ${STATS[uid0_users]}"
  echo "  监听端口数: ${STATS[listening_ports]}"
  echo "  可疑进程数: ${STATS[suspicious_processes]}"
  echo "  SUID文件数: ${STATS[suid_files]}"
  
  if [ "${STATS[uid0_users]}" -gt 0 ]; then
    print_error "发现${STATS[uid0_users]}个异常UID为0用户，建议立即检查！"
  else
    print_success "用户权限配置正常"
  fi
  
  echo
  print_status "建议使用增强版Web界面查看详细分析结果："
  echo "  python3 enhanced_rules_engine.py"
}

# 执行主函数
main "$@"