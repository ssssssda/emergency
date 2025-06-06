#!/usr/bin/env python3
"""
增强版应急响应规则引擎
- 添加文件上传功能
- 增加统计分析
- 提供智能建议
- 改进安全配置
"""
import yaml
import re
import json
import os
import hashlib
import datetime
from pathlib import Path
from collections import defaultdict, Counter
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('emergency_response.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
# 限制CORS只允许特定来源（生产环境中应该配置具体域名）
CORS(app, origins=["http://localhost:*", "https://*.prod-runtime.all-hands.dev"])

# 配置文件上传
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'json', 'log'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class EnhancedRuleEngine:
    def __init__(self):
        self.rules = self.load_rules()
        self.analysis_stats = defaultdict(int)
        
    def load_rules(self):
        rules_dir = Path(__file__).parent / 'rules'
        rules = {}
        loaded_files = 0
        
        for rule_file in rules_dir.rglob('*.yml'):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule_data = yaml.safe_load(f)
                    if isinstance(rule_data, list):
                        for rule in rule_data:
                            if isinstance(rule, dict) and 'id' in rule:
                                rules[rule['id']] = rule
                                loaded_files += 1
                    elif isinstance(rule_data, dict) and 'id' in rule_data:
                        rules[rule_data['id']] = rule_data
                        loaded_files += 1
            except Exception as e:
                logging.error(f"Error loading rule file {rule_file}: {str(e)}")
                
        logging.info(f"Loaded {loaded_files} rules from {len(list(rules_dir.rglob('*.yml')))} files")
        return rules

    def evaluate_rule(self, rule, data):
        try:
            if 'pattern' not in rule:
                return False
                
            pattern = re.compile(rule['pattern'], re.I if rule.get('case_insensitive', True) else 0)
            content = data.get(rule.get('target_field', 'content'), '')
            
            if not content:
                return False
                
            matches = list(pattern.finditer(content))
            if matches:
                findings = []
                for match in matches:
                    findings.append({
                        'start': match.start(),
                        'end': match.end(),
                        'matched_text': match.group(0),
                        'line_number': content[:match.start()].count('\n') + 1
                    })
                
                return {
                    'rule_id': rule['id'],
                    'level': rule.get('level', 'medium'),
                    'description': rule.get('description', ''),
                    'findings': findings,
                    'recommendation': self.get_recommendation(rule['id'])
                }
        except Exception as e:
            logging.error(f"Rule evaluation error for {rule.get('id', 'unknown')}: {str(e)}")
        return False

    def get_recommendation(self, rule_id):
        """根据规则ID提供具体的处置建议"""
        recommendations = {
            'non_root_uid0': '建议立即检查该用户的创建来源，确认是否为恶意账户。如确认为异常，应立即禁用该账户并检查其活动日志。',
            'suspicious_cron_download': '发现可疑的定时下载任务，建议立即停止相关cron任务，检查下载的文件内容，并追踪任务的创建来源。',
            'hidden_startup_script': '发现隐藏的启动脚本，这通常是恶意软件的特征。建议立即检查脚本内容，如确认为恶意代码应立即删除并进行全面安全扫描。',
            'reverse_shell_startup': '检测到反向Shell配置，这是严重的安全威胁。建议立即断开相关网络连接，删除恶意配置，并进行完整的系统安全审计。',
            'webshell_detection': '发现WebShell特征，建议立即隔离相关Web服务，检查Web目录中的可疑文件，并审查Web服务器访问日志。',
            'rootkit_detection': '检测到Rootkit特征，这是高级持久化威胁。建议使用专业的Rootkit检测工具进行深度扫描，必要时考虑系统重建。'
        }
        return recommendations.get(rule_id, '建议联系安全团队进行进一步分析和处置。')

    def generate_statistics(self, report_data):
        """生成统计分析报告"""
        stats = {
            'system_overview': {},
            'security_summary': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # 系统概览统计
        if 'user' in report_data:
            user_data = report_data['user']
            if '所有用户' in user_data:
                users = user_data['所有用户'].strip().split('\n')
                stats['system_overview']['total_users'] = len([u for u in users if u.strip()])
                
                # 检查UID为0的用户
                uid0_users = []
                if 'UID为0的非root用户' in report_data.get('backdoor', {}):
                    uid0_content = report_data['backdoor']['UID为0的非root用户']
                    if uid0_content.strip():
                        uid0_users = [line for line in uid0_content.split('\n') if 'UID 0用户' in line]
                
                if not uid0_users:
                    stats['recommendations'].append({
                        'level': 'info',
                        'title': '用户权限检查',
                        'description': f'系统共有 {stats["system_overview"]["total_users"]} 个用户账户，除root外未发现其他UID为0的高权限用户，这是良好的安全实践。',
                        'action': '建议定期审查用户账户，确保权限分配合理。'
                    })
                else:
                    stats['recommendations'].append({
                        'level': 'critical',
                        'title': '发现异常高权限用户',
                        'description': f'发现 {len(uid0_users)} 个非root的UID为0用户，这可能是安全威胁。',
                        'action': '建议立即与运维和开发人员确认这些用户的合法性，如无法确认应立即禁用。'
                    })

        # 网络连接统计
        if 'network' in report_data:
            network_data = report_data['network']
            if '监听端口' in network_data:
                listening_ports = network_data['监听端口']
                port_lines = [line for line in listening_ports.split('\n') if 'LISTEN' in line or ':' in line]
                stats['system_overview']['listening_ports'] = len(port_lines)
                
                # 分析常见端口
                common_ports = {'22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '3306': 'MySQL', '5432': 'PostgreSQL'}
                found_services = []
                for line in port_lines:
                    for port, service in common_ports.items():
                        if f':{port} ' in line or f':{port}\t' in line:
                            found_services.append(service)
                
                if found_services:
                    stats['recommendations'].append({
                        'level': 'info',
                        'title': '网络服务检查',
                        'description': f'检测到以下网络服务: {", ".join(set(found_services))}',
                        'action': '建议确认所有服务都是必需的，关闭不必要的服务以减少攻击面。'
                    })

        # 进程分析
        if 'process' in report_data:
            process_data = report_data['process']
            if '可疑脚本进程' in process_data:
                suspicious_processes = process_data['可疑脚本进程']
                process_lines = [line for line in suspicious_processes.split('\n') if line.strip()]
                if process_lines:
                    stats['recommendations'].append({
                        'level': 'medium',
                        'title': '可疑进程检查',
                        'description': f'发现 {len(process_lines)} 个可疑脚本进程',
                        'action': '建议检查这些进程的合法性，确认其业务必要性。'
                    })

        # 文件系统检查
        if 'filesystem' in report_data:
            fs_data = report_data['filesystem']
            if 'SUID文件' in fs_data:
                suid_files = fs_data['SUID文件']
                suid_lines = [line for line in suid_files.split('\n') if '-rws' in line]
                stats['system_overview']['suid_files'] = len(suid_lines)
                
                if len(suid_lines) > 50:  # 假设正常系统SUID文件数量
                    stats['recommendations'].append({
                        'level': 'medium',
                        'title': 'SUID文件数量异常',
                        'description': f'发现 {len(suid_lines)} 个SUID文件，数量较多',
                        'action': '建议审查SUID文件列表，确认是否存在异常的提权文件。'
                    })

        return stats

    def analyze_report(self, report_data):
        results = {
            'high': [],
            'medium': [],
            'low': [],
            'statistics': {},
            'summary': {}
        }
        
        # 生成统计信息
        results['statistics'] = self.generate_statistics(report_data)
        
        # 规则匹配分析
        total_rules_checked = 0
        total_matches = 0
        
        for section, content in report_data.items():
            if isinstance(content, dict):
                for subsection, subcontent in content.items():
                    data = {
                        'section': section,
                        'subsection': subsection,
                        'content': str(subcontent)
                    }
                    
                    for rule in self.rules.values():
                        total_rules_checked += 1
                        if rule.get('target_section') == section or not rule.get('target_section'):
                            result = self.evaluate_rule(rule, data)
                            if result:
                                total_matches += 1
                                level = result['level']
                                if level == 'critical':
                                    level = 'high'  # 将critical映射到high
                                
                                if level in results:
                                    results[level].append({
                                        **result,
                                        'section': section,
                                        'subsection': subsection
                                    })
        
        # 生成总结
        results['summary'] = {
            'total_rules_checked': total_rules_checked,
            'total_matches': total_matches,
            'high_risk_count': len(results['high']),
            'medium_risk_count': len(results['medium']),
            'low_risk_count': len(results['low']),
            'analysis_time': datetime.datetime.now().isoformat(),
            'overall_risk_level': self.calculate_overall_risk(results)
        }
        
        # 记录分析统计
        self.analysis_stats['total_analyses'] += 1
        self.analysis_stats['total_alerts'] += total_matches
        
        logging.info(f"Analysis completed: {total_matches} alerts found from {total_rules_checked} rule checks")
        
        return results

    def calculate_overall_risk(self, results):
        """计算整体风险等级"""
        high_count = len(results['high'])
        medium_count = len(results['medium'])
        low_count = len(results['low'])
        
        if high_count > 0:
            return 'HIGH'
        elif medium_count > 3:
            return 'MEDIUM'
        elif medium_count > 0 or low_count > 5:
            return 'LOW'
        else:
            return 'NORMAL'

engine = EnhancedRuleEngine()

# Web界面HTML模板
WEB_INTERFACE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux应急响应分析平台</title>
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
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .upload-section {
            padding: 40px;
            text-align: center;
            background: #f8f9fa;
        }
        .upload-area {
            border: 3px dashed #007bff;
            border-radius: 10px;
            padding: 40px;
            margin: 20px 0;
            background: white;
            transition: all 0.3s ease;
            cursor: pointer;
        }
        .upload-area:hover {
            border-color: #0056b3;
            background: #f0f8ff;
        }
        .upload-area.dragover {
            border-color: #28a745;
            background: #f0fff0;
        }
        .file-input {
            display: none;
        }
        .upload-btn {
            background: #007bff;
            color: white;
            padding: 12px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin: 10px;
            transition: background 0.3s;
        }
        .upload-btn:hover { background: #0056b3; }
        .analyze-btn {
            background: #28a745;
            color: white;
            padding: 15px 40px;
            border: none;
            border-radius: 5px;
            font-size: 18px;
            cursor: pointer;
            margin-top: 20px;
            transition: background 0.3s;
        }
        .analyze-btn:hover { background: #1e7e34; }
        .analyze-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
        }
        .results-section {
            padding: 40px;
            display: none;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #666;
            font-size: 1.1em;
        }
        .risk-high { color: #dc3545; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #17a2b8; }
        .risk-normal { color: #28a745; }
        .alert-section {
            margin-top: 30px;
        }
        .alert {
            background: white;
            border-left: 5px solid;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 8px 8px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .alert-high { border-left-color: #dc3545; }
        .alert-medium { border-left-color: #ffc107; }
        .alert-low { border-left-color: #17a2b8; }
        .alert-title {
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .alert-description {
            margin-bottom: 15px;
            line-height: 1.6;
        }
        .alert-recommendation {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #007bff;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 40px;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .recommendations {
            background: #e8f4fd;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
        }
        .recommendation-item {
            background: white;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Linux应急响应分析平台</h1>
            <p>智能化安全威胁检测与分析系统</p>
        </div>
        
        <div class="upload-section">
            <h2>上传应急响应报告</h2>
            <div class="upload-area" onclick="document.getElementById('fileInput').click()">
                <div id="uploadText">
                    <h3>📁 点击选择文件或拖拽文件到此处</h3>
                    <p>支持 .txt, .json, .log 格式文件，最大16MB</p>
                </div>
            </div>
            <input type="file" id="fileInput" class="file-input" accept=".txt,.json,.log">
            <div>
                <button class="upload-btn" onclick="document.getElementById('fileInput').click()">
                    选择文件
                </button>
                <button class="analyze-btn" id="analyzeBtn" onclick="analyzeReport()" disabled>
                    开始分析
                </button>
            </div>
        </div>
        
        <div class="loading" id="loading">
            <div class="spinner"></div>
            <h3>正在分析报告，请稍候...</h3>
        </div>
        
        <div class="results-section" id="results">
            <!-- 分析结果将在这里显示 -->
        </div>
    </div>

    <script>
        let uploadedFile = null;
        let analysisResults = null;

        // 文件上传处理
        document.getElementById('fileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                uploadedFile = file;
                document.getElementById('uploadText').innerHTML = 
                    `<h3>✅ 已选择文件: ${file.name}</h3>
                     <p>文件大小: ${(file.size / 1024 / 1024).toFixed(2)} MB</p>`;
                document.getElementById('analyzeBtn').disabled = false;
            }
        });

        // 拖拽上传
        const uploadArea = document.querySelector('.upload-area');
        uploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const file = files[0];
                if (file.name.match(/\\.(txt|json|log)$/i)) {
                    uploadedFile = file;
                    document.getElementById('uploadText').innerHTML = 
                        `<h3>✅ 已选择文件: ${file.name}</h3>
                         <p>文件大小: ${(file.size / 1024 / 1024).toFixed(2)} MB</p>`;
                    document.getElementById('analyzeBtn').disabled = false;
                } else {
                    alert('请选择 .txt, .json 或 .log 格式的文件');
                }
            }
        });

        // 分析报告
        async function analyzeReport() {
            if (!uploadedFile) {
                alert('请先选择文件');
                return;
            }

            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';

            try {
                // 读取文件内容
                const text = await readFileAsText(uploadedFile);
                let data;
                
                try {
                    data = JSON.parse(text);
                } catch (jsonError) {
                    data = parseTextReport(text);
                }

                // 发送到后端分析
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data)
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                analysisResults = await response.json();
                displayResults(analysisResults);

            } catch (error) {
                console.error('分析失败:', error);
                alert('分析失败: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
            }
        }

        function readFileAsText(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => resolve(e.target.result);
                reader.onerror = reject;
                reader.readAsText(file);
            });
        }

        function parseTextReport(text) {
            const sections = text.split("##########################################");
            const data = {};
            
            const TAB_TITLES = {
                "系统后门排查": "backdoor",
                "用户与登录检查": "user", 
                "日志分析": "log",
                "网络检查": "network",
                "进程检查": "process",
                "文件系统检查": "filesystem",
                "软件包检查": "package",
                "持久化检查": "persistence",
                "系统完整性": "integrity",
                "恶意进程与提权点": "malware"
            };
            
            for (const section of sections) {
                if (!section.trim()) continue;
                
                const moduleMatch = section.match(/模块: (.*?)\\n/);
                if (!moduleMatch) continue;
                
                const moduleTitle = moduleMatch[1];
                const moduleKey = TAB_TITLES[moduleTitle];
                if (!moduleKey) continue;
                
                const subSections = section.split("------------------------------------------");
                data[moduleKey] = {};
                
                for (let i = 1; i < subSections.length; i += 2) {
                    const titleMatch = subSections[i].match(/子项: (.*?)\\n/);
                    if (!titleMatch) continue;
                    const title = titleMatch[1];
                    const content = subSections[i + 1] ? subSections[i + 1].trim() : "";
                    data[moduleKey][title] = content;
                }
            }
            
            return data;
        }

        function displayResults(results) {
            const resultsDiv = document.getElementById('results');
            
            const summary = results.summary || {};
            const stats = results.statistics || {};
            
            let html = `
                <h2>📊 分析结果概览</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number risk-${summary.overall_risk_level?.toLowerCase() || 'normal'}">${summary.overall_risk_level || 'NORMAL'}</div>
                        <div class="stat-label">整体风险等级</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number risk-high">${results.high?.length || 0}</div>
                        <div class="stat-label">高危告警</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number risk-medium">${results.medium?.length || 0}</div>
                        <div class="stat-label">中危告警</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number risk-low">${results.low?.length || 0}</div>
                        <div class="stat-label">低危告警</div>
                    </div>
                </div>
            `;

            // 显示智能建议
            if (stats.recommendations && stats.recommendations.length > 0) {
                html += `
                    <div class="recommendations">
                        <h3>🎯 智能分析建议</h3>
                `;
                stats.recommendations.forEach(rec => {
                    html += `
                        <div class="recommendation-item">
                            <strong>${rec.title}</strong>
                            <p>${rec.description}</p>
                            <p><strong>建议措施:</strong> ${rec.action}</p>
                        </div>
                    `;
                });
                html += `</div>`;
            }

            // 显示告警详情
            if (results.high?.length > 0 || results.medium?.length > 0 || results.low?.length > 0) {
                html += `<div class="alert-section"><h3>🚨 安全告警详情</h3>`;
                
                ['high', 'medium', 'low'].forEach(level => {
                    if (results[level] && results[level].length > 0) {
                        results[level].forEach(alert => {
                            html += `
                                <div class="alert alert-${level}">
                                    <div class="alert-title">${alert.description}</div>
                                    <div class="alert-description">
                                        <strong>检测位置:</strong> ${alert.section} → ${alert.subsection}<br>
                                        <strong>规则ID:</strong> ${alert.rule_id}
                                    </div>
                                    ${alert.recommendation ? `
                                        <div class="alert-recommendation">
                                            <strong>处置建议:</strong> ${alert.recommendation}
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        });
                    }
                });
                html += `</div>`;
            }

            resultsDiv.innerHTML = html;
            resultsDiv.style.display = 'block';
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(WEB_INTERFACE)

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # 添加时间戳避免文件名冲突
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            logging.info(f"File uploaded: {filename}")
            return jsonify({'message': 'File uploaded successfully', 'filename': filename})
        else:
            return jsonify({'error': 'Invalid file type'}), 400
    except Exception as e:
        logging.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        report_data = request.json
        if not report_data:
            return jsonify({'error': 'No data provided'}), 400
        
        # 记录分析请求
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        logging.info(f"Analysis request from {client_ip}")
        
        results = engine.analyze_report(report_data)
        return jsonify(results)
    except Exception as e:
        logging.error(f"Analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/stats')
def get_stats():
    """获取系统统计信息"""
    return jsonify({
        'total_analyses': engine.analysis_stats['total_analyses'],
        'total_alerts': engine.analysis_stats['total_alerts'],
        'rules_count': len(engine.rules),
        'uptime': datetime.datetime.now().isoformat()
    })

@app.route('/health')
def health_check():
    """健康检查接口"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.now().isoformat()})

if __name__ == '__main__':
    # 生产环境配置
    port = int(os.environ.get('PORT', 12000))  # 使用环境变量或默认端口
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logging.info(f"Starting Enhanced Emergency Response Engine on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)