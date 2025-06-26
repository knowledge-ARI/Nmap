# 网络扫描和漏洞检测工具

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

一个功能强大的Python网络扫描工具，专注于服务识别、版本检测和漏洞发现。支持多种网络协议的识别，包括摄像头设备检测和漏洞扫描功能。

## 📖 目录

- [主要特性](#-主要特性)
- [项目结构](#-项目结构)
- [快速开始](#-快速开始)
- [安装指南](#-安装指南)
- [使用示例](#-使用示例)
- [命令行参数](#-命令行参数)
- [配置说明](#-配置说明)
- [输出格式](#-输出格式)
- [安全说明](#-安全说明)
- [贡献指南](#-贡献指南)

## 🚀 主要特性

### 核心功能
- **端口扫描**: 支持TCP端口扫描，可自定义端口范围
- **服务识别**: 基于Nmap服务指纹库进行服务版本检测
- **设备指纹识别**: 支持摄像头设备等专项检测
- **漏洞扫描**: 集成ExploitDB数据库进行漏洞检测
- **POC验证**: 支持自动化漏洞验证和自定义POC脚本

### 扫描模式
- **基础扫描**: 端口扫描 + 服务识别
- **漏洞扫描**: 基础扫描 + 漏洞检测
- **摄像头检测**: 专项摄像头设备识别
- **漏洞搜索**: 基于服务名称和版本搜索已知漏洞
- **POC测试**: 执行漏洞验证脚本

### 技术特点
- **纯Python实现**: 基于Python标准库，减少外部依赖
- **多线程扫描**: 支持并发扫描提高效率
- **灵活配置**: 可自定义超时、线程数等参数
- **多种输出格式**: 支持文本、JSON、XML格式输出

## 📦 项目结构

```
scanner/
├── main.py              # 主程序入口
├── config.py            # 配置管理
├── scan.py              # 核心扫描引擎
├── parser.py            # Nmap数据解析器
├── vuln_search.py       # 漏洞搜索模块
├── poc_test.py          # POC测试模块
├── __init__.py          # 模块初始化
└── data/                # 数据文件目录
    ├── nmap-services    # 服务端口映射
    ├── nmap-service-probes  # 服务探测规则
    ├── nmap-os-db       # 操作系统指纹
    ├── files_exploits.csv   # 漏洞数据索引
    └── exploits/        # ExploitDB漏洞库
        ├── linux/       # Linux平台漏洞
        ├── windows/     # Windows平台漏洞
        ├── multiple/    # 跨平台漏洞
        └── ...
```

## 🚀 快速开始

### 环境要求
- **Python**: 3.6 或更高版本
- **操作系统**: Windows, Linux, macOS
- **依赖**: 主要基于Python标准库，可选外部依赖

### 快速安装

```bash
# 克隆项目
git clone https://github.com/knowledge-ARI/Nmap.git
cd Nmap

# 创建虚拟环境（推荐）
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/macOS
scanner_env\Scripts\activate     # Windows

# 安装项目
pip install .

# 验证安装
python scanner/main.py --help
```

### 基础使用

```bash
# 进入scanner目录
cd scanner

# 基础端口扫描
python main.py -t 192.168.1.1

# 扫描指定端口范围
python main.py -t 192.168.1.1 -p 1-1000

# 扫描网段
python main.py -t 192.168.1.0/24

# 从文件读取目标
python main.py -f targets.txt
```

## 📚 安装指南

详细安装说明请参考 [INSTALL.md](INSTALL.md)

### 标准安装

```bash
# 克隆项目
git clone https://github.com/knowledge-ARI/Nmap.git
cd Nmap

# 安装项目（包含所有功能）
pip install .
```

**注意**: 项目主要基于Python标准库，即使不安装任何依赖也可以运行基础功能。

## 💡 使用示例

### 基础扫描
```bash
# 单个主机扫描
python main.py -t 192.168.1.1

# 网段扫描
python main.py -t 192.168.1.0/24

# 指定端口范围
python main.py -t 192.168.1.1 -p 1-1000

# 多线程扫描
python main.py -t 192.168.1.1 --threads 100
```

### 高级功能
```bash
# 漏洞扫描
python main.py -t 192.168.1.1 --vuln-scan

# 摄像头设备检测
python main.py -t 192.168.1.0/24 --camera

# POC验证测试
python main.py -t 192.168.1.1 --poc-test

# 自定义POC脚本
python main.py -t 192.168.1.1 --custom-poc /path/to/poc/
```

### 输出和报告
```bash
# 保存到文件
python main.py -t 192.168.1.1 -o scan_result.txt

# JSON格式输出
python main.py -t 192.168.1.1 --format json -o result.json

# 详细输出模式
python main.py -t 192.168.1.1 -v
```

## 📋 命令行参数

### 目标参数
| 参数 | 说明 | 示例 |
|------|------|------|
| `-t, --target` | 目标IP地址或网段 | `192.168.1.1`, `10.0.0.0/24` |
| `-f, --file` | 从文件读取目标列表 | `targets.txt` |
| `-p, --ports` | 端口范围 | `80,443`, `1-1000` |

### 扫描选项
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--threads` | 20 | 并发线程数 |
| `--timeout` | 5 | 连接超时时间(秒) |
| `--ping-timeout` | 3 | Ping超时时间(秒) |
| `--skip-ping` | - | 跳过主机存活检测 |
| `--camera` | - | 启用摄像头设备检测 |

### 漏洞检测
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--vuln-scan` | - | 启用漏洞扫描 |
| `--vuln-search` | - | 搜索指定服务漏洞 |
| `--poc-test` | - | 执行POC验证 |
| `--custom-poc` | - | 自定义POC脚本路径 |
| `--max-poc` | 20 | 最大POC测试数量 |
| `--poc-timeout` | 30 | POC执行超时(秒) |

### 输出选项
| 参数 | 说明 | 支持格式 |
|------|------|----------|
| `-o, --output` | 输出文件名 | 任意文件名 |
| `--format` | 输出格式 | `txt`, `json`, `xml` |
| `-v, --verbose` | 详细输出 | - |

## 🔧 配置说明

### 核心配置文件

| 文件 | 用途 | 说明 |
|------|------|------|
| `config.py` | 主配置文件 | 扫描参数、端口配置、服务探测规则 |
| `data/nmap-services` | 服务端口映射 | 端口与服务的对应关系 |
| `data/nmap-service-probes` | 服务探测规则 | 服务版本检测的探测规则 |
| `data/nmap-os-db` | 操作系统指纹 | 操作系统识别规则 |

### 扫描配置 (config.py)
```python
class ScanConfig:
    # 通用配置
    timeout = 5                    # 连接超时时间
    socket_read_buffer = 4096      # Socket读取缓冲区
    
    # 端口配置
    common_ports = {               # 常用端口
        21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP',
        443: 'HTTPS', ...
    }
    
    camera_ports = {               # 摄像头端口
        554: 'RTSP', 8000: 'Hikvision',
        8080: 'HTTP Camera', 37777: 'Dahua', ...
    }
```

### 自定义配置
- **端口范围**: 修改 `config.py` 中的端口配置
- **服务规则**: 编辑 `data/nmap-services` 文件
- **探测规则**: 自定义 `data/nmap-service-probes` 文件
- **超时设置**: 调整 `timeout` 和相关参数

## 📊 输出格式

### 文本格式
```
🎯 扫描目标: 192.168.1.1
📊 扫描统计: 开放端口 3/1000, 用时 12.34秒

🔍 开放端口:
端口    服务信息                     漏洞
22      SSH OpenSSH 7.4             2
80      HTTP Apache 2.4.41          5
443     HTTPS Apache 2.4.41         3
```

### JSON格式
```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "start_time": "2025-01-XX XX:XX:XX",
    "duration": 12.34
  },
  "results": [
    {
      "port": 22,
      "service": "SSH OpenSSH 7.4",
      "vulnerabilities": [...]
    }
  ]
}
```

## 🛡️ 安全说明

### ⚠️ 重要提醒

**本工具仅供学习和授权的安全测试使用！**

### 使用须知
- ✅ **合法使用**: 仅在获得明确授权的网络和系统上使用
- ✅ **教育目的**: 用于网络安全学习和研究
- ✅ **安全测试**: 在自己的测试环境中使用
- ❌ **禁止行为**: 不得用于非法入侵、攻击或恶意活动

### 功能限制
- **POC测试**: 默认只进行检测，不执行破坏性操作
- **漏洞扫描**: 基于公开漏洞库，可能存在误报或漏报
- **网络影响**: 扫描可能被目标系统检测并记录
- **法律责任**: 使用者需自行承担使用风险和法律责任

### 最佳实践
- 🔒 在隔离的测试环境中进行测试
- 📋 获得书面授权后再进行扫描
- ⏰ 避免在生产环境的高峰时段扫描
- 📊 保留扫描日志以备审计

## 🤝 贡献指南

我们欢迎社区贡献！请遵循以下步骤：

### 贡献流程
1. **Fork** 项目到你的GitHub账户
2. **Clone** 你的fork到本地
   ```bash
   git clone https://github.com/your-username/Nmap.git
   ```
3. **创建分支** 进行开发
   ```bash
   git checkout -b feature/amazing-feature
   ```
4. **提交更改** 并推送
   ```bash
   git commit -m 'Add some amazing feature'
   git push origin feature/amazing-feature
   ```
5. **创建Pull Request**

### 贡献类型
- 🐛 **Bug修复**: 报告和修复问题
- ✨ **新功能**: 添加新的扫描功能
- 📚 **文档**: 改进文档和示例
- 🧪 **测试**: 添加测试用例
- 🎨 **优化**: 性能优化和代码重构

### 开发环境
```bash
# 安装开发依赖
pip install .[dev]

# 运行测试
python -m pytest

# 代码格式化
black scanner/
flake8 scanner/
```


## 🙏 致谢

- [Nmap](https://nmap.org/) - 网络扫描工具和数据库
- [ExploitDB](https://www.exploit-db.com/) - 漏洞数据库
- [Python社区](https://python.org) - 优秀的编程语言和生态
- 所有贡献者和用户的支持

<div align="center">

**⚠️ 免责声明 ⚠️**

本工具仅供学习和授权的安全测试使用。

使用者需自行承担使用风险和法律责任。

请遵守当地法律法规，不得用于非法用途。

</div>