# 网络扫描和漏洞检测工具

一个功能强大的Python网络扫描工具，专注于服务识别、版本检测和漏洞发现。支持多种网络协议的识别，包括摄像头设备检测和漏洞扫描功能。

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
├── requirements.txt     # 依赖说明
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

## 🛠️ 安装和使用

### 环境要求
- Python 3.6+
- 无需额外依赖（使用Python标准库）

### 快速开始

```bash
# 克隆项目
git clone <repository-url>
cd Nmap/scanner

# 基础端口扫描
python main.py -t 192.168.1.1

# 扫描指定端口范围
python main.py -t 192.168.1.1 -p 1-1000

# 扫描多个目标
python main.py -t 192.168.1.1,192.168.1.2

# 从文件读取目标列表
python main.py -f targets.txt
```

### 高级功能

#### 漏洞扫描
```bash
# 启用漏洞扫描
python main.py -t 192.168.1.1 --vuln-scan

# 搜索特定服务漏洞
python main.py --vuln-search apache 2.4.41

# POC验证测试
python main.py -t 192.168.1.1 --poc-test

# 使用自定义POC脚本
python main.py -t 192.168.1.1 --custom-poc /path/to/poc/
```

#### 摄像头设备检测
```bash
# 启用摄像头专项检测
python main.py -t 192.168.1.0/24 --camera
```

#### 输出选项
```bash
# 保存结果到文件
python main.py -t 192.168.1.1 -o scan_result.txt

# JSON格式输出
python main.py -t 192.168.1.1 --format json -o result.json

# 详细输出
python main.py -t 192.168.1.1 -v
```

## 📋 命令行参数

### 目标参数
- `-t, --target`: 目标IP地址或网段
- `-f, --file`: 从文件读取目标列表
- `-p, --ports`: 端口范围 (默认: 1-1000)

### 扫描选项
- `--threads`: 线程数 (默认: 100)
- `--timeout`: 连接超时时间 (默认: 3秒)
- `--skip-ping`: 跳过主机存活检测
- `--camera`: 启用摄像头设备检测

### 漏洞检测
- `--vuln-scan`: 启用漏洞扫描
- `--vuln-search`: 搜索指定服务漏洞
- `--poc-test`: 执行POC验证
- `--custom-poc`: 自定义POC脚本路径
- `--max-poc`: 最大POC测试数量 (默认: 20)
- `--poc-timeout`: POC执行超时 (默认: 30秒)

### 输出选项
- `-o, --output`: 输出文件名
- `--format`: 输出格式 (txt/json/xml)
- `-v, --verbose`: 详细输出

## 🔧 配置说明

### 扫描配置 (config.py)
```python
class ScanConfig:
    # 通用配置
    timeout = 3              # 连接超时时间
    socket_read_buffer = 1024  # Socket读取缓冲区
    
    # 扫描配置
    parser = None            # Nmap数据解析器
    ports = "1-1000"         # 默认端口范围
    
    # 端口配置
    common_ports = [21, 22, 23, 25, 53, 80, ...]  # 常用端口
    camera_ports = [554, 8080, 8081, ...]         # 摄像头端口
```

### 自定义端口和服务
可以通过修改 `data/nmap-services` 文件来添加自定义服务识别规则。

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

### 使用须知
- 本工具仅用于授权的安全测试
- 请遵守相关法律法规
- 不得用于非法入侵或攻击

### 功能限制
- POC测试默认只进行检测，不执行破坏性操作
- 漏洞扫描基于公开漏洞库，可能存在误报
- 建议在隔离环境中进行测试

## 🤝 贡献指南

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🙏 致谢

- [Nmap](https://nmap.org/) - 网络扫描工具
- [ExploitDB](https://www.exploit-db.com/) - 漏洞数据库
- Python社区的贡献者们

---

**免责声明**: 本工具仅供学习和授权的安全测试使用，使用者需自行承担使用风险和法律责任。