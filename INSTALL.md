# 安装指南

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

本文档提供了网络扫描和漏洞检测工具的详细安装说明和配置指南。

## 📖 目录

- [系统要求](#-系统要求)
- [快速安装](#-快速安装)
- [依赖管理](#-依赖管理)
- [安装验证](#-安装验证)
- [常见问题](#-常见问题)
- [平台特定说明](#-平台特定说明)
- [高级配置](#-高级配置)
- [卸载说明](#-卸载说明)

## 📋 系统要求

### 最低要求
| 组件 | 要求 | 说明 |
|------|------|------|
| **Python版本** | 3.6+ | 必须，支持f-string和类型注解 |
| **操作系统** | Windows 7+, Linux, macOS 10.12+ | 跨平台支持 |
| **内存** | 512MB RAM | 基础扫描功能 |
| **磁盘空间** | 100MB | 不含ExploitDB数据库 |
| **网络** | 互联网连接 | 用于下载依赖和更新 |

### 推荐配置
| 组件 | 推荐 | 优势 |
|------|------|------|
| **Python版本** | 3.8+ | 更好的性能和新特性 |
| **内存** | 2GB+ | 支持大规模扫描 |
| **磁盘空间** | 1GB+ | 包含完整ExploitDB数据库 |
| **CPU** | 多核处理器 | 提高并发扫描性能 |

### 权限要求
- **Windows**: 普通用户权限（某些功能需要管理员权限）
- **Linux/macOS**: 普通用户权限（原始套接字需要root权限）

## 🚀 快速安装

### 方法1: 从源码安装（推荐）

```bash
# 1. 克隆项目
git clone https://github.com/knowledge-ARI/Nmap.git
cd Nmap

# 2. 创建虚拟环境（强烈推荐）
python -m venv scanner_env

# 3. 激活虚拟环境
# Windows PowerShell:
scanner_env\Scripts\Activate.ps1
# Windows CMD:
scanner_env\Scripts\activate.bat
# Linux/macOS:
source scanner_env/bin/activate

# 4. 升级pip（推荐）
python -m pip install --upgrade pip

# 5. 安装项目
pip install .

# 6. 验证安装
python scanner/main.py --help
```

### 方法2: 直接使用（无需安装）

```bash
# 1. 克隆项目
git clone https://github.com/knowledge-ARI/Nmap.git
cd Nmap

# 2. 直接运行（使用Python标准库）
cd scanner
python main.py --help

# 3. 可选：安装最小依赖以获得更多功能
pip install requests python-nmap
```

### 方法3: 开发者安装

```bash
# 1. 克隆并进入项目
git clone https://github.com/knowledge-ARI/Nmap.git
cd Nmap

# 2. 创建开发环境
python -m venv dev_env
source dev_env/bin/activate  # Linux/macOS
dev_env\Scripts\activate     # Windows

# 3. 安装开发依赖
pip install -e .[dev]

# 4. 安装pre-commit钩子（可选）
pre-commit install
```

## 📦 依赖管理

### 统一安装方式

本项目采用统一的依赖管理策略，所有功能依赖都包含在 `requirements.txt` 中。

```bash
# 标准安装（推荐）
pip install .
```

**包含功能**:
- ✅ 端口扫描和主机发现
- ✅ HTTP/HTTPS扫描
- ✅ Nmap集成
- ✅ 高级网络分析
- ✅ 数据分析和可视化
- ✅ 加密通信支持
- ✅ 报告生成

**主要依赖**:
- `requests>=2.25.0` - HTTP客户端
- `python-nmap>=0.6.1` - Nmap接口
- `scapy>=2.4.0` - 网络包分析
- `pandas>=1.3.0` - 数据处理
- `cryptography>=3.4.0` - 加密支持
- `jinja2>=3.0.0` - 报告模板
- 其他增强功能依赖

**注意**: 项目主要基于Python标准库设计，即使不安装任何依赖也可以运行基础功能。

## ✅ 安装验证

### 1. 检查Python环境
```bash
# 检查Python版本
python --version
# 期望输出: Python 3.6.x 或更高版本

# 检查pip版本
pip --version
# 期望输出: pip 20.0+ 或更高版本

# 检查虚拟环境（如果使用）
which python  # Linux/macOS
where python  # Windows
```

### 2. 验证核心模块
```bash
# 测试Python标准库模块
python -c "import socket, threading, subprocess; print('✅ 核心模块正常')"

# 测试可选依赖（如果已安装）
python -c "import requests; print('✅ requests可用')" 2>/dev/null || echo "ℹ️ requests未安装"
python -c "import nmap; print('✅ python-nmap可用')" 2>/dev/null || echo "ℹ️ python-nmap未安装"
```

### 3. 功能测试
```bash
# 进入scanner目录
cd scanner

# 显示帮助信息
python main.py --help
# 期望输出: 完整的帮助信息

# 测试基础扫描功能
python main.py -t 127.0.0.1 -p 80 --timeout 1
# 期望输出: 扫描结果或"主机不可达"

# 测试参数解析
python main.py -t 192.168.1.1 --skip-ping -v
# 期望输出: 详细的扫描过程
```

### 4. 性能测试
```bash
# 测试多线程扫描
python main.py -t 127.0.0.1 -p 1-100 --threads 50 --timeout 1

# 测试内存使用
python -c "import scanner.main; print('✅ 模块导入正常')"
```

### 5. 安装状态检查
```bash
# 检查已安装的包
pip list | grep -E "(requests|nmap|scapy|pandas)"

# 检查项目是否正确安装
pip show network-scanner-vuln-detector 2>/dev/null || echo "ℹ️ 项目未通过pip安装"

# 验证命令行工具（如果已安装）
network-scanner --help 2>/dev/null || echo "ℹ️ 命令行工具未安装"
```

## 🐛 常见问题

### Python环境问题

#### 问题1: Python版本过低
```
RuntimeError: 此项目需要Python 3.6或更高版本
```
**解决方案**:
```bash
# 检查当前版本
python --version

# Windows: 从python.org下载最新版本
# Linux: 使用包管理器升级
sudo apt update && sudo apt install python3.8  # Ubuntu
sudo yum install python38                      # CentOS

# macOS: 使用Homebrew
brew install python@3.8
```

#### 问题2: 找不到python命令
```
'python' is not recognized as an internal or external command
```
**解决方案**:
```bash
# Windows: 使用python3或py命令
python3 --version
py --version

# 或添加Python到PATH环境变量
# Linux/macOS: 创建软链接
sudo ln -s /usr/bin/python3 /usr/bin/python
```

### 依赖安装问题

#### 问题3: pip安装失败
```
ERROR: Could not install packages due to an EnvironmentError
```
**解决方案**:
```bash
# 方案1: 升级pip
python -m pip install --upgrade pip

# 方案2: 使用用户安装
pip install --user .

# 方案3: 使用虚拟环境
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/macOS
scanner_env\Scripts\activate     # Windows
pip install .

# 方案4: 清理缓存
pip cache purge
pip install --no-cache-dir .
```

#### 问题4: 权限错误
```
PermissionError: [Errno 13] Permission denied
```
**解决方案**:
```bash
# 推荐: 使用虚拟环境
python -m venv venv
source venv/bin/activate
pip install .

# 或使用用户安装
pip install --user .

# Linux/macOS: 修复权限（不推荐）
sudo chown -R $USER:$USER ~/.local/lib/python*/site-packages
```

### 网络连接问题

#### 问题5: 下载超时
```
ConnectionError: Failed to establish a new connection
```
**解决方案**:
```bash
# 使用国内镜像源
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple .

# 或配置永久镜像源
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple

# 使用代理
pip install --proxy http://proxy.example.com:8080 .

# 增加超时时间
pip install --timeout 300 .
```

### 运行时问题

#### 问题6: 模块导入错误
```
ModuleNotFoundError: No module named 'scanner'
```
**解决方案**:
```bash
# 确保在正确的目录
cd /path/to/Nmap
python scanner/main.py --help

# 或设置PYTHONPATH
export PYTHONPATH="$PWD:$PYTHONPATH"  # Linux/macOS
set PYTHONPATH=%CD%;%PYTHONPATH%      # Windows

# 或使用-m参数
python -m scanner.main --help
```

#### 问题7: 权限不足（扫描时）
```
PermissionError: Operation not permitted
```
**解决方案**:
```bash
# Linux/macOS: 某些功能需要root权限
sudo python scanner/main.py -t target

# 或使用非特权端口
python scanner/main.py -t target -p 80,443,8080

# Windows: 以管理员身份运行PowerShell
```

### 性能问题

#### 问题8: 扫描速度慢
**解决方案**:
```bash
# 增加线程数
python main.py -t target --threads 100

# 减少超时时间
python main.py -t target --timeout 1

# 跳过ping检测
python main.py -t target --skip-ping

# 扫描特定端口
python main.py -t target -p 80,443,22,21
```

## 🔒 安全注意事项

### 环境隔离
```bash
# 强烈推荐使用虚拟环境
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/macOS
scanner_env\Scripts\activate     # Windows

# 验证环境隔离
which python  # 应该指向虚拟环境
pip list      # 应该只显示基础包
```

### 权限最小化原则
| 功能 | 所需权限 | 说明 |
|------|----------|------|
| 基础端口扫描 | 普通用户 | TCP连接扫描 |
| ICMP ping | root/管理员 | 原始套接字 |
| 低端口绑定 | root/管理员 | 端口 < 1024 |
| 网络接口操作 | root/管理员 | 高级网络功能 |

### 依赖安全
```bash
# 定期更新依赖
pip list --outdated
pip install --upgrade package_name

# 检查安全漏洞（如果安装了safety）
pip install safety
safety check

# 审计依赖
pip-audit  # 需要安装pip-audit
```

### 网络安全
- ✅ **仅在授权网络中使用**
- ✅ **获得书面授权**
- ✅ **遵守法律法规**
- ❌ **不扫描未授权目标**
- ❌ **不在生产环境测试**

## 📱 平台特定说明

### Windows 平台

#### 环境准备
```powershell
# 检查PowerShell版本（推荐5.1+）
$PSVersionTable.PSVersion

# 设置执行策略（如果需要）
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 设置编码（避免中文乱码）
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"
```

#### 安装Python
```powershell
# 方法1: 从Microsoft Store安装
# 搜索"Python 3.x"并安装

# 方法2: 从python.org下载
# 下载并运行安装程序，勾选"Add Python to PATH"

# 方法3: 使用Chocolatey
choco install python

# 验证安装
python --version
pip --version
```

#### Windows特定问题
```powershell
# 问题: 长路径支持
# 解决: 启用长路径支持（需要管理员权限）
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force

# 问题: 防火墙阻止
# 解决: 添加Python到防火墙例外
New-NetFirewallRule -DisplayName "Python Scanner" -Direction Inbound -Program "C:\Python\python.exe" -Action Allow
```

### Linux 平台

#### Ubuntu/Debian
```bash
# 更新包列表
sudo apt update

# 安装Python和相关工具
sudo apt install python3 python3-pip python3-venv python3-dev

# 安装编译工具（某些包需要）
sudo apt install build-essential

# 安装网络工具（可选）
sudo apt install nmap netcat-openbsd
```

#### CentOS/RHEL/Fedora
```bash
# CentOS 7/8
sudo yum install python3 python3-pip python3-devel gcc

# CentOS 8+/Fedora
sudo dnf install python3 python3-pip python3-devel gcc

# 启用EPEL仓库（CentOS）
sudo yum install epel-release
```

#### Arch Linux
```bash
# 安装Python
sudo pacman -S python python-pip

# 安装开发工具
sudo pacman -S base-devel
```

### macOS 平台

#### 使用Homebrew（推荐）
```bash
# 安装Homebrew（如果未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装Python
brew install python@3.9

# 创建软链接
brew link python@3.9

# 验证安装
python3 --version
pip3 --version
```

#### 使用系统Python
```bash
# macOS 10.15+自带Python 3
python3 --version

# 安装pip（如果需要）
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
```

#### macOS特定配置
```bash
# 解决SSL证书问题
/Applications/Python\ 3.x/Install\ Certificates.command

# 或手动更新证书
pip install --upgrade certifi
```

## ⚡ 高级配置

### 性能调优

#### 内存优化
```bash
# 限制并发线程数（避免内存溢出）
python main.py -t target --threads 50

# 减少扫描范围
python main.py -t target -p 80,443,22,21  # 仅扫描关键端口

# 监控内存使用
python -c "import psutil; print(f'内存使用: {psutil.virtual_memory().percent}%')"
```

#### 网络优化
```bash
# 调整超时时间（平衡速度和准确性）
python main.py -t target --timeout 3      # 快速扫描
python main.py -t target --timeout 10     # 准确扫描

# 跳过主机发现（提高速度）
python main.py -t target --skip-ping

# 批量扫描优化
python main.py -f large_targets.txt --threads 200 --timeout 2
```

#### CPU优化
```bash
# 根据CPU核心数调整线程
NUM_CORES=$(nproc)  # Linux
NUM_CORES=$(sysctl -n hw.ncpu)  # macOS
python main.py -t target --threads $((NUM_CORES * 10))
```

### 环境变量配置

```bash
# 设置默认配置
export SCANNER_THREADS=100
export SCANNER_TIMEOUT=5
export SCANNER_OUTPUT_DIR="./results"

# Python优化
export PYTHONOPTIMIZE=1          # 启用优化
export PYTHONUNBUFFERED=1        # 禁用缓冲
export PYTHONDONTWRITEBYTECODE=1 # 不生成.pyc文件
```

### 日志配置

```bash
# 启用详细日志
python main.py -t target -v

# 自定义日志级别
export SCANNER_LOG_LEVEL=DEBUG
python main.py -t target

# 日志文件输出
python main.py -t target 2>&1 | tee scan.log
```

### 代理配置

```bash
# HTTP代理
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# SOCKS代理
export ALL_PROXY=socks5://127.0.0.1:1080

# 验证代理
curl -I http://httpbin.org/ip
```

## 🗑️ 卸载说明

### 卸载项目

```bash
# 如果通过pip安装
pip uninstall network-scanner-vuln-detector

# 删除虚拟环境
rm -rf scanner_env  # Linux/macOS
rmdir /s scanner_env  # Windows

# 删除项目文件
rm -rf /path/to/Nmap
```

### 清理配置

```bash
# 清理pip缓存
pip cache purge

# 清理Python缓存
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -name "*.pyc" -delete

# 重置pip配置
rm ~/.pip/pip.conf  # Linux/macOS
del %APPDATA%\pip\pip.ini  # Windows
```

## 📞 获取帮助

### 文档资源
- 📖 **使用指南**: [README.md](README.md)
- 🔧 **安装指南**: 本文档
- 📝 **更新日志**: [CHANGELOG.md](CHANGELOG.md)
- ⚖️ **许可证**: [LICENSE](LICENSE)

### 社区支持
- 🐛 **问题报告**: [GitHub Issues](https://github.com/knowledge-ARI/Nmap/issues)
- 💡 **功能请求**: [GitHub Discussions](https://github.com/knowledge-ARI/Nmap/discussions)
- 📧 **邮箱联系**: security@example.com

### 快速诊断

```bash
# 生成诊断报告
python -c "
import sys, platform, subprocess
print(f'Python: {sys.version}')
print(f'Platform: {platform.platform()}')
print(f'Architecture: {platform.architecture()}')
try:
    import requests
    print(f'Requests: {requests.__version__}')
except ImportError:
    print('Requests: Not installed')
"

# 检查网络连接
python -c "import socket; socket.create_connection(('8.8.8.8', 53), timeout=3); print('✅ 网络连接正常')"

# 测试基础功能
cd scanner && python main.py -t 127.0.0.1 -p 80 --timeout 1
```

---

<div align="center">

**🎉 安装完成！**

请查看 [README.md](README.md) 了解详细使用说明

如有问题，请参考上述故障排除指南或联系我们

</div>