# 安装指南

本文档提供了网络扫描和漏洞检测工具的详细安装说明。

## 📋 系统要求

### 最低要求
- **Python版本**: Python 3.6 或更高版本
- **操作系统**: Windows, Linux, macOS
- **内存**: 至少 512MB RAM
- **磁盘空间**: 至少 100MB 可用空间

### 推荐配置
- **Python版本**: Python 3.8 或更高版本
- **内存**: 2GB RAM 或更多
- **磁盘空间**: 500MB 可用空间（包含完整ExploitDB数据库）

## 🚀 快速安装

### 方法1: 从源码安装（推荐）

```bash
# 1. 克隆项目
git clone <repository-url>
cd Nmap

# 2. 创建虚拟环境（推荐）
python -m venv venv

# 3. 激活虚拟环境
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# 4. 安装依赖
pip install -r requirements-minimal.txt

# 5. 测试安装
python scanner/main.py --help
```

### 方法2: 使用pip安装（开发中）

```bash
# 从PyPI安装（未来版本）
pip install network-scanner-vuln-detector

# 或从源码安装
pip install .
```

## 📦 依赖选择

### 最小安装（仅核心功能）
```bash
pip install -r requirements-minimal.txt
```
包含：
- requests（HTTP功能）
- python-nmap（可选）

### 完整安装（所有功能）
```bash
pip install -r requirements.txt
```
包含：
- 所有核心依赖
- 数据分析库（pandas, numpy）
- 高级网络库（scapy, cryptography）
- 报告生成库（jinja2, markdown）

### 开发环境安装
```bash
pip install -r requirements.txt -r requirements-dev.txt
```
额外包含：
- 测试框架（pytest）
- 代码质量工具（black, flake8）
- 文档生成工具（sphinx）

## 🔧 配置验证

### 检查Python版本
```bash
python --version
# 应该显示 Python 3.6.x 或更高版本
```

### 检查依赖安装
```bash
python -c "import requests; print('requests OK')"
python -c "import socket; print('socket OK')"
python -c "import threading; print('threading OK')"
```

### 运行基础测试
```bash
# 显示帮助信息
python scanner/main.py --help

# 测试基础扫描（需要网络连接）
python scanner/main.py -t 127.0.0.1 -p 80
```

## 🐛 常见问题

### 问题1: Python版本过低
```
RuntimeError: 此项目需要Python 3.6或更高版本
```
**解决方案**: 升级Python到3.6或更高版本

### 问题2: 依赖安装失败
```
ERROR: Could not install packages due to an EnvironmentError
```
**解决方案**:
```bash
# 升级pip
pip install --upgrade pip

# 使用用户安装
pip install --user -r requirements-minimal.txt

# 或使用虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements-minimal.txt
```

### 问题3: 权限错误
```
PermissionError: [Errno 13] Permission denied
```
**解决方案**:
```bash
# 使用用户安装
pip install --user -r requirements-minimal.txt

# 或使用sudo（Linux/macOS）
sudo pip install -r requirements-minimal.txt
```

### 问题4: 网络连接问题
```
ConnectionError: Failed to establish a new connection
```
**解决方案**:
```bash
# 使用国内镜像源
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements-minimal.txt

# 或配置代理
pip install --proxy http://proxy.example.com:8080 -r requirements-minimal.txt
```

## 🔒 安全注意事项

### 虚拟环境（强烈推荐）
```bash
# 创建独立的Python环境
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/macOS
scanner_env\Scripts\activate     # Windows
```

### 权限管理
- 避免使用root权限运行
- 仅在必要时使用管理员权限
- 定期更新依赖包

### 网络安全
- 仅在授权网络中使用
- 遵守相关法律法规
- 不要扫描未授权的目标

## 📱 平台特定说明

### Windows
```cmd
# 使用PowerShell或命令提示符
python -m pip install -r requirements-minimal.txt

# 如果遇到编码问题
chcp 65001
set PYTHONIOENCODING=utf-8
```

### Linux
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv

# CentOS/RHEL
sudo yum install python3 python3-pip
# 或
sudo dnf install python3 python3-pip
```

### macOS
```bash
# 使用Homebrew
brew install python3

# 或使用系统Python
python3 -m pip install -r requirements-minimal.txt
```

## 🚀 性能优化

### 内存优化
```bash
# 限制线程数
python scanner/main.py -t target --threads 50

# 减少端口范围
python scanner/main.py -t target -p 1-100
```

### 网络优化
```bash
# 调整超时时间
python scanner/main.py -t target --timeout 5

# 跳过ping检测
python scanner/main.py -t target --skip-ping
```

## 📞 获取帮助

- **文档**: 查看 [README.md](README.md)
- **问题报告**: 提交到项目Issues
- **邮箱**: security@example.com
- **更新日志**: 查看 [CHANGELOG.md](CHANGELOG.md)

---

**安装完成后，请查看 [README.md](README.md) 了解详细使用说明。**