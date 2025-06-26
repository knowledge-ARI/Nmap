#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络扫描和漏洞检测工具 - 安装配置文件

Author: Security Engineer
Date: 2025
"""

from setuptools import setup, find_packages
import os
import sys

# 确保Python版本兼容性
if sys.version_info < (3, 6):
    raise RuntimeError("此项目需要Python 3.6或更高版本")

# 获取项目根目录
here = os.path.abspath(os.path.dirname(__file__))

# 读取README文件作为长描述
try:
    with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "网络扫描和漏洞检测工具 - 一个功能强大的Python网络扫描工具"

# 读取requirements文件
def read_requirements(filename):
    """读取requirements文件并返回依赖列表"""
    requirements = []
    try:
        filepath = os.path.join(here, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-') and '==' in line or '>=' in line:
                    # 只保留有版本号的依赖
                    requirements.append(line)
    except FileNotFoundError:
        pass
    return requirements

# 项目依赖（从requirements.txt读取）
install_requires = read_requirements('requirements.txt')

# 可选依赖（保留向后兼容性）
extras_require = {
    'all': read_requirements('requirements.txt'),  # 与默认安装相同
}

# 获取版本信息
def get_version():
    """从__init__.py文件中获取版本号"""
    try:
        with open(os.path.join(here, 'scanner', '__init__.py'), 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('__version__'):
                    return line.split('=')[1].strip().strip('"\'')
    except:
        pass
    return '1.0.0'

setup(
    name='network-scanner-vuln-detector',
    version=get_version(),
    author='Security Engineer',
    author_email='security@example.com',
    description='网络扫描和漏洞检测工具 - 专注于服务识别、版本检测和漏洞发现',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/knowledge-ARI/Nmap',
    project_urls={
        'Bug Reports': 'https://github.com/knowledge-ARI/Nmap/issues',
        'Source': 'https://github.com/knowledge-ARI/Nmap',
        'Documentation': 'https://github.com/knowledge-ARI/Nmap#readme',
    },
    packages=find_packages(),
    package_data={
        'scanner': [
            'data/*',
            'data/exploits/**/*',
        ],
    },
    include_package_data=True,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
        'Environment :: Console',
    ],
    keywords='network scanner vulnerability security penetration testing nmap',
    python_requires='>=3.6',
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        'console_scripts': [
            'network-scanner=scanner.main:main',
            'vuln-scanner=scanner.main:main',
            'nmap-scanner=scanner.main:main',
        ],
    },
    zip_safe=False,
    platforms=['any'],
    license='MIT',
    test_suite='tests',
    tests_require=extras_require.get('dev', []),
)

# 如果直接运行setup.py，显示帮助信息
if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("网络扫描和漏洞检测工具 - 安装脚本")
        print("")
        print("使用方法:")
        print("  python setup.py install          # 安装项目")
        print("  python setup.py develop          # 开发模式安装")
        print("  python setup.py sdist            # 创建源码分发包")
        print("  python setup.py bdist_wheel      # 创建wheel分发包")
        print("  python setup.py clean --all      # 清理构建文件")
        print("")
        print("安装选项:")
        print("  pip install .                    # 标准安装（推荐）")
        print("  pip install .[all]               # 完整安装（与标准安装相同）")
        print("")
        print("更多信息请查看 README.md 和 INSTALL.md")
        sys.exit(0)