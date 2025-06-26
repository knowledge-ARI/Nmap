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

# 读取README文件作为长描述
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# 读取requirements文件
def read_requirements(filename):
    """读取requirements文件并返回依赖列表"""
    requirements = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    requirements.append(line)
    except FileNotFoundError:
        pass
    return requirements

# 基础依赖
install_requires = [
    'requests>=2.25.0',
]

# 可选依赖
extras_require = {
    'full': read_requirements('requirements.txt'),
    'dev': read_requirements('requirements-dev.txt'),
    'minimal': read_requirements('requirements-minimal.txt'),
    'nmap': ['python-nmap>=0.6.1'],
    'advanced': [
        'scapy>=2.4.0',
        'cryptography>=3.4.0',
        'paramiko>=2.7.0',
    ],
    'analysis': [
        'pandas>=1.3.0',
        'numpy>=1.21.0',
    ],
    'reporting': [
        'jinja2>=3.0.0',
        'markdown>=3.3.0',
    ],
}

setup(
    name='network-scanner-vuln-detector',
    version='1.0.0',
    author='Security Engineer',
    author_email='security@example.com',
    description='网络扫描和漏洞检测工具',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/security-engineer/network-scanner',
    project_urls={
        'Bug Reports': 'https://github.com/security-engineer/network-scanner/issues',
        'Source': 'https://github.com/security-engineer/network-scanner',
        'Documentation': 'https://network-scanner.readthedocs.io/',
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
        ],
    },
    zip_safe=False,
    platforms=['any'],
    license='MIT',
    test_suite='tests',
    tests_require=extras_require['dev'],
)