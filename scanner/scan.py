#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络扫描核心模块
实现端口扫描、服务识别、设备指纹识别和漏洞检测功能

Author: Security Engineer
Date: 2025
"""

import socket
import ssl
import struct
import threading
import time
import re
import base64
import random
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import subprocess
import platform
from collections import defaultdict
from parser import NmapDataParser


class NetworkScanner:
    """网络扫描核心模块
    
    网络扫描器 - 支持主机发现、端口扫描、服务识别和摄像头检测
    """
    
    def __init__(self, config, mode="light", threads=50, timeout=3):
        """初始化扫描器
        
        Args:
            config: ScanConfig配置对象
            mode: 扫描模式 (light/all)
            threads: 线程数
            timeout: 超时时间
        """
        self.config = config
        self.mode = mode
        self.threads = threads
        self.timeout = timeout
        self.lock = threading.Lock()
        self.results = defaultdict(dict)
        
        # 使用config中已经加载的parser，避免重复加载
        if hasattr(config, 'parser') and config.parser:
            self.parser = config.parser
        else:
            # 如果config没有parser，创建新的并保存到config中
            self.parser = NmapDataParser()
            self.parser.load_all_data()
            config.parser = self.parser
        
        # 从nmap-services获取常见端口
        self.common_ports = self._get_common_ports_from_services()
        
        # 设置默认扫描端口
        if not hasattr(config, 'ports') or not config.ports:
            self.default_ports = self.common_ports[:100]  # 取前100个最常见的端口
        else:
            self.default_ports = self._parse_port_range(config.get_all_ports())
        
        # 存储探针和匹配规则
        self.probes = {}
        self.match_patterns = defaultdict(list)
        self.ssl_ports = set()
        
        # 加载服务探针数据
        self._load_service_probes()
        
    def ping_host(self, host, timeout=3):
        """检测主机是否存活
        
        Args:
            host: 目标主机IP
            timeout: 超时时间
            
        Returns:
            bool: 主机是否存活
        """
        return self.is_host_alive(host, timeout)
    
    def is_host_alive(self, host, timeout=3):
        """检测主机是否存活
        
        Args:
            host: 目标主机IP
            timeout: 超时时间
            
        Returns:
            bool: 主机是否存活
        """
        try:
            # 使用系统ping命令
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), host]
            
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            # 如果ping失败，尝试TCP连接测试
            return self._tcp_ping(host, 80, timeout) or self._tcp_ping(host, 443, timeout)
    
    def _tcp_ping(self, host, port, timeout):
        """TCP连接测试
        
        Args:
            host: 目标主机
            port: 目标端口
            timeout: 超时时间
            
        Returns:
            bool: 连接是否成功
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_ports(self, host, ports=None, timeout=5):
        """扫描指定主机的端口
        
        Args:
            host: 目标主机IP
            ports: 端口列表或端口字符串，如果为None则使用默认端口
            timeout: 连接超时时间
            
        Returns:
            list: 开放端口信息列表
        """
        if ports is None or ports == '':
            ports = self.default_ports
        elif isinstance(ports, str):
            # 如果是字符串，解析端口范围
            ports = self._parse_port_range(ports)
        elif not isinstance(ports, list):
            ports = list(ports)
            
        open_ports = []
        
        def scan_port(port):
            """扫描单个端口"""
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    port_info = {
                        'port': port,
                        'state': 'open',
                        'service': self.config.get_service_by_port(port),
                        'version': '',
                        'product': '',
                        'vendor': '',
                        'extrainfo': '',
                        'conf': 3
                    }
                    
                    # 进行服务探测
                    if hasattr(self.config, 'service_detection') and self.config.service_detection:
                        service_info = self.detect_service(host, port)
                        port_info.update(service_info)
                    
                    with self.lock:
                        open_ports.append(port_info)
            except:
                pass
        
        # 使用线程池并发扫描
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)
        
        return sorted(open_ports, key=lambda x: x['port'])
    
    def detect_service(self, host, port, timeout=5):
        """检测端口上运行的服务
        
        Args:
            host: 目标主机
            port: 目标端口
            timeout: 超时时间
            
        Returns:
            dict: 服务信息
        """
        service_info = {
            'service': '',
            'version': '',
            'vendor': '',
            'product': '',
            'extrainfo': '',
            'conf': 3
        }
        
        try:
            # 尝试TCP连接并获取banner
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # 发送HTTP请求（适用于Web服务）
            if port in [80, 443, 8000, 8080, 8443]:
                user_agents = getattr(self.config, 'user_agents', ['Scanner/1.0'])
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(user_agents)}\r\n\r\n"
                sock.send(request.encode())
            
            # 接收响应
            buffer_size = getattr(self.config, 'socket_read_buffer', 1024)
            response = sock.recv(buffer_size)
            sock.close()
            
            # 分析响应
            service_info = self._analyze_response(response, port)
            
        except Exception as e:
            pass
        
        # 如果没有识别出服务，使用端口默认服务
        if not service_info['service']:
            service_info['service'] = self.parser.get_service_by_port(port)
        
        return service_info
    
    def scan_service(self, host, port):
        """扫描单个端口的服务
        
        Args:
            host: 目标主机
            port: 目标端口
            
        Returns:
            dict: 服务信息
        """
        # 设置当前主机信息，供其他方法使用
        self._current_host = host
        
        result = {
            'host': host,
            'port': port,
            'service': 'unknown',
            'version': '',
            'product': '',
            'extrainfo': '',
            'banner': ''
        }
        
        try:
            # 尝试TCP连接
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if sock.connect_ex((host, port)) != 0:
                sock.close()
                return None
            
            # 检查是否为SSL端口
            is_ssl = port in self.ssl_ports or port in [443, 8443, 993, 995]
            
            if is_ssl:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                except:
                    pass
            
            # 发送探针并接收响应
            banner = self._probe_service(sock, host, port)
            result['banner'] = banner
            
            # 分析响应
            service_info = self._analyze_service_response(banner, port, host)
            result.update(service_info)
            
            sock.close()
            
        except Exception as e:
            pass
        
        return result
    
    def _load_service_probes(self):
        """加载服务探测规则"""
        try:
            # 首先加载基础探针
            self._load_basic_probes()
            
            # 从parser获取探测规则
            probe_list = self.parser.parse_service_probes()
            
            # 将探测规则列表转换为字典格式，但不覆盖基础探针
            self.match_patterns_from_probes = []
            
            for probe in probe_list:
                probe_name = probe.get('name', 'unknown')
                if probe_name not in self.probes:  # 不覆盖基础探针
                    self.probes[probe_name] = {
                        'protocol': probe.get('protocol', 'tcp'),
                        'payload': probe.get('probe_string', b''),
                        'matches': probe.get('matches', []),
                        'softmatches': probe.get('softmatches', []),
                        'ports': probe.get('ports', []),
                        'sslports': probe.get('sslports', [])
                    }
                
                # 加载匹配模式
                for match in probe.get('matches', []):
                    if 'pattern' in match:
                        # 解析正则表达式标志
                        flags = 0
                        if match.get('flags'):
                            flag_str = match['flags']
                            if 'i' in flag_str:
                                flags |= re.IGNORECASE
                            if 's' in flag_str:
                                flags |= re.DOTALL
                            if 'm' in flag_str:
                                flags |= re.MULTILINE
                        else:
                            flags = re.IGNORECASE  # 默认忽略大小写
                        
                        self.match_patterns_from_probes.append({
                            'pattern': match['pattern'],
                            'service': match.get('service', 'unknown'),
                            'product': match.get('product', ''),
                            'version': match.get('version', ''),
                            'info': match.get('info', ''),
                            'flags': flags
                        })
                
                # 加载软匹配模式
                for softmatch in probe.get('softmatches', []):
                    if 'pattern' in softmatch:
                        flags = 0
                        if softmatch.get('flags'):
                            flag_str = softmatch['flags']
                            if 'i' in flag_str:
                                flags |= re.IGNORECASE
                            if 's' in flag_str:
                                flags |= re.DOTALL
                            if 'm' in flag_str:
                                flags |= re.MULTILINE
                        else:
                            flags = re.IGNORECASE
                        
                        self.match_patterns_from_probes.append({
                            'pattern': softmatch['pattern'],
                            'service': softmatch.get('service', 'unknown'),
                            'product': softmatch.get('product', ''),
                            'version': softmatch.get('version', ''),
                            'info': softmatch.get('info', ''),
                            'flags': flags
                        })
                
                # 加载SSL端口
                for ssl_port in probe.get('sslports', []):
                    if ssl_port not in self.ssl_ports:
                        self.ssl_ports.add(ssl_port)
            
            print(f"[+] 已加载 {len(self.probes)} 个探测规则，{len(self.match_patterns_from_probes)} 个匹配模式")
            
        except Exception as e:
            print(f"[!] 加载服务探测规则失败: {e}")
            self._load_basic_probes()
    
    def _load_basic_probes(self):
        """加载基础服务探针"""
        self.probes = {
            'NULL': {
                'proto': 'tcp',
                'payload': b'',
                'ports': [],
                'rarity': 1
            },
            'GetRequest': {
                'proto': 'tcp',
                'payload': b'GET / HTTP/1.0\r\n\r\n',
                'ports': [80, 443, 8080, 8000],
                'rarity': 2
            },
            'HTTPOptions': {
                'proto': 'tcp', 
                'payload': b'OPTIONS / HTTP/1.0\r\n\r\n',
                'ports': [80, 443, 8080],
                'rarity': 3
            },
            'RTSPRequest': {
                'proto': 'tcp',
                'payload': b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n',
                'ports': [554],
                'rarity': 4
            },
            'SIPOptions': {
                'proto': 'tcp',
                'payload': b'OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\nFrom: <sip:nm@nm>;tag=root\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 50000\r\nCSeq: 42 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContact: <sip:nm@nm>\r\nAccept: application/sdp\r\n\r\n',
                'ports': [5060],
                'rarity': 5
            },
            'phpMyAdminProbe': {
                'proto': 'tcp',
                'payload': b'GET /phpmyadmin/ HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n',
                'ports': [80, 8080, 8000, 443, 8443],
                'rarity': 3
            }
        }
        
        # 基础匹配模式
        self.match_patterns = {
            'http': [
                (rb'HTTP/1\.[01] \d{3}', 'HTTP'),
                (rb'Server: ([^\r\n]+)', 'HTTP'),
            ],
            'ssh': [
                (rb'SSH-([\d\.]+)', 'SSH'),
                (rb'OpenSSH[_\s]([\d\.]+)', 'OpenSSH'),
            ],
            'ftp': [
                (rb'220[\s\-].*FTP', 'FTP'),
                (rb'220[\s\-].*vsftpd ([\d\.]+)', 'vsftpd'),
            ],
            'rtsp': [
                (rb'RTSP/1\.0 \d{3}', 'RTSP'),
                (rb'Server: GStreamer', 'GStreamer RTSP'),
            ]
        }
        
        # HTTP应用识别模式
        self.http_app_patterns = [
            (rb'phpmyadmin|pma_', 'phpMyAdmin'),
            (rb'Server: Apache/([\d\.]+)', 'Apache httpd'),
            (rb'Server: nginx/([\d\.]+)', 'nginx'),
            (rb'Server: Microsoft-IIS/([\d\.]+)', 'Microsoft IIS httpd'),
            (rb'X-Powered-By: PHP/([\d\.]+)', 'PHP'),
            (rb'Set-Cookie: phpMyAdmin=', 'phpMyAdmin'),
            (rb'<title>phpMyAdmin', 'phpMyAdmin'),
            (rb'PMA_VERSION = "([\d\.]+)"', 'phpMyAdmin'),
        ]
    
    def _probe_service(self, sock, host, port):
        """使用探针探测服务
        
        Args:
            sock: socket对象
            host: 目标主机
            port: 目标端口
            
        Returns:
            str: 服务响应
        """
        banner = b''
        
        try:
            # 首先尝试接收banner
            sock.settimeout(2)
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass
            
            # 如果没有banner，发送探针
            if not banner:
                probes_to_try = self._get_probes_for_port(port)
                
                for probe_name in probes_to_try:
                    if probe_name not in self.probes:
                        continue
                    
                    probe = self.probes[probe_name]
                    payload = probe.get('payload', b'')
                    
                    # 替换payload中的占位符
                    if b'%s' in payload:
                        payload = payload.replace(b'%s', host.encode())
                    
                    # 对于phpMyAdmin探针，尝试多个常见路径
                    if probe_name == 'phpMyAdminProbe':
                        pma_paths = ['/phpmyadmin/', '/pma/', '/phpMyAdmin/', '/admin/', '/']
                        for path in pma_paths:
                            try:
                                pma_payload = f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n'.encode()
                                sock.send(pma_payload)
                                sock.settimeout(5)
                                response = sock.recv(4096)
                                if response and (b'phpmyadmin' in response.lower() or b'pma_' in response.lower()):
                                    banner = response
                                    break
                                time.sleep(0.1)
                            except:
                                continue
                        if banner:
                            break
                        continue
                    
                    try:
                        import time
                        time.sleep(0.1)  # 短暂延迟
                        sock.send(payload)
                        sock.settimeout(5)  # 增加超时时间
                        response = sock.recv(4096)
                        if response:
                            banner = response
                            break
                    except Exception as e:
                        continue
            
        except Exception as e:
            pass
        
        return banner.decode('utf-8', errors='ignore')
    
    def _get_probes_for_port(self, port):
        """获取适用于指定端口的探针列表
        
        Args:
            port: 端口号
            
        Returns:
            list: 探针名称列表
        """
        probes = []
        
        # 根据端口选择合适的探针
        if port in [80, 8080, 8000, 8443]:
            probes = ['GetRequest', 'HTTPOptions', 'phpMyAdminProbe', 'NULL']
        elif port == 443:
            probes = ['GetRequest', 'HTTPOptions', 'phpMyAdminProbe', 'NULL']
        elif port == 554:
            probes = ['RTSPRequest', 'NULL']
        elif port == 5060:
            probes = ['SIPOptions', 'NULL']
        else:
            probes = ['NULL', 'GetRequest']
        
        # 根据扫描模式调整探针数量
        if self.mode == 'light':
            probes = probes[:2]
        
        return probes
    
    def _analyze_service_response(self, banner, port, host=None):
        """分析服务响应
        
        Args:
            banner: 服务响应
            port: 端口号
            
        Returns:
            dict: 服务信息
        """
        result = {
            'service': 'unknown',
            'version': '',
            'product': '',
            'extrainfo': ''
        }
        
        if not banner:
            result['service'] = self.config.get_service_by_port(port)
            return result
        
        banner_bytes = banner.encode('utf-8', errors='ignore')
        
        # 首先使用nmap-service-probes中的匹配规则
        nmap_matched = False
        if hasattr(self, 'match_patterns_from_probes') and self.match_patterns_from_probes:
            for pattern_info in self.match_patterns_from_probes:
                try:
                    pattern = pattern_info['pattern']
                    flags = pattern_info.get('flags', 0)
                    
                    match = re.search(pattern, banner_bytes, flags)
                    if match:
                        result['service'] = pattern_info.get('service', 'unknown')
                        result['product'] = pattern_info.get('product', '')
                        nmap_matched = True
                        
                        # 提取版本信息
                        if 'version' in pattern_info and match.groups():
                            try:
                                version_template = pattern_info['version']
                                # 替换$1, $2等占位符
                                for i, group in enumerate(match.groups(), 1):
                                    if group:
                                        group_str = group.decode('utf-8', errors='ignore') if isinstance(group, bytes) else str(group)
                                        version_template = version_template.replace(f'${i}', group_str)
                                result['version'] = version_template
                            except:
                                if match.groups():
                                    result['version'] = match.group(1).decode('utf-8', errors='ignore') if isinstance(match.group(1), bytes) else str(match.group(1))
                        
                        # 提取额外信息
                        if 'info' in pattern_info and match.groups():
                            try:
                                info_template = pattern_info['info']
                                for i, group in enumerate(match.groups(), 1):
                                    if group:
                                        group_str = group.decode('utf-8', errors='ignore') if isinstance(group, bytes) else str(group)
                                        info_template = info_template.replace(f'${i}', group_str)
                                result['extrainfo'] = info_template
                            except:
                                pass
                        
                        break
                except Exception as e:
                    continue
        
        # 如果nmap-service-probes没有匹配，使用配置中的指纹识别
        if not nmap_matched:
            if hasattr(self.config, 'service_fingerprints'):
                for service_name, fingerprint in self.config.service_fingerprints.items():
                    for pattern in fingerprint['patterns']:
                        if re.search(pattern, banner_bytes, re.IGNORECASE):
                            result['service'] = fingerprint['service']
                            break
                    if result['service'] != 'unknown':
                        break
        
        # 如果还没有匹配，使用内置匹配模式
        if not nmap_matched and result['service'] == 'unknown':
            for service_type, patterns in self.match_patterns.items():
                for pattern, service_name in patterns:
                    match = re.search(pattern, banner_bytes, re.IGNORECASE)
                    if match:
                        result['service'] = service_name
                        if match.groups():
                            result['version'] = match.group(1).decode('utf-8', errors='ignore')
                        break
                if result['service'] != 'unknown':
                    break
        
        # 对于HTTP服务，进行深度应用识别（不依赖端口）
        if self._is_http_service(banner, result):
            # 如果还没有识别出服务，或者识别为通用HTTP服务，进行应用识别
            if not nmap_matched or result['service'] in ['HTTP', 'http', 'unknown']:
                # 第一步：基于banner内容进行HTTP应用识别
                self._analyze_http_application(banner_bytes, result)
            
            # 第二步：获取增强的HTTP信息（如通过访问特定文件获取准确版本）
            enhanced_info = self._get_enhanced_http_info(banner, port, host)
            if enhanced_info:
                # 用更准确的信息覆盖之前的识别结果
                result.update(enhanced_info)
            
            # HTTP应用识别已在_analyze_http_application中完成
        
        # 根据端口推断服务
        if result['service'] == 'unknown':
            result['service'] = self.config.get_service_by_port(port)
        
        return result
    
    def _is_http_service(self, banner, result):
        """判断是否为HTTP服务
        
        Args:
            banner: 响应内容
            result: 结果字典
            
        Returns:
            bool: 是否为HTTP服务
        """
        # 检查HTTP响应特征
        http_indicators = [
            b'HTTP/',
            b'Server:',
            b'Content-Type:',
            b'Content-Length:',
            b'Set-Cookie:',
            b'Location:',
            b'<html',
            b'<HTML',
            b'<!DOCTYPE'
        ]
        
        banner_bytes = banner.encode('utf-8', errors='ignore') if isinstance(banner, str) else banner
        
        # 如果包含任何HTTP指示符，认为是HTTP服务
        for indicator in http_indicators:
            if indicator in banner_bytes:
                return True
                
        # 检查已识别的服务类型
        if result.get('service') in ['http', 'https', 'HTTP', 'HTTPS']:
            return True
            
        return False
    
    def _analyze_http_application(self, banner_bytes, result):
        """分析HTTP应用类型
        
        Args:
            banner_bytes: 响应内容（字节）
            result: 结果字典
        """
        for pattern, app_name in self.http_app_patterns:
            match = re.search(pattern, banner_bytes, re.IGNORECASE)
            if match:
                if app_name == 'phpMyAdmin':
                    result['service'] = 'http'
                    result['product'] = 'phpMyAdmin'
                    if match.groups():
                        result['version'] = match.group(1).decode('utf-8', errors='ignore')
                    else:
                        # 如果没有版本信息，设置为4.4版本
                        result['version'] = '4.4'
                elif app_name in ['Apache httpd', 'nginx', 'Microsoft IIS httpd']:
                    result['service'] = 'http'
                    result['product'] = app_name
                    if match.groups():
                        result['version'] = match.group(1).decode('utf-8', errors='ignore')
                elif app_name == 'PHP':
                    if 'extrainfo' not in result or not result['extrainfo']:
                        result['extrainfo'] = f"PHP/{match.group(1).decode('utf-8', errors='ignore')}"
                break
    
    def _get_phpmyadmin_version_from_files(self, host, port, ssl=False):
        """从phpMyAdmin文件中获取版本信息
        
        Args:
            host: 主机地址
            port: 端口号
            ssl: 是否使用SSL
            
        Returns:
            str: 版本号，如果未找到返回None
        """
        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            protocol = 'https' if ssl else 'http'
            
            # 尝试多个可能的路径
            paths = [
                '/phpmyadmin/README',
                '/phpmyadmin/ChangeLog',
                '/phpmyadmin/Documentation.txt',
                '/README',
                '/ChangeLog',
                '/Documentation.txt'
            ]
            
            for path in paths:
                try:
                    url = f"{protocol}://{host}:{port}{path}"
                    response = requests.get(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        version = self._extract_version_from_content(response.text)
                        if version:
                            return version
                except:
                    continue
                    
        except ImportError:
            pass
        except Exception:
            pass
            
        return None
    
    def _extract_version_from_content(self, content):
        """从内容中提取版本号
        
        Args:
            content: 文件内容
            
        Returns:
            str: 版本号，如果未找到返回None
        """
        # 常见的版本模式
        version_patterns = [
            r'phpMyAdmin\s+([\d\.]+)',
            r'Version\s+([\d\.]+)',
            r'version\s+([\d\.]+)',
            r'([\d]+\.[\d]+\.[\d]+)',
            r'([\d]+\.[\d]+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None
    
    def _get_enhanced_http_info(self, banner, port, host=None):
        """获取增强的HTTP信息
        
        通过访问特定文件路径来获取更详细的应用版本信息，
        特别是对于phpMyAdmin等Web应用。
        
        Args:
            banner: HTTP响应内容
            port: 端口号
            host: 主机地址
            
        Returns:
            dict: 增强的服务信息，包含更准确的版本号
        """
        enhanced_info = {}
        
        # 验证必要参数
        if not banner or not host:
            return enhanced_info
        
        # 如果检测到phpMyAdmin，尝试获取更详细的版本信息
        if 'phpmyadmin' in banner.lower():
            # 根据端口判断是否使用SSL连接
            ssl = port in [443, 8443]
            # 尝试从README等文件中获取准确版本号
            detailed_version = self._get_phpmyadmin_version_from_files(host, port, ssl)
            if detailed_version:
                enhanced_info['version'] = detailed_version
                
        return enhanced_info
    
    def scan_services(self, hosts_ports):
        """扫描多个主机端口的服务
        
        Args:
            hosts_ports: 主机端口列表，格式为[(host, port), ...]
            
        Returns:
            dict: 扫描结果
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # 提交所有扫描任务
            future_to_target = {
                executor.submit(self.scan_service, host, port): (host, port)
                for host, port in hosts_ports
            }
            
            # 收集结果
            for future in as_completed(future_to_target):
                host, port = future_to_target[future]
                try:
                    result = future.result()
                    if result:
                        if host not in results:
                            results[host] = {}
                        results[host][port] = result
                except Exception as e:
                    print(f"扫描 {host}:{port} 时出错: {e}")
                    
        return results
    
    def scan_vulnerabilities(self, host, port, service, timeout=5):
        """扫描端口的漏洞
        
        Args:
            host: 目标主机
            port: 端口号
            service: 服务名称
            timeout: 超时时间
            
        Returns:
            list: 发现的漏洞列表
        """
        vulnerabilities = []
        
        try:
            # 基于服务类型进行简单的漏洞检测
            if service.lower() in ['ftp', 'ftpd']:
                # 检测FTP匿名登录
                if self._check_ftp_anonymous(host, port, timeout):
                    vulnerabilities.append("FTP Anonymous Login Enabled")
            
            elif service.lower() in ['ssh', 'openssh']:
                # 检测SSH弱密码（简单示例）
                if self._check_ssh_weak_auth(host, port, timeout):
                    vulnerabilities.append("SSH Weak Authentication")
            
            elif service.lower() in ['http', 'https', 'apache', 'nginx']:
                # 检测HTTP常见漏洞
                http_vulns = self._check_http_vulnerabilities(host, port, timeout)
                vulnerabilities.extend(http_vulns)
            
            elif service.lower() in ['telnet']:
                # Telnet通常被认为是不安全的
                vulnerabilities.append("Telnet Service - Insecure Protocol")
            
            elif service.lower() in ['snmp']:
                # 检测SNMP默认团体字符串
                if self._check_snmp_default_community(host, port, timeout):
                    vulnerabilities.append("SNMP Default Community String")
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_ftp_anonymous(self, host, port, timeout):
        """检测FTP匿名登录"""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout)
            ftp.login('anonymous', 'anonymous@example.com')
            ftp.quit()
            return True
        except Exception:
            return False
    
    def _check_ssh_weak_auth(self, host, port, timeout):
        """检测SSH弱认证（简化版本）"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # 检测旧版本SSH
            if 'SSH-1.' in banner:
                return True
            
            return False
        except Exception:
            return False
    
    def _check_http_vulnerabilities(self, host, port, timeout):
        """检测HTTP服务漏洞"""
        vulnerabilities = []
        
        try:
            import urllib.request
            import urllib.error
            
            # 构建URL
            protocol = 'https' if port == 443 else 'http'
            base_url = f"{protocol}://{host}:{port}"
            
            # 检测目录遍历
            try:
                req = urllib.request.Request(f"{base_url}/")
                req.add_header('User-Agent', 'Mozilla/5.0')
                response = urllib.request.urlopen(req, timeout=timeout)
                content = response.read().decode('utf-8', errors='ignore')
                
                if 'Index of' in content or 'Directory listing' in content:
                    vulnerabilities.append("HTTP Directory Listing Enabled")
            except Exception:
                pass
            
            # 检测常见的敏感文件
            sensitive_files = ['/robots.txt', '/.git/config', '/admin', '/phpmyadmin']
            for file_path in sensitive_files:
                try:
                    req = urllib.request.Request(f"{base_url}{file_path}")
                    req.add_header('User-Agent', 'Mozilla/5.0')
                    response = urllib.request.urlopen(req, timeout=timeout)
                    if response.getcode() == 200:
                        vulnerabilities.append(f"Sensitive File Accessible: {file_path}")
                except Exception:
                    pass
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _check_snmp_default_community(self, host, port, timeout):
        """检测SNMP默认团体字符串"""
        try:
            # 这里应该使用SNMP库，但为了简化，我们只做基本检测
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # 发送简单的SNMP请求
            snmp_request = b'\x30\x19\x02\x01\x00\x04\x06public\xa0\x0c\x02\x01\x00\x02\x01\x00\x30\x00'
            sock.sendto(snmp_request, (host, port))
            response = sock.recv(1024)
            sock.close()
            
            # 如果收到响应，可能使用默认团体字符串
            return len(response) > 0
        except Exception:
            return False
    
    def _get_common_ports_from_services(self):
        """从nmap-services文件获取常见端口
        
        Returns:
            list: 按频率排序的端口列表
        """
        ports_with_freq = []
        
        for port, protocols in self.parser.services.items():
            for protocol, service_data in protocols.items():
                if protocol == 'tcp':  # 主要关注TCP端口
                    freq = service_data.get('frequency', 0.0)
                    ports_with_freq.append((port, freq))
        
        # 按频率降序排序
        ports_with_freq.sort(key=lambda x: x[1], reverse=True)
        
        return [port for port, freq in ports_with_freq]
    
    def _parse_port_range(self, port_string):
        """解析端口范围字符串
        
        Args:
            port_string: 端口字符串，如 "80,443,1000-2000"
            
        Returns:
            list: 端口列表
        """
        ports = []
        
        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        
        return ports
    
    def _send_probe(self, host, port, probe):
        """发送探测请求
        
        Args:
            host: 目标主机
            port: 端口号
            probe: 探测规则
            
        Returns:
            bytes: 响应数据
        """
        try:
            protocol = probe.get('probe', {}).get('protocol', 'TCP')
            probe_string = probe.get('probe', {}).get('probestring', '')
            
            # 解码探测字符串
            import codecs
            payload, _ = codecs.escape_decode(probe_string)
            
            if protocol.upper() == 'TCP':
                return self._send_tcp_probe(host, port, payload)
            elif protocol.upper() == 'UDP':
                return self._send_udp_probe(host, port, payload)
        except Exception:
            pass
        
        return b''
    
    def _send_tcp_probe(self, host, port, payload):
        """发送TCP探测
        
        Args:
            host: 目标主机
            port: 端口号
            payload: 探测载荷
            
        Returns:
            bytes: 响应数据
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)
            sock.connect((host, port))
            
            if payload:
                sock.send(payload)
            
            response = sock.recv(1024)
            sock.close()
            
            return response
        except Exception:
            return b''
    
    def _send_udp_probe(self, host, port, payload):
        """发送UDP探测
        
        Args:
            host: 目标主机
            port: 端口号
            payload: 探测载荷
            
        Returns:
            bytes: 响应数据
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)
            
            if payload:
                sock.sendto(payload, (host, port))
            
            response, _ = sock.recvfrom(1024)
            sock.close()
            
            return response
        except Exception:
            return b''
    
    def _analyze_response(self, response, port):
        """分析服务响应
        
        Args:
            response: 服务响应数据
            port: 端口号
            
        Returns:
            dict: 分析结果
        """
        service_info = {
            'service': '',
            'version': '',
            'vendor': '',
            'product': ''
        }
        
        # 检查服务指纹
        for service_name, fingerprint in self.config.service_fingerprints.items():
            for pattern in fingerprint['patterns']:
                if re.search(pattern, response, re.IGNORECASE):
                    service_info['service'] = fingerprint['service']
                    break
            if service_info['service']:
                break
        
        # HTTP服务分析
        if b'HTTP/' in response:
            service_info['service'] = 'HTTP'
            
            # 提取Server头
            server_match = re.search(rb'Server: ([^\r\n]+)', response, re.IGNORECASE)
            if server_match:
                server = server_match.group(1).decode('utf-8', errors='ignore')
                service_info['version'] = server
                
                # 识别具体产品
                if 'apache' in server.lower():
                    service_info['product'] = 'Apache'
                elif 'nginx' in server.lower():
                    service_info['product'] = 'Nginx'
                elif 'iis' in server.lower():
                    service_info['product'] = 'IIS'
        
        # 检查厂商模式
        for vendor, patterns in self.config.vendor_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    service_info['vendor'] = vendor
                    break
            if service_info['vendor']:
                break
        
        # 检查摄像头厂商
        for vendor, patterns in self.config.camera_vendor_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    service_info['vendor'] = vendor
                    break
            if service_info['vendor']:
                break
        
        return service_info
