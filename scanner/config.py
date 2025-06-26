#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描工具配置文件
定义网络扫描的端口、协议、指纹等配置信息

Author: Security Engineer
Date: 2025
"""


class ScanConfig:
    """扫描配置类"""
    
    def __init__(self):
        """初始化配置"""
        
        # 通用配置
        self.timeout = 5  # 重命名为timeout，与scan.py中的使用保持一致
        self.socket_read_buffer = 4096
        
        # 扫描配置
        self.parser = None  # NmapDataParser实例，延迟初始化
        self.ports = None   # 自定义端口列表，如果为None则使用默认端口
        
        # 通用端口配置
        self.common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }
        
        # 摄像头设备端口配置
        self.camera_ports = {
            554: 'RTSP',                 # Real Time Streaming Protocol
            8000: 'Hikvision',           # 海康威视
            8080: 'HTTP Camera',         # HTTP摄像头
            8443: 'HTTPS Camera',        # HTTPS摄像头
            37777: 'Dahua',              # 大华摄像头
            34567: 'Dahua',              # 大华摄像头备用端口
            6667: 'Bosch',               # 博世摄像头
            80: 'HTTP/ONVIF',            # ONVIF over HTTP
            443: 'HTTPS/ONVIF',          # ONVIF over HTTPS
            3702: 'ONVIF Discovery',     # ONVIF设备发现
            1024: 'Axis Camera',         # Axis摄像头
            8090: 'Synology',            # 群晖摄像头
            9000: 'Hanwha',              # 韩华摄像头
            10554: 'RTSP Alt',           # RTSP备用端口
        }
        
        # 通用服务探测载荷
        self.service_probes = {
            'http': {
                'port': 80,
                'probe': b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scanner\r\n\r\n',
                'description': 'HTTP GET请求'
            },
            'https': {
                'port': 443,
                'probe': b'GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scanner\r\n\r\n',
                'description': 'HTTPS GET请求'
            },
            'ftp': {
                'port': 21,
                'probe': b'',
                'description': 'FTP连接测试'
            },
            'ssh': {
                'port': 22,
                'probe': b'',
                'description': 'SSH连接测试'
            },
            'telnet': {
                'port': 23,
                'probe': b'',
                'description': 'Telnet连接测试'
            }
        }
        
        # 摄像头探测载荷
        self.camera_probes = {
            'rtsp': {
                'port': 554,
                'probe': b'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: Scanner\r\n\r\n',
                'description': 'RTSP OPTIONS请求'
            },
            'onvif': {
                'port': 80,
                'probe': b'POST /onvif/device_service HTTP/1.1\r\nHost: %s\r\nContent-Type: application/soap+xml\r\nContent-Length: 0\r\n\r\n',
                'description': 'ONVIF设备服务请求'
            },
            'hikvision': {
                'port': 8000,
                'probe': b'GET /PSIA/System/deviceInfo HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scanner\r\n\r\n',
                'description': '海康威视设备信息请求'
            },
            'dahua': {
                'port': 37777,
                'probe': b'\xa0\x00\x00\x60\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
                'description': '大华摄像头协议探测'
            }
        }
        

        
        # 服务指纹识别规则
        self.service_fingerprints = {
            'http': {
                'patterns': [
                    rb'HTTP/1\.[01] \d{3}',
                    rb'Server: ',
                    rb'Content-Type: ',
                ],
                'service': 'HTTP'
            },
            'ftp': {
                'patterns': [
                    rb'220 ',
                    rb'FTP',
                    rb'vsftpd',
                ],
                'service': 'FTP'
            },
            'ssh': {
                'patterns': [
                    rb'SSH-2\.0',
                    rb'SSH-1\.',
                    rb'OpenSSH',
                ],
                'service': 'SSH'
            },
            'rtsp': {
                'patterns': [
                    rb'RTSP/1.0 200 OK',
                    rb'RTSP/1.0 401 Unauthorized',
                    rb'Server: GStreamer',
                    rb'Server: VLC',
                ],
                'service': 'RTSP'
            },
            'hikvision': {
                'patterns': [
                    rb'Server: App-webs/',
                    rb'<DeviceInfo>',
                    rb'HIKVISION',
                ],
                'service': 'Hikvision Camera'
            },
            'dahua': {
                'patterns': [
                    rb'\xa1\x00\x00\x60',  # 大华协议响应头
                    rb'Dahua',
                    rb'DH-',
                ],
                'service': 'Dahua Camera'
            },
            'onvif': {
                'patterns': [
                    rb'<s:Envelope',
                    rb'onvif.org',
                    rb'GetDeviceInformationResponse',
                ],
                'service': 'ONVIF'
            }
        }
        
        # HTTP用户代理字符串
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Scanner/1.0'
        ]
        
        # 通用服务厂商识别
        self.vendor_patterns = {
            'apache': [rb'Apache', rb'httpd'],
            'nginx': [rb'nginx', rb'Nginx'],
            'iis': [rb'Microsoft-IIS', rb'IIS'],
            'openssh': [rb'OpenSSH'],
            'vsftpd': [rb'vsftpd'],
            'proftpd': [rb'ProFTPD'],
        }
        
        # 摄像头厂商识别
        self.camera_vendor_patterns = {
            'hikvision': [rb'HIKVISION', rb'DS-', rb'App-webs'],
            'dahua': [rb'Dahua', rb'DH-', rb'DHI-'],
            'axis': [rb'AXIS', rb'Axis Communications'],
            'bosch': [rb'Bosch', rb'DINION', rb'FLEXIDOME'],
            'sony': [rb'Sony', rb'SNC-'],
            'panasonic': [rb'Panasonic', rb'WV-'],
            'samsung': [rb'Samsung', rb'SNB-', rb'SND-'],
            'vivotek': [rb'VIVOTEK', rb'IP8'],
            'foscam': [rb'Foscam', rb'FI8'],
            'uniview': [rb'Uniview', rb'IPC'],
            'tiandy': [rb'Tiandy', rb'TC-'],
            'hanwha': [rb'Hanwha', rb'XNP-'],
        }

    def get_common_ports(self):
        """获取通用端口列表"""
        return list(self.common_ports.keys())
    
    def get_camera_ports(self):
        """获取摄像头端口列表"""
        return list(self.camera_ports.keys())
    
    def get_all_ports(self):
        """获取所有专用端口列表"""
        # 将端口列表转换为字符串形式的端口列表
        ports = [str(port) for port in self.get_common_ports() + self.get_camera_ports()]
        return str(set(ports))
    
    def get_service_by_port(self, port):
        """根据端口号获取服务名称"""
        if port in self.common_ports:
            return self.common_ports[port]
        elif port in self.camera_ports:
            return self.camera_ports[port]
        else:
            return 'Unknown'
    
    def is_common_port(self, port):
        """判断是否为通用端口"""
        return port in self.common_ports
    
    def is_camera_port(self, port):
        """判断是否为摄像头端口"""
        return port in self.camera_ports
