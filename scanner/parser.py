#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap数据文件解析器
解析nmap-services、nmap-service-probes等数据文件

Author: Security Engineer
Date: 2025
"""

import re
import os
from typing import Dict, List, Tuple, Optional


class NmapDataParser:
    """Nmap数据文件解析器"""
    
    def __init__(self, data_dir: str = None):
        """初始化解析器
        
        Args:
            data_dir: 数据文件目录路径
        """
        # 使用scanner/data目录下的数据文件
        if data_dir:
            self.data_dir = data_dir
        else:
            self.data_dir = os.path.join(os.path.dirname(__file__), 'data')
            print(f"[+] 使用数据文件目录: {self.data_dir}")
        
        self.services = {}
        self.service_probes = []
        self.os_fingerprints = {}
    
    def parse_nmap_services(self, filename: str = None) -> Dict[int, Dict]:
        """解析nmap-services文件
        
        Args:
            filename: 服务文件路径
            
        Returns:
            dict: 端口到服务的映射
        """
        if filename is None:
            filename = os.path.join(self.data_dir, 'nmap-services')
        
        services = {}
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    # 跳过注释和空行
                    if not line or line.startswith('#'):
                        continue
                    
                    # 解析服务行格式: service_name port/protocol frequency
                    parts = line.split()
                    if len(parts) >= 2:
                        service_name = parts[0]
                        port_proto = parts[1]
                        frequency = float(parts[2]) if len(parts) > 2 else 0.0
                        
                        # 解析端口和协议
                        if '/' in port_proto:
                            port_str, protocol = port_proto.split('/', 1)
                            try:
                                port = int(port_str)
                                
                                if port not in services:
                                    services[port] = {}
                                
                                services[port][protocol] = {
                                    'service': service_name,
                                    'frequency': frequency
                                }
                            except ValueError:
                                continue
        
        except FileNotFoundError:
            print(f"Warning: {filename} not found, using built-in service data")
            # 返回内置的常见服务
            services = self._get_builtin_services()
        
        self.services = services
        return services
    
    def _get_builtin_services(self) -> Dict[int, Dict]:
        """获取内置的常见服务数据
        
        Returns:
            dict: 内置服务映射
        """
        builtin_services = {
            21: {'tcp': {'service': 'ftp', 'frequency': 0.197}},
            22: {'tcp': {'service': 'ssh', 'frequency': 0.182}},
            23: {'tcp': {'service': 'telnet', 'frequency': 0.221}},
            25: {'tcp': {'service': 'smtp', 'frequency': 0.131}},
            53: {
                'tcp': {'service': 'domain', 'frequency': 0.024},
                'udp': {'service': 'domain', 'frequency': 0.156}
            },
            80: {'tcp': {'service': 'http', 'frequency': 0.484}},
            102: {'tcp': {'service': 's7', 'frequency': 0.001}},
            110: {'tcp': {'service': 'pop3', 'frequency': 0.109}},
            143: {'tcp': {'service': 'imap', 'frequency': 0.114}},
            443: {'tcp': {'service': 'https', 'frequency': 0.281}},
            502: {'tcp': {'service': 'modbus', 'frequency': 0.001}},
            554: {'tcp': {'service': 'rtsp', 'frequency': 0.005}},
            993: {'tcp': {'service': 'imaps', 'frequency': 0.062}},
            995: {'tcp': {'service': 'pop3s', 'frequency': 0.052}},
            3389: {'tcp': {'service': 'ms-wbt-server', 'frequency': 0.024}},
            4840: {'tcp': {'service': 'opc-ua', 'frequency': 0.001}},
            8000: {'tcp': {'service': 'http-alt', 'frequency': 0.025}},
            8080: {'tcp': {'service': 'http-proxy', 'frequency': 0.035}},
            20000: {'tcp': {'service': 'dnp3', 'frequency': 0.001}},
            37777: {'tcp': {'service': 'dahua', 'frequency': 0.001}},
            44818: {'tcp': {'service': 'ethernet-ip', 'frequency': 0.001}},
            47808: {'udp': {'service': 'bacnet', 'frequency': 0.001}}
        }
        return builtin_services
    
    def parse_service_probes(self, filename: str = None) -> List[Dict]:
        """解析nmap-service-probes文件
        
        Args:
            filename: 探测文件路径
            
        Returns:
            list: 服务探测规则列表
        """
        if filename is None:
            filename = os.path.join(self.data_dir, 'nmap-service-probes')
        
        probes = []
        current_probe = None
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except FileNotFoundError:
            print(f"Warning: {filename} not found, using built-in probe data")
            content = self._get_builtin_probes()
        
        # 按探测块分割
        probe_blocks = re.split(r'\n(?=Probe\s)', content)
        
        for block in probe_blocks:
            if not block.strip():
                continue
            
            probe = self._parse_probe_block(block)
            if probe:
                probes.append(probe)
        
        self.service_probes = probes
        return probes
    
    def _parse_probe_block(self, block: str) -> Optional[Dict]:
        """解析单个探测块
        
        Args:
            block: 探测块文本
            
        Returns:
            dict: 解析后的探测规则
        """
        lines = block.strip().split('\n')
        if not lines:
            return None
        
        probe = {
            'protocol': '',
            'name': '',
            'string': b'',
            'matches': [],
            'softmatches': [],
            'ports': [],
            'sslports': [],
            'totalwaitms': 5000,
            'tcpwrappedms': 2000,
            'rarity': 1,
            'fallback': ''
        }
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 解析Probe行
            if line.startswith('Probe '):
                probe_match = re.match(r'Probe\s+(\w+)\s+(\w+)\s+q\|(.*)\|', line)
                if probe_match:
                    probe['protocol'] = probe_match.group(1)
                    probe['name'] = probe_match.group(2)
                    probe['string'] = self._decode_probe_string(probe_match.group(3))
            
            # 解析match行
            elif line.startswith('match '):
                match = self._parse_match_line(line)
                if match:
                    probe['matches'].append(match)
            
            # 解析softmatch行
            elif line.startswith('softmatch '):
                softmatch = self._parse_softmatch_line(line)
                if softmatch:
                    probe['softmatches'].append(softmatch)
            
            # 解析ports行
            elif line.startswith('ports '):
                ports = self._parse_ports_line(line)
                probe['ports'].extend(ports)
            
            # 解析sslports行
            elif line.startswith('sslports '):
                sslports = self._parse_ports_line(line)
                probe['sslports'].extend(sslports)
            
            # 解析其他属性
            elif line.startswith('totalwaitms '):
                try:
                    probe['totalwaitms'] = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            
            elif line.startswith('tcpwrappedms '):
                try:
                    probe['tcpwrappedms'] = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            
            elif line.startswith('rarity '):
                try:
                    probe['rarity'] = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            
            elif line.startswith('fallback '):
                probe['fallback'] = line.split()[1] if len(line.split()) > 1 else ''
        
        return probe if probe['protocol'] and probe['name'] else None
    
    def _decode_probe_string(self, encoded_string: str) -> bytes:
        """解码探测字符串
        
        Args:
            encoded_string: 编码的探测字符串
            
        Returns:
            bytes: 解码后的字节串
        """
        try:
            # 处理转义字符
            decoded = encoded_string.encode('utf-8').decode('unicode_escape')
            return decoded.encode('latin-1')
        except:
            return encoded_string.encode('utf-8', errors='ignore')
    
    def _parse_match_line(self, line: str) -> Optional[Dict]:
        """解析match行
        
        Args:
            line: match行文本
            
        Returns:
            dict: 解析后的匹配规则
        """
        # match service_name m|pattern|flags [version_info]
        match_pattern = r'match\s+(\w+)\s+m\|([^|]*)\|([^\s]*)\s*(.*)'
        match_obj = re.match(match_pattern, line)
        
        if match_obj:
            service = match_obj.group(1)
            pattern = match_obj.group(2)
            flags = match_obj.group(3)
            version_info = match_obj.group(4).strip()
            
            # 解析版本信息
            product = ''
            version = ''
            info = ''
            
            if version_info:
                # 解析 p/product/ v/version/ i/info/ 格式
                parts = re.findall(r'([pvi])/([^/]*?)/', version_info)
                for part_type, part_value in parts:
                    if part_type == 'p':
                        product = part_value
                    elif part_type == 'v':
                        version = part_value
                    elif part_type == 'i':
                        info = part_value
            
            return {
                'service': service,
                'pattern': pattern.encode('utf-8'),  # 保持原始pattern
                'flags': flags,
                'product': product,
                'version': version,
                'info': info
            }
        
        return None
    
    def _parse_softmatch_line(self, line: str) -> Optional[Dict]:
        """解析softmatch行
        
        Args:
            line: softmatch行文本
            
        Returns:
            dict: 解析后的软匹配规则
        """
        # softmatch service_name m|pattern|flags
        softmatch_pattern = r'softmatch\s+(\w+)\s+m\|([^|]*)\|([^\s]*)'
        match_obj = re.match(softmatch_pattern, line)
        
        if match_obj:
            service = match_obj.group(1)
            pattern = match_obj.group(2)
            flags = match_obj.group(3)
            
            return {
                'service': service,
                'pattern': pattern.encode('utf-8'),  # 保持原始pattern
                'flags': flags,
                'product': '',
                'version': '',
                'info': ''
            }
        
        return None
    
    def _parse_ports_line(self, line: str) -> List[int]:
        """解析ports行
        
        Args:
            line: ports行文本
            
        Returns:
            list: 端口列表
        """
        ports = []
        
        # 提取端口部分
        parts = line.split()
        if len(parts) < 2:
            return ports
        
        port_string = ' '.join(parts[1:])
        
        # 解析端口范围和单个端口
        port_parts = port_string.split(',')
        
        for part in port_parts:
            part = part.strip()
            
            if '-' in part:
                # 端口范围
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    ports.extend(range(start_port, end_port + 1))
                except ValueError:
                    pass
            else:
                # 单个端口
                try:
                    port = int(part)
                    ports.append(port)
                except ValueError:
                    pass
        
        return ports
    
    def _get_builtin_probes(self) -> str:
        """获取内置的探测规则
        
        Returns:
            str: 内置探测规则文本
        """
        return r"""
# Built-in service probes for industrial and camera devices

Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
rarity 1
ports 80,443,8000,8080,8443
match http m|^HTTP/1\.[01] \d+ .*\r\n|s p/HTTP/ cpe:/a:apache:http_server/
softmatch http m|^HTTP/|

Probe TCP RTSPRequest q|OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n|
rarity 2
ports 554
match rtsp m|^RTSP/1\.0 200 OK|s p/RTSP/ 
softmatch rtsp m|^RTSP/|

Probe TCP ModbusRequest q|\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01|
rarity 3
ports 502
match modbus m|^\x00\x01\x00\x00\x00\x05\x01\x03\x02|s p/Modbus TCP/
softmatch modbus m|^\x00\x01|

Probe TCP S7Request q|\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02|
rarity 4
ports 102
match s7 m|^\x03\x00|s p/Siemens S7/
softmatch s7 m|^\x03\x00|

Probe UDP BACnetRequest q|\x81\x0a\x00\x08\x01\x20\xff\xff|
rarity 5
ports 47808
match bacnet m|^\x81|s p/BACnet/
softmatch bacnet m|^\x81|

Probe TCP DNP3Request q|\x05\x64\x05\xc9\x01\x00\x00\x04\xe9\x21|
rarity 6
ports 20000
match dnp3 m|^\x05\x64|s p/DNP3/
softmatch dnp3 m|^\x05\x64|

Probe TCP EtherNetIPRequest q|\x6f\x00\x18\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|
rarity 7
ports 44818
match ethernet-ip m|^\x6f\x00|s p/EtherNet\/IP/
softmatch ethernet-ip m|^\x6f\x00|

Probe TCP OPCUARequest q|HEL\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00|
rarity 8
ports 4840
match opc-ua m|^HEL|s p/OPC UA/
softmatch opc-ua m|^HEL|
"""
    
    def get_service_by_port(self, port: int, protocol: str = 'tcp') -> str:
        """根据端口获取服务名
        
        Args:
            port: 端口号
            protocol: 协议类型
            
        Returns:
            str: 服务名
        """
        if port in self.services:
            if protocol in self.services[port]:
                return self.services[port][protocol]['service']
            elif 'tcp' in self.services[port]:
                return self.services[port]['tcp']['service']
        
        return 'unknown'
    
    def get_probes_for_port(self, port: int) -> List[Dict]:
        """获取适用于指定端口的探测规则
        
        Args:
            port: 端口号
            
        Returns:
            list: 适用的探测规则列表
        """
        applicable_probes = []
        
        for probe in self.service_probes:
            # 检查端口是否在探测范围内
            if not probe['ports'] or port in probe['ports']:
                applicable_probes.append(probe)
        
        # 按稀有度排序
        applicable_probes.sort(key=lambda x: x['rarity'])
        
        return applicable_probes
    
    def match_service_response(self, response: bytes, port: int) -> Dict:
        """匹配服务响应
        
        Args:
            response: 服务响应数据
            port: 端口号
            
        Returns:
            dict: 匹配结果
        """
        result = {
            'service': '',
            'version': '',
            'product': '',
            'vendor': '',
            'confidence': 0
        }
        
        # 获取适用的探测规则
        probes = self.get_probes_for_port(port)
        
        for probe in probes:
            # 尝试精确匹配
            for match in probe['matches']:
                try:
                    match_obj = match['pattern'].search(response)
                    if match_obj:
                        result['service'] = match['service']
                        result['confidence'] = 10
                        
                        # 解析版本信息
                        version_info = self._parse_version_info(match['version_info'], match_obj)
                        result.update(version_info)
                        
                        return result
                except:
                    continue
            
            # 尝试软匹配
            for softmatch in probe['softmatches']:
                try:
                    if softmatch['pattern'].search(response):
                        if not result['service']:
                            result['service'] = softmatch['service']
                            result['confidence'] = 5
                except:
                    continue
        
        return result
    
    def _parse_version_info(self, version_template: str, match_obj) -> Dict:
        """解析版本信息模板
        
        Args:
            version_template: 版本信息模板
            match_obj: 正则匹配对象
            
        Returns:
            dict: 解析后的版本信息
        """
        info = {
            'version': '',
            'product': '',
            'vendor': '',
            'hostname': '',
            'os': ''
        }
        
        if not version_template:
            return info
        
        try:
            # 替换捕获组
            for i, group in enumerate(match_obj.groups(), 1):
                if group:
                    version_template = version_template.replace(f'${i}', group.decode('utf-8', errors='ignore'))
            
            # 解析字段
            fields = re.findall(r'(\w+)/([^/\s]+)', version_template)
            for field, value in fields:
                if field in info:
                    info[field] = value
        
        except Exception:
            pass
        
        return info
    
    def load_all_data(self):
        """加载所有数据文件"""
        print("正在加载nmap数据文件...")
        
        # 解析服务文件
        self.parse_nmap_services()
        print(f"已加载 {len(self.services)} 服务定义")
        
        # 解析探测文件
        self.parse_service_probes()

        


if __name__ == '__main__':
    # 测试解析器
    parser = NmapDataParser()
    parser.load_all_data()
    
    # 测试服务查询
    print(f"Port 80 service: {parser.get_service_by_port(80)}")
    print(f"Port 502 service: {parser.get_service_by_port(502)}")
    
    # 测试探测规则
    probes = parser.get_probes_for_port(80)
    print(f"Probes for port 80: {len(probes)}")