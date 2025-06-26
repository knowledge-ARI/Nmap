#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络扫描工具
主程序入口，提供命令行接口进行网络扫描、服务识别、版本检测和漏洞发现

Author: Security Engineer
Date: 2025
"""

import argparse
import sys
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from scan import NetworkScanner
from config import ScanConfig
from vuln_search import VulnerabilitySearcher
from poc_test import POCTester


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='网络扫描工具 - 主机发现、端口扫描、服务识别和版本检测',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  python main.py -t 192.168.1.1-100 -p 80,443,22,21
  python main.py -f targets.txt --threads 50 --version-scan
  python main.py -t 10.0.0.0/24 --poc-test
        """
    )
    
    # 目标参数
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-t', '--target', 
                             help='目标IP地址或范围 (如: 192.168.1.1, 192.168.1.1-100, 10.0.0.0/24)')
    target_group.add_argument('-f', '--file', 
                             help='包含目标IP的文件，每行一个IP')
    
    # 扫描参数
    parser.add_argument('-p', '--ports', 
                       default='',
                       help='要扫描的端口列表，用逗号分隔 (默认: 常见1000端口)')
    parser.add_argument('--threads', type=int, default=20,
                       help='并发线程数 (默认: 20)')
    parser.add_argument('--timeout', type=int, default=5,
                       help='连接超时时间，秒 (默认: 5)')
    parser.add_argument('--ping-timeout', type=int, default=3,
                       help='Ping超时时间，秒 (默认: 3)')
    
    # 基础扫描选项
    parser.add_argument('--skip-ping', action='store_true',
                       help='跳过主机存活检测')
    parser.add_argument('--version-scan', action='store_true',
                       help='启用服务版本探测（默认已启用）')
    parser.add_argument('--skip-version', action='store_true',
                       help='跳过服务版本探测')
    parser.add_argument('--camera', action='store_true',
                       help='启用摄像头设备专项检测')
    
    # 漏洞扫描选项（可选）
    parser.add_argument('--vuln-scan', action='store_true',
                       help='启用漏洞扫描')
    parser.add_argument('--vuln-search', nargs='+',
                       help='搜索指定服务的漏洞 (格式: --vuln-search service [version])')
    parser.add_argument('--poc-test', action='store_true',
                       help='执行POC测试验证漏洞')
    parser.add_argument('--custom-poc', 
                       help='指定自定义POC脚本路径或目录')
    parser.add_argument('--exploitdb-path', 
                       default=None,
                       help='ExploitDB数据库路径 (默认: 使用scanner/data目录)')
    parser.add_argument('--max-poc', type=int, default=20,
                       help='每个目标最大POC测试数量 (默认: 20)')
    parser.add_argument('--poc-timeout', type=int, default=30,
                       help='POC执行超时时间，秒 (默认: 30)')
    
    # 输出参数
    parser.add_argument('-o', '--output', 
                       help='输出文件名')
    parser.add_argument('--format', choices=['txt', 'json', 'xml'], default='txt',
                       help='输出格式 (默认: txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='详细输出')

    return parser.parse_args()


def load_targets_from_file(filename):
    """从文件加载目标IP列表"""
    targets = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except FileNotFoundError:
        print(f"错误: 文件 {filename} 不存在")
        sys.exit(1)
    except Exception as e:
        print(f"错误: 读取文件 {filename} 失败: {e}")
        sys.exit(1)
    
    return targets


def expand_ip_range(target):
    """扩展IP范围为具体IP列表"""
    import ipaddress
    
    targets = []
    
    try:
        # 处理CIDR格式 (如: 192.168.1.0/24)
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        
        # 处理范围格式 (如: 192.168.1.1-100)
        elif '-' in target and target.count('.') == 3:
            base_ip, end_range = target.rsplit('-', 1)
            if '.' in base_ip:
                base_parts = base_ip.split('.')
                start_num = int(base_parts[-1])
                end_num = int(end_range)
                base_prefix = '.'.join(base_parts[:-1])
                
                for i in range(start_num, end_num + 1):
                    targets.append(f"{base_prefix}.{i}")
        
        # 单个IP地址
        else:
            ipaddress.ip_address(target)  # 验证IP格式
            targets = [target]
            
    except ValueError as e:
        print(f"错误: 无效的IP地址或范围格式: {target}")
        sys.exit(1)
    
    return targets


def scan_target(target, args, scanner, service_scanner=None):
    """扫描单个目标
    
    扫描流程:
    1. 主机存活检测
    2. 端口扫描
    3. 服务识别和版本检测
    4. 摄像头检测（可选）
    5. 漏洞扫描（仅在指定参数时）
    """
    result = {
        'target': target,
        'alive': False,
        'ports': [],
        'services': [],
        'vulnerabilities': [],
        'cameras': []
    }
    
    try:
        # 1. 主机存活检测
        if not args.skip_ping:
            if args.verbose:
                print(f"[*] 检测主机存活性: {target}")
            if not scanner.ping_host(target, args.ping_timeout):
                if args.verbose:
                    print(f"[-] 主机 {target} 不可达")
                return result
        
        result['alive'] = True
        if args.verbose:
            print(f"[+] 主机 {target} 存活")
        
        # 2. 端口扫描
        if args.verbose:
            print(f"[*] 扫描端口: {target}")
        
        open_ports = scanner.scan_ports(target, args.ports, args.timeout)
        
        # 转换端口信息格式
        for port_info in open_ports:
            if isinstance(port_info, dict):
                port = port_info['port']
                port_result = {
                    'port': port,
                    'status': port_info.get('state', 'open'),
                    'service': port_info.get('service', ''),
                    'version': port_info.get('version', ''),
                    'product': port_info.get('product', ''),
                    'vendor': port_info.get('vendor', ''),
                    'extrainfo': port_info.get('extrainfo', ''),
                    'conf': port_info.get('conf', 3)
                }
            else:
                port = port_info
                port_result = {
                    'port': port,
                    'status': 'open',
                    'service': '',
                    'version': ''
                }
            
            result['ports'].append(port_result)
        
        if not result['ports']:
            if args.verbose:
                print(f"[-] 主机 {target} 没有发现开放端口")
            return result
        
        if args.verbose:
            print(f"[+] 发现 {len(result['ports'])} 个开放端口: {[p['port'] for p in result['ports']]}")
        
        # 3. 服务识别和版本检测
        if service_scanner:  # 如果服务扫描器已初始化，则进行版本检测
            if args.verbose:
                print(f"[*] 进行服务版本检测: {target}")
            
            for port_info in result['ports']:
                port = port_info['port']
                service_info = service_scanner.scan_service(target, port)
                if service_info:
                    port_info.update(service_info)
                    result['services'].append({
                        'port': port,
                        'service': service_info.get('service', 'unknown'),
                        'version': service_info.get('version', ''),
                        'product': service_info.get('product', ''),
                        'vendor': service_info.get('vendor', '')
                    })
        
        # 4. 摄像头检测（可选）
        if args.camera:
            if args.verbose:
                print(f"[*] 进行摄像头检测: {target}")
            # 摄像头检测功能已简化，通过服务识别中的厂商模式识别摄像头设备
            for port_info in result['ports']:
                if port_info.get('vendor') in ['hikvision', 'dahua', 'axis', 'bosch', 'sony', 'panasonic']:
                    port_info['device_type'] = 'camera'
                    result['cameras'].append({
                        'port': port_info['port'],
                        'vendor': port_info.get('vendor', 'unknown')
                    })
        
        # 5. 漏洞扫描（仅在用户指定参数时）
        if args.vuln_scan:
            if args.verbose:
                print(f"[*] 进行漏洞扫描: {target}")
            # 注意：这里需要确保scan_vulnerabilities方法存在
            if hasattr(scanner, 'scan_vulnerabilities'):
                for port_info in result['ports']:
                    port = port_info['port']
                    vulns = scanner.scan_vulnerabilities(target, port, port_info.get('service', ''), args.timeout)
                    if vulns:
                        port_info['vulnerabilities'] = vulns
                        result['vulnerabilities'].extend(vulns)
            else:
                if args.verbose:
                    print(f"[!] 漏洞扫描功能暂未实现")
        
        return result
        
    except KeyboardInterrupt:
        raise
    except Exception as e:
        if args.verbose:
            print(f"[!] 扫描 {target} 时发生错误: {e}")
        return result


def format_output(ports,results, output_format='text', poc_results=None):
    """格式化输出结果
    
    Args:
        ports: 扫描的端口数 --list
        results: 扫描结果
        output_format: 输出格式 (text, json, xml)
        poc_results: POC测试结果
        
    Returns:
        str: 格式化后的输出
    """
    import json
    if output_format == 'json':
        # 为JSON格式添加POC结果
        output_data = {
            'scan_results': results,
            'poc_results': poc_results if poc_results else []
        }
        return json.dumps(output_data, indent=2, ensure_ascii=False)
    elif output_format == 'xml':
        return format_xml_output(results, poc_results)
    else:
        return format_nmap_style_output(ports,results, poc_results)


def format_xml_output(results, poc_results=None):
    """格式化XML输出"""
    import xml.etree.ElementTree as ET
    root = ET.Element('scan_results')
    
    # 处理POC结果
    poc_vulns = {}
    if poc_results:
        for poc_result in poc_results:
            # 使用POC结果中的target_port字段，如果没有则构建
            target_port = poc_result.get('target_port')
            if not target_port:
                target_port = f"{poc_result.get('target', '')}:{poc_result.get('port', '')}"
            
            if poc_result.get('vulnerable', False):
                if target_port not in poc_vulns:
                    poc_vulns[target_port] = []
                poc_vulns[target_port].append(poc_result)
    
    # 按目标分组
    targets = {}
    for result in results:
        target = result['target']
        if target not in targets:
            targets[target] = []
        targets[target].append(result)
    
    for target, target_results in targets.items():
        host_elem = ET.SubElement(root, 'host')
        host_elem.set('ip', target)
        
        # 统计端口信息
        open_ports = [r for r in target_results if r['status'] == 'open']
        # 计算实际扫描的端口数量
        total_scanned_ports = len(target_results)
        closed_ports = total_scanned_ports - len(open_ports)
        if closed_ports > 0:
            status_elem = ET.SubElement(host_elem, 'status')
            status_elem.set('state', 'up')
            status_elem.set('reason', 'echo-reply')
            
            extraports_elem = ET.SubElement(host_elem, 'extraports')
            extraports_elem.set('state', 'closed')
            extraports_elem.set('count', str(closed_ports))
        
        ports_elem = ET.SubElement(host_elem, 'ports')
        
        for result in sorted(target_results, key=lambda x: x['port']):
            port_elem = ET.SubElement(ports_elem, 'port')
            port_elem.set('protocol', 'tcp')
            port_elem.set('portid', str(result['port']))
            
            state_elem = ET.SubElement(port_elem, 'state')
            state_elem.set('state', result['status'])
            state_elem.set('reason', 'syn-ack')
            
            if result.get('service'):
                service_elem = ET.SubElement(port_elem, 'service')
                service_elem.set('name', result['service'])
                if result.get('product'):
                    service_elem.set('product', result['product'])
                if result.get('version'):
                    service_elem.set('version', result['version'])
                if result.get('extrainfo'):
                    service_elem.set('extrainfo', result['extrainfo'])
            
            # 添加常规漏洞信息
            if result.get('vulnerabilities'):
                vulns_elem = ET.SubElement(port_elem, 'vulnerabilities')
                for vuln in result['vulnerabilities']:
                    vuln_elem = ET.SubElement(vulns_elem, 'vulnerability')
                    vuln_elem.set('name', vuln)
            
            # 添加POC验证的漏洞详情
            target_port_key = f"{target}:{result['port']}"
            if target_port_key in poc_vulns:
                confirmed_vulns_elem = ET.SubElement(port_elem, 'confirmed_vulnerabilities')
                for poc_vuln in poc_vulns[target_port_key]:
                    confirmed_vuln_elem = ET.SubElement(confirmed_vulns_elem, 'confirmed_vulnerability')
                    confirmed_vuln_elem.set('name', poc_vuln.get('vuln_name', 'Unknown'))
                    confirmed_vuln_elem.set('poc_path', poc_vuln.get('poc_path', 'N/A'))
                    confirmed_vuln_elem.set('execution_time', str(poc_vuln.get('execution_time', 0)))
                    if poc_vuln.get('output'):
                        output_elem = ET.SubElement(confirmed_vuln_elem, 'output')
                        output_elem.text = poc_vuln['output']
    
    return ET.tostring(root, encoding='unicode')


def format_nmap_style_output(ports,results, poc_results=None):
    """格式化Nmap风格的文本输出"""
    output = []
    output.append("Starting Network Scanner...")
    output.append("")
    
    # 按目标分组
    targets = {}
    for result in results:
        target = result['target']
        if target not in targets:
            targets[target] = []
        targets[target].append(result)
    
    # 处理POC结果
    poc_vulns = {}
    if poc_results:
        for poc_result in poc_results:
            target_port = f"{poc_result.get('target', '')}:{poc_result.get('port', '')}"
            if poc_result.get('vulnerable', False):
                if target_port not in poc_vulns:
                    poc_vulns[target_port] = []
                poc_vulns[target_port].append(poc_result)
    
    for target, target_results in targets.items():
        output.append(f"Nmap scan report for {target}")
        
        # 统计开放端口
        open_ports = [r for r in target_results if r['status'] == 'open']
        if open_ports:
            output.append(f"Host is up.")
            # 计算实际扫描的端口数量
            total_scanned_ports = len(ports)
            output.append(f"(The {total_scanned_ports} ports scanned but not shown below are in state: closed)")
            output.append("PORT     STATE SERVICE")
            
            for result in sorted(open_ports, key=lambda x: x['port']):
                port_str = f"{result['port']}/tcp"
                state = result['status']
                base_service = result.get('service', 'unknown')
                
                # 构建完整的服务信息（包含应用名称和版本）
                service_parts = [base_service]
                if result.get('product'):
                    service_parts.append(result['product'])
                if result.get('version'):
                    service_parts.append(result['version'])
                if result.get('extrainfo'):
                    service_parts.append(f"({result['extrainfo']})")
                
                # 完整的服务字符串
                full_service = ' '.join(service_parts)
                
                # 格式化输出行 - 现在SERVICE列包含完整信息
                line = f"{port_str:<8} {state:<5} {full_service}"
                output.append(line)
                
                # 显示设备信息
                if result.get('device_type'):
                    output.append(f"  Device Type: {result['device_type']}")
                
                # 显示漏洞
                if result.get('vulnerabilities'):
                    output.append("  Vulnerabilities:")
                    for vuln in result['vulnerabilities']:
                        output.append(f"    - {vuln}")
                
                # 显示POC验证的漏洞详情
                target_port_key = f"{target}:{result['port']}"
                # 尝试多种可能的键格式
                possible_keys = [
                    target_port_key,
                    f"{target}:{result['port']}",
                    f"{target}:{result['port']}:",  # 添加带冒号的格式
                    result.get('target_port', ''),
                    f"{result.get('host', target)}:{result['port']}",
                    f"{result.get('host', target)}:{result['port']}:"
                ]
                
                found_key = None
                for key in possible_keys:
                    if key and key in poc_vulns:
                        found_key = key
                        break
                

                
                if found_key:
                    output.append("  Confirmed Vulnerabilities (POC Verified):")
                    for poc_vuln in poc_vulns[found_key]:
                        vuln_name = poc_vuln.get('vuln_name', 'Unknown')
                        poc_path = poc_vuln.get('poc_path', 'N/A')
                        exec_time = poc_vuln.get('execution_time', 0)
                        vuln_output = poc_vuln.get('output', '')
                        
                        output.append(f"    + {vuln_name}")
                        output.append(f"      POC: {poc_path}")
                        output.append(f"      Execution Time: {exec_time:.2f}s")
                        if vuln_output:
                            # 限制输出长度，避免过长
                            if len(vuln_output) > 200:
                                output.append(f"      Output: {vuln_output[:200]}...")
                            else:
                                output.append(f"      Output: {vuln_output}")
        else:
            output.append("Host is up.")
            output.append("All scanned ports on {} are closed".format(target))
        
        output.append("")
    
    return "\n".join(output)


def save_results(ports,results, output_file, output_format, poc_results=None):
    """保存扫描结果到文件"""
    if not results:
        print("没有发现开放的端口")
        return
    
    try:
        formatted_output = format_output(ports,results, output_format, poc_results)
        
        if output_format == 'xml':
            import xml.etree.ElementTree as ET
            root = ET.fromstring(formatted_output)
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
        else:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
        
        print(f"结果已保存到: {output_file}")
        
        # 如果有POC结果，显示统计信息
        if poc_results:
            vulnerable_count = sum(1 for r in poc_results if r.get('vulnerable', False))
            if vulnerable_count > 0:
                print(f"包含 {vulnerable_count} 个POC验证的漏洞详情")
        
    except Exception as e:
        print(f"保存结果失败: {e}")


def vulnerability_search_mode(args):
    """漏洞搜索模式"""
    print("漏洞搜索模式")
    print("=" * 30)
    
    searcher = VulnerabilitySearcher(args.exploitdb_path)
    
    # 解析搜索查询
    query_parts = args.vuln_search  # 现在是一个列表
    service_name = query_parts[0]
    version = ' '.join(query_parts[1:]) if len(query_parts) > 1 else None
    
    print(f"搜索服务: {service_name}")
    if version:
        print(f"版本: {version}")
    print()
    
    # 搜索漏洞
    exploits = searcher.search_by_service(service_name, version, max_results=20)
    
    if exploits:
        print(searcher.format_results(exploits, show_details=True))
        
        # 如果启用POC测试，直接进行探测
        if args.poc_test:
            print("\n[*] 开始执行POC测试...")
            # 直接使用漏洞搜索结果进行POC测试
            poc_test_mode(None, None, exploits, args)
    else:
        print("未找到相关漏洞")


def custom_poc_mode(args):
    """自定义POC测试模式 - 只进行主机存活性探测后直接执行POC"""
    print(f"\n自定义POC测试模式")
    print("=" * 30)
    
    # 验证目标参数
    if not args.target and not args.file:
        print("[!] 错误: 必须指定目标 (-t 或 -f 参数)")
        sys.exit(1)
    
    # 获取目标列表
    if args.file:
        targets = load_targets_from_file(args.file)
    else:
        targets = expand_ip_range(args.target)
    
    # 解析端口（如果提供）
    port = None
    if args.ports:
        try:
            port = int(args.ports.split(',')[0])  # 取第一个端口
        except ValueError:
            print(f"[!] 警告: 端口格式无效，将使用默认端口")
    
    print(f"目标数量: {len(targets)} 个")
    print(f"POC路径: {args.custom_poc}")
    if port:
        print(f"目标端口: {port}")
    print()
    
    # 初始化扫描器（仅用于主机存活性探测）
    config = ScanConfig()
    scanner = NetworkScanner(config)
    
    # 初始化POC测试器
    poc_tester = POCTester(timeout=args.poc_timeout, max_workers=3, custom_poc_path=args.custom_poc)
    
    start_time = time.time()
    alive_targets = []
    
    print("Starting Host Discovery...\n")
    
    # 对每个目标进行主机存活性探测
    for target in targets:
        try:
            # 主机存活检测
            if not args.skip_ping:
                print(f"[*] 检测主机存活性: {target}")
                if not scanner.ping_host(target, args.ping_timeout):
                    print(f"[-] 主机 {target} 不可达")
                    continue
            
            print(f"[+] 主机 {target} 存活")
            alive_targets.append(target)
            
        except Exception as e:
            print(f"[-] 检测 {target} 时出错: {e}")
    
    if not alive_targets:
        print("\n[!] 未发现存活主机，无法进行POC测试")
        return
    
    print(f"\n[+] 发现 {len(alive_targets)} 个存活主机")
    print("\n开始POC测试...\n")
    
    # 对存活的主机执行POC测试
    total_vulnerable = 0
    for target in alive_targets:
        try:
            print(f"[*] 测试目标: {target}:{port if port else 'N/A'}")
            
            # 创建自定义exploit对象用于POC测试
            custom_exploit = {
                'path': args.custom_poc,
                'title': f'Custom POC: {args.custom_poc}',
                'type': 'custom'
            }
            
            # 执行POC测试
            results = poc_tester.test_single_target(target, port, [custom_exploit])
            
            # 显示结果
            if results:
                formatted_results = poc_tester.format_results(results)
                print(formatted_results)
                
                # 统计漏洞数量
                vulnerable_count = sum(1 for r in results if r.get('vulnerable', False))
                total_vulnerable += vulnerable_count
            else:
                print(f"[-] {target} 未发现漏洞")
                
        except Exception as e:
            print(f"[-] 测试 {target} 时出错: {e}")
    
    end_time = time.time()
    
    # 显示总结
    print(f"\n自定义POC测试完成")
    print(f"测试目标: {len(alive_targets)} 个")
    print(f"发现漏洞: {total_vulnerable} 个")
    print(f"测试耗时: {end_time - start_time:.2f} 秒")


def poc_test_mode(target_host, target_port, exploits, args):
    """POC测试模式"""
    print(f"\nPOC测试模式")
    print("=" * 30)
    print(f"目标: {target_host}:{target_port if target_port else 'N/A'}")
    print(f"漏洞数量: {len(exploits)}")
    print()
    
    # 初始化POC测试器
    poc_tester = POCTester(timeout=args.poc_timeout, max_workers=3, custom_poc_path=args.custom_poc)
    
    # 限制POC数量
    test_exploits = exploits[:args.max_poc]
    if len(exploits) > args.max_poc:
        print(f"[!] 限制POC测试数量为 {args.max_poc} 个")
    
    # 执行POC测试
    try:
        port = int(target_port) if target_port else None
        results = poc_tester.test_single_target(target_host, port, test_exploits)
        
        # 显示结果
        print(poc_tester.format_results(results, show_details=True))
        
        # 显示统计信息
        stats = poc_tester.get_statistics()
        if stats:
            print(f"\n测试统计:")
            print(f"总计: {stats['total']} 个")
            print(f"成功: {stats['success']} 个 ({stats['success_rate']:.1f}%)")
            print(f"发现漏洞: {stats['vulnerable']} 个 ({stats['vulnerability_rate']:.1f}%)")
            print(f"平均执行时间: {stats['avg_execution_time']:.2f} 秒")
    
    except Exception as e:
        print(f"POC测试过程中出错: {e}")


def _build_progressive_search_queries(service, version, product):
    """
    构建渐进式搜索查询列表，从精确到模糊
    
    Args:
        service: 服务名称
        version: 版本信息
        product: 产品名称
        
    Returns:
        list: 搜索查询字符串列表
    """
    import re
    
    queries = []
    
    # 产品名称映射
    product_mapping = {
        'phpMyAdmin': 'phpMyAdmin',
        'Apache httpd': 'Apache',
        'nginx': 'nginx',
        'Microsoft IIS httpd': 'IIS',
        'OpenSSH': 'OpenSSH',
        'SSH': 'OpenSSH',
        'Apache Tomcat': 'Tomcat',
        'lighttpd': 'lighttpd'
    }
    
    # 服务名称映射
    service_mapping = {
        'ssh': 'OpenSSH',
        'http': 'Apache',
        'https': 'Apache',
        'ftp': 'FTP',
        'smtp': 'SMTP',
        'pop3': 'POP3',
        'imap': 'IMAP'
    }
    
    # 确定主要产品名称
    main_product = None
    if product:
        main_product = product_mapping.get(product, product)
    elif service:
        main_product = service_mapping.get(service.lower(), service)
    
    if not main_product:
        return ['unknown']
    
    # 清理版本信息
    clean_version = None
    if version and version != 'unknown':
        clean_version = re.sub(r'\s*\([^)]*\)', '', version).strip()
    
    # 1. 精确搜索：完整产品名称 + 完整版本
    if clean_version:
        queries.append(f"{main_product} {clean_version}")
    
    # 2. 主版本搜索：产品名称 + 主版本号
    if clean_version:
        # 提取主版本号（如 4.4.15.6 -> 4.4）
        version_parts = clean_version.split('.')
        if len(version_parts) >= 2:
            major_version = f"{version_parts[0]}.{version_parts[1]}"
            queries.append(f"{main_product} {major_version}")
        
        # 提取大版本号（如 4.4.15.6 -> 4）
        if len(version_parts) >= 1:
            major_only = version_parts[0]
            queries.append(f"{main_product} {major_only}")
    
    # 3. 产品名称搜索：只搜索产品名称
    queries.append(main_product)
    
    # 4. 如果是特定产品，添加相关的通用搜索词
    if main_product.lower() == 'phpmyadmin':
        queries.extend(['phpMyAdmin 4.', 'phpMyAdmin'])
    elif main_product.lower() == 'apache':
        queries.extend(['Apache httpd', 'Apache'])
    elif main_product.lower() == 'tomcat':
        queries.extend(['Apache Tomcat', 'Tomcat'])
    elif main_product.lower() == 'openssh':
        queries.extend(['OpenSSH', 'SSH'])
    
    # 去重并保持顺序
    unique_queries = []
    seen = set()
    for query in queries:
        if query.lower() not in seen:
            unique_queries.append(query)
            seen.add(query.lower())
    
    return unique_queries


def print_summary(results):
    """打印扫描摘要"""
    if not results:
        print("\n扫描完成，未发现开放端口")
        return
    
    targets = set(r['target'] for r in results)
    open_ports = len(results)
    services = set(r['service'] for r in results if r['service'])
    vulns = sum(len(r['vulnerabilities']) for r in results)
    
    print(f"\n扫描摘要:")
    print(f"扫描目标: {len(targets)} 个")
    print(f"开放端口: {open_ports} 个")
    print(f"识别服务: {len(services)} 种")
    print(f"发现漏洞: {vulns} 个")
    
    if services:
        print(f"\n发现的服务: {', '.join(sorted(services))}")

def print_detailed_summary(results):
    """打印详细的汇总报告
    
    Args:
        results: 扫描结果列表
    """
    if not results:
        print("\n未发现任何开放端口")
        return
    
    print("\n" + "="*80)
    print("扫描结果汇总")
    print("="*80)
    
    # 按目标分组统计
    target_stats = {}
    service_stats = {}
    port_details = []
    total_vulns = 0
    
    for result in results:
        target = result['target']
        port = result['port']
        service = result.get('service', 'unknown')
        product = result.get('product', '')
        version = result.get('version', '')
        extrainfo = result.get('extrainfo', '')
        
        # 构建完整的服务信息
        service_parts = [service]
        if product:
            service_parts.append(product)
        if version:
            service_parts.append(version)
        if extrainfo:
            service_parts.append(f"({extrainfo})")
        full_service = ' '.join(service_parts)
        
        # 收集端口详情
        port_details.append({
            'target': target,
            'port': port,
            'service': full_service,
            'vulns': len(result.get('vulnerabilities', []))
        })
        
        # 目标统计
        if target not in target_stats:
            target_stats[target] = {'ports': [], 'services': set(), 'vulns': 0}
        target_stats[target]['ports'].append(port)
        if service != 'unknown':
            target_stats[target]['services'].add(service)
        target_stats[target]['vulns'] += len(result.get('vulnerabilities', []))
        total_vulns += len(result.get('vulnerabilities', []))
        
        # 服务统计
        if service != 'unknown':
            if service not in service_stats:
                service_stats[service] = {'count': 0, 'versions': set(), 'full_info': set()}
            service_stats[service]['count'] += 1
            if version:
                service_stats[service]['versions'].add(version)
            service_stats[service]['full_info'].add(full_service)
    
    # 打印总体统计
    print(f"\n📊 总体统计:")
    print(f"扫描目标: {len(target_stats)} 个")
    print(f"开放端口: {len(results)} 个")
    print(f"识别服务: {len(service_stats)} 种")

    
    # 打印目标汇总
    print(f"\n🎯 目标汇总 ({len(target_stats)} 个目标):")
    print("-" * 80)
    print(f"{'目标地址':<20} {'开放端口':<25} {'识别服务':<15} {'发现漏洞':<10}")
    print("-" * 80)
    for target, stats in sorted(target_stats.items()):
        ports_str = ','.join(map(str, sorted(stats['ports'])))
        if len(ports_str) > 23:
            ports_str = ports_str[:23] + '...'
        services_str = ', '.join(sorted(stats['services'])) if stats['services'] else '无'
        if len(services_str) > 12:
            services_str = services_str[:12] + '...'
        print(f"{target:<20} {ports_str:<25} {services_str:<15} {stats['vulns']:<10}")
    
    # 打印端口详情
    print(f"\n🔍 端口详情:")
    print("-" * 80)
    print(f"{'目标地址':<18} {'端口':<8} {'服务信息':<40} {'漏洞':<6}")
    print("-" * 80)
    for detail in sorted(port_details, key=lambda x: (x['target'], x['port'])):
        service_display = detail['service'][:38] + '...' if len(detail['service']) > 38 else detail['service']
        print(f"{detail['target']:<18} {detail['port']:<8} {service_display:<40} {detail['vulns']:<6}")
    
    # 打印服务汇总
    if service_stats:
        print(f"\n🔧 服务汇总 ({len(service_stats)} 种服务):")
        print("-" * 80)
        print(f"{'服务类型':<15} {'发现次数':<10} {'完整服务信息':<50}")
        print("-" * 80)
        for service, stats in sorted(service_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            full_info_list = list(stats['full_info'])
            full_info_str = ', '.join(full_info_list) if full_info_list else service
            if len(full_info_str) > 48:
                full_info_str = full_info_str[:48] + '...'
            print(f"{service:<15} {stats['count']:<10} {full_info_str:<50}")
    
    print("="*80)


def main():
    """主函数"""
    print("网络扫描和漏洞检测工具 v2.0")
    print("=" * 50)
    
    args = parse_arguments()
    
    # 漏洞搜索模式
    if args.vuln_search:
        vulnerability_search_mode(args)
        return
    
    # 自定义POC测试模式 - 只需要主机存活性探测
    if args.custom_poc:
        custom_poc_mode(args)
        return
    
    # 验证目标参数（非漏洞搜索模式时必须提供）
    if not args.target and not args.file:
        print("[!] 错误: 必须指定目标 (-t 或 -f 参数)")
        print("[!] 使用 --vuln-search 进行漏洞搜索时不需要指定目标")
        sys.exit(1)
    
    # 获取目标列表
    if args.file:
        targets = load_targets_from_file(args.file)
    else:
        targets = expand_ip_range(args.target)
    
    # 解析端口列表
    def parse_port_range(port_string):
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
    
    # 初始化扫描器
    config = ScanConfig()
    scanner = NetworkScanner(config)
    
    # 初始化服务扫描器（默认启用版本探测，除非明确跳过且不进行POC测试）
    service_scanner = None
    # 如果启用POC测试，强制启用版本探测以获取准确的服务信息
    enable_version_scan = not args.skip_version or args.poc_test
    
    if enable_version_scan:
        try:
            # 使用NetworkScanner进行服务扫描
            service_scanner = scanner  # 复用已创建的NetworkScanner实例
            print("[+] 服务扫描器初始化成功")
            if args.poc_test and args.skip_version:
                print("[!] POC测试模式下自动启用版本探测")
        except Exception as e:
            print(f"[!] 服务扫描器初始化失败: {e}")
            print("[!] 将使用基础服务识别功能")
    
    # 处理端口参数
    if args.ports:
        ports = parse_port_range(args.ports)
    else:
        # 如果没有指定端口，使用默认的前1000个最常见端口
        ports = scanner.default_ports
    
    print(f"目标数量: {len(targets)} 个")
    print(f"扫描端口: {len(ports)} 个")
    print(f"并发线程: {args.threads}")
    if enable_version_scan:
        print(f"版本探测: 启用 ({'高级' if service_scanner else '基础'})")
    else:
        print(f"版本探测: 禁用")
    if args.camera:
        print(f"摄像头检测: 启用")
    if args.vuln_scan:
        print(f"漏洞扫描: 启用")
    print()
    
    # 开始扫描
    start_time = time.time()
    all_results = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        # 提交扫描任务
        future_to_target = {
            executor.submit(scan_target, target, args, scanner, service_scanner): target 
            for target in targets
        }
        
        # 收集结果
        completed = 0
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                if result['alive'] and result['ports']:
                    # 将端口信息转换为扁平化格式以保持兼容性
                    for port_info in result['ports']:
                        port_result = {
                            'target': result['target'],
                            'port': port_info['port'],
                            'status': port_info['status'],
                            'service': port_info.get('service', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'vulnerabilities': port_info.get('vulnerabilities', []),
                            'device_type': port_info.get('device_type', ''),
                            'device_info': port_info.get('device_info', {})
                        }
                        all_results.append(port_result)
            except Exception as e:
                if args.verbose:
                    print(f"[-] 扫描 {target} 时出错: {e}")
            
            completed += 1
            if args.verbose:
                print(f"进度: {completed}/{len(targets)} ({completed/len(targets)*100:.1f}%)")
    
    end_time = time.time()
    
    # 初始化POC结果
    all_poc_results = []
    
    # 如果发现了服务且启用了POC测试，提供交互选项
    if args.poc_test and all_results:
        services_found = [(r['target'], r['port'], r['service'], r.get('version', ''), r.get('product', ''), r.get('extrainfo', '')) 
                         for r in all_results if r.get('service')]
        
        if services_found:
            print(f"\n[+] 发现 {len(services_found)} 个服务，可进行POC测试")
            if args.poc_test:
                print("[*] 开始执行POC测试...")
                try:
                    # 对每个发现的服务进行漏洞搜索和POC测试
                    searcher = VulnerabilitySearcher(args.exploitdb_path)
                    poc_tester = POCTester(timeout=args.poc_timeout, max_workers=3)
                    all_poc_results = []  # 收集所有POC测试结果
                    
                    for target, port, service, version, product, extrainfo in services_found[:5]:  # 限制数量
                        print(f"\n[*] 测试 {target}:{port} ({service} {version})")
                        
                        # 构建搜索查询列表，从精确到模糊
                        search_queries = _build_progressive_search_queries(service, version, product)
                        
                        exploits = []
                        found_executable_poc = False
                        
                        for i, search_query in enumerate(search_queries):
                            print(f"[*] 搜索漏洞: {search_query}")
                            # 搜索更多结果以确保找到可执行POC，而不是限制在max_poc
                            current_exploits = searcher.search_exploits(search_query, max_results=20)
                            
                            if current_exploits:
                                exploits.extend(current_exploits)
                                
                                # 检查是否有可执行的POC文件（Python脚本）
                                executable_in_current = []
                                for exploit in current_exploits:
                                    if exploit['path'].endswith('.py'):
                                        executable_in_current.append(exploit)
                                        found_executable_poc = True
                                        print(f"[+] 找到可执行POC: {exploit['title']}")
                                
                                # 只有找到可执行POC时才停止搜索，不再因为漏洞数量而停止
                                if found_executable_poc:
                                    print(f"[*] 找到 {len(executable_in_current)} 个可执行POC，停止搜索")
                                    break
                                else:
                                    print(f"[*] 找到 {len(current_exploits)} 个漏洞，但没有可执行POC，继续搜索")
                            else:
                                print(f"[*] 没有找到漏洞，继续下一个查询")
                            
                            # 如果已经找到可执行POC，停止搜索
                            if found_executable_poc:
                                break
                        
                        if exploits:
                            # 去重并统计可执行POC
                            unique_exploits = []
                            seen_ids = set()
                            executable_pocs = []
                            
                            # 首先完整去重并统计所有可执行POC
                            for exploit in exploits:
                                if exploit['id'] not in seen_ids:
                                    unique_exploits.append(exploit)
                                    seen_ids.add(exploit['id'])
                                    # 统计可执行POC
                                    if exploit['path'].endswith('.py'):
                                        executable_pocs.append(exploit)
                            
                            # 优先选择可执行POC，然后补充其他漏洞
                            if len(unique_exploits) > args.max_poc:
                                # 分离可执行POC和其他漏洞
                                executable_exploits = [e for e in unique_exploits if e['path'].endswith('.py')]
                                non_executable_exploits = [e for e in unique_exploits if not e['path'].endswith('.py')]
                                
                                # 优先保留所有可执行POC，然后补充其他漏洞
                                selected_exploits = executable_exploits[:]
                                remaining_slots = args.max_poc - len(selected_exploits)
                                
                                if remaining_slots > 0:
                                    selected_exploits.extend(non_executable_exploits[:remaining_slots])
                                
                                unique_exploits = selected_exploits
                            
                            # 重新统计可执行POC
                            executable_pocs = [exploit for exploit in unique_exploits if exploit['path'].endswith('.py')]
                            
                            print(f"[*] 找到 {len(unique_exploits)} 个漏洞，其中 {len(executable_pocs)} 个可执行POC")
                            
                            if executable_pocs:
                                # 构建详细的服务信息，包含完整信息
                                service_parts = [service]
                                if product and product != 'unknown':
                                    service_parts.append(product)
                                if version and version != 'unknown':
                                    service_parts.append(version)
                                if extrainfo and extrainfo != 'unknown':
                                    service_parts.append(f"({extrainfo})")
                                service_detail = ' '.join(service_parts)
                                results = poc_tester.test_single_target(target, port, unique_exploits, service_detail)
                                # 将结果添加到总结果中，并标记端口信息
                                for result in results:
                                    # POC结果中的target字段已经是host:port格式，直接使用
                                    result['target_port'] = result.get('target', f"{target}:{port}")
                                    result['service_info'] = service_detail
                                all_poc_results.extend(results)
                            else:
                                print(f"[!] 没有找到可执行的POC文件")
                        else:
                            print(f"[-] 未找到 {service} {version} 相关漏洞")
                    
                    # 在所有POC测试完成后，进行统一汇总
                    if all_poc_results:
                        print("\n" + "="*80)
                        print("POC测试总体汇总")
                        print("="*80)
                        print(poc_tester.format_comprehensive_results(all_poc_results))
                    
                except KeyboardInterrupt:
                    print("\n操作被用户取消")
        else:
            print("\n[!] 未发现可识别的服务，无法进行POC测试")
    
    # 输出结果（包含POC结果）
    if args.output:
        save_results(ports,all_results, args.output, args.format, all_poc_results)
    else:
        # 直接输出到控制台
        formatted_output = format_output(ports,all_results, args.format, all_poc_results)
        print(formatted_output)
    
    print_detailed_summary(all_results)
    print(f"\n扫描耗时: {end_time - start_time:.2f} 秒")
    
    # 显示POC测试统计
    if all_poc_results:
        vulnerable_count = sum(1 for r in all_poc_results if r.get('vulnerable', False))
        if vulnerable_count > 0:
            print(f"POC验证发现 {vulnerable_count} 个确认漏洞")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n扫描被用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"程序执行出错: {e}")
        sys.exit(1)