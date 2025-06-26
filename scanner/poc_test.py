# -*- coding: utf-8 -*-
"""
POC测试模块
执行漏洞验证脚本

Author: Security Engineer
Date: 2025
"""

import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


class POCTester:
    """POC测试器"""
    
    def __init__(self, timeout=30, max_workers=5, custom_poc_path=None):
        """
        初始化POC测试器
        
        Args:
            timeout: 单个POC执行超时时间（秒）
            max_workers: 最大并发数
            custom_poc_path: 自定义POC脚本路径或目录
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.custom_poc_path = custom_poc_path
        self.results = []
        self.lock = threading.Lock()
    
    def get_custom_poc_scripts(self):
        """
        获取自定义POC脚本列表（仅Python脚本）
        
        Returns:
            list: POC脚本路径列表
        """
        if not self.custom_poc_path:
            return []
        
        poc_scripts = []
        
        if os.path.isfile(self.custom_poc_path):
            # 单个文件，检查是否为Python脚本
            if self.custom_poc_path.lower().endswith('.py'):
                poc_scripts.append(self.custom_poc_path)
        elif os.path.isdir(self.custom_poc_path):
            # 目录，仅搜索Python脚本文件
            for root, dirs, files in os.walk(self.custom_poc_path):
                for file in files:
                    if file.lower().endswith('.py'):
                        poc_scripts.append(os.path.join(root, file))
        
        return poc_scripts
    
    def extract_vuln_name(self, poc_path, service_info=None):
        """
        从POC文件中提取漏洞名称
        
        Args:
            poc_path: POC文件路径
            service_info: 服务信息
            
        Returns:
            str: 漏洞名称
        """
        try:
            # 首先尝试从POC文件内容中提取CVE信息
            cve_info = self.extract_cve_from_file(poc_path)
            if cve_info:
                return cve_info
            
            # 如果没有CVE信息，使用服务探测结果中的版本信息
            if service_info and service_info not in ['http', 'https', 'unknown']:
                return service_info
            
            # 最后从文件名提取
            filename = os.path.basename(poc_path)
            vuln_name = os.path.splitext(filename)[0]
            
            # 如果文件名只是数字，尝试从路径中获取更多信息
            if re.match(r'^\d+$', vuln_name):
                # 尝试从父目录获取信息
                parent_dir = os.path.basename(os.path.dirname(poc_path))
                if parent_dir and parent_dir != 'exploits':
                    vuln_name = f"{parent_dir}"
                else:
                    vuln_name = f"CVE-{vuln_name}"
            else:
                # 清理文件名，移除数字前缀但保留有意义的部分
                cleaned = re.sub(r'^\d+[-_]?', '', vuln_name)
                if cleaned.strip():  # 如果清理后还有内容
                    vuln_name = cleaned
                # 替换下划线和连字符为空格
                vuln_name = re.sub(r'[-_]', ' ', vuln_name)
            
            return vuln_name.strip() if vuln_name.strip() else f"POC-{os.path.splitext(filename)[0]}"
        except:
            return "Unknown Vulnerability"
    
    def extract_cve_from_file(self, poc_path):
        """
        从POC文件内容中提取CVE信息
        
        Args:
            poc_path: POC文件路径
            
        Returns:
            str: CVE信息或None
        """
        try:
            if not os.path.exists(poc_path):
                return None
                
            with open(poc_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 提取CVE信息
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            cve_matches = re.findall(cve_pattern, content, re.IGNORECASE)
            
            if cve_matches:
                # 返回第一个找到的CVE
                return cve_matches[0].upper()
            
            return None
        except:
            return None
    
    def run_poc(self, poc_path, target_host, target_port=None, service_info=None):
        """
        执行单个POC脚本
        
        Args:
            poc_path: POC脚本路径
            target_host: 目标主机
            target_port: 目标端口
            service_info: 服务信息
            
        Returns:
            dict: 执行结果
        """
        vuln_name = self.extract_vuln_name(poc_path, service_info)
        
        result = {
            'vuln_name': vuln_name,
            'poc_path': poc_path,
            'target': f"{target_host}:{target_port}" if target_port else target_host,
            'status': 'failed',
            'output': '',
            'error': '',
            'execution_time': 0,
            'vulnerable': False
        }
        
        if not os.path.exists(poc_path):
            result['error'] = f"POC文件不存在: {poc_path}"
            return result
        
        try:
            start_time = time.time()
            
            # 仅支持Python脚本
            file_ext = os.path.splitext(poc_path)[1].lower()
            
            if file_ext == '.py':
                cmd = ['python', poc_path]
            else:
                result['error'] = f"不支持的脚本类型: {file_ext}，仅支持Python脚本(.py)"
                return result
            
            # 添加目标参数
            if target_port:
                cmd.extend([target_host, str(target_port)])
            else:
                cmd.append(target_host)
            
            # 执行POC脚本
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.path.dirname(poc_path) if os.path.dirname(poc_path) else None
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
                result['output'] = stdout
                result['error'] = stderr
                result['execution_time'] = time.time() - start_time
                
                # 判断是否成功
                if process.returncode == 0:
                    result['status'] = 'success'
                    
                    # 检查输出中的漏洞指示词
                    success_indicators = [
                        'vulnerable', 'exploit', 'success', 'pwned',
                        'shell', 'backdoor', 'compromised', 'breached'
                    ]
                    
                    output_lower = stdout.lower()
                    if any(indicator in output_lower for indicator in success_indicators):
                        result['vulnerable'] = True
                else:
                    result['status'] = 'failed'
            
            except subprocess.TimeoutExpired:
                process.kill()
                result['error'] = f"POC执行超时 ({self.timeout}秒)"
                result['execution_time'] = self.timeout
        
        except Exception as e:
            result['error'] = str(e)
            result['execution_time'] = time.time() - start_time
        
        return result
    
    def run_poc_batch(self, poc_list, target_host, target_port=None, service_info=None):
        """
        批量执行POC脚本
        
        Args:
            poc_list: POC脚本路径列表
            target_host: 目标主机
            target_port: 目标端口
            service_info: 服务信息
            
        Returns:
            list: 执行结果列表
        """
        if not poc_list:
            print("[!] 没有可执行的POC脚本")
            return []
        
        print(f"\n" + "="*60)
        print(f"开始POC批量测试")
        print(f"="*60)
        print(f"目标地址: {target_host}:{target_port if target_port else 'N/A'}")
        print(f"POC数量: {len(poc_list)} 个")
        print(f"并发数量: {self.max_workers}")
        print(f"超时时间: {self.timeout}秒")
        print(f"="*60)
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_poc = {
                executor.submit(self.run_poc, poc_path, target_host, target_port, service_info): poc_path
                for poc_path in poc_list
            }
            
            # 收集结果
            for future in as_completed(future_to_poc):
                poc_path = future_to_poc[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    with self.lock:
                        self.results.append(result)
                
                except Exception as e:
                    error_result = {
                        'vuln_name': self.extract_vuln_name(poc_path, service_info),
                        'poc_path': poc_path,
                        'target': f"{target_host}:{target_port}" if target_port else target_host,
                        'status': 'error',
                        'output': '',
                        'error': str(e),
                        'execution_time': 0,
                        'vulnerable': False
                    }
                    results.append(error_result)
                    
                    with self.lock:
                        self.results.append(error_result)
        
        return results
    
    def test_single_target(self, target_host, target_port, exploits, service_info=None):
        """
        对单个目标执行POC测试
        
        Args:
            target_host: 目标主机
            target_port: 目标端口
            exploits: 漏洞信息列表
            service_info: 服务信息
            
        Returns:
            list: 测试结果
        """
        poc_files = []
        
        # 优先使用自定义POC脚本
        if self.custom_poc_path:
            custom_pocs = self.get_custom_poc_scripts()
            if custom_pocs:
                print(f"[+] 使用自定义POC脚本: {len(custom_pocs)} 个")
                poc_files.extend(custom_pocs)
        
        # 如果没有自定义POC或需要补充，使用ExploitDB目录中的Python POC
        if not poc_files or len(poc_files) < 3:  # 最多补充到3个
            for exploit in exploits:
                poc_path = exploit.get('path', '')
                if poc_path.endswith('.py'):  # 仅支持Python脚本
                    # 构建完整路径 - 使用相对于当前脚本的data目录
                    # 检查是否已经是完整路径
                    if os.path.isabs(poc_path):
                        full_path = poc_path
                    else:
                        # 获取当前脚本所在目录，然后构建data目录路径
                        current_dir = os.path.dirname(os.path.abspath(__file__))
                        data_dir = os.path.join(current_dir, "data")
                        full_path = os.path.join(data_dir, poc_path)
                        print(f"[*] 构建POC路径: {full_path}")
                    
                    if full_path and os.path.exists(full_path):
                        poc_files.append(full_path)
                        print(f"[+] 找到POC文件: {full_path}")
                    else:
                        print(f"[!] POC文件不存在: {full_path}")
        
        if not poc_files:
            print(f"[!] 没有找到可执行的POC文件")
            return []
        
        return self.run_poc_batch(poc_files, target_host, target_port, service_info)
    
    def analyze_poc_content(self, poc_path):
        """
        分析POC脚本内容
        
        Args:
            poc_path: POC脚本路径
            
        Returns:
            dict: 分析结果
        """
        analysis = {
            'language': 'unknown',
            'requires_args': False,
            'target_services': [],
            'description': '',
            'author': '',
            'cve': []
        }
        
        if not os.path.exists(poc_path):
            return analysis
        
        try:
            with open(poc_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 仅支持Python脚本
            if poc_path.endswith('.py'):
                analysis['language'] = 'python'
            else:
                analysis['language'] = 'unsupported'
                return analysis  # 不支持的脚本类型，直接返回
            
            # 检查是否需要参数（仅Python）
            if 'sys.argv' in content:
                analysis['requires_args'] = True
            
            # 提取CVE信息
            cve_pattern = r'CVE-\d{4}-\d{4,}'
            analysis['cve'] = re.findall(cve_pattern, content, re.IGNORECASE)
            
            # 提取描述和作者信息
            lines = content.split('\n')[:20]  # 只检查前20行
            for line in lines:
                line = line.strip()
                if line.startswith('#') or line.startswith('//'):
                    if 'author' in line.lower():
                        analysis['author'] = line
                    elif 'description' in line.lower() or 'exploit' in line.lower():
                        analysis['description'] = line
        
        except Exception as e:
            print(f"[-] 分析POC文件失败 {poc_path}: {e}")
        
        return analysis
    
    def format_results(self, results, show_details=True):
        """
        格式化测试结果
        
        Args:
            results: 测试结果列表
            show_details: 是否显示详细信息
            
        Returns:
            str: 格式化后的结果
        """
        if not results:
            return "[!] 没有POC测试结果"
        
        output = []
        vulnerable_count = sum(1 for r in results if r['vulnerable'])
        total_count = len(results)
        
        output.append(f"\n" + "="*80)
        output.append(f"POC测试汇总结果")
        output.append(f"="*80)
        
        # 添加快速统计表格
        success_count = sum(1 for r in results if r['status'] == 'success')
        failed_count = sum(1 for r in results if r['status'] == 'failed')
        success_rate = (success_count / total_count * 100) if total_count > 0 else 0
        vuln_rate = (vulnerable_count / total_count * 100) if total_count > 0 else 0
        
        output.append(f"📊 测试统计:")
        output.append(f"{'项目':<15} {'数量':<8} {'比例':<10}")
        output.append("-" * 35)
        output.append(f"{'总计执行':<15} {total_count:<8} {'100.0%':<10}")
        output.append(f"{'执行成功':<15} {success_count:<8} {success_rate:<10.1f}%")
        output.append(f"{'执行失败':<15} {failed_count:<8} {(100-success_rate):<10.1f}%")
        output.append(f"{'漏洞确认':<15} {vulnerable_count:<8} {vuln_rate:<10.1f}%")
        output.append(f"{'目标安全':<15} {success_count-vulnerable_count:<8} {(success_rate-vuln_rate):<10.1f}%")
        output.append("="*80)
        
        # 按状态分组
        vulnerable = [r for r in results if r['vulnerable']]
        failed = [r for r in results if not r['vulnerable'] and r['status'] == 'failed']
        success_but_safe = [r for r in results if not r['vulnerable'] and r['status'] == 'success']
        
        if vulnerable:
            output.append(f"\n[!] 确认存在的漏洞 ({len(vulnerable)} 个):")
            output.append("-" * 40)
            for i, result in enumerate(vulnerable, 1):
                output.append(f"  {i}. 漏洞名称: {result['vuln_name']}")
                output.append(f"     目标地址: {result['target']}")
                output.append(f"     POC脚本: {result['poc_path']}")
                output.append(f"     执行时间: {result['execution_time']:.2f}秒")
                output.append(f"     验证状态: 漏洞存在")
                output.append("")
        
        if success_but_safe:
            output.append(f"[+] 执行成功但未发现漏洞 ({len(success_but_safe)} 个):")
            output.append("-" * 40)
            for i, result in enumerate(success_but_safe, 1):
                output.append(f"  {i}. 漏洞名称: {result['vuln_name']}")
                output.append(f"     目标地址: {result['target']}")
                output.append(f"     POC脚本: {result['poc_path']}")
                output.append(f"     执行时间: {result['execution_time']:.2f}秒")
                output.append(f"     验证状态: 目标安全")
                output.append("")
        
        if failed:
            output.append(f"[-] 执行失败的POC: {len(failed)} 个")
        
        output.append("="*60)
        return "\n".join(output)
    
    def get_statistics(self):
        """
        获取测试统计信息
        
        Returns:
            dict: 统计信息
        """
        if not self.results:
            return {}
        
        stats = {
            'total': len(self.results),
            'vulnerable': sum(1 for r in self.results if r['vulnerable']),
            'success': sum(1 for r in self.results if r['status'] == 'success'),
            'failed': sum(1 for r in self.results if r['status'] == 'failed'),
            'avg_execution_time': sum(r['execution_time'] for r in self.results) / len(self.results)
        }
        
        stats['success_rate'] = (stats['success'] / stats['total']) * 100
        stats['vulnerability_rate'] = (stats['vulnerable'] / stats['total']) * 100
        
        return stats
    
    def clear_results(self):
        """清空测试结果"""
        with self.lock:
            self.results.clear()
    
    def format_comprehensive_results(self, all_results):
        """
        格式化综合测试结果，按端口进行统计
        
        Args:
            all_results: 所有POC测试结果列表
            
        Returns:
            str: 格式化后的综合结果
        """
        if not all_results:
            return "[!] 没有POC测试结果"
        
        output = []
        
        # 按端口分组统计
        port_stats = {}
        total_vulnerable = 0
        total_tests = len(all_results)
        
        for result in all_results:
            target_port = result.get('target_port', 'unknown')
            service_info = result.get('service_info', 'unknown')
            
            if target_port not in port_stats:
                port_stats[target_port] = {
                    'service_info': service_info,
                    'total': 0,
                    'vulnerable': 0,
                    'success': 0,
                    'failed': 0,
                    'vulnerable_details': []
                }
            
            port_stats[target_port]['total'] += 1
            
            if result['vulnerable']:
                port_stats[target_port]['vulnerable'] += 1
                total_vulnerable += 1
                port_stats[target_port]['vulnerable_details'].append(result)
            
            if result['status'] == 'success':
                port_stats[target_port]['success'] += 1
            elif result['status'] == 'failed':
                port_stats[target_port]['failed'] += 1
        
        # 总体统计
        total_success = sum(1 for r in all_results if r['status'] == 'success')
        total_failed = sum(1 for r in all_results if r['status'] == 'failed')
        success_rate = (total_success / total_tests * 100) if total_tests > 0 else 0
        vuln_rate = (total_vulnerable / total_tests * 100) if total_tests > 0 else 0
        
        output.append(f"📊 总体测试统计:")
        output.append(f"{'项目':<15} {'数量':<8} {'比例':<10}")
        output.append("-" * 35)
        output.append(f"{'总计执行':<15} {total_tests:<8} {'100.0%':<10}")
        output.append(f"{'执行成功':<15} {total_success:<8} {success_rate:<10.1f}%")
        output.append(f"{'执行失败':<15} {total_failed:<8} {(100-success_rate):<10.1f}%")
        output.append(f"{'漏洞确认':<15} {total_vulnerable:<8} {vuln_rate:<10.1f}%")
        output.append(f"{'目标安全':<15} {total_success-total_vulnerable:<8} {(success_rate-vuln_rate):<10.1f}%")
        
        # 按端口详细统计
        output.append(f"\n🎯 按端口统计 ({len(port_stats)} 个端口):")
        output.append("-" * 100)
        output.append(f"{'目标端口':<20} {'服务信息':<45} {'测试':<6} {'成功':<6} {'失败':<6} {'漏洞':<6}")
        output.append("-" * 100)
        
        for target_port, stats in sorted(port_stats.items()):
            output.append(f"{target_port:<20} {stats['service_info']:<45} {stats['total']:<6} {stats['success']:<6} {stats['failed']:<6} {stats['vulnerable']:<6}")
        
        # 详细漏洞信息
        if total_vulnerable > 0:
            output.append(f"\n🚨 确认存在的漏洞详情 ({total_vulnerable} 个):")
            output.append("=" * 80)
            
            vuln_count = 1
            for target_port, stats in sorted(port_stats.items()):
                if stats['vulnerable_details']:
                    output.append(f"\n📍 {target_port} ({stats['service_info']}):")
                    output.append("-" * 60)
                    
                    for vuln in stats['vulnerable_details']:
                        output.append(f"  {vuln_count}. 漏洞名称: {vuln['vuln_name']}")
                        output.append(f"     POC脚本: {vuln['poc_path']}")
                        output.append(f"     执行时间: {vuln['execution_time']:.2f}秒")
                        output.append(f"     验证状态: 漏洞存在")
                        if vuln.get('output'):
                            #output.append(f"     输出摘要: {vuln['output'][:100]}..." if len(vuln['output']) > 100 else f"     输出摘要: {vuln['output']}")
                            output.append(f"     输出详情: {vuln['output']}")
                        output.append("")
                        vuln_count += 1
        
        output.append("=" * 80)
        return "\n".join(output)