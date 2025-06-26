# -*- coding: utf-8 -*-
"""
漏洞搜索模块
基于ExploitDB数据库搜索相关漏洞

Author: Security Engineer
Date: 2025
"""

import csv
import os
import re
import time
from collections import defaultdict


class VulnerabilitySearcher:
    """漏洞搜索器"""
    
    def __init__(self, exploitdb_path=None):
        """
        初始化漏洞搜索器
        
        Args:
            exploitdb_path: ExploitDB数据库路径
        """
        if exploitdb_path:
            self.exploitdb_path = exploitdb_path
        else:
            # 使用相对于当前脚本的data目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.exploitdb_path = os.path.join(current_dir, "data")
        
        self.csv_file = os.path.join(self.exploitdb_path, "files_exploits.csv")
        self.exploits_dir = os.path.join(self.exploitdb_path, "exploits")
        
        # 检查数据库文件是否存在
        if not os.path.exists(self.csv_file):
            print(f"[!] ExploitDB数据库文件不存在: {self.csv_file}")
            print(f"[!] 请确保ExploitDB数据库位于项目根目录")
    
    def compare_versions(self, target_version, base_version):
        """
        比较两个版本号
        
        Args:
            target_version: 目标版本
            base_version: 基准版本
            
        Returns:
            tuple: (target_parts, base_parts)
        """
        try:
            target_parts = [int(x) for x in target_version.split('.')]
            base_parts = [int(x) for x in base_version.split('.')]
            
            # 补零使长度一致
            while len(target_parts) < len(base_parts):
                target_parts.append(0)
            while len(base_parts) < len(target_parts):
                base_parts.append(0)
            
            return target_parts, base_parts
        except:
            return [], []
    
    def version_in_range(self, target_version, version_range):
        """
        检查目标版本是否在指定的版本范围内
        
        Args:
            target_version: 目标版本
            version_range: 版本范围描述
            
        Returns:
            bool: 是否在范围内
        """
        if not target_version or not version_range:
            return False
        
        # 清理版本范围字符串
        version_range = re.sub(r'[^\d<>=., ]', '', version_range)
        conditions = re.split(r'[;,/]', version_range)
        
        for condition in conditions:
            condition = condition.strip()
            if not condition:
                continue
            
            match = re.match(r'([<>]=?)\s*([\d.]+)', condition)
            if not match:
                continue
            
            op, version = match.groups()
            
            # 使用统一的版本比较逻辑
            target_parts, check_parts = self.compare_versions(target_version, version)
            if not target_parts or not check_parts:
                continue
            
            if op == '<':
                if target_parts >= check_parts:
                    return False
            elif op == '<=':
                if target_parts > check_parts:
                    return False
            elif op == '>':
                if target_parts <= check_parts:
                    return False
            elif op == '>=':
                if target_parts < check_parts:
                    return False
            elif op == '=':
                if target_parts != check_parts:
                    return False
        
        return True
    
    def clean_title(self, title):
        """
        清理标题，在第一个破折号处截断
        
        Args:
            title: 原始标题
            
        Returns:
            str: 清理后的标题
        """
        dash_index = title.find('-')
        return title[:dash_index].strip() if dash_index != -1 else title
    
    def search_exploits(self, query, max_results=20):
        """
        搜索漏洞利用代码
        
        Args:
            query: 搜索查询字符串
            max_results: 最大结果数量
            
        Returns:
            list: 搜索结果列表
        """
        start_time = time.time()
        print(f"[*] 搜索漏洞: {query}")
        
        if not os.path.exists(self.csv_file):
            print(f"[-] ExploitDB数据库文件不存在: {self.csv_file}")
            return []
        
        # 改进的查询解析
        query_lower = query.lower()
        
        # 提取版本信息（支持更多格式）
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # x.y.z
            r'(\d+\.\d+)',       # x.y
            r'(\d+)',             # x
        ]
        
        target_version = None
        for pattern in version_patterns:
            version_match = re.search(pattern, query)
            if version_match:
                target_version = version_match.group(1)
                break
        
        # 提取服务名称（移除版本号和特殊字符）
        base_query = re.sub(r'\d+\.\d+(?:\.\d+)?', '', query_lower)
        base_query = re.sub(r'[()/\[\]]', ' ', base_query).strip()
        
        # 分割为关键词
        keywords = [word.strip() for word in base_query.split() if len(word.strip()) > 2]
        
        results = []
        
        try:
            with open(self.csv_file, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    if len(results) >= max_results:
                        break
                    
                    # 清理标题
                    clean_title = self.clean_title(row["description"])
                    
                    # 搜索字段
                    search_fields = [
                        row["description"].lower(),
                        row["file"].lower(),
                        clean_title.lower()
                    ]
                    
                    # 改进的匹配逻辑
                    match_score = 0
                    total_keywords = len(keywords)
                    
                    if total_keywords == 0:
                        continue
                    
                    # 计算关键词匹配分数
                    for keyword in keywords:
                        for field in search_fields:
                            if keyword in field:
                                match_score += 1
                                break
                    
                    # 要求至少匹配一半的关键词
                    match_threshold = max(1, total_keywords // 2)
                    
                    if match_score >= match_threshold:
                        exploit_info = {
                            "id": row["id"],
                            "title": clean_title,
                            "description": row["description"],
                            "path": row["file"],
                            "date": row["date_published"],
                            "author": row["author"],
                            "type": row["type"],
                            "platform": row["platform"],
                            "port": row.get("port", ""),
                            "verified": row.get("verified", "0") == "1"
                        }
                        
                        # 如果没有指定版本，直接添加结果
                        if not target_version:
                            results.append(exploit_info)
                        else:
                            # 检查版本范围
                            version_range_match = re.search(
                                r'([<>]=?)\s*([\d.]+)\s*(?:/|;|,|or)\s*([<>]=?)\s*([\d.]+)',
                                row["description"]
                            )
                            
                            if version_range_match or target_version in row["description"]:
                                if version_range_match:
                                    version_range = version_range_match.group(0)
                                    if self.version_in_range(target_version, version_range):
                                        exploit_info["version_match"] = True
                                        results.append(exploit_info)
                                else:
                                    exploit_info["version_match"] = False
                                    results.append(exploit_info)
        
        except Exception as e:
            print(f"[-] 搜索过程中出错: {e}")
            return []
        
        elapsed = time.time() - start_time
        print(f"[*] 搜索完成，找到 {len(results)} 个相关漏洞，耗时 {elapsed:.2f} 秒")
        
        return results
    
    def search_by_service(self, service_name, version=None, max_results=10):
        """
        根据服务名称和版本搜索漏洞
        
        Args:
            service_name: 服务名称
            version: 服务版本
            max_results: 最大结果数量
            
        Returns:
            list: 搜索结果列表
        """
        query = service_name
        if version:
            query += f" {version}"
        
        return self.search_exploits(query, max_results)
    
    def get_exploit_content(self, exploit_path):
        """
        获取漏洞利用代码内容
        
        Args:
            exploit_path: 漏洞文件路径
            
        Returns:
            str: 文件内容
        """
        full_path = os.path.join(self.exploitdb_path, exploit_path)
        
        if not os.path.exists(full_path):
            return None
        
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            print(f"[-] 读取文件失败 {full_path}: {e}")
            return None
    
    def categorize_exploits(self, exploits):
        """
        对漏洞进行分类
        
        Args:
            exploits: 漏洞列表
            
        Returns:
            dict: 分类后的漏洞
        """
        categories = defaultdict(list)
        
        for exploit in exploits:
            exploit_type = exploit.get('type', 'unknown')
            platform = exploit.get('platform', 'unknown')
            
            category = f"{exploit_type}_{platform}"
            categories[category].append(exploit)
        
        return dict(categories)
    
    def format_results(self, results, show_details=False):
        """
        格式化搜索结果
        
        Args:
            results: 搜索结果列表
            show_details: 是否显示详细信息
            
        Returns:
            str: 格式化后的结果
        """
        if not results:
            return "[!] 未找到相关漏洞"
        
        output = []
        output.append(f"\n[+] 找到 {len(results)} 个相关漏洞:\n")
        
        for i, exploit in enumerate(results, 1):
            output.append(f"{i:2d}. {exploit['title']}")
            output.append(f"    ID: {exploit['id']}")
            output.append(f"    类型: {exploit['type']}")
            output.append(f"    平台: {exploit['platform']}")
            output.append(f"    日期: {exploit['date']}")
            output.append(f"    作者: {exploit['author']}")
            output.append(f"    路径: {exploit['path']}")
            
            if show_details:
                output.append(f"    描述: {exploit['description']}")
            
            if exploit.get('verified'):
                output.append(f"    [已验证]")
            
            output.append("")
        
        return "\n".join(output)
    
    def get_poc_files(self, exploit_path):
        """
        获取POC文件列表
        
        Args:
            exploit_path: 漏洞文件路径
            
        Returns:
            list: POC文件路径列表
        """
        poc_files = []
        
        # 检查是否为Python脚本
        if exploit_path.endswith('.py'):
            full_path = os.path.join(self.exploitdb_path, exploit_path)
            if os.path.exists(full_path):
                poc_files.append(full_path)
        
        return poc_files