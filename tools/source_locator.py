"""
源码定位工具
"""
import os
import re
from typing import List, Dict, Any
from pathlib import Path


class SourceLocator:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def locate_symbol(self, symbol_name: str, symbol_type: str = None) -> List[Dict[str, Any]]:
        """
        在项目中定位符号

        Args:
            symbol_name: 符号名称
            symbol_type: 符号类型 (class, method, etc.)

        Returns:
            符号位置信息列表
        """
        results = []

        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    file_content = self._read_file(file_path)

                    if symbol_type == "class" or not symbol_type:
                        # 查找类定义
                        class_pattern = rf'\bclass\s+{symbol_name}\b'
                        if re.search(class_pattern, file_content):
                            results.append({
                                "type": "class",
                                "name": symbol_name,
                                "file_path": file_path,
                                "location": self._find_line_numbers(file_content, symbol_name, class_pattern)
                            })

                    if symbol_type == "method" or not symbol_type:
                        # 查找方法定义
                        method_pattern = rf'\b{symbol_name}\s*\('
                        if re.search(method_pattern, file_content):
                            results.append({
                                "type": "method",
                                "name": symbol_name,
                                "file_path": file_path,
                                "location": self._find_line_numbers(file_content, symbol_name, method_pattern)
                            })

        return results

    def find_files_by_content(self, search_content: str, use_regex: bool = False) -> List[str]:
        """
        根据内容搜索文件

        Args:
            search_content: 搜索内容
            use_regex: 是否使用正则表达式

        Returns:
            匹配文件路径列表
        """
        results = []

        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(('.java', '.xml', '.yml', '.yaml', '.properties')):
                    file_path = os.path.join(root, file)
                    file_content = self._read_file(file_path)

                    if use_regex:
                        if re.search(search_content, file_content):
                            results.append(file_path)
                    else:
                        if search_content in file_content:
                            results.append(file_path)

        return results

    def find_files_by_name(self, file_name: str, use_regex: bool = False) -> List[str]:
        """
        根据文件名搜索文件

        Args:
            file_name: 文件名
            use_regex: 是否使用正则表达式

        Returns:
            匹配文件路径列表
        """
        results = []

        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if use_regex:
                    if re.match(file_name, file):
                        results.append(os.path.join(root, file))
                else:
                    if file_name in file:
                        results.append(os.path.join(root, file))

        return results

    def _read_file(self, file_path: str) -> str:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def _find_line_numbers(self, content: str, search_term: str, pattern: str) -> List[int]:
        """查找匹配项的行号"""
        lines = content.split('\n')
        line_numbers = []
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                line_numbers.append(i)
        return line_numbers