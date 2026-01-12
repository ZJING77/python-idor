"""
调用图分析工具
"""
import os
import re
import ast
from typing import Dict, List, Any
from pathlib import Path


class CallGraphAnalyzer:
    def __init__(self, project_path: str):
        self.project_path = project_path

    def forward_call_graph(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        获取方法的前向调用图（该方法调用了哪些其他方法）

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            调用图信息
        """
        # 找到目标方法的实现
        target_file = self._find_class_file(class_fqn)
        if not target_file:
            return {"error": f"Could not find file for class {class_fqn}"}

        method_content = self._extract_method_content(target_file, method_name)
        if not method_content:
            return {"error": f"Could not find method {method_name} in class {class_fqn}"}

        # 提取方法内调用的其他方法
        calls = self._extract_method_calls(method_content)

        # 对每个调用进行分析
        detailed_calls = []
        for call in calls:
            # 尝试解析调用的完整签名
            callee_info = self._analyze_call_target(call)
            if callee_info:
                detailed_calls.append(callee_info)

        return {
            "method": f"{class_fqn}#{method_name}",
            "file_path": target_file,
            "calls_made": detailed_calls
        }

    def backward_call_graph(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        获取方法的后向调用图（哪些方法调用了该方法）

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            调用图信息
        """
        # 搜索整个项目中调用该方法的地方
        all_java_files = self._get_all_java_files()

        callers = []
        call_pattern = rf'\b{method_name}\s*\('  # 简单的调用模式

        for java_file in all_java_files:
            content = self._read_file(java_file)
            if re.search(call_pattern, content):
                # 检查是否在方法内部调用了目标方法
                methods_in_file = self._extract_method_names(content)
                for method_name_found in methods_in_file:
                    method_content = self._extract_method_content(java_file, method_name_found)
                    if method_content and re.search(call_pattern, method_content):
                        # 检查是否是直接调用
                        if f'{method_name}(' in method_content:
                            callers.append({
                                "caller_class": self._get_class_name_from_file(java_file),
                                "caller_method": method_name_found,
                                "file_path": java_file
                            })

        return {
            "target": f"{class_fqn}#{method_name}",
            "callers": callers
        }

    def _find_class_file(self, class_fqn: str) -> str:
        """根据完全限定类名找到文件"""
        class_name = class_fqn.split('.')[-1]
        package_path = class_fqn.replace('.', '/')[:-len(class_name)-1]

        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file == f"{class_name}.java":
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.project_path)
                    if package_path in rel_path.replace(os.sep, '/'):
                        return file_path

        # 如果没找到精确匹配，尝试模糊匹配
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file == f"{class_name}.java":
                    return os.path.join(root, file)

        return None

    def _extract_method_content(self, file_path: str, target_method: str) -> str:
        """提取文件中特定方法的内容"""
        content = self._read_file(file_path)

        # 匹配方法定义的模式
        method_pattern = rf'((?:public|private|protected|static|final|\s)*)\s*(?:[\w.<>]+(?:\[\])?\s+)?{target_method}\s*\([^)]*\)\s*{{'

        start_match = re.search(method_pattern, content, re.MULTILINE)
        if not start_match:
            return None

        start_pos = start_match.start()

        # 计算大括号匹配
        bracket_count = 0
        for pos in range(start_pos, len(content)):
            char = content[pos]
            if char == '{':
                bracket_count += 1
            elif char == '}':
                bracket_count -= 1
                if bracket_count == 0:
                    return content[start_pos:pos+1]

        return content[start_pos:start_pos+2000]  # fallback

    def _read_file(self, file_path: str) -> str:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return ""

    def _get_all_java_files(self) -> List[str]:
        """获取项目中所有Java文件"""
        java_files = []
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))
        return java_files

    def _extract_method_calls(self, code: str) -> List[str]:
        """从代码中提取方法调用"""
        # 简单的模式匹配方法调用：word(或object.method(
        call_pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        matches = re.findall(call_pattern, code)
        return matches

    def _analyze_call_target(self, call: str) -> Dict[str, Any]:
        """分析调用目标"""
        return {
            "callee": call,
            "resolved": False,  # 简单版本，不实际解析调用目标
            "source": "Not resolved in this simple version"
        }

    def _extract_method_names(self, content: str) -> List[str]:
        """提取所有方法名"""
        try:
            tree = ast.parse(content)
            methods = []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    methods.append(node.name)
            return methods
        except:
            # 使用正则表达式作为备选方案
            method_pattern = r'(?:public|private|protected|static|final|\s)*\s*(?:[\w.<>]+(?:\[\])?\s+)?([a-zA-Z_]\w*)\s*\([^)]*\)\s*{'
            matches = re.findall(method_pattern, content)
            return matches

    def _get_class_name_from_file(self, file_path: str) -> str:
        """从文件路径中提取类名"""
        filename = os.path.basename(file_path)
        if filename.endswith('.java'):
            return filename[:-5]  # 移除 .java 扩展名
        return filename