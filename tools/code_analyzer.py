"""
代码分析工具 - 使用AST和tree-sitter进行代码分析
"""
import ast
import astor
import os
import re
from typing import List, Dict, Any, Optional
import tree_sitter
from tree_sitter import Language, Parser

class CodeAnalyzer:
    def __init__(self, project_path: str):
        """
        初始化代码分析器
        Args:
            project_path: 项目根路径
        """
        self.project_path = project_path
        self.parser = None
        self.setup_parser()

    def setup_parser(self):
        """设置Parser"""
        try:
            import tree_sitter_java
            # 修复Tree-sitter API使用
            JAVA_LANGUAGE = Language(tree_sitter_java.language(), "java")
            self.parser = Parser()
            self.parser.set_language(JAVA_LANGUAGE)
        except (ImportError, TypeError):
            print("Warning: tree_sitter_java not available, using basic AST")
            self.parser = None

    def get_source_code(self, class_fqn: str, method_name: Optional[str] = None) -> Dict[str, Any]:
        """
        获取类或方法的源代码

        Args:
            class_fqn: 完全限定类名 (e.g., com.example.MyClass)
            method_name: 可选，方法名

        Returns:
            包含源代码和相关信息的字典
        """
        class_name = class_fqn.split('.')[-1]
        file_path = self._find_class_file(class_fqn)

        if not file_path:
            return {"error": f"Could not find class file for {class_fqn}"}

        code_content = self._read_file(file_path)

        if method_name and self.parser:
            method_code = self._extract_method_code_ast(code_content, method_name)
            return {
                "file_path": file_path,
                "language": "java",
                "class_fqn": class_fqn,
                "method_name": method_name,
                "source_code": method_code,
                "imports": self._extract_imports(code_content)
            }
        elif method_name:
            # 如果parser不可用，使用正则表达式提取方法
            method_code = self._extract_method_code_regex(code_content, method_name)
            return {
                "file_path": file_path,
                "language": "java",
                "class_fqn": class_fqn,
                "method_name": method_name,
                "source_code": method_code,
                "imports": self._extract_imports(code_content)
            }
        else:
            # 返回整个类
            return {
                "file_path": file_path,
                "language": "java",
                "class_fqn": class_fqn,
                "source_code": code_content,
                "imports": self._extract_imports(code_content)
            }

    def _find_class_file(self, class_fqn: str) -> Optional[str]:
        """根据FQN找出对应的文件路径"""
        class_name = class_fqn.split('.')[-1]
        package_path = class_fqn.replace('.', '/')[:-len(class_name)-1]  # 移除类名部分

        # 搜索项目中的Java文件
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file == f"{class_name}.java":
                    file_path = os.path.join(root, file)
                    # 检查包路径是否匹配
                    rel_path = os.path.relpath(file_path, self.project_path)
                    if package_path in rel_path.replace(os.sep, '/'):
                        return file_path

        # 如果没找到精确匹配，尝试模糊匹配
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file == f"{class_name}.java":
                    return os.path.join(root, file)

        return None

    def _read_file(self, file_path: str) -> str:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            return f"Error reading file: {str(e)}"

    def _extract_imports(self, content: str) -> List[str]:
        """提取所有import语句"""
        import_pattern = r'^\s*import\s+([a-zA-Z0-9._*]+);'
        matches = re.findall(import_pattern, content, re.MULTILINE)
        return matches

    def _extract_method_code_ast(self, content: str, method_name: str) -> str:
        """使用AST提取方法代码"""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == method_name:
                    # 计算起始和结束行
                    start_line = node.lineno - 1
                    end_line = node.end_lineno if hasattr(node, 'end_lineno') else node.lineno + 10  # fallback
                    lines = content.split('\n')

                    # 找到方法的完整代码块（考虑嵌套的}）
                    code_block_lines = []
                    bracket_count = 0
                    in_method = False
                    for i, line in enumerate(lines):
                        if start_line <= i <= end_line and method_name in line and '{' in line:
                            in_method = True
                            bracket_count = 1
                            if '{' in line:
                                bracket_count += line.count('{') - line.count('}')
                        elif in_method:
                            if '{' in line:
                                bracket_count += line.count('{')
                            if '}' in line:
                                bracket_count -= line.count('}')
                            code_block_lines.append(line)
                            if bracket_count <= 0:
                                break
                        elif i == start_line:
                            code_block_lines.append(line)

                    # 基本的AST方法提取
                    lines = content.split('\n')
                    start_idx = node.lineno - 1
                    end_idx = min(node.end_lineno, len(lines)) if hasattr(node, 'end_lineno') else start_idx + 20
                    return '\n'.join(lines[start_idx:end_idx])

            # 如果没找到方法，返回整个内容
            return content
        except:
            return self._extract_method_code_regex(content, method_name)

    def _extract_method_code_regex(self, content: str, method_name: str) -> str:
        """使用正则表达式提取方法代码"""
        # 匹配public/private/protected返回类型方法名(参数列表){...}的模式
        # 处理嵌套的大括号
        method_pattern = r'((?:public|private|protected|static|final|\s)*)\s*(?:[\w.<>]+(?:\[\])?\s+)?%s\s*\([^)]*\)\s*{' % method_name

        # 找到方法开始位置
        start_match = re.search(method_pattern, content, re.MULTILINE)
        if not start_match:
            return f"Method {method_name} not found in provided content"

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

        # 如果没有正确闭合，返回部分内容
        return content[start_pos:start_pos+2000]

    def get_call_graph(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        获取方法的调用图

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            包含调用关系的字典
        """
        file_path = self._find_class_file(class_fqn)
        if not file_path:
            return {"error": f"Could not find class file for {class_fqn}"}

        content = self._read_file(file_path)

        # 使用正则表达式提取方法内部的调用
        # 找到指定方法的代码
        method_code = self._extract_method_code_regex(content, method_name)
        method_ast = ast.parse(method_code) if method_code else None

        calls = []
        if method_ast:
            for node in ast.walk(method_ast):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.append({
                            "callee_name": node.func.id,
                            "line_number": node.lineno if hasattr(node, 'lineno') else 0,
                            "args_count": len(node.args)
                        })
                    elif isinstance(node.func, ast.Attribute):
                        calls.append({
                            "callee_name": f"{node.func.value.id}.{node.func.attr}" if hasattr(node.func.value, 'id') else node.func.attr,
                            "line_number": node.lineno if hasattr(node, 'lineno') else 0,
                            "args_count": len(node.args)
                        })

        return {
            "method_name": method_name,
            "class_fqn": class_fqn,
            "file_path": file_path,
            "calls": calls
        }