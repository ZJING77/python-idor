"""
服务层 - 包含分析逻辑的协调
"""
from agents.horizontal_privilege_agent import HorizontalPrivilegeAgent
from tools.source_locator import SourceLocator
import os
import re
from typing import List, Dict, Any


class AnalysisService:
    def __init__(self, project_path: str, model: str = "qwen3-max", model_type: str = "dashscope", api_key: str = None, base_url: str = None):
        """
        初始化分析服务

        Args:
            project_path: 项目路径
            model: 使用的模型
            model_type: 模型类型 ('dashscope', 'openai', 'anthropic', 'gemini')
            api_key: API密钥
            base_url: API基础URL
        """
        self.project_path = project_path
        self.agent = HorizontalPrivilegeAgent(project_path, model, model_type, api_key, base_url)
        self.source_locator = SourceLocator(project_path)

    def analyze_all_sources_in_project(self, source_annotations: List[str] = None) -> List[Dict[str, Any]]:
        """
        分析项目中的所有源点

        Args:
            source_annotations: 搜索的注解列表，例如["@PostMapping", "@GetMapping"]

        Returns:
            所有分析结果的列表
        """
        if source_annotations is None:
            # 默认搜索常见的Web方法注解
            source_annotations = ["@PostMapping", "@GetMapping", "@PutMapping", "@DeleteMapping", "@RequestMapping"]

        print("🔍 查找项目中的潜在入口方法...")

        # 查找所有含有指定注解的方法
        sources = self._find_sources_with_annotations(source_annotations)

        if not sources:
            print("⚠️ 未找到任何带注解的方法")
            return []

        print(f"📊 发现 {len(sources)} 个待分析的方法")

        # 批量分析
        results = self.agent.analyze_sources(sources)

        return results

    def _find_sources_with_annotations(self, annotations: List[str]) -> List[Dict[str, str]]:
        """查找带有特定注解的方法"""
        sources = []
        java_files = []

        # 找到所有Java文件
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(os.path.join(root, file))

        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 提取文件中的类名
                class_matches = []
                class_pattern = r'(?:public|private|protected)\s+class\s+(\w+)'
                class_match = re.search(class_pattern, content)
                if class_match:
                    class_name = class_match.group(1)

                    # 计算包名（基于文件路径，处理多模块项目结构）
                    rel_path = os.path.relpath(java_file, self.project_path)
                    # 寻找 "src/main/java" 模式，这表示这是标准的Maven结构
                    parts = rel_path.split(os.sep)
                    java_start_idx = -1
                    for i, part in enumerate(parts):
                        if i < len(parts) - 1 and part == "src" and parts[i+1] == "main":
                            if i + 2 < len(parts) and parts[i+2] == "java":
                                java_start_idx = i + 3
                                break

                    if java_start_idx != -1:
                        # Maven项目结构: some/parent/src/main/java/com/package/Class.java
                        package_parts = ".".join(parts[java_start_idx:-1])  # 不包含类名.java文件部分
                        full_class_name = f"{package_parts}.{class_name}"
                    else:
                        # 其他结构，使用相对路径
                        dir_part = os.path.dirname(rel_path).replace(os.sep, '.')
                        if dir_part:
                            full_class_name = f"{dir_part}.{class_name}"
                        else:
                            full_class_name = class_name

                    # 查找该类中的方法注解
                    for annotation in annotations:
                        # 查找形如 @annotation(参数) methodName(参数) 的模式
                        method_pattern = r'%s\s*(?:\([^}]*?\))?\s*\n\s*(?:public|private|protected|static\s+)*\s*\w+\s+(\w+)\s*\(' % annotation
                        method_matches = re.findall(method_pattern, content)

                        for method_name in method_matches:
                            sources.append({
                                "class_fqn": full_class_name,
                                "method_name": method_name
                            })

            except Exception as e:
                print(f"处理文件 {java_file} 时出错: {e}")

        return sources

    def analyze_specific_source(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        分析特定的方法

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            分析结果
        """
        return self.agent.analyze_method(class_fqn, method_name)

    def find_user_controllable_sources(self) -> List[Dict[str, str]]:
        """
        寻找用户可控的输入源点，通常指Controller中的方法

        Returns:
            用户可控方法列表
        """
        controller_sources = []
        java_files = []

        # 首先找到所有Controller类
        controller_files = []
        for root, dirs, files in os.walk(self.project_path):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # 查找@Controller或@RestController注解
                        if '@Controller' in content or '@RestController' in content:
                            controller_files.append(file_path)

        for controller_file in controller_files:
            try:
                with open(controller_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # 提取类名
                class_pattern = r'(?:public|private|protected)\s+class\s+(\w+)'
                class_match = re.search(class_pattern, content)
                if not class_match:
                    continue

                class_name = class_match.group(1)

                # 计算包名（基于文件路径，处理多模块项目结构）
                rel_path = os.path.relpath(controller_file, self.project_path)
                # 寻找 "src/main/java" 模式，这表示这是标准的Maven结构
                parts = rel_path.split(os.sep)
                java_start_idx = -1
                for i, part in enumerate(parts):
                    if i < len(parts) - 1 and part == "src" and parts[i+1] == "main":
                        if i + 2 < len(parts) and parts[i+2] == "java":
                            java_start_idx = i + 3
                            break

                if java_start_idx != -1:
                    # Maven项目结构: some/parent/src/main/java/com/package/Class.java
                    package_parts = ".".join(parts[java_start_idx:-1])  # 不包含类名.java文件部分
                    full_class_name = f"{package_parts}.{class_name}"
                else:
                    # 其他结构，使用相对路径
                    dir_part = os.path.dirname(rel_path).replace(os.sep, '.')
                    if dir_part:
                        full_class_name = f"{dir_part}.{class_name}"
                    else:
                        full_class_name = class_name

                # 查找Web方法注解
                web_annotations = ["@PostMapping", "@GetMapping", "@PutMapping", "@DeleteMapping", "@RequestMapping"]
                for annotation in web_annotations:
                    method_pattern = r'%s\s*(?:\([^(]*\))?(?:\s*//.*?)*\s*\n\s*(?:public|private|protected|static\s+)*\s*[\w<>\[\].,]*\s+(\w+)\s*\(' % annotation
                    method_matches = re.findall(method_pattern, content)

                    for method_name in method_matches:
                        controller_sources.append({
                            "class_fqn": full_class_name,
                            "method_name": method_name
                        })

            except Exception as e:
                print(f"处理Controller文件 {controller_file} 时出错: {e}")

        return controller_sources