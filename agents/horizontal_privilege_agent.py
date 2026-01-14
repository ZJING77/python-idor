"""
水平越权漏洞检测Agent
"""
from typing import Dict, Any, Optional, List
import json
import openai
import requests
from tools.code_analyzer import CodeAnalyzer
from tools.source_locator import SourceLocator
from tools.call_graph_analyzer import CallGraphAnalyzer
import os
from pathlib import Path
from models import ModelAdapterFactory
from models.base_adapter import ModelAdapter
import concurrent.futures
import threading

class HorizontalPrivilegeAgent:
    def __init__(self,
                 project_path: str,
                 model: str = "qwen3-max",
                 model_type: str = "dashscope",
                 api_key: str = None,
                 base_url: str = None):
        """
        初始化水平越权检测Agent

        Args:
            project_path: 项目根路径
            model: 使用的模型名称
            model_type: 模型类型 ('dashscope', 'openai', 'anthropic', 'gemini')
            api_key: API密钥
            base_url: API基础URL
        """
        self.project_path = project_path
        self.model = model
        self.model_type = model_type

        # 设置API客户端
        if api_key:
            openai.api_key = api_key
        if base_url:
            openai.base_url = base_url

        # 创建模型适配器
        self.model_adapter: ModelAdapter = ModelAdapterFactory.create_adapter(
            model_type, api_key, base_url, model
        )

        # 初始化工具
        self.code_analyzer = CodeAnalyzer(project_path)
        self.source_locator = SourceLocator(project_path)
        self.call_graph_analyzer = CallGraphAnalyzer(project_path)

    def analyze_method(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        分析指定方法是否存在水平越权漏洞（使用深度分析来跟踪完整的调用链）

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            分析结果字典
        """
        try:
            print(f"🔍 开始分析: {class_fqn}#{method_name}")

            # 1. 获取当前方法源代码
            print("📝 获取原始方法源代码...")
            source_info = self.code_analyzer.get_source_code(class_fqn, method_name)
            if "error" in source_info:
                return {"error": source_info["error"]}

            source_code = source_info["source_code"]
            file_path = source_info["file_path"]

            # 2. 获取调用图，深入分析相关的Service方法
            print("🔗 分析调用图以获得完整方法链...")
            try:
                call_graph = self.call_graph_analyzer.forward_call_graph(class_fqn, method_name)
                if "error" not in call_graph:
                    # 搜索潜在的Service方法调用
                    additional_context = self._get_service_method_context(call_graph)
                    if additional_context:
                        source_code += "\n\n// 为了更全面地进行水平越权分析，还分析了以下相关方法：\n" + additional_context
            except Exception as e:
                print(f"⚠️ 获取调用图时出现错误（将继续分析原始方法）: {e}")

            # 3. 构建用户提示，包含调用链信息
            user_prompt = self._build_user_prompt_with_call_chain(file_path, source_code)

            # 4. 读取系统提示
            system_prompt = self._read_system_prompt()

            # 5. 调用LLM进行分析
            print("🤖 调用LLM进行深度分析...")
            try:
                # 使用模型适配器进行API调用
                headers = self.model_adapter.get_headers()

                # 准备请求数据
                messages = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]

                data = self.model_adapter.prepare_request_payload(
                    messages,
                    temperature=0.1,
                    response_format={"type": "json_object"}
                )

                # 处理Gemini等特殊模型的API URL
                if self.model_type == 'gemini':
                    # Gemini的API URL格式不同，包含API密钥
                    from models.gemini_adapter import GeminiAdapter
                    adapter = self.model_adapter
                    if isinstance(adapter, GeminiAdapter):
                        url = adapter.get_full_url()
                    else:
                        url = f"{self.model_adapter.base_url.rstrip('/')}/chat/completions"
                else:
                    url = f"{self.model_adapter.base_url.rstrip('/')}/chat/completions"

                response = requests.post(url, headers=headers, json=data)

                if response.status_code != 200:
                    raise Exception(f"API请求失败，状态码: {response.status_code}, 响应: {response.text}")

                response_data = response.json()
                analysis_result = self.model_adapter.extract_response_content(response_data)
            except Exception as e:
                import traceback
                print(f"❌ API调用失败: {str(e)}")
                print(f"📋 详细错误信息: {traceback.format_exc()}")
                print(f"🔧 模型: {self.model}")
                print(f"🔧 模型类型: {self.model_type}")
                print(f"🔧 基础URL: {self.model_adapter.base_url if hasattr(self.model_adapter, 'base_url') else '未设置'}")
                return {
                    "has_vulnerability": False,
                    "reason": "API调用失败",
                    "vulnerable_graph": [],
                    "solution": "请检查API配置",
                    "detection_confidence": 0,
                    "tags": ["api_error"],
                    "error_details": str(e)
                }

            # 6. 解析返回的JSON
            try:
                result = json.loads(analysis_result)
                return result
            except json.JSONDecodeError:
                print(f"解析LLM结果失败: {analysis_result}")
                # 尝试从```json```标记中提取
                import re
                json_match = re.search(r'```json\s*(.*?)\s*```', analysis_result, re.DOTALL)
                if json_match:
                    try:
                        result = json.loads(json_match.group(1))
                        return result
                    except:
                        pass

                return {
                    "has_vulnerability": False,
                    "error": f"Could not parse LLM response: {analysis_result}"
                }

        except Exception as e:
            print(f"分析过程中出现错误: {e}")
            import traceback
            traceback.print_exc()
            return {
                "has_vulnerability": False,
                "error": f"Analysis error: {str(e)}"
            }

    def _get_service_method_context(self, call_graph: Dict[str, Any]) -> str:
        """从调用图中提取Service层方法的上下文"""
        context = ""
        if "calls_made" in call_graph:
            for call in call_graph["calls_made"]:
                if "callee" in call:
                    callee_name = call["callee"]
                    # 简单判断是否可能为Service层方法
                    if ("service" in callee_name.lower() or "serivce" in callee_name.lower() or  # 兼容拼写错误
                        callee_name.lower().endswith(("manager", "impl", "service", "dao", "repository"))):
                        # 尝试获取这些方法的源代码
                        # 这里简化处理，实际中可能需要通过类名解析
                        context += f"\n// 潜在的Service方法: {callee_name}\n// 注意：需要验证此方法是否进行用户权限校验\n"
        return context

    def _build_user_prompt_with_call_chain(self, file_path: str, code: str) -> str:
        """构建包含调用链信息的用户提示"""
        return f"""
以下是需要进行水平越权漏洞分析的代码及其相关方法链：

文件路径: {file_path}

主要方法代码内容:
```java
{code}
```

请根据代码内容分析是否存在水平越权漏洞，并按照要求的JSON格式返回结果。
分析时请重点关注:
1. 用户可控参数如何影响资源访问
2. 是否缺少用户身份校验逻辑
3. 数据查询和操作是否过滤了用户权限
4. 在整个调用链中，是否有适当的权限验证（特别是在Service层）
5. 是否仅在Controller层验证了参数，但在Service层缺少权限校验（这是常见的水平越权漏洞）

请严格按照指定的JSON格式返回结果，请用JSON格式输出。
        """

    def _build_user_prompt(self, file_path: str, code: str) -> str:
        """构建用户提示信息"""
        return f"""
以下是需要进行水平越权漏洞分析的代码：

文件路径: {file_path}

代码内容:
```java
{code}
```

请根据代码内容分析是否存在水平越权漏洞，并按照要求的JSON格式返回结果。
分析时请重点关注:
1. 用户可控参数如何影响资源访问
2. 是否缺少用户身份校验逻辑
3. 数据查询和操作是否过滤了用户权限

请严格按照指定的JSON格式返回结果，请用JSON格式输出。
        """

    def _read_system_prompt(self) -> str:
        """读取系统提示"""
        prompt_path = Path(__file__).parent.parent / "prompts" / "horizontal_privilege_escalation_v10.md"
        return prompt_path.read_text(encoding="utf-8")

    def analyze_sources(self, sources_list: List[Dict[str, str]], max_workers: int = 3) -> List[Dict[str, Any]]:
        """
        多线程批量分析多个源点

        Args:
            sources_list: 源点信息列表, 格式: [{"class_fqn": "...", "method_name": "..."}]
            max_workers: 最大线程数，默认为3（避免API调用过于频繁）

        Returns:
            分析结果列表
        """
        if not sources_list:
            return []

        total = len(sources_list)
        print(f"📊 开始批量分析 {total} 个方法 (使用 {max_workers} 个线程)")

        # 创建新的适配器实例用于多线程
        # 每个线程需要独立的消息队列和请求参数，这里复用model_adapter是线程安全的
        results = []

        # 使用ThreadPoolExecutor进行多线程执行
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务并获取Future对象
            future_to_source = {
                executor.submit(self._analyze_method_with_params,
                              source['class_fqn'],
                              source['method_name']): source
                for source in sources_list
            }

            # 按完成顺序处理结果
            completed = 0
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                completed += 1

                try:
                    result = future.result()
                    result['source_class'] = source['class_fqn']
                    result['source_method'] = source['method_name']
                    results.append(result)

                    # 更新进度提示
                    vulnerability_status = "⚠️ 漏洞" if result.get('has_vulnerability') else "✅ 安全"
                    print(f"({completed}/{total}) {source['class_fqn']}#{source['method_name']} → {vulnerability_status} (置信度: {result.get('detection_confidence', 0)/10})")

                except Exception as e:
                    print(f"({completed}/{total}) 分析 {source['class_fqn']}#{source['method_name']} 时出现错误: {e}")
                    error_result = {
                        'source_class': source['class_fqn'],
                        'source_method': source['method_name'],
                        'has_vulnerability': False,
                        'error': f"分析错误: {str(e)}"
                    }
                    results.append(error_result)

        return results

    def _analyze_method_with_params(self, class_fqn: str, method_name: str) -> Dict[str, Any]:
        """
        包装方法以确保可以在多线程环境中调用

        Args:
            class_fqn: 类的完全限定名
            method_name: 方法名

        Returns:
            分析结果
        """
        return self.analyze_method(class_fqn, method_name)

    def get_tool_call_result(self, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行工具调用

        Args:
            tool_name: 工具名称
            parameters: 参数字典

        Returns:
            工具执行结果
        """
        if tool_name == "get_source_code":
            return self.code_analyzer.get_source_code(
                parameters.get("class_fqn"),
                parameters.get("method_name")
            )
        elif tool_name == "locate_symbol":
            symbol_type = parameters.get("symbol_type")
            symbol_name = parameters.get("symbol_name")
            return {"result": self.source_locator.locate_symbol(symbol_name, symbol_type)}
        elif tool_name == "forward_call_graph":
            return self.call_graph_analyzer.forward_call_graph(
                parameters.get("class_fqn"),
                parameters.get("method_name")
            )
        elif tool_name == "backward_call_graph":
            return self.call_graph_analyzer.backward_call_graph(
                parameters.get("class_fqn"),
                parameters.get("method_name")
            )
        elif tool_name == "find_file_content":
            content = parameters.get("content", "")
            use_regex = parameters.get("regexp", False)
            return {"result": self.source_locator.find_files_by_content(content, use_regex)}
        else:
            return {"error": f"Unknown tool: {tool_name}"}