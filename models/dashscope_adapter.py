"""
DashScope模型适配器
适用于阿里云通义千问系列模型
"""
from typing import Dict, Any, List
from .base_adapter import ModelAdapter


class DashScopeAdapter(ModelAdapter):
    """
    DashScope模型适配器，适用于阿里云通义千问等模型
    """

    def prepare_request_payload(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        为DashScope API准备请求负载
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.1),
        }

        # 检查是否需要JSON输出格式
        if kwargs.get("response_format", {}).get("type") == "json_object":
            # DashScope需要在用户消息中包含"json"才能使用JSON格式
            if messages and messages[-1]["role"] == "user":
                last_message = messages[-1]["content"]
                if "json" not in last_message.lower():
                    messages[-1]["content"] = last_message + " 请用JSON格式输出。"
            payload["response_format"] = {"type": "json_object"}

        return payload

    def extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """
        从DashScope API响应中提取内容
        """
        return response_data["choices"][0]["message"]["content"]

    def get_headers(self) -> Dict[str, str]:
        """
        获取DashScope API的请求头
        """
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }