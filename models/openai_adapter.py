"""
OpenAI模型适配器
适用于GPT系列模型
"""
from typing import Dict, Any, List
from .base_adapter import ModelAdapter


class OpenAIAdapter(ModelAdapter):
    """
    OpenAI模型适配器，适用于GPT-3.5/4系列模型
    """

    def prepare_request_payload(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        为OpenAI API准备请求负载
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.1),
        }

        # 添加response_format如果需要输出JSON
        if kwargs.get("response_format", {}).get("type") == "json_object":
            payload["response_format"] = {"type": "json_object"}

        # 添加其他可能的参数
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs["max_tokens"]
        if "top_p" in kwargs:
            payload["top_p"] = kwargs["top_p"]

        return payload

    def extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """
        从OpenAI API响应中提取内容
        """
        return response_data["choices"][0]["message"]["content"]

    def get_headers(self) -> Dict[str, str]:
        """
        获取OpenAI API的请求头
        """
        return {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }