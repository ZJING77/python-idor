"""
Anthropic模型适配器
适用于Claude系列模型
"""
from typing import Dict, Any, List
from .base_adapter import ModelAdapter
import json


class AnthropicAdapter(ModelAdapter):
    """
    Anthropic模型适配器，适用于Claude 2.1/3系列模型
    """

    def prepare_request_payload(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        为Anthropic API准备请求负载
        """
        # Anthropic API要求system消息单独处理
        system_content = ""
        user_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_content = msg["content"]
            elif msg["role"] == "user":
                user_messages.append(msg)
            elif msg["role"] == "assistant":
                user_messages.append(msg)

        # Anthropic要求消息必须是user和assistant交替，所以将system合并到第一个user消息
        if user_messages and system_content:
            user_messages[0]["content"] = f"{system_content}\n\n{user_messages[0]['content']}"
            system_content = ""

        # 如果没有system消息，确保第一条消息是user
        if not user_messages:
            user_messages.append({"role": "user", "content": "你好，请回复。"})

        payload = {
            "model": self.model,
            "messages": user_messages,
            "temperature": kwargs.get("temperature", 0.1),
        }

        # 设置system字段（如果有的话，且第一条消息不是assistant）
        if system_content:
            payload["system"] = system_content

        # 添加最大输出标记数
        payload["max_tokens"] = kwargs.get("max_tokens", 4096)

        # 添加response_format如果需要输出JSON
        if kwargs.get("response_format", {}).get("type") == "json_object":
            # Anthropic的JSON模式稍微不同
            payload["messages"].append({"role": "user", "content": "请严格按照JSON格式输出你的回复。"})

        return payload

    def extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """
        从Anthropic API响应中提取内容
        """
        return response_data["content"][0]["text"] if response_data["content"] else ""

    def get_headers(self) -> Dict[str, str]:
        """
        获取Anthropic API的请求头
        """
        return {
            'x-api-key': self.api_key,
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01'
        }