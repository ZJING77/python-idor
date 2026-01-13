"""
Google Gemini模型适配器
适用于Gemini系列模型
"""
from typing import Dict, Any, List
from .base_adapter import ModelAdapter
import json


class GeminiAdapter(ModelAdapter):
    """
    Google Gemini模型适配器，适用于Gemini Pro/Flash等模型
    """

    def prepare_request_payload(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        为Google Gemini API准备请求负载
        """
        # 将消息转换为Gemini格式
        gemini_messages = []
        system_instruction = ""

        for msg in messages:
            if msg["role"] == "system":
                # Gemini使用systemInstruction字段
                system_instruction = msg["content"]
            elif msg["role"] == "user" or msg["role"] == "assistant":
                # 转换角色
                role = "user" if msg["role"] == "user" else "model"
                gemini_messages.append({
                    "role": role,
                    "parts": [{"text": msg["content"]}]
                })

        # Gemini API结构不同
        payload = {
            "contents": gemini_messages
        }

        # 构建生成配置
        generation_config = {
            "temperature": kwargs.get("temperature", 0.1),
        }

        # 最大输出令牌数
        if "max_tokens" in kwargs:
            generation_config["maxOutputTokens"] = kwargs["max_tokens"]

        payload["generationConfig"] = generation_config

        # 如果需要JSON输出格式
        if kwargs.get("response_format", {}).get("type") == "json_object":
            # 提示AI返回JSON格式
            last_message = gemini_messages[-1]["parts"][0]["text"]
            gemini_messages[-1]["parts"][0]["text"] = last_message + " 请严格按照JSON格式输出。"

        return payload

    def extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """
        从Google Gemini API响应中提取内容
        """
        return response_data["candidates"][0]["content"]["parts"][0]["text"]

    def get_headers(self) -> Dict[str, str]:
        """
        获取Google Gemini API的请求头
        """
        return {
            'Content-Type': 'application/json'
        }

    def get_full_url(self) -> str:
        """
        Gemini API使用不同的URL模式包含API密钥
        """
        return f"{self.base_url.rstrip('/')}/models/{self.model}:generateContent?key={self.api_key}"