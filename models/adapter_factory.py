"""
模型工厂类
根据配置创建适当的模型适配器
"""
from typing import Dict, Any
from .base_adapter import ModelAdapter
from .dashscope_adapter import DashScopeAdapter
from .openai_adapter import OpenAIAdapter
from .anthropic_adapter import AnthropicAdapter
from .gemini_adapter import GeminiAdapter


class ModelAdapterFactory:
    """
    模型适配器Factory，根据模型类型创建相应的适配器
    """
    @staticmethod
    def create_adapter(model_type: str, api_key: str, base_url: str, model: str) -> ModelAdapter:
        """
        创建指定类型的模型适配器

        Args:
            model_type: 模型类型 ('dashscope', 'openai', 'anthropic', 'gemini')
            api_key: API密钥
            base_url: API基础URL
            model: 模型名称

        Returns:
            ModelAdapter实例
        """
        if model_type.lower() == 'dashscope':
            return DashScopeAdapter(api_key, base_url, model)
        elif model_type.lower() == 'openai':
            return OpenAIAdapter(api_key, base_url, model)
        elif model_type.lower() == 'anthropic':
            return AnthropicAdapter(api_key, base_url, model)
        elif model_type.lower() == 'gemini':
            return GeminiAdapter(api_key, base_url, model)
        else:
            raise ValueError(f"不支持的模型类型: {model_type}")