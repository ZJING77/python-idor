"""
模型适配器的抽象基类
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List


class ModelAdapter(ABC):
    """
    模型适配器的抽象基类，定义了所有模型适配器的通用接口
    """

    def __init__(self, api_key: str, base_url: str, model: str):
        """
        初始化模型适配器

        Args:
            api_key: API密钥
            base_url: API基础URL
            model: 模型名称
        """
        self.api_key = api_key
        self.base_url = base_url
        self.model = model

    @abstractmethod
    def prepare_request_payload(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        为不同模型准备特定的请求负载

        Args:
            messages: 消息列表
            **kwargs: 额外参数

        Returns:
            准备好的请求负载
        """
        pass

    @abstractmethod
    def extract_response_content(self, response_data: Dict[str, Any]) -> str:
        """
        从不同模型的响应中提取内容

        Args:
            response_data: API响应数据

        Returns:
            提取出的内容文本
        """
        pass

    @abstractmethod
    def get_headers(self) -> Dict[str, str]:
        """
        获取适用于此模型API的请求头

        Returns:
            请求头字典
        """
        pass