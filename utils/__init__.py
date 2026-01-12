"""
工具和辅助函数
"""
import json
from typing import Dict, Any


def sanitize_json_response(text: str) -> str:
    """
    从LLM响应中提取JSON
    """
    # 移除开头和结尾的```标记
    import re
    # 匹配 ```json ... ``` 或 ``` ... ```
    match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def validate_vulnerability_result(result: Dict[str, Any]) -> bool:
    """
    验证漏洞分析结果的格式是否正确
    """
    required_keys = ["has_vulnerability", "reason", "solution", "detection_confidence"]
    return all(key in result for key in required_keys)


class AnalysisResult:
    def __init__(self, source_class: str, source_method: str, result: Dict[str, Any]):
        self.source_class = source_class
        self.source_method = source_method
        self.result = result

    def is_vulnerable(self) -> bool:
        return self.result.get("has_vulnerability", False)

    def confidence(self) -> int:
        return self.result.get("detection_confidence", 0)

    def summary(self) -> str:
        status = "漏洞" if self.is_vulnerable() else "安全"
        confidence = self.confidence()
        return f"{self.source_class}#{self.source_method}: {status} (置信度: {confidence}/10)"