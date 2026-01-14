#!/usr/bin/env python3
"""
水平越权漏洞检测工具 - 主程序
"""
import argparse
import json
import os
from pathlib import Path
import sys

# 导入项目模块
from services import AnalysisService
from utils import AnalysisResult


def get_config_from_env():

    return {
        'api_key': None,  # 不使用环境变量
        'base_url': None,  # 不使用环境变量
        'model': None  # 不使用环境变量
    }


def get_config_from_file(config_path):
    """从配置文件获取配置"""
    if not os.path.exists(config_path):
        print(f"❌ 配置文件不存在: {config_path}")
        print("💡 请创建配置文件或设置环境变量")
        return None

    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

        # 检查是否为新格式配置
        if 'default_model_type' in config_data and 'models' in config_data:
            # 新格式: 使用指定的默认模型类型
            default_type = config_data['default_model_type']
            model_config = config_data['models'].get(default_type, {})
            return model_config
        else:
            # 兼容旧格式
            return config_data


def get_model_config_from_file(config_path, model_type: str = None):
    """从配置文件获取特定模型类型的完整配置"""
    if not os.path.exists(config_path):
        print(f"❌ 配置文件不存在: {config_path}")
        print("💡 请创建配置文件或设置环境变量")
        return None, None

    with open(config_path, 'r', encoding='utf-8') as f:
        config_data = json.load(f)

        if 'default_model_type' in config_data and 'models' in config_data:
            # 使用指定的模型类型或默认类型
            actual_type = model_type or config_data['default_model_type']
            model_config = config_data['models'].get(actual_type, {})

            if not model_config:
                print(f"❌ 配置文件中未找到模型类型 '{actual_type}' 的配置")
                return None, None

            # 添加模型类型信息
            model_config['model_type'] = actual_type
            return model_config, actual_type
        else:
            # 兼容旧格式
            config_data['model_type'] = 'dashscope'  # 默认类型
            return config_data, 'dashscope'


def main():
    parser = argparse.ArgumentParser(description="水平越权漏洞检测工具")
    parser.add_argument("--project", required=True, help="项目根路径")
    parser.add_argument("--model", help="使用的大模型名称")
    parser.add_argument("--model-type", choices=["dashscope", "openai", "anthropic", "gemini"], help="模型类型")
    parser.add_argument("--api-key", help="API密钥")
    parser.add_argument("--base-url", help="API基础URL")
    parser.add_argument("--target-class", help="指定分析的类名（完全限定名）")
    parser.add_argument("--target-method", help="指定分析的方法名")
    parser.add_argument("--find-all-sources", action="store_true", help="查找并分析所有潜在的源点")
    parser.add_argument("--output", default="results.json", help="输出文件路径，例如 /tmp/results.json")
    parser.add_argument("--config", default="config.json", help="配置文件路径，默认为 config.json")
    parser.add_argument("--max-workers", type=int, default=3, help="最大并发线程数（默认为3，避免API调用过于频繁）")

    args = parser.parse_args()

    # 获取完整模型配置
    file_config, model_type = get_model_config_from_file(args.config, args.model_type)

    # 优先级: 命令行参数 > 配置文件 > 环境变量
    config = get_config_from_env()  # 从环境变量获取

    if file_config:
        config.update({k: v for k, v in file_config.items() if v is not None})

    # 保留模型类型信息
    final_model_type = config.get('model_type', 'dashscope')

    # 命令行参数覆盖其他配置
    if args.api_key:
        config['api_key'] = args.api_key
    if args.base_url:
        config['base_url'] = args.base_url
    if args.model:
        config['model'] = args.model
    if args.model_type:
        final_model_type = args.model_type

    # 检查必要参数
    if not config.get('api_key') or not config.get('base_url') or not config.get('model'):
        print("❌ 错误: 未找到API密钥、基础URL或模型名称配置")
        print("   请通过以下任一方式提供配置:")
        print("   1. 配置文件: config.json (支持多种模型配置)")
        print("   2. 命令行参数: --api-key, --base-url, --model, --model-type")
        print("   \n示例配置文件内容:")
        print("   {")
        print('     "default_model_type": "dashscope",')
        print('     "models": {')
        print('       "dashscope": {')
        print('         "api_key": "your-dashscope-api-key",')
        print('         "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",')
        print('         "model": "qwen3-max-2025-09-23"')
        print('       },')
        print('       "openai": {')
        print('         "api_key": "your-openai-api-key",')
        print('         "base_url": "https://api.openai.com/v1",')
        print('         "model": "gpt-4-turbo-preview"')
        print('       }')
        print('     }')
        print("   }")
        sys.exit(1)

    print("🚀 启动水平越权漏洞检测Agent...")
    print(f"📁 项目路径: {args.project}")
    print(f"🤖 使用模型: {config['model']}")
    print(f"🏷️  模型类型: {final_model_type}")
    print(f"📊 结果将输出到: {args.output}")

    # 创建分析服务，现在包括模型类型参数
    service = AnalysisService(
        project_path=args.project,
        model=config['model'],
        model_type=final_model_type,
        api_key=config['api_key'],
        base_url=config['base_url']
    )

    results = []

    if args.target_class and args.target_method:
        # 分析指定的方法
        print(f"🔍 分析指定方法: {args.target_class}#{args.target_method}")
        result = service.analyze_specific_source(args.target_class, args.target_method)
        result['source_class'] = args.target_class
        result['source_method'] = args.target_method
        results = [result]

    elif args.find_all_sources:
        # 查找并分析所有源点
        results = service.analyze_user_controllable_sources(max_workers=args.max_workers)
        if not results:
            return

    else:
        # 默认：分析所有带Web注解的方法
        print("🔍 分析项目中所有Web入口方法...")
        results = service.analyze_all_sources_in_project(max_workers=args.max_workers)

    # 保存结果
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"💾 结果已保存到: {args.output}")

    # 输出摘要
    vulnerable_count = sum(1 for r in results if r.get('has_vulnerability'))
    safe_count = len(results) - vulnerable_count
    total_confidence = sum(r.get('detection_confidence', 0) for r in results if 'detection_confidence' in r)
    avg_confidence = total_confidence / len(results) if results else 0

    print("\n" + "="*50)
    print("📊 分析摘要:")
    print(f"   总共分析: {len(results)} 个方法")
    print(f"   发现漏洞: {vulnerable_count} 个")
    print(f"   安全方法: {safe_count} 个")
    print(f"   平均置信度: {avg_confidence:.2f}/10")
    print("="*50)

    # 详细输出
    print("\n📋 详细结果:")
    for result in results:
        analysis_result = AnalysisResult(
            result.get('source_class', 'Unknown'),
            result.get('source_method', 'Unknown'),
            result
        )
        print(f"  {analysis_result.summary()}")
        if analysis_result.is_vulnerable():
            print(f"    原因: {result.get('reason', 'N/A')[:100]}...")
            print(f"    解决方案: {result.get('solution', 'N/A')[:100]}...")


if __name__ == "__main__":
    main()