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
    """从环境变量获取配置 - 改为硬编码避免环境变量干扰"""
    # 直接返回 None，优先使用配置文件
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
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="水平越权漏洞检测工具")
    parser.add_argument("--project", required=True, help="项目根路径")
    parser.add_argument("--model", help="使用的大模型名称")
    parser.add_argument("--api-key", help="API密钥")
    parser.add_argument("--base-url", help="API基础URL")
    parser.add_argument("--target-class", help="指定分析的类名（完全限定名）")
    parser.add_argument("--target-method", help="指定分析的方法名")
    parser.add_argument("--find-all-sources", action="store_true", help="查找并分析所有潜在的源点")
    parser.add_argument("--output", default="results.json", help="输出文件路径，例如 /tmp/results.json")
    parser.add_argument("--config", default="config.json", help="配置文件路径，默认为 config.json")

    args = parser.parse_args()

    # 优先级: 命令行参数 > 配置文件 > 环境变量
    config = get_config_from_env()  # 从环境变量获取

    # 尝试从配置文件加载
    file_config = get_config_from_file(args.config)
    if file_config:
        config.update({k: v for k, v in file_config.items() if v is not None})

    # 命令行参数覆盖其他配置
    if args.api_key:
        config['api_key'] = args.api_key
    if args.base_url:
        config['base_url'] = args.base_url
    if args.model:
        config['model'] = args.model

    # 检查必要参数
    if not config['api_key'] or not config['base_url']:
        print("❌ 错误: 未找到API密钥和基础URL配置")
        print("   请通过以下任一方式提供配置:")
        print("   1. 环境变量: OPENAI_API_KEY 和 OPENAI_BASE_URL")
        print("   2. 配置文件: config.json")
        print("   3. 命令行参数: --api-key 和 --base-url")
        print("   \n示例配置文件内容:")
        print("   {")
        print('       "api_key": "your-api-key",')
        print('       "base_url": "https://api.example.com/v1",')
        print('       "model": "qwen3-max"')
        print("   }")
        sys.exit(1)

    print("🚀 启动水平越权漏洞检测Agent...")
    print(f"📁 项目路径: {args.project}")
    print(f"🤖 使用模型: {config['model']}")
    print(f"📊 结果将输出到: {args.output}")

    # 创建分析服务
    service = AnalysisService(
        project_path=args.project,
        model=config['model'],
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
        print("🔍 搜索项目中所有潜在的用户输入源点...")
        source_methods = service.find_user_controllable_sources()
        print(f"📊 找到 {len(source_methods)} 个潜在源点")

        if source_methods:
            print("⏳ 开始批量分析...")
            results = service.agent.analyze_sources(source_methods)
        else:
            print("⚠️ 未找到任何源点")
            return

    else:
        # 默认：分析所有带Web注解的方法
        print("🔍 分析项目中所有Web入口方法...")
        results = service.analyze_all_sources_in_project()

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