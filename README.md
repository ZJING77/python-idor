# Python IDOR (水平越权) 漏洞检测 Agent

一个使用Python实现的Agent水平越权（IDOR - Insecure Direct Object Reference）漏洞检测工具。

## 功能特点

- 🤖 基于大语言模型的智能漏洞检测
- 🔍 智能代码分析工具套件
- 📊 详细的结果分析和报告


## 安装

```bash
git clone <your-repo-url>
cd python-idor
pip install -r requirements.txt
```

安装`tree-sitter`解析器:

```bash
pip install tree-sitter tree-sitter-java
```

## 使用方法

### 简化配置
为了简化使用，支持多种配置方式，优先级如下：
1. 命令行参数
2. 配置文件 (config.json)
3. 环境变量

### 配置方式

#### 1. 配置文件 (config.json)
```json
{
  "api_key": "your-api-key",
  "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
  "model": "qwen3-max-2025-09-23"
}
```

### 基本使用

#### 分析整个项目
```bash
python main.py --project /path/to/java/project
```

#### 分析指定方法
```bash
python main.py \
    --project /path/to/java/project \
    --target-class com.example.Controller \
    --target-method vulnerableMethod
```

#### 查找并分析所有源点
```bash
python main.py \
    --project /path/to/java/project \
    --find-all-sources
```

### 其他参数
- `--output`: 指定输出文件路径 (默认: results.json)
- `--config`: 指定配置文件路径 (默认: config.json)
- `--model`: 指定模型 (覆盖配置文件中的设置)
- `--api-key`: 指定API密钥 (覆盖配置文件和环境变量)
- `--base-url`: 指定API基础URL (覆盖配置文件和环境变量)

# 新增大模型的切换
  python3 main.py --project /path/to/java/project --find-all-sources //默认使用qwen3

  # 使用OpenAI
  python3 main.py --project /path/to/java/project --model-type openai --model gpt-4-turbo

  # 使用Anthropic
  python3 main.py --project /path/to/java/project --model-type anthropic --model claude-3-sonnet

  # 使用Gemini
  python3 main.py --project /path/to/java/project --model-type gemini --model gemini-pro


## 核心组件

### 1. Agents
- `HorizontalPrivilegeAgent`: 核心检测Agent
- 智能调用代码分析工具
- 向LLM请求漏洞分析
- 解析LLM返回的结果

### 2. Tools (工具箱)
- `CodeAnalyzer`: 代码解析分析工具
- `SourceLocator`: 源码定位工具
- `CallGraphAnalyzer`: 调用图分析工具

### 3. 服务层
- `AnalysisService`: 协调分析逻辑
- 批量处理能力
- 结果汇总

### 4. 实用工具层
- 结果验证
- JSON格式化
- 分析报告生成

## 工作流程

1. **源码发现**: 自动扫描项目查找潜在的Web入口方法
2. **代码提取**: 提取目标方法的源代码
3. **LLM分析**: 向大模型提供代码并请求安全分析
4. **结果处理**: 解析模型输出并验证结果
5. **报告生成**: 生成详细的漏洞报告



## 代码结构

```
python-idor/
├── agents/                 # Agent层
│   ├── __init__.py
│   └── horizontal_privilege_agent.py
├── tools/                  # 工具层
│   ├── __init__.py
│   ├── code_analyzer.py
│   ├── source_locator.py
│   └── call_graph_analyzer.py
├── services/               # 服务层
│   └── __init__.py
├── utils/                  # 工具函数
│   └── __init__.py
├── prompts/                # 提示模板
│   └── horizontal_privilege_escalation_v10.md
├── tests/                  # 测试
│   └── test_agent.py
├── main.py                 # 主程序入口
├── requirements.txt        # 依赖
└── README.md
```

## 示例

检测一个典型的水平越权漏洞：

```java
@RestController
public class UserController {

    @GetMapping("/api/users/{id}")
    public User getUser(@PathVariable String id) {
        // 漏洞: 直接根据用户提供的ID查询用户信息
        // 没有验证用户是否有权限访问该ID对应的用户
        return userService.findById(id);
    }
}
```

这个Python Agent能自动识别这种模式并报告安全漏洞。

## 扩展性

- 可以轻松添加新的分析工具
- 支持多种LLM模型
- 模块化设计便于功能扩展
