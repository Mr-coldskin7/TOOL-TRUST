# register-tool Skill 设计

日期：2026-08-12
状态：设计草案（待 review）
项目：tool-trust

## 背景

tool-trust 是 toolguard 工具行为可信度证明产品（见 knowledge base `tool-behavior-attestation`）。当前阶段：打通 FastMCP——让各种语言/脚本的真实可执行文件，能被 MCP agent 调用。

已跑通手动路径：C++ 二进制 `test` → FastMCP server 用 `subprocess.run` 调用 → client 拿 stdout。本设计把这条路径产品化：做成项目 skill，LLM 代用户完成注册全流程。

## 目标

用户加一个新工具，体验 = **说一句话**。用户不碰文件系统、不编译、不写 wrapper。

## 核心设计

### 目录结构（目录即注册表）

```
.claude/skills/register-tool/
  SKILL.md                  # LLM 执行的注册流程
  templates/
    tool.py.tmpl            # FastMCP wrapper 模板
    tool.yaml.tmpl          # manifest 模板

tools/                      # 注册表 = 文件目录，无独立存储
  <name>/
    <源码>                   # LLM 写或用户贴，如 test.cpp
    <二进制>                 # 编译产物，如 test
    tool.py                 # 生成：FastMCP wrapper
    tool.yaml               # 生成：manifest（只存语义，不存类型）

server.py                   # 一次写死，自动加载 tools/*/tool.py
```

### 触发与流程（用户只说话，LLM 全干）

用户入口两种：
- 从零造：`/register-tool 帮我做个工具，把输入转大写`
- 从现成：`/register-tool` + 贴代码 / 指已有文件

LLM 执行：
1. 从自然语言或代码定语义（语言、运行命令、参数、输出）
2. 写 `tools/<name>/` 源码（或直接用用户贴的）
3. 编译（C++/Go）或确认解释器命令（TS/Python/Java）
4. 生成 `tool.py`：真实类型签名 + `subprocess.run`
5. 生成 `tool.yaml`：只存 `name / description / command`
6. 手动跑二进制验证
7. client 冒烟测试，确认返回
8. 汇报："已注册，可调用 run_xxx"

### server.py 自动加载（加工具不改 Python）

```python
import importlib, pathlib
from fastmcp import FastMCP

mcp = FastMCP("toolhub")

for p in pathlib.Path("tools").glob("*/tool.py"):
    mod = importlib.import_module(f"tools.{p.parent.name}.tool")
    mod.register(mcp)

mcp.run(transport="http", port=8000)
```

约定：每个 `tools/<name>/tool.py` 必须暴露 `register(mcp)` 函数。当前 glob `*/tool.py` 只覆盖一层；演进到按域分子目录时改为 `**/tool.py` 递归。

### 类型处理

- **简单参数**：LLM 读源码手写 Python 类型注解，FastMCP/Pydantic 自动生成 schema。
- **复杂参数**（嵌套、自定义类、list）：LLM 手写 Pydantic model。YAML 不表达类型，类型只归 Python 注解，避免双份声明漂移。
- **CLI 传输限制**：subprocess 参数只能是字符串。结构化数据 → 工具签名收 Pydantic model，函数内序列化成 JSON 喂二进制。

### tool.yaml 职责（只存语义）

```yaml
name: cpp-test
description: 把输入消息转大写输出
command: ./tools/cpp-test/test
```

不存参数类型——那是 tool.py 的事。避免 YAML 与 Python 注解重复声明、互相漂移。

### 熵减（可选步骤，不是独立系统）

注册流程尾部，仅当 `tools/` 已有 ≥10 个工具时附带：

```
1. LLM 扫描 tools/，生成熵减报告
   每项：现状 | 问题 | 建议动作 | 风险
2. 用户看报告
3. 用户确认执行哪些
4. LLM 只动确认的，跑验证
```

动作类型：去重 / 分类 / 归档 / 体检。删除合并必须用户确认（不可逆），LLM 只建议不自动删。阈值 10 以下不做，避免骚扰。

### 目录规模演进（不提前拆）

- 现在：单 server + `tools/` 目录 = 注册表
- 多工具：`tools/` 按域分子目录（`tools/text/`、`tools/analyze/`），server 递归扫，仍单注册表
- 产品期：按域拆多个 MCP server，一个 server = 一个域，agent 按需连接

不另建数据库存工具清单——目录即注册表，独立存储必然与目录漂移。

## 不做什么（YAGNI）

- 不做运行时动态签名（`__signature__` 黑魔法）。签名由 LLM dev-time 手写，产物是普通可审代码。
- 不做用户手动填 wrapper 流程。LLM 全代劳。
- 不做独立熵减系统。只在注册时顺带，阈值 10。
- 不做多个 MCP server。现在工具数未到。

## 验证标准

1. 项目里有 `.claude/skills/register-tool/SKILL.md` + templates
2. 用户对 Claude 说"注册一个转大写工具"，LLM 全流程产出 `tools/to-upper/`（源码+二进制+tool.py+tool.yaml）
3. `server.py` 启动扫到该工具
4. client 调用返回正确输出
5. 用户全程没碰文件系统

## 后续（不在本 spec）

- AGENTS.md 变体：让 Codex 也能跑（用户常用则抽摘要）
- manifest → strace 对账：toolguard attestation 本体
