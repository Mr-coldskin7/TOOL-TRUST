# tool-trust

**正在建立中的项目。** 

目标：让软件工具的行为可验证、可信任，并且可以打通cli tool和mcp的载体软件

## 为什么做

cli tool虽然方便，但是其一各个写的标准不同，像是read_file一个最基本的工具，claude code和codex都会有所差异，并且cli在很长的发展时间里，是给人看的，他的返回原没有mcp的json一样那么讨agent喜欢
开始想做一个简单的cli agent工具与mcp的互相转换，但是慢慢意识到如果还是这样做的话他只会是个玩具或者不成熟的项目，即使足够成熟，从产品的角度上来看也是用处不大，所以我打算加一些安全机制
工具正越来越多地被 agent / LLM 直接调用，但没有任何机制能证明一个工具"宣称做什么"和"实际做什么"是一致的。本项目的方向是：

- 在 Docker 沙箱里用 strace 观察工具的真实行为
- 与工具自己声明的行为清单（manifest）对账
- 产出机器可读的 JSON attestation report
- agent 在调用工具之前先读这份报告，决定信不信它

不采用"信用评分"方案（依赖声誉和生态，冷启动即死），而采用"行为证明"方案（每次运行产出一份报告，第一个工具就能产出第一份）。

## 当前状态（2026-08）

当前阶段不是写 attestation 本体，而是先打通：**任意语言/脚本的工具如何被 MCP agent 调用**。这条管道走通后，attestation 逻辑才有承载它的 MCP 载体。

已完成：

- ✅ FastMCP 概念打通：server 组件、Pydantic 自动 schema、工具参数限制
- ✅ C++ 二进制 → FastMCP 工具（subprocess 包装）
- ✅ `register-tool` 项目 skill：用户说一句话，LLM 完成"源码 → 编译 → 包装 → 验证"全流程
- ✅ `tools/` 目录即注册表，`server.py` 启动自动加载
- ✅ 第一个工具 `cpp-test`（C++ 转大写），端到端验证通过

## 快速开始

```bash
uv sync
uv run python server.py     # 终端 1，起 server（port 8000）
uv run python client.py     # 终端 2，调 cpp_test 工具
```

测试：

```bash
uv run --with pytest pytest tests/ -v
```

## 注册新工具

跟 Claude 说一句话即可，不用碰文件系统：

```
/register-tool 帮我做个工具，把输入转大写
```

LLM 会代你完成：写源码 → 编译 → 生成 wrapper + manifest → 冒烟验证。详细流程见 `.claude/skills/register-tool/SKILL.md`。

## 目录结构

```
.claude/skills/register-tool/   # 注册 skill：指令 + 模板
tools/                          # 注册表 = 目录，每工具一个子目录
  cpp-test/                     # 示例：C++ 转大写
    test.cpp                    #   源码
    test                        #   编译产物（gitignore）
    tool.py                     #   FastMCP wrapper
    tool.yaml                   #   manifest（只存语义，不存类型）
server.py                       # 自动加载 tools/*/tool.py
client.py                       # 冒烟客户端
docs/superpowers/               # 设计 spec + 实施计划
```

## 路线图

- [ ] 第二个语言工具（TS / Python / Java），验证 register-tool 通用性
- [ ] manifest 全量驱动：加工具只加 `tool.yaml`，Python 层零改动
- [ ] 熵减：`tools/` 工具健康扫描（去重/分类/归档），LLM 建议、用户确认
- [ ] attestation 本体：Docker 沙箱 + strace 观察 vs manifest 对账，产出 JSON attestation report
- [ ] AGENTS.md 变体，让 Codex 也能跑注册流程
