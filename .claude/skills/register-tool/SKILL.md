---
name: register-tool
description: 用户说一句话，LLM 完成把一个脚本/语言注册成 FastMCP 工具的全流程。触发："/register-tool"、"帮我注册工具"、"把这段代码变成 MCP 工具"。
---

# register-tool

用户只说话，不做文件操作。LLM 全流程代劳。

## 两条用户入口

1. **从零造**：用户描述意图 → LLM 写源码。
   例："帮我做个工具，把输入转大写"
2. **从现成**：用户贴代码 / 指已有文件 → LLM 包装。
   例："注册这个文件 test.cpp"

## 流程（LLM 执行）

1. **定语义**：从自然语言或代码确定——语言、运行命令、参数、输出。不确定就问用户一句（一次一个问题）。
2. **写源码**：在 `tools/<name>/` 写源码（或直接用用户贴的）。name = 小写短横线。
3. **编译/定命令**：
   - C++: `g++ <src>.cpp -o <name>` → command = `./tools/<name>/<name>`
   - TS: command = `npx tsx tools/<name>/<name>.ts`（或先编译）
   - Python: command = `python3 tools/<name>/<name>.py`
   - Java: command = `java -jar tools/<name>/<name>.jar`
4. **生成 tool.yaml**：只存 `name / description / command`。不存参数类型。
5. **生成 tool.py**：真实类型签名。简单参数直接注解；复杂参数（嵌套/list/自定义）写 Pydantic model，函数内序列化成 JSON 喂二进制。用 templates/tool.py.tmpl 结构，必须暴露 `register(mcp)`。
6. **手动跑二进制**：直接执行 command，确认输出符合描述。
7. **client 冒烟**：写/改 client 调用，确认 MCP 返回正确。C++ 二进制记得带 `./` 前缀。
8. **汇报**："已注册，可调用 <函数名>，参数：<类型>"。

## 熵减（可选）

若 `tools/` 已有 ≥10 个工具，注册尾附带 60 秒扫描报告：每项"现状|问题|建议|风险"。只建议，删除/合并必须用户确认。

## 硬性约定

- 工具名避开 shell 内置命令（如 `test`）→ 用 `tools/<name>/` 目录名做函数名
- 编译二进制不 commit，加 `tools/*/<name>` 到 .gitignore
- 不删用户文件
