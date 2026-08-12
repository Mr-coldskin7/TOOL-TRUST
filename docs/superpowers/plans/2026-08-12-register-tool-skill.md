# register-tool Skill 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 做一个 `register-tool` 项目 skill，用户说一句话即可让 LLM 完成"源码→编译→FastMCP wrapper→manifest→验证"全流程，server 自动加载。

**Architecture:** `tools/` 目录即注册表。每个 `tools/<name>/` 含源码、二进制、`tool.py`（暴露 `register(mcp)`）、`tool.yaml`（只存语义）。`server.py` 启动时 glob 扫描 `tools/*/tool.py` 并 importlib 加载。skill 本体是 `.claude/skills/register-tool/SKILL.md` + 两个模板文件。

**Tech Stack:** FastMCP、Python 3.12+、uv、C++ (g++) 作示例工具语言。

## Global Constraints

- Python 3.12+；依赖只有 `fastmcp`（已有）
- 每个 `tools/<name>/tool.py` 必须暴露 `register(mcp: FastMCP) -> None`
- `tool.yaml` 只存 `name / description / command`，不存参数类型（类型归 Python 注解）
- subprocess 参数只能是字符串；结构化数据 → Pydantic model 签名 + 函数内序列化 JSON
- 运行：`uv run python server.py`（repo 根目录）
- 不删用户已有文件（`main.py`、`client.py` 保留）

---

### Task 1: server.py 自动加载器

**Files:**
- Create: `server.py`
- Test: `tests/test_server.py`

**Interfaces:**
- Produces: `load_tools(mcp: FastMCP, tools_dir: pathlib.Path) -> int` — 扫 `tools_dir/*/tool.py`，importlib 加载并调 `register(mcp)`，返回加载数。被 Task 5 的端到端验证用。

- [ ] **Step 1: 写失败测试**

```python
# tests/test_server.py
import importlib, sys, pathlib, subprocess
from fastmcp import FastMCP
import server

def test_load_tools_registers_each_tool(tmp_path):
    tool_dir = tmp_path / "tools" / "demo"
    tool_dir.mkdir(parents=True)
    (tool_dir / "tool.py").write_text(
        "from fastmcp import FastMCP\n"
        "def register(mcp: FastMCP) -> None:\n"
        "    @mcp.tool\n"
        "    def demo() -> str:\n"
        "        '''demo tool'''\n"
        "        return 'ok'\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        mcp = FastMCP("test")
        count = server.load_tools(mcp, tmp_path / "tools")
        assert count == 1
    finally:
        sys.path.remove(str(tmp_path))
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /Users/lishanyi/Documents/projects/tool-trust && uv run pytest tests/test_server.py -v`
Expected: FAIL，`ModuleNotFoundError: No module named 'server'`

- [ ] **Step 3: 写实现**

```python
# server.py
import importlib
import pathlib
from fastmcp import FastMCP


def load_tools(mcp: FastMCP, tools_dir: pathlib.Path = pathlib.Path("tools")) -> int:
    """扫描 tools/*/tool.py，import 并调用其 register(mcp)。返回加载数。"""
    count = 0
    for p in sorted(tools_dir.glob("*/tool.py")):
        module_path = f"{tools_dir.name}.{p.parent.name}.tool"
        mod = importlib.import_module(module_path)
        mod.register(mcp)
        count += 1
    return count


if __name__ == "__main__":
    mcp = FastMCP("toolhub")
    n = load_tools(mcp)
    print(f"loaded {n} tool(s)")
    mcp.run(transport="http", port=8000)
```

- [ ] **Step 4: 跑测试确认通过**

Run: `uv run pytest tests/test_server.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add server.py tests/test_server.py
git commit -m "feat: server auto-loads tools/*/tool.py as FastMCP tools"
```

---

### Task 2: 模板文件

**Files:**
- Create: `.claude/skills/register-tool/templates/tool.py.tmpl`
- Create: `.claude/skills/register-tool/templates/tool.yaml.tmpl`

**Interfaces:**
- Produces: 两个模板，Task 3 的 SKILL.md 引用它们。

- [ ] **Step 1: 写 tool.py 模板**

```python
# .claude/skills/register-tool/templates/tool.py.tmpl
import subprocess
from fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    """把二进制包装成 FastMCP 工具。命令与参数来自 tool.yaml。"""
    @mcp.tool
    def {{ tool_name }}({{ params }}) -> str:
        """{{ description }}"""
        result = subprocess.run(
            [{{ command_literal }}, *{{ args_list }}],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"exit {result.returncode}")
        return result.stdout.strip()
```

- [ ] **Step 2: 写 tool.yaml 模板**

```yaml
# .claude/skills/register-tool/templates/tool.yaml.tmpl
name: {{ name }}
description: {{ description }}
command: {{ command }}
```

- [ ] **Step 3: 目检模板**

Run: `cat .claude/skills/register-tool/templates/*.tmpl`
Expected: 两文件存在，占位符用 `{{ }}` 包裹，与 SKILL.md 引用一致

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/register-tool/templates/
git commit -m "feat: register-tool templates for tool.py and tool.yaml"
```

---

### Task 3: SKILL.md 指令

**Files:**
- Create: `.claude/skills/register-tool/SKILL.md`

**Interfaces:**
- Consumes: Task 2 的两个模板。
- Produces: LLM 注册全流程指令。含"从零造"和"从现成"两条用户入口、编译、验证、汇报。

- [ ] **Step 1: 写 SKILL.md**

```markdown
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
```

- [ ] **Step 2: 目检 SKILL.md**

Run: `cat .claude/skills/register-tool/SKILL.md | head -5`
Expected: frontmatter `name: register-tool` 存在

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/register-tool/SKILL.md
git commit -m "feat: register-tool skill with full LLM registration flow"
```

---

### Task 4: 首个示例工具 cpp-test + 端到端验证

**Files:**
- Create: `tools/cpp-test/tool.py`
- Create: `tools/cpp-test/tool.yaml`
- Modify: `.gitignore`（加 `tools/*/cpp-test` 二进制）
- Test: `tests/test_e2e.py`

**Interfaces:**
- Consumes: Task 1 的 `server.load_tools`、`tools/cpp-test/tool.py` 的 `register(mcp)`。
- Produces: 证明"目录即注册表"端到端可用。验证标准见 spec 第 4 条。

- [ ] **Step 1: 写工具包装（复用已编译的 test 二进制）**

`tools/cpp-test/tool.py`:
```python
import subprocess
from fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.tool
    def cpp_test(message: str) -> str:
        """把输入消息转大写输出（C++ 二进制）"""
        result = subprocess.run(
            ["./tools/cpp-test/test", message],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"exit {result.returncode}")
        return result.stdout.strip()
```

`tools/cpp-test/tool.yaml`:
```yaml
name: cpp-test
description: 把输入消息转大写输出
command: ./tools/cpp-test/test
```

`.gitignore` 追加：
```
tools/*/test
```

- [ ] **Step 2: 复制二进制到位**

Run: `cp /Users/lishanyi/Documents/projects/tool-trust/test /Users/lishanyi/Documents/projects/tool-trust/tools/cpp-test/test`
Expected: `ls tools/cpp-test/` 有 `test` 可执行文件

- [ ] **Step 3: 写端到端测试**

```python
# tests/test_e2e.py
import subprocess, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from fastmcp import FastMCP
import server

def test_cpp_tool_registers_and_runs():
    mcp = FastMCP("test")
    server.load_tools(mcp, pathlib.Path("tools"))
    tools = mcp.get_tools()
    assert "cpp_test" in tools
    # 直接跑二进制验证包装命令正确
    r = subprocess.run(["./tools/cpp-test/test", "hello"],
                       capture_output=True, text=True, cwd=pathlib.Path(__file__).parent.parent)
    assert r.stdout.strip() == "hello"
```

- [ ] **Step 4: 跑测试确认通过**

Run: `uv run pytest tests/ -v`
Expected: 全 PASS（Task 1 + Task 4）

- [ ] **Step 5: 手工冒烟（server + client）**

Run:
```bash
uv run python server.py &   # 后台起 server
sleep 2
uv run python client.py     # 改 client 为调 cpp_test
```
Expected: client 终端打印 C++ 二进制输出

- [ ] **Step 6: Commit**

```bash
git add tools/cpp-test/ .gitignore tests/test_e2e.py
git commit -m "feat: register cpp-test as first tool, e2e verified"
```

---

## 自审记录

- **Spec 覆盖**：SKILL.md（Task 3）✓、模板（Task 2）✓、server 自动加载（Task 1）✓、目录即注册表（Task 4）✓、熵减（SKILL.md 段落）✓、类型归注解（SKILL.md + tool.py 模板）✓。
- **占位符**：SKILL.md 和模板中的 `{{ }}` 是有意占位（LLM 填充），非遗漏。
- **类型一致性**：`load_tools(mcp, tools_dir)` 签名在 Task 1 定义，Task 4 使用一致；`register(mcp)` 约定贯穿。

---

