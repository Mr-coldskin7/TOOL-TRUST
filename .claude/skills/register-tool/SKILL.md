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
3. **定命令**（脚本运行时优先,srt 时代脚本工具无 build/base_image 字段；编译型工具不能在宿主 enforce,不接纳）：
   - Python: command = `python3 <name>.py`
   - Shell: command = `sh <name>.sh`（`chmod +x`）
4. **生成 tool.yaml**：用 templates/tool.yaml.tmpl。联网工具**必须**把 `network` 收窄成
   `class: network, hosts: [...]`（白名单真实端点，禁止裸 `network`）；写文件工具**必须**
   带 `mode + paths` 白名单；无副作用工具保持模板的 deny 默认。`requires.exec` 写运行时。
5. **生成 tool.py**：用 templates/tool.py.tmpl（gate 决策闸包装，参数顺序需与 tool.yaml 的 `inputs` 一致）。
6. **手动跑二进制**：直接执行 command，确认输出符合描述。
7. **观察→授权（必经）**：
   ```bash
   uv run python observe.py <name> --scan <样例输入>   # 最小 srt 沙箱观察 → srt-settings.json.proposed + tool.yaml 声明 sandbox.srt_settings
   #   审阅 proposed:域名/写路径与意图一致才批准(不要求它凭空比 claims 更全)
   uv run python observe.py <name> --approve           # 打印权限摘要 → y/N → 锁定(settings 内容 sha256 进 contract.json)
   uv run python observe.py --status                   # 确认该工具显示 operator-approved
   ```
   - 参考 `tools/demo-fetch` + `bash scripts/demo_onboarding.sh` 看完整链路
   - 未批准 = unmanaged,永远进不了强制路径；改源码/claims/settings 后必须重新 approve(Gate 3/4 会拒)
8. **client 冒烟**：写/改 client 调用，确认 MCP 返回正确。C++ 二进制记得带 `./` 前缀。
9. **汇报**："已注册，可调用 <函数名>，参数：<类型>，attestation pass"。

## 熵减（可选）

若 `tools/` 已有 ≥10 个工具，注册尾附带 60 秒扫描报告：每项"现状|问题|建议|风险"。只建议，删除/合并必须用户确认。

## 硬性约定

- 工具名避开 shell 内置命令（如 `test`）→ 用 `tools/<name>/` 目录名做函数名
- `contract.json`/`srt-settings.json` 必须 commit（授权快照 + 锁定边界）；已删除的 report.json 语义不再使用
- 不删用户文件
