# tool-trust

**可验证的 MCP 工具中心（Attested MCP Tool Hub）**。把日常脚本变成带“行为体检报告”的 MCP 工具。每个工具都内置一份机器可读的 attestation report，由 Docker + strace 一次观察生成。

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)

---

## 为什么做

LLM Agent 越来越频繁地替你调用命令行工具，但工具的 README 和它**实际做什么**往往对不上。`tool-trust` 补上这个缺口：

1. **观察**：把工具放进带 `strace` 的最小 Docker 容器跑一次。
2. **对账**：把观察到的系统调用与工具自声明的 manifest（`tool.yaml`）对比。
3. **决策**：调用前检查 attestation 是否通过、当前环境是否满足 requires。
4. **暴露**：通过标准 MCP 服务器把工具暴露给 pi、Claude Code 等客户端。

不需要声誉评分，也不需要人工安全审计。你写的第一个工具就能产出第一份体检报告。

---

## 工作原理

```
┌─────────────┐     Docker + strace     ┌──────────────────┐
│  tool.py    │ ────────────────────────► │  JSON report     │
│  tool.yaml  │     observe.py          │  (verdict /      │
└─────────────┘                         │   claims /       │
                                        │   violations)    │
                                        └────────┬─────────┘
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    │                            │                            │
                    ▼                            ▼                            ▼
            ┌───────────────┐          ┌───────────────┐          ┌──────────────────┐
            │  server.py    │          │  gate.py      │          │  runtime agent   │
            │ 跳过 fail     │          │ requires +    │          │ 通过才执行       │
            │ 的工具        │          │ claims 检查   │          │                 │
            └───────────────┘          └───────────────┘          └──────────────────┘
```

- **`observe.py`**：一次性行为体检。
- **`gate.py`**：每次调用前的看门人。
- **`server.py`**：stdio MCP 服务器，只注册 attestation 通过的工具。

---

## 公开工具

| 工具 | 功能 | 声明的能力 |
|------|------|-----------|
| `cpp_test` | 输入转大写 | 纯计算 |
| `us_quote` | 美股实时行情（Yahoo Finance） | 网络 |
| `us_market` | 美股技术面快照 | 网络 |
| `fx_rate`  | 汇率换算（open.er-api.com） | 网络 |
| `repo_stats` | 仓库概览（文件数、行数、TODO 数） | 只读文件系统 |
| `sha_tool` | 输入字符串 SHA-256 | 纯计算 |
| `cache_tool` | 向 `/tmp/cache.log` 追加一行 | 追加写 |
| `env_gate` | 环境不匹配时硬拒演示 | 无副作用 |

> **个人工具**（`cityu_mail`、`us_news`）放在 `tools/` 下但被 `.gitignore` 排除，不会进入 git，只在作者本机可用。你可以复制它们作为私有工具模板。

---

## 快速开始

### 1. 安装

需要 Python 3.12+、`uv`、Docker。

```bash
git clone https://github.com/Mr-coldskin7/TOOL-TRUST.git
cd TOOL-TRUST
uv sync
```

### 2. 本地体检并运行工具

```bash
# 从一次干净运行生成 claims
uv run python observe.py cpp-test --generate-claims hello

# 验证后续运行仍符合声明
uv run python observe.py cpp-test hello | jq .verdict
# "pass"
```

### 3. 启动 MCP 服务器

```bash
uv run python server.py --stdio
```

然后在 MCP 客户端中配置，例如在 **pi** 里：

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "uv",
      "args": ["run", "python", "server.py", "--stdio"],
      "cwd": "/path/to/TOOL-TRUST"
    }
  }
}
```

执行 `/reload` 后即可调用：

```text
toolhub_us_quote ticker=AAPL
```

### 4. 注册新工具

使用内置 skill（`.claude/skills/register-tool/`）：

```text
/register-tool 帮我做一个获取城市天气的工具
```

Skill 会自动生成源码、manifest、attestation wrapper 和冒烟测试。

---

## 安全模型

| 层级 | 职责 | 关键设计 |
|------|------|----------|
| **Attestation**（`observe.py`） | 一次性行为采样 | 产出报告，不是“永远安全”的证明。 |
| **Requires**（`prereq.py`） | 起飞前硬检查 | `exec`/`files`/`env`/`writable` 缺一即拒，避免浪费 token/算力。 |
| **Gate**（`gate.py`） | 每次调用决策 | 缓存 `verdict=fail` 拒绝；运行时 claims 不匹配拒绝。 |
| **Server 过滤**（`server.py`） | 注册时过滤 | attestation fail 的工具不会被注册，Agent 根本看不到。 |

我们**不**对每次调用再套内核沙箱（bwrap/sandbox-exec）。工具本就运行在 Agent 的 bash runtime 里，再加内核隔离属于过度设计。Docker 隔离**仅用于体检阶段**来发现真相；运行时依赖体检报告 + gate 把关。

### 路径白名单加固

`file-write` 声明使用路径白名单。我们对路径做 normpath 并严格检查目录边界，因此 `/tmp/../etc/passwd` 无法绕过 `/tmp/`。

---

## 架构

```text
TOOL-TRUST/
├── attest/              # 核心体检与决策逻辑
│   ├── build.py         # 基础镜像（现为内联 Dockerfile）+ 工具构建
│   ├── run.py           # 在容器内用 strace 运行工具
│   ├── parse.py         # 解析 strace 输出
│   ├── rules.py         # syscall → 行为类别
│   ├── reconcile.py     # claims 与观察事件对账
│   ├── prereq.py        # requires 推断与硬检查
│   ├── gate.py          # 决策门 + 运行时调用
│   └── report.py        # JSON 报告组装
├── observe.py           # 一次性体检 CLI
├── server.py            # stdio MCP 服务器
├── tools/               # 工具目录
│   ├── us-quote/
│   ├── us-market/
│   ├── fx-rate/
│   ├── repo_stats/
│   ├── sha_tool/
│   ├── cache-tool/
│   ├── env_gate/
│   ├── cpp-test/
│   └── conditional-evil/   # 边界测试夹具,不被注册
├── bench/               # 合成语料 + 量化指标(不需要 Docker)
├── tests/               # pytest 测试
└── .claude/skills/register-tool/  # 注册新工具的 skill
```

---

## 开发

跑测试:

```bash
uv run pytest -q
```

### 量化指标

管道本质是一个确定性分类器,所以用数字卡它。`bench/` 用一批手写合成 strace 日志(每条带 ground-truth 的良性/恶意标签),走与 `observe.py` 完全相同的代码路径,输出混淆矩阵 + 精确率/召回率/F1/准确率:

```bash
uv run python bench/run_bench.py              # 表格
uv run python bench/run_bench.py --json      # 机器可读
```

当前基线:**22/22 全命中,precision=recall=F1=accuracy=1.000**。bench 有真牙齿——构建过程中暴露并修复了一个真实误报:`dup2(1,3)` 后 `write(3)` 被误判成写文件,冤枉了只声明 stdout 的良性工具。语料覆盖路径穿越(`/tmp/../etc/x`)、模式越权(声明 create 却 O_TRUNC)、未声明网络 host、读文件外传等。`tests/test_bench.py` 把指标变成回归门槛(每个 case 必须与 ground truth 一致;指标 ≥ 0.95)。

不经过 MCP 直接跑工具：

```bash
uv run python observe.py fx-rate USD HKD 100
```

查看某工具的最新体检报告：

```bash
cat tools/<name>/report.json | jq
```

---

## 路线图

- [x] 体检管道：Docker 沙箱 + strace → JSON report
- [x] 结构化 claims：`file-write` 支持 `mode` + `paths` 白名单
- [x] `requires` 起飞前检查：自动推断 + 硬校验
- [x] 决策 gate + 服务端注册过滤
- [x] C++/Python 工具端到端跑通
- [x] 网络工具 `hosts` 白名单 + resolver 注入
- [x] 路径遍历加固（修复 `..` 绕过漏洞）
- [x] 边界夹具（`evil-write`、`conditional-evil`）持续压测 gate
- [ ] 完全 manifest 驱动：新增工具只需改 `tool.yaml`
- [ ] `toolhub` 健康扫描：检测过期或失败的 attestation report
- [ ] 基础镜像支持更多语言运行时（Node、Go）
- [ ] 基于 `cache_tool` 日志的 telemetry 看板

---

## License

MIT
