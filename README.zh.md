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
uv run python bench/run_bench.py                # 教学 corpus 22 case
uv run python bench/run_bench.py --fuzz 500     # + 500 个对抗随机 case
uv run python bench/run_bench.py --json         # 机器可读(含 CI)
```

当前基线:**522 case,precision=recall=F1=accuracy=1.000**(22 个手写教学 case + 500 个对抗随机 case)。样本量通过 95% Wilson 置信区间读进数字:accuracy CI `[0.993, 1.0]`,precision/recall CI `[0.987, 1.0]`——所以头号数字从来不是一个裸 `1.000`。

为什么 fuzz 语料不是自证预言:`bench/fuzz.py` 从**意图模型**生成随机 case——claims 来自「声明侧」,strace 文本来自「行为侧」,ground-truth 标签来自意图级对比,与事件级对账管道**零共享代码**。构建过程中它抓出了两个手写 case 漏掉的真缺陷(根路径白名单边界 bug、fd-class 相关逻辑错误),都已修并加了回归测试。

bench 只测**对账引擎本身**——不测 Docker 隔离、不测运行时 gate 的 subprocess 内部、不测工具源码恶意性(一次观察只是采样,`conditional-evil` 证明了这缺口)。这些边界在每次报告的末尾随指标一起打印。

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

详细且持续更新的工作清单:[TODO.md](TODO.md)。

- [x] 体检管道：Docker 沙箱 + strace → JSON report
- [x] 结构化 claims：`file-write` 支持 `mode` + `paths` 白名单
- [x] `requires` 起飞前检查：自动推断 + 硬校验
- [x] 决策 gate + 服务端注册过滤
- [x] C++/Python 工具端到端跑通
- [x] 网络工具 `hosts` 白名单 + resolver 注入
- [x] 路径遍历加固（修复 `..` 绕过漏洞）
- [x] 边界夹具（`evil-write`、`conditional-evil`）持续压测 gate
- [ ] 完全 manifest 驱动:新增工具只需改 `tool.yaml`
- [ ] `toolhub` 健康扫描:检测过期或失败的 attestation report
- [ ] **工具 provenance(供应链信任)**:manifest 加 `source`/`version`/`hash`;版本一变 → attestation 失效(SCA 式);gate 拒绝被篡改的工具
- [ ] **未知来源工具首次接入人工审查**(参照浏览器未知 CA 模型)— 缓解 Tool Misuse
- [ ] **gate 记录调用者身份**:session/agent 上下文 — 缓解 Identity Spoofing
- [ ] 基础镜像支持更多语言运行时(Node、Go)
- [ ] 基于 `cache_tool` 日志的 telemetry 看板

## 方向(为什么 roadmap 长这样)

tool-trust 的存在理由:AI Agent 信任得太多。现代针对 Agent 的攻击(Prompt
Injection / Tool Misuse / Intent Breaking / Identity Spoofing / Code Attacks)
都在利用某个**「无条件信任」**——模型信任文本、信任工具、信任计划、信任身份、信任代码执行。
我们只把其中一个点(工具行为)从信任云里抠出来,换成**可验证事实**:Docker 沙箱观察工具
实际做了什么,确定性对账引擎把它与声明对比。

这个框架决定接下来三个方向:

1. **工具 provenance(SCA 式供应链信任)** — manifest 携带 `source` / `version` /
   `hash`。版本一变 → attestation 失效;`tool.py` 被篡改 → gate 拒绝。这填补当前威胁
   模型的唯一真实盲区:**诚实声明恶意行为的工具现在照样过体检**(行为证明是防漂移,不是
   杀毒)。
2. **未知来源首次接入人工审查** — 像浏览器对待自签名 CA 一样,未知来源工具首次使用前需要
   一次性人工批准。这是对 Tool Misuse(「Agent 被骗着加了恶意 MCP server」)的工程答案。
3. **gate 记录调用者身份** — 记录哪个 session/agent 调用了每个工具,被攻破的调用 Agent 无法
   冒充合法身份(Identity Spoofing)。

更远期:**可执行计划问责**。声明 vs 实际 的验证已经能证明一个*工具*说到做到;同一思路
套到 Agent 的*执行计划*上(声明步骤 → 验证步骤真的执行),就是 Intent Breaking 的候选方案
——今天唯一没有干净工程解的向量。

---

## License

MIT
