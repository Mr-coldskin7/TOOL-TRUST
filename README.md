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

核心方向：**attestation report = 体检证书，是决策输入；真实运行属于工具所在的 bash runtime。**

> 设计裁定：不做 per-call 沙箱隔离（bwrap/sandbox-exec 每调用加锁）——工具本就活在 runtime
> agent 的 bash 语境里，再套内核锁是过度设计。Docker+strace **只在体检阶段**隔离，为了发现真相；
> 上岗阶段 agent 读报告 + requires 硬拒 + claims 决策契约，在 **决策时**把关。注意：一次 strace 观察
> 是行为采样，不是能力上界；报告给它"大致画像"，requires 确认当前 runtime 跑得动，越界由
> claims/consequences 在调用前把关。

已完成：

- ✅ **体检管道**：Docker 沙箱 + strace → `observe.py` 产出 JSON attestation report
- ✅ **claims 三级对账**：`file-write` 从"一个字"升级为 `class + mode(create/append/overwrite) + paths(白名单)`，对账 class → paths → mode 三级，deny 优先
- ✅ **requires 前置条件**：`--generate-requires` 从 strace 反推（env/files/exec/cwd/writable，滤系统噪音）；`--check-requires` 硬校验
- ✅ **决策闸 gate**：缓存报告 verdict=fail → 拒绝；requires 缺任一 → 硬拒(env-mismatch)，不运行省 token；通过则交 runtime 正常执行
- ✅ **server 消费闸门**：注册前跳过 attestation 判 fail 的工具（agent 看不到）
- ✅ `cpp-test`（C++ 转大写）端到端验证；`evil-write`/`evil-overwrite` 作为越界测试钳

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
attest/                         # 体检 + 决策逻辑
  run.py / build.py             #   Docker 沙箱、编译
  parse.py / rules.py           #   strace 解析、syscall→class 归类
  reconcile.py                  #   claims 三级对账(class→paths→mode)
  report.py                     #   JSON attestation report 组装
  prereq.py                     #   requires 硬校验 + 从 strace 反推
  gate.py                       #   决策闸(attestation 校验 + requires 硬拒)
observe.py                      # 体检 CLI（--generate-claims/requires、--check-requires）
server.py                       # 自动加载 tools/*/tool.py，注册前跳过 fail
client.py                       # 冒烟客户端
tools/                          # 注册表 = 目录，每工具一个子目录
  cpp-test/                     # 示例：C++ 转大写（tool.py + tool.yaml + report.json）
  evil-write/ evil-overwrite/   # 越界测试钳
```

## 路线图

- [x] attestation 本体：Docker 沙箱 + strace 观察 vs manifest 对账，产出 JSON report
- [x] claims 结构化：file-write 的 mode + paths 白名单，三级对账
- [x] requires 前置条件：自动反推 + 硬校验（省 token/算力）
- [x] 决策闸 gate + server 消费闸门（拒绝 fail 工具、requires 硬拒）
- [ ] 真实运行形态确定：runtime agent 在 bash 里用报告 + 决策闸把关
- [ ] 第二个语言工具（TS / Python / Java），验证 register-tool 通用性
- [ ] manifest 全量驱动：加工具只加 `tool.yaml`，Python 层零改动
- [ ] `tools/` 工具健康扫描（去重/分类/归档），LLM 建议、用户确认
- [ ] AGENTS.md 变体，让 Codex 也能跑注册流程
