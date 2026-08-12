# attest 观察管道 + claims 对账 设计

日期：2026-08-12
状态：设计定稿
项目：tool-trust

## 背景

tool-trust 打通"工具被 MCP agent 调用"后，进入第二阶段：**观察工具真实行为，与声明对账，产出 attestation report**。本 spec 是 attestation 最小闭环。

哲学（对齐 CI/CD，非 LLM 判断）：**确定性规则 + 不变量 + 可复现**。不依赖 LLM 判断安全性——LLM 不参与对账逻辑，只可能在生成阶段辅助。

## 目标

`python observe.py <tool> <input...>` 一条命令，产出机器可读 JSON 报告：观察的 syscall、违反的声明、verdict。

## CLI 入口

```
python observe.py <tool> <input...>          # 单输入 → 单报告
python observe.py <tool> --adversarial       # 对抗模板全跑 → 聚合报告
python observe.py <tool> --fuzz --iters 50   # 变异 fuzz → 聚合报告
python observe.py <tool> --generate-claims <input...>  # 建 claims 基线
```

聚合报告：
```json
{
  "mode": "adversarial",
  "runs": 42,
  "failures": [{"input": "../../etc/passwd", "violations": [...]}],
  "summary": {"pass": 40, "fail": 2}
}
```

## 输入来源（激进性三档）

| 档 | 输入来源 | 用途 | 实现 |
|---|---|---|---|
| L1 正常 | 用户手敲 | 建 claims 基线 | `--generate-claims` 专用 |
| L2 对抗 | 手写攻击模板清单 | 验证 claims 成立 | `attest/adversarial.py` |
| L3 变异 | 种子变异 fuzz | 深挖意外行为 | `attest/fuzz.py` |

- L2 模板（OWASP 思路）：路径遍历 `../`、`..\\..\\`、绝对路径、超长输入、空串、空白、命令注入 `; rm -rf`、`$(...)`、反引号、Unicode 边界、NUL 字节、符号链接路径、`~` 展开
- L3 fuzz：种子（正常输入）变异——截断、超长填充、随机字符、Unicode 注入。盲变异（无覆盖率引导），确定性随机种子可复现
- 语义：对抗/fuzz 的"失败" = 该输入下出现 violation。正常输入建基线，对抗/fuzz 是试金石

## 总架构

```
observe.py <tool> <input...>
  │
  ├─ 1. build     读 manifest → docker run base_image → 容器内跑 build
  ├─ 2. run       docker run --rm --cap-add=SYS_PTRACE 镜像 strace -f -o obs.txt ./test <input>
  ├─ 3. parse     strace 文本 → 结构化事件（确定性正则解析）
  ├─ 4. scan      危险规则表扫描（手写，非 LLM）
  ├─ 5. reconcile manifest claims vs 观察事件 对账
  └─ 6. report    JSON（含 verdict）
```

## Manifest Schema（定稿）

```yaml
# tools/<name>/tool.yaml
name: <name>
description: <自然语言描述>
base_image: ubuntu:24.04          # 编译/运行环境
build: g++ test.cpp -o test       # 容器内编译命令（相对 tools/<name>/）
command: ./test                    # 运行命令
claims:
  allow: [file-read, stdout, stderr, exit]   # 白名单 class
  deny: [network, file-write, exec]          # 明确禁止（覆盖 allow）
```

- 不存参数类型（归 tool.py / Python 注解）
- claims 用白名单 + deny 例外混合模型

## 编译（build 步骤）

1. `docker run --rm -v tools/<name>:/src -w /src <base_image> sh -c '<build>'`
2. 产物留挂载卷 `tools/<name>/`
3. mtime 缓存：产物比所有源码新 → 跳过重编译
4. 源码集合：`tools/<name>/*` 排除已产物、tool.py、tool.yaml

## 观察（run 步骤）

```bash
docker run --rm --cap-add=SYS_PTRACE \
  -v tools/<name>:/src -w /src \
  <base_image> \
  strace -f -o /tmp/obs.txt \
  <command> <input...>
```

- `--cap-add=SYS_PTRACE`：容器内 strace 需要 ptrace
- `-f`：跟子进程
- **不限定 `-e trace=`，全量跟踪**：默认拒绝对账依赖"能看到未声明 class"。若限定跟踪，未声明的类永不出现在数据里，对账失效。噪音靠 parse 归 class 处理

## 解析（parse 步骤）

strace 文本 → 事件列表。确定性正则，不赌 strace JSON 版本。

```python
Event = {"pid": int, "syscall": str, "args": str, "ret": int, "class": str}
```

class 归类规则（含 fd 判断）：
- `write(fd in {1,2})` → `stdout`/`stderr`，**不算 file-write**
- `openat(...O_WRONLY|O_RDWR...)` → `file-write`；`O_RDONLY` → `file-read`
- `connect/sendto/bind/socket/accept` → `network`
- `execve/execveat` → `exec`
- `exit/exit_group` → `exit`
- 其它 → 按 syscall 名查规则表，未定义 → `other`

## 危险规则表（scan 步骤，手写）

| class | 匹配 syscall | 严重度 |
|---|---|---|
| file-write | write(w/ fd∉1,2), writev, openat(O_WRONLY/O_RDWR), mkdir, unlink, rename, truncate | high |
| network | connect, sendto, sendmsg, bind, socket, accept, accept4 | high |
| exec | execve, execveat | high |
| process | kill, ptrace, clone, fork | medium |
| perms | chmod, chown, mount, symlink, mknod | high |
| other | 未分类 syscall | medium |

## 对账（reconcile 步骤）

```
observed 事件 class：
  ∈ deny            → violation（禁止但发生）
  ∈ allow           → pass
  ∉ allow ∪ deny    → violation（默认拒绝，未声明即禁止）
```

- class 全部归并后去重判断
- violation 记录证据：syscall 名 + 关键 args + pid

## 报告（report 步骤）

```json
{
  "tool": "cpp-test",
  "input": ["hello"],
  "claims": {"allow": ["file-read", ...], "deny": ["network", ...]},
  "observed": {
    "syscall_count": 42,
    "classes": {"file-read": 10, "stdout": 1, "exit": 1},
    "events": [{"syscall": "openat", "class": "file-read", "args": "/etc/ld.so.cache", "ret": 3}]
  },
  "violations": [
    {"class": "network", "severity": "high", "syscall": "connect", "evidence": "fd=3 -> 10.0.0.1:443"}
  ],
  "verdict": "pass" | "fail"
}
```

verdict 规则：`violations 非空 → fail`。

## --generate-claims

`python observe.py --generate-claims <tool> <input...>`

```
观察跑一遍 → 汇总 observed class 集合
→ 生成建议 claims：
    allow = observed class 集合
    deny  = 全部已知 class - allow（默认拒绝）
→ 输出建议 YAML，写回 tool.yaml，claims 段标 # auto-generated
→ 用户 review 后 accept
```

注意：基线 claims 只证明"这组输入下没越界"，不证明"所有输入安全"。基线 + 对抗/fuzz 配对使用（L2/L3 见"输入来源"段）。

## 文件结构

```
observe.py                # CLI 入口
attest/
  __init__.py
  build.py                # docker build（容器内编译 + mtime 缓存）
  run.py                  # docker run + strace
  parse.py                # strace 文本 → 事件
  rules.py                # class 规则表 + 扫描
  reconcile.py            # claims vs observed 对账
  report.py               # JSON 输出 + verdict
  adversarial.py          # L2 对抗输入模板清单
  fuzz.py                 # L3 变异 fuzz 引擎
tests/
  test_parse.py           # strace 文本 → 事件（纯函数）
  test_rules.py           # class 归类 + 规则匹配（纯函数）
  test_reconcile.py       # 对账逻辑（纯函数）
  test_fuzz.py            # fuzz 变异器（纯函数）
tools/cpp-test/tool.yaml  # 补 base_image + build + claims 字段
```

## 测试策略

- 单元测试（纯函数，不碰 docker）：parse / rules / reconcile / fuzz 变异器
- 手工冒烟：`python observe.py cpp-test hello` 出完整 JSON
- docker 集成测试用 `@pytest.mark.skipif(无 docker)` 保护
- 对账边界测试：fd 判断（write fd=1 → stdout 不算 file-write）、默认拒绝（未声明 class → violation）

## 风险与边界

- strace 文本格式跨版本差异 → parse 规则聚焦核心行，未知行跳过 + 计数
- 动态链接噪音（ld.so 读 .so）→ 归为 file-read，第一版接受
- 解释器运行时噪音（node 自身 syscall）→ 归 class，第一版接受；语义过滤下轮
- 不做：路径级 claims（read_paths）、静态源码规则扫描（Semgrep）、覆盖率引导 fuzz、多输入批次（非对抗模式）

## 验证标准

1. `python observe.py cpp-test hello` → 单报告，verdict=pass
2. `python observe.py cpp-test --adversarial` → 聚合报告，cpp-test 应 pass 或暴露真越界
3. `python observe.py cpp-test --fuzz --iters 50` → 聚合报告
4. 故意越界工具（打印时写文件）→ `--adversarial` 下 verdict=fail，violations 列出
5. `--generate-claims` 产出建议 claims，写回 tool.yaml
6. 单元测试全绿（不碰 docker）
