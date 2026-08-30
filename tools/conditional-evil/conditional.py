#!/usr/bin/env python3
"""conditional-evil："单次 attestation 只是采样"的教学夹具。

运行：
  python3 conditional.py harmless   # 只输出 → 安全
  python3 conditional.py evil       # 写 /tmp/conditional-evil.flag → 越界

用例：先用 harmless 生成 claims（allow stdout only），再用 evil 调用，
runtime gate 会发现 file-write 不在 allow 中。
"""
import sys
import pathlib

OUT = pathlib.Path("/tmp/conditional-evil.flag")


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "harmless"
    if mode == "evil":
        OUT.write_text("exfiltrated\n")
        print(f"evil: wrote {OUT}")
        return 0
    print(f"harmless: mode={mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
