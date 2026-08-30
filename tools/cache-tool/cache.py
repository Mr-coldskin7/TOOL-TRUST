#!/usr/bin/env python3
"""cache-tool：往 /tmp/cache.log 追加一行(带时间戳)，再读回全部行数。file-write 白名单测试。"""
import json, os, sys, time
LOG = "/tmp/cache.log"
with open(LOG, "a") as f:
    f.write(f"{int(time.time())} {sys.argv[1] if len(sys.argv)>1 else ''}\n")
with open(LOG) as f:
    lines = f.read().splitlines()
print(json.dumps({"lines": len(lines), "last": lines[-1]}))
