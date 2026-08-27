# attest 观察管道 base 镜像：工具链 + strace + 语言运行时
# 注意：被体检工具用什么语言，它的运行时必须在这(容器里要真正跑它观察行为)。
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    strace \
    python3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*