# attest 观察管道 base 镜像：工具链 + strace
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    gcc \
    strace \
    && rm -rf /var/lib/apt/lists/*
