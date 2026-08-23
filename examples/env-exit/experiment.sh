#!/usr/bin/env bash
# 环境可退出性实验：Docker 挂载卷是 undo 的泄漏点吗？
# 对应 dsh 模型：γ = 宿主 data 目录的状态，φ = 撤销手段
set -uo pipefail
cd "$(dirname "$0")"

echo "=== 准备实验数据 ==="
rm -rf data && mkdir -p data
echo "用户的重要文件内容" > data/important.txt
ls data/

echo ""
echo "=== 实验1: rw 挂载 —— 容器内改，退出后宿主被改（无 undo）==="
docker run --rm -v "$(pwd)/data":/data ubuntu:24.04 sh -c 'echo "pwned" > /data/important.txt'
echo ">>> 退出容器后，宿主文件变成了："
cat data/important.txt

echo ""
echo "=== 实验2: ro 挂载 —— 容器内想改，被拒绝（有 undo）==="
rm -rf data && mkdir -p data
echo "用户的重要文件内容" > data/important.txt
docker run --rm -v "$(pwd)/data":/data:ro ubuntu:24.04 sh -c 'echo "pwned" > /data/important.txt' 2>&1 || true
echo ">>> 退出容器后，宿主文件仍然是："
cat data/important.txt

echo ""
echo "=== 实验3: 容器内非挂载路径 —— 随便改，退出全消失（天然 undo）==="
docker run --rm ubuntu:24.04 sh -c 'echo "随便写" > /tmp/rubbish.txt; echo 改完了'
echo ">>> 宿主上 /tmp/rubbish.txt 存在吗？"
ls /tmp/rubbish.txt 2>&1 || echo "不存在 —— 容器销毁 = 环境回滚"