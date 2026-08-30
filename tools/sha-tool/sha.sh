#!/bin/sh
# 纯计算：输入 → SHA-256，无文件/网络副作用
printf '%s' "$1" | sha256sum | cut -d' ' -f1
