#!/bin/sh
# embed_bpf.sh — 将编译好的 .bpf.o 文件用 xxd -i 转成 C 嵌入头文件
#
# 用法：./scripts/embed_bpf.sh <build_dir> <src/bpf/embed>
#
# 示例：./scripts/embed_bpf.sh build/bpf src/bpf/embed
#
# 对于每个 .bpf.o 文件，生成对应的 .embed.h 文件：
#   routing.bpf.o → routing.bpf.embed.h
#                → 内部定义 routing_bpf_o[] 和 routing_bpf_o_len

set -eu

build_dir="${1:?usage: $0 <build_dir> <embed_dir>}"
embed_dir="${2:?usage: $0 <build_dir> <embed_dir>}"

mkdir -p "$embed_dir"

found=0
for obj in "$build_dir"/*.bpf.o; do
    [ -f "$obj" ] || continue

    base="$(basename "$obj" .bpf.o)"
    out="$embed_dir/${base}.bpf.embed.h"

    echo "Embedding: $obj → $out"

    # xxd -i 把二进制文件转成 C 数组
    # 例如 routing.bpf.o → routing_bpf_o[] + routing_bpf_o_len
    xxd -i "$obj" > "$out"

    found=1
done

if [ "$found" -eq 0 ]; then
    echo "WARNING: no .bpf.o files found in $build_dir" >&2
fi

echo "Done. Embed headers in: $embed_dir"
