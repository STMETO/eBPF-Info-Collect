# eBPF-Info-collect Makefile
#
# 构建流程：
#   1. clang 编译 .bpf.c → .bpf.o  (BPF 字节码)
#   2. xxd -i 生成 embed 头文件    (嵌入到可执行文件)
#   3. g++ 编译用户态 C++          (链接 libbpf.a)
#   4. 链接 → vsomeip_collector    (单文件部署)

# ── 目录 ───────────────────────────────────────────────────────────────
PROJ_DIR  := $(CURDIR)
SRC_DIR   := $(PROJ_DIR)/src
BPF_DIR   := $(SRC_DIR)/bpf
USER_DIR  := $(SRC_DIR)/user
COMMON_DIR:= $(SRC_DIR)/common
BUILD_DIR := $(PROJ_DIR)/build
GEN_DIR    := $(SRC_DIR)/gen
EMBED_DIR := $(GEN_DIR)/embed
SCRIPTS   := $(PROJ_DIR)/scripts

# ── 库路径 ────────────────────────────────────────────────────────────
LIBBPF_DIR   := $(PROJ_DIR)/lib/libbpf/src
LIBBPF_A     := $(LIBBPF_DIR)/build/lib64/libbpf.a
LIBBPF_INC   := $(LIBBPF_DIR)/build/include
LIBBPF_UAPI  := $(PROJ_DIR)/lib/libbpf/include/uapi
VMLINUX_DIR  := $(PROJ_DIR)/vmlinux

# ── 编译器 ────────────────────────────────────────────────────────────
CLANG    := clang
CXX      := g++

# BPF 编译标志
# -target bpf: 生成 BPF 字节码
# -D__TARGET_ARCH_arm64: 告诉 bpf_tracing.h 用 ARM64 的 pt_regs 布局
BPF_CFLAGS := -target bpf -g -O2 \
              -D__TARGET_ARCH_arm64 \
              -D__BPF__ \
              -I$(SRC_DIR) \
              -I$(GEN_DIR) \
              -I$(VMLINUX_DIR) \
              -I$(LIBBPF_INC) \
              -I$(COMMON_DIR) \
              -I$(BPF_DIR) \
              -Wall -Wno-unused-value \
              -Wno-unknown-attributes -Wno-ignored-attributes \
              -Wno-gnu-variable-sized-type-not-at-end -Wno-attributes \
              -Wno-incompatible-function-pointer-types

# 用户态编译标志
CXXFLAGS := -std=c++17 -g -O2 -Wall \
            -I$(SRC_DIR) \
            -I$(COMMON_DIR) \
            -I$(LIBBPF_DIR) \
            -I$(LIBBPF_INC) \
            -I$(LIBBPF_UAPI) \
            -I$(USER_DIR)

# 链接标志
LDFLAGS := -lelf -lz -lpthread

# ── BPF 源文件 ────────────────────────────────────────────────────────
BPF_SRCS := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS := $(patsubst $(BPF_DIR)/%.bpf.c, $(BUILD_DIR)/%.bpf.o, $(BPF_SRCS))
EMBED_HDRS:= $(patsubst $(BPF_DIR)/%.bpf.c, $(EMBED_DIR)/%.bpf.embed.h, $(BPF_SRCS))

# ── 用户态源文件 ──────────────────────────────────────────────────────
USER_SRCS := $(shell find $(USER_DIR) -name '*.cpp')
USER_OBJS := $(patsubst $(USER_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(USER_SRCS))

# embed 数据编译（单独编译，避免多重定义）
EMBED_DATA_SRC := $(GEN_DIR)/embed_data.cpp
EMBED_DATA_OBJ := $(BUILD_DIR)/embed_data.o

# ── 最终产物 ──────────────────────────────────────────────────────────
TARGET := $(BUILD_DIR)/vsomeip_collector

# ═══════════════════════════════════════════════════════════════════════
# 顶层目标
# ═══════════════════════════════════════════════════════════════════════

.PHONY: all clean embed hooks

all: hooks embed $(TARGET)
	@echo ""
	@echo "==========================================="
	@echo "  Build complete: $(TARGET)"
	@echo "  BPF bytecode embedded — single binary deploy"
	@echo "==========================================="

# ── 1. 生成 hook_config.h ─────────────────────────────────────────────
hooks:
	@echo "[HOOKS] Generating hook_config.h..."
	@$(SCRIPTS)/gen_hook_config.sh

# ── 2. 编译 BPF → 生成 embed 头文件 ────────────────────────────────────
embed: $(EMBED_HDRS)
	@echo "[EMBED] Done"

$(BUILD_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c | $(BUILD_DIR)
	@echo "[BPF]  Compiling $< ..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(EMBED_DIR)/%.bpf.embed.h: $(BUILD_DIR)/%.bpf.o | $(EMBED_DIR)
	@echo "[EMBED] $< → $@"
	# xxd -i 会用输入路径生成变量名，cd 到 build/ 避免绝对路径
	(cd $(BUILD_DIR) && xxd -i $*.bpf.o) > $@

# 生成 embed_data.cpp（自动包含所有 embed 头文件）
$(EMBED_DATA_SRC): $(EMBED_HDRS)
	@mkdir -p $(GEN_DIR)
	@echo "// Auto-generated — includes all embed BPF bytecode" > $@
	@for h in $(EMBED_HDRS); do \
		echo "#include \"embed/$$(basename $$h)\"" >> $@; \
	done

# ── 3. 编译用户态 → 链接 ──────────────────────────────────────────────
$(TARGET): $(USER_OBJS) $(EMBED_DATA_OBJ) $(LIBBPF_A)
	@echo "[LINK] $@"
	$(CXX) $(CXXFLAGS) $(USER_OBJS) $(EMBED_DATA_OBJ) $(LIBBPF_A) $(LDFLAGS) -o $@

$(EMBED_DATA_OBJ): $(EMBED_DATA_SRC) | $(BUILD_DIR)
	@echo "[CXX]  $< (embed data)"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 用户态编译规则
$(BUILD_DIR)/%.o: $(USER_DIR)/%.cpp | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@echo "[CXX]  $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ── 目录创建 ──────────────────────────────────────────────────────────
$(BUILD_DIR) $(EMBED_DIR):
	@mkdir -p $@

# ═══════════════════════════════════════════════════════════════════════
# 清理
# ═══════════════════════════════════════════════════════════════════════

clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned."

distclean: clean
	rm -rf $(EMBED_DIR)/*.h
	@echo "Deep cleaned (embed headers removed)."

# ═══════════════════════════════════════════════════════════════════════
# 帮助
# ═══════════════════════════════════════════════════════════════════════

help:
	@echo "Targets:"
	@echo "  make          — 完整构建（hooks → embed → link）"
	@echo "  make hooks    — 只重新生成 hook_config.h"
	@echo "  make embed    — 只重新编译 BPF 并生成 embed 头文件"
	@echo "  make clean    — 删除 build/"
	@echo "  make distclean— 删除 build/ + embed 头文件"
	@echo ""
	@echo "Build output: build/vsomeip_collector  (single binary, no external files)"
