# CLAUDE.md — 项目上下文

本文件等价于 AGENTS.md，请修改时对两者同时进行修改。

## 项目概述

基于 eBPF 的容器异常检测 — 中国科学院大学"高级操作系统"课程项目。系统通过 eBPF 采集容器行为数据，使用机器学习检测异常行为。

## 架构（数据流）

```
raw_tp/sys_enter + raw_tp/sys_exit (内核) → BPF ring buffer → C 加载器 (libbpf skeleton)
    → stdout (二进制结构体) → Python subprocess → struct.unpack → 终端输出
```

## BPF Maps

| Map | 类型 | 用途 |
|-----|------|------|
| `ringbuf` | `BPF_MAP_TYPE_RINGBUF` | 256KB 事件环形缓冲区 |
| `filter_pid` | `BPF_MAP_TYPE_ARRAY` | 过滤目标 PID（0=不过滤） |
| `sample_rate` | `BPF_MAP_TYPE_ARRAY` | 采样率分母（1=全部采样） |
| `sample_counter` | `BPF_MAP_TYPE_PERCPU_ARRAY` | 每 CPU 采样计数器 |

## 当前进度

- ✅ **Phase 1 已完成**（系统调用监控流水线，含所有 Issue 修复）
- ❌ Phase 2（完整采集器）— 未开始
- ❌ Phase 3（ML 检测）— 未开始
- ❌ Phase 4（测试）— 未开始

## 目录结构

```
.
├── bpf/                  # eBPF C 程序
│   ├── syscall.bpf.c    # Phase 1: raw_tp/sys_enter 钩子
│   └── common.h         # packed 事件结构体
├── src/
│   ├── loader/loader.c  # C 代理：libbpf skeleton + stdout
│   ├── collector/
│   │   ├── base.py      # 采集器抽象接口
│   │   └── syscall_collector.py  # subprocess + struct.unpack
│   └── main.py          # 入口
├── build/               # 构建产物（已 gitignore）
├── Makefile             # 构建系统
└── setup.sh             # 一键环境搭建
```

## 关键定义

### 事件结构体 (bpf/common.h) — `__attribute__((packed))`
```c
struct event {
    __u64 timestamp_ns;   // bpf_ktime_get_ns()
    __u32 pid;
    __u32 cgroup_id;       // bpf_get_current_cgroup_id()
    __s32 syscall_id;      // ctx->id 来自 raw_tp/sys_enter
    __s32 ret;             // 返回值（sys_exit），enter 时为 0
    char comm[16];         // bpf_get_current_comm() — 进程名
};
```
- **总大小：40 字节** — 必须与 Python `struct.Struct('Q2I2i16s')` 匹配
- **Packed** 因为 BPF 目标与 x86_64 对 struct 对齐规则可能不一致

### Python 结构体解包
```python
EVENT_FORMAT = struct.Struct("Q2I2i16s")
# Q=u64, I=u32, I=u32, i=s32, i=s32, 16s=char[16]
# 大小：8+4+4+4+4+16 = 40 字节
```

## 构建系统

```
make clean && make all    # 完整重建
```

步骤：
1. `bpftool btf dump` → `build/vmlinux.h`
2. `clang -target bpf` → `build/syscall.bpf.o`
3. `bpftool gen skeleton` → `build/syscall.skel.h`
4. `gcc -lbpf -lelf -lz` → `build/loader`

## 运行

```bash
# 需要 sudo 权限
echo 密码 | sudo -S .venv/bin/python3 -m src.main
```

## 已知问题 / 注意事项

1. **libbpf 版本**：Ubuntu 22.04 自带 libbpf 0.5.0，与内核 6.8 BTF 不兼容。必须从源码编译 libbpf v1.4.7。`setup.sh` 已处理。
2. **sudo 密码**：bash 工具不能运行交互式 sudo。使用 `echo 密码 | sudo -S`。
3. **自捕获**：加载器会捕获自身的系统调用（write、mmap 等），产生噪音。生产环境需要过滤加载器自身的 PID。
4. **Ring buffer 大小**：当前 256KB。高系统调用负载下可能需要调整。
5. **采样率**：默认全部采样。传递 `--rate N` 给 loader 可每 N 个事件采样 1 个。
6. **PID 过滤**：loader 默认自动过滤自身 PID（`getpid()` 写入 `filter_pid` map）。可用 `--pid PID` 指定过滤目标。
