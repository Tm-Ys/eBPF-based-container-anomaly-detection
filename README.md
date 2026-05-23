# eBPF-based-container-anomaly-detection

中国科学院大学 — "高级操作系统"课程项目

基于 eBPF 的容器异常检测系统。通过 eBPF 采集容器行为数据（系统调用、进程、网络、资源），使用机器学习算法自动识别异常行为。

---
## 原实验要求
### 实验内容：
近年来，由于容器的可扩展、轻量级等优点，基于容器的虚拟化在云计算中越来越受欢迎。与传统的基于虚拟机监视器（VMM）的虚拟化不同，基于容器的虚拟化技术共享相同的底层主机操作系统(OS)，而没有VMM和Guest OS。这种差异有助于容器消除大部分虚拟机(VM)所遭受的开销。最近的研究表明，在各种工作负载下，容器在CPU、内存和输入/输出方面实现了接近原生性能。虽然容器的轻量级隔离机制带来了开销优势，但是隔离不足也会导致容器异常。因此容器异常事件频发，例如性能不稳定、系统崩溃和安全问题。
eBPF（extended Berkeley Packet Filter）是一种内核技术，它允许开发人员在不修改内核代码的情况下运行特定的功能。eBPF 的概念源自于 Berkeley Packet Filter（BPF），后者最初是由贝尔实验室开发的一种捕获和过滤网络数据包的过滤器。eBPF经过不断的发展和功能完善已经被广泛应用于网络监控、安全过滤、性能分析等多种场景中。eBPF的强大能力也为容器异常检测提供了更多的机会。
本题目旨在通过ebpf实现容器异常检测框架。该框架通过ebpf收集容器的行为特征（例如系统调用频率、系统调用序列、文件访问、网络通信等活动）、指标特征（例如IO吞吐、内存利用率、CPU利用率等）等数据，采用人工智能算法自动识别具有异常行为的容器。检测的容器异常行为包括：可疑的系统调用、未经授权的容器互访、容器内异常进程的创建、异常的资源使用量等。
### 评分标准（折算为百分制）
- 可扩展的ebpf数据采集框架。该框架需要使用ebpf采集各种有助于判断异常容器行为的数据。常见的数据包括：系统调用类型、资源使用量、流量特征等等。该框架需要具有扩展能力，用户可以快速方便地添加新的数据采集类型。(40分）
- 采集框架具有可忽略的性能开销。CPU占用控制在10%以内，保证被监控容器的正常流畅运行。（30分）
- 准确的检测算法。利用机器学习、深度学习等技术实现容器异常行为的自动检测。该检测算法需要具有高准确率，选择合适的指标作为输入，检测各种不同类型的异常行为。（30分）




---
## 快速开始

```bash
# 1. 一键搭建环境
./setup.sh

# 2. 激活虚拟环境
source .venv/bin/activate

# 3. 运行（需要 sudo）
echo YOUR_PASSWORD | sudo -S .venv/bin/python3 -m src.main
```

**输出示例：**
```
[SYSCALL] pid=26276 comm=loader syscall=write cgroup=7798
[SYSCALL] pid=1251  comm=gnome-shell syscall=getpid cgroup=5446
[SYSCALL] pid=1512  comm=io.flutter.rast syscall=read cgroup=6832
```

## 系统架构

```
内核态 (eBPF)                    用户态 (C)                   用户态 (Python)
┌─────────────────┐   ringbuf   ┌────────────────┐   pipe   ┌─────────────────┐
│ raw_tp/sys_enter │──────────▶│ libbpf skeleton │─────────▶│ main.py         │
│ sched_process_*  │            │  C 加载器       │          │ collector/*.py  │
│ syscalls:connect │            │  stdout 输出    │          │ detector/*.py   │
│ /sys/fs/cgroup   │            └────────────────┘          │ CLI 输出         │
└─────────────────┘                                         └─────────────────┘
```

## 项目结构

```
.
├── bpf/                   # eBPF 内核程序 (C)
│   ├── syscall.bpf.c     # 系统调用监控钩子
│   └── common.h          # 事件结构体定义 (packed)
├── src/
│   ├── loader/loader.c   # C 加载器 (libbpf + ring buffer)
│   ├── collector/        # Python 采集模块
│   │   ├── base.py       # 采集器抽象接口
│   │   └── syscall_collector.py
│   └── main.py           # 入口
├── setup.sh              # 环境搭建脚本
├── Makefile              # 构建系统
├── PLAN.md               # 项目计划与进度
├── AGENTS.md             # 项目上下文 (AI 参考)
└── CLAUDE.md             # 项目上下文 (AI 参考)
```

## 进度

| Phase | 内容 | 状态 |
|-------|------|------|
| **Phase 1** | 系统调用监控流水线（内核钩子 → ring buffer → C 加载器 → Python 输出） | ✅ 完成 |
| **Phase 2** | 完善采集器（进程、网络、资源） + 可扩展插件机制 | ❌ 未开始 |
| **Phase 3** | 异常检测算法（特征工程 + ML 模型 + 告警） | ❌ 未开始 |
| **Phase 4** | 测试、性能优化、文档 | ❌ 未开始 |

详见 [PLAN.md](PLAN.md)。

## 构建

```bash
make clean     # 清理构建产物
make all       # 完整构建
```

构建步骤：
1. `bpftool btf dump` 生成 `build/vmlinux.h`
2. `clang -target bpf` 编译 BPF 程序
3. `bpftool gen skeleton` 生成 C 骨架
4. `gcc` 链接 libbpf 生成加载器

## 依赖

- **系统**: Linux 5.4+（推荐 6.x），支持 BTF / CO-RE
- **工具**: clang, llvm, bpftool, cmake, git
- **库**: libbpf (≥ 1.0), libelf, libz
- **Python**: 3.10+, scikit-learn, numpy, pandas

`setup.sh` 会自动安装所有依赖，包括从源码编译 libbpf v1.4.7。

## 已知问题

1. **libbpf 兼容性**：Ubuntu 22.04 自带 libbpf 0.5.0 与内核 6.8 BTF 不兼容，必须编译安装 v1.4.7
2. **自捕获噪音**：C 加载器会捕获自身的系统调用（write 等），后续需过滤加载器 PID
3. **Ring buffer 大小**：默认 256KB，高负载下可能需要调大

## 许可证

课程项目，仅供学习参考。
