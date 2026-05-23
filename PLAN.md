# 项目计划 — 基于 eBPF 的容器异常检测

## 系统架构

```
┌─────────────────────────────────────────────────┐
│                   Python 用户态                    │
│  ┌──────────┐  ┌──────────┐  ┌────────────────┐ │
│  │ Collector │─▶│ Detector │─▶│ Alert/Reporter │ │
│  │  采集器   │  │  检测器   │  │   告警/报告    │ │
│  └─────┬────┘  └──────────┘  └────────────────┘ │
│        │                                         │
│  ┌─────▼────┐  ┌─────────────┐                   │
│  │  main.py  │  │  特征工程    │                   │
│  │ subprocess│  │             │                   │
│  └─────┬────┘  └─────────────┘                   │
└────────┼─────────────────────────────────────────┘
         │ 二进制事件流 stdout pipe
┌────────▼─────────────────────────────────────────┐
│           C 加载器 (build/loader)                 │
│  ┌──────────────────────────────────────────────┐ │
│  │  libbpf skeleton → ring_buffer__poll → fwrite│ │
│  └──────┬───────────────────────────────────────┘ │
└─────────┼─────────────────────────────────────────┘
          │ ring buffer (BPF_MAP_TYPE_RINGBUF)
┌─────────▼─────────────────────────────────────────┐
│               内核 (eBPF 程序)                     │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌───────────┐ │
│  │ syscall│ │process │ │network │ │  resource  │ │
│  │ 系统调用│ │ 进程   │ │ 网络   │ │   资源     │ │
│  └────────┘ └────────┘ └────────┘ └───────────┘ │
│  raw_tp/sys_enter / sched / cgroup               │
└─────────────────────────────────────────────────┘
```

## 技术选型

| 层面 | 选择 | 理由 |
|------|------|------|
| **eBPF 程序** | C + libbpf CO-RE (`SEC()` 宏) | 现代标准写法，便携 |
| **编译** | `clang -target bpf` → .o 文件 | 无运行时 LLVM 依赖 |
| **BPF 加载** | C 加载器 via libbpf skeleton，stdout pipe 到 Python | 轻量，简单 IPC |
| **libbpf** | v1.4.7（源码编译安装） | Ubuntu 22.04 自带 0.5.0 与内核 6.8 BTF 不兼容 |
| **Python** | .venv + scikit-learn | 数据处理 + ML |
| **数据传输** | BPF ring buffer → fwrite(stdout) → Python subprocess pipe | 零拷贝，低开销 |
| **容器识别** | `bpf_get_current_cgroup_id()` | 精准区分容器边界 |
| **结构体对齐** | `__attribute__((packed))` | BPF 目标与 x86_64 布局必须一致 |

## 目录结构

```
.
├── bpf/                      # eBPF 内核态程序 (C)
│   ├── syscall.bpf.c        # Phase 1: raw_tp/sys_enter（全部系统调用）
│   ├── process.bpf.c        # Phase 2
│   ├── network.bpf.c        # Phase 2
│   ├── resource.bpf.c       # Phase 2
│   └── common.h             # 共享结构体定义（packed！）
├── src/                      # 用户态代码
│   ├── loader/
│   │   └── loader.c          # C 加载器（libbpf skeleton + stdout）
│   ├── collector/            # Python 采集模块
│   │   ├── __init__.py
│   │   ├── base.py           # 抽象基类（可扩展接口）
│   │   ├── syscall_collector.py  # Phase 1
│   │   ├── process_collector.py  # Phase 2
│   │   ├── network_collector.py  # Phase 2
│   │   └── resource_collector.py # Phase 2
│   ├── detector/             # Phase 3
│   │   ├── __init__.py
│   │   ├── features.py
│   │   ├── model.py
│   │   └── alert.py
│   ├── config.py             # 全局配置
│   └── main.py               # 入口
├── build/                    # 构建产物（已 gitignore）
├── tests/
├── data/
├── setup.sh                  # 环境一键安装
├── requirements.txt          # Python 依赖
├── AGENTS.md                 # 上下文文件（等价于 CLAUDE.md）
├── CLAUDE.md                 # 上下文文件（等价于 AGENTS.md）
└── README.md
```

## 评分标准与分工（3 人小组）

| 评分项 | 分数 | 对应模块 | 建议分工 |
|--------|------|----------|----------|
| **可扩展采集框架** | 40 | `bpf/*.bpf.c` + `src/collector/` + `src/loader/` | **A 同学** — BPF 内核程序 + C 加载器 |
| **低开销 (<10% CPU)** | 30 | ring buffer + 采样率控制 | **A 同学**（内嵌在采集框架中） |
| **检测算法 (高准确率)** | 30 | `src/detector/` + 特征工程 | **B、C 同学** — Python ML 流水线 |

## 实施阶段

### Phase 1 — 最小原型 ✅（2026-05-24 完成）
- [x] `bpf/syscall.bpf.c`：raw_tp/sys_enter 钩子，捕获全部系统调用
- [x] `bpf/common.h`：packed 事件结构体（时间戳、PID、cgroup_id、syscall_id、进程名）
- [x] `src/loader/loader.c`：libbpf skeleton 加载器，读取 ring buffer → fwrite stdout
- [x] `Makefile`：vmlinux.h 生成 → BPF .o → skeleton → C 链接
- [x] `src/collector/base.py`：抽象接口 `start()` / `stop()` / `events()`
- [x] `src/collector/syscall_collector.py`：subprocess.Popen + struct.unpack
- [x] `src/main.py`：系统调用名称查询 + 格式化输出
- [x] **libbpf 兼容性修复**：Ubuntu 22.04 自带 libbpf 0.5.0 太旧，无法读取内核 6.8 的 BTF，源码编译 v1.4.7
- [x] **结构体对齐修复**：`__attribute__((packed))` 保证 BPF 目标与 x86_64 布局一致

**运行效果：**
```
[SYSCALL] pid=26276 comm=loader syscall=write cgroup=7798
[SYSCALL] pid=1251  comm=gnome-shell syscall=getpid cgroup=5446
[SYSCALL] pid=1512  comm=io.flutter.rast syscall=read cgroup=6832
```

### Phase 2 — 完善采集 + 可扩展性（待开始）
- [ ] 进程采集器：`sched_process_exec` / `fork` / `exit` tracepoints
- [ ] 网络采集器：trace connect/accept/sendto/recvfrom
- [ ] 资源采集器：读取 `/sys/fs/cgroup` 获取每个容器的 CPU/内存
- [ ] 插件注册机制
- [ ] Unix Socket IPC 支持多采集器

### Phase 3 — 异常检测（待开始）
- [ ] 特征工程：系统调用频率直方图、序列熵值、资源时间序列
- [ ] 训练 Isolation Forest / One-Class SVM
- [ ] 实时检测 + 告警

### Phase 4 — 测试与优化（待开始）
- [ ] 模拟正常/异常容器场景
- [ ] CPU 开销调优（采样率、聚合窗口）
- [ ] 准确率调优

## 关键技术决策

1. **stdout pipe vs Unix Socket**：Phase 1 用简单的 stdout pipe。Phase 2 应升级到 Unix Socket 以支持多采集器。
2. **libbpf 1.4.7 源码编译**：Ubuntu 22.04 自带 libbpf 0.5.0 无法读取内核 6.8 的 BTF，必须从 GitHub 编译安装。
3. **Packed 结构体**：BPF 目标与 x86_64 可能对 struct 对齐规则不一致，`__attribute__((packed))` 强制完全一致。
4. **CO-RE + vmlinux.h**：通过 `bpftool btf dump` 从当前内核生成，确保跨内核版本的可移植性。
