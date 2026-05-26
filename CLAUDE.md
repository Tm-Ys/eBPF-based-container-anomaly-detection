# CLAUDE.md — 项目上下文

本文件等价于 AGENTS.md，请修改时对两者同时进行修改。

## 项目概述

基于 eBPF 的容器异常检测 — 中国科学院大学"高级操作系统"课程项目。系统通过 eBPF 采集容器行为数据，使用机器学习检测异常行为。

## 架构（数据流）

```
raw_tp/sys_enter + raw_tp/sys_exit + sched_process_* (内核) → BPF ring buffer
    → C 加载器 (libbpf skeleton) → stdout (二进制结构体)
    → Python subprocess → struct.unpack
        ├── feed() → SyscallCollector / ProcessCollector / NetworkCollector
        └── broadcast() → Unix socket (/tmp/ebpf_events.sock)
                            └── 外部进程订阅（UnixSocketCollector）
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
- ✅ **Phase 2 已完成**（进程/网络/资源采集器 + 插件注册 + Unix Socket IPC + 测试）
- ✅ **Phase 3 已完成**（ML 检测流水线）
  - ✅ `src/detector/recorder.py` — DataRecorder 采集器，注册为插件，写入 3 个 CSV：
    - `raw_*.csv`：原始事件（事件级记录）
    - `windows_*.csv`：1 秒窗口聚合（按 cgroup_id 分桶，17 个 syscall 分类 + process 事件计数，在 feed() 中同步刷出）
    - `resources_*.csv`：cgroup CPU/memory 资源（每 2 秒轮询）
  - ✅ `src/detector/features.py` — 特征提取：20 维特征向量 + RobustScaler + 滚动窗口统计
  - ✅ `src/detector/model.py` — AnomalyDetector（IsolationForest/PCA 双模式，train/predict/anomaly_score/save/load）
  - ✅ `src/detector/train.py` — 训练脚本：自动运行 sim_normal.sh 收集数据 → 训练模型 → 保存 model.joblib
  - ✅ `src/detector/detect.py` — RealTimeDetector：加载 model.joblib，对新窗口评分，输出 ALARM/OK
  - ✅ `scripts/sim_normal.sh` — 正常行为模拟（文件 I/O、网络、进程创建、内存）
  - ✅ `scripts/sim_anomaly.sh` — 异常行为模拟（fork 炸弹、文件写入风暴、端口扫描、CPU 峰值）
  - ✅ `scripts/collect_container_data.sh` — Docker 容器数据采集脚本（启动 4 个容器跑 workload → eBPF 监控 → 存 CSV → 清理）
- ❌ Phase 4（测试）— 未开始

## 目录结构

```
.
├── bpf/                  # eBPF C 程序
│   ├── syscall.bpf.c    # Phase 1+2: raw_tp 钩子 + sched tracepoints
│   └── common.h         # packed 事件结构体
├── src/
│   ├── loader/loader.c  # C 代理：libbpf skeleton + stdout
│   ├── collector/
│   │   ├── base.py      # 采集器抽象接口 + 插件注册
│   │   ├── syscall_collector.py  # subprocess + struct.unpack
│   │   ├── process_collector.py  # Phase 2: 进程事件
│   │   ├── network_collector.py  # Phase 2: 网络 syscall 过滤
│   │   └── resource_collector.py # Phase 2: cgroup 资源读取
│   ├── detector/        # Phase 3: ML 检测
│   │   └── recorder.py  # DataRecorder 采集器，CSV 记录
│   └── main.py          # 入口 + 事件分发
├── build/               # 构建产物（已 gitignore）
├── Makefile             # 构建系统
├── scripts/             # 模拟脚本
│   ├── sim_normal.sh    # 正常行为模拟
│   └── sim_anomaly.sh   # 异常行为模拟
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
    __u8 type;             // 事件类型：0=syscall, 1=process
    char comm[16];         // bpf_get_current_comm() — 进程名
};
```
- **总大小：41 字节** — 必须与 Python `struct.Struct('Q2I2iB16s')` 匹配
- **Packed** 因为 BPF 目标与 x86_64 对 struct 对齐规则可能不一致

### Python 结构体解包
```python
EVENT_FORMAT = struct.Struct("Q2I2iB16s")
# Q=u64, I=u32, I=u32, i=s32, i=s32, B=u8, 16s=char[16]
# 大小：8+4+4+4+4+1+16 = 41 字节
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

## Python 虚拟环境

```bash
source .venv/bin/activate
```

如需使用 Python 做分析或绘图，务必先激活 `.venv` 虚拟环境（已安装 scikit-learn、numpy、pandas、matplotlib、psutil）。所有 Python 相关操作（脚本运行、Jupyter、测试等）均应在虚拟环境内执行。

## 已知问题 / 注意事项

1. **libbpf 版本**：Ubuntu 22.04 自带 libbpf 0.5.0，与内核 6.8 BTF 不兼容。必须从源码编译 libbpf v1.4.7。`setup.sh` 已处理。
2. **sudo 密码**：bash 工具不能运行交互式 sudo。使用 `echo 密码 | sudo -S`。
3. **自捕获**：加载器会捕获自身的系统调用（write、mmap 等），产生噪音。生产环境需要过滤加载器自身的 PID。
4. **Ring buffer 大小**：当前 256KB。高系统调用负载下可能需要调整。
5. **采样率**：默认全部采样。传递 `--rate N` 给 loader 可每 N 个事件采样 1 个。
6. **PID 过滤**：loader 默认自动过滤自身 PID（`getpid()` 写入 `filter_pid` map）。可用 `--pid PID` 指定过滤目标。
