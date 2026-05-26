# eBPF-based Container Anomaly Detection

中国科学院大学 — "高级操作系统"课程项目

基于 eBPF 的容器异常检测系统。通过 eBPF 采集容器行为数据（系统调用、进程事件、网络活动、cgroup 资源），使用 IsolationForest/PCA 自动识别异常行为。

---

## 数据流

```
raw_tp/sys_enter + sched_process_* (内核) → BPF ring buffer
    → C 加载器 (libbpf skeleton) → stdout (41 字节二进制结构体)
    → Python subprocess → struct.unpack
        ├── feed() → SyscallCollector / ProcessCollector / NetworkCollector / DataRecorder
        └── broadcast() → Unix socket (/tmp/ebpf_events.sock)
```

## 快速开始

```bash
# 1. 搭建环境
./setup.sh

# 2. 激活虚拟环境
source .venv/bin/activate

# 3. 构建
make clean && make all

# 4. 运行（实时查看系统调用）
echo 123456 | sudo -S python3 -m src.main --rate 1000
```

## 容器数据采集

有两种方式采集训练数据：

### 方式 A：用真实 Docker 容器（推荐）

```bash
# 60 秒采集：启动容器 → 跑 workload → eBPF 监控 → 存 CSV → 清理
echo 123456 | sudo -S bash scripts/collect_container_data.sh 60

# 查看采集结果
wc -l data/*.csv
```

启动 4 个容器分别模拟不同行为：
- **ebpf_io**: 文件 I/O + 进程创建
- **ebpf_net**: 网络活动（ping、/proc/net 读取）
- **ebpf_proc**: 子进程派生（sh fork）
- **ebpf_cpu**: CPU 密集型（sha256 散列）

### 方式 B：用模拟脚本（无需 Docker）

```bash
# 终端 1：启动 eBPF 监控
echo 123456 | sudo -S timeout 60 python3 -m src.main --rate 1000 2>/dev/null

# 终端 2：运行正常行为模拟
bash scripts/sim_normal.sh

# 或者运行异常行为模拟（会生成告警）
bash scripts/sim_anomaly.sh
```

## 训练与检测

```bash
source .venv/bin/activate

# 训练模型（自动采集数据 → 训练 → 保存 model.joblib）
python3 -m src.detector.train

# 或用已有 CSV 训练
python3 -m src.detector.train data/windows_20260526_*.csv

# 检测：对 CSV 文件评分
python3 -c "
from src.detector.detect import RealTimeDetector
d = RealTimeDetector('model.joblib')
import glob
for f in sorted(glob.glob('data/windows_*.csv'))[-3:]:
    r = d.score_window(f)
    print('ALARM' if r['alarm'] else 'OK', r['n_anomalies'], 'anomalies, score=', round(r['max_score'], 4))
"
```

## 输出数据

| 文件 | 内容 | 更新频率 |
|------|------|----------|
| `data/raw_*.csv` | 原始事件（逐条记录） | 实时 |
| `data/windows_*.csv` | 1 秒窗口聚合（20 维特征） | 每秒 |
| `data/resources_*.csv` | cgroup CPU + 内存资源 | 每 2 秒 |
| `model.joblib` | 训练好的 IsolationForest 模型 | 手动 |

### 窗口特征（20 维）

17 个 syscall 分类计数（file_read, file_write, file_open, file_close, file_meta, file_sync, mem_mmap, net_sock, net_io, proc_create, proc_exit_wait, proc_signal, ipc, futex, clock, poll_epoll, other）+ 3 个进程事件计数（exec, fork, exit）

## 项目结构

```
.
├── bpf/                    # eBPF 内核程序
│   ├── syscall.bpf.c      # raw_tp 钩子 + sched tracepoint
│   └── common.h           # packed 事件结构体 (41B)
├── src/
│   ├── loader/loader.c    # C 加载器 (libbpf skeleton)
│   ├── collector/         # Python 采集模块
│   │   ├── base.py                # 抽象接口 + 插件注册 + UnixSocketCollector
│   │   ├── syscall_collector.py   # 系统调用解析与输出
│   │   ├── process_collector.py   # 进程事件 (exec/fork/exit)
│   │   ├── network_collector.py   # 网络 syscall 过滤 + 统计
│   │   └── resource_collector.py  # cgroup 资源读取
│   ├── detector/          # ML 检测流水线
│   │   ├── recorder.py    # DataRecorder → 3 个 CSV
│   │   ├── features.py    # 特征提取 (20 维 + 归一化)
│   │   ├── model.py       # AnomalyDetector (IsolationForest/PCA)
│   │   ├── train.py       # 训练脚本
│   │   └── detect.py      # 实时检测
│   └── main.py            # 入口：事件分发 + Unix socket 广播
├── scripts/               # 辅助脚本
│   ├── sim_normal.sh      # 正常行为模拟（宿主机）
│   ├── sim_anomaly.sh     # 异常行为模拟（fork 炸弹/端口扫描等）
│   └── collect_container_data.sh  # Docker 容器数据采集
├── data/                  # CSV 数据输出目录
├── build/                 # 构建产物
├── Makefile               # 构建系统
├── setup.sh               # 环境搭建
├── tests/test_bpf_capture.sh  # 集成测试（8 项）
├── PLAN.md                # 规划与进度
├── AGENTS.md              # 项目上下文
└── CLAUDE.md              # 项目上下文
```

## 进度

| Phase | 内容 | 状态 |
|-------|------|------|
| Phase 1 | 系统调用监控流水线（内核钩子 → ring buffer → C 加载器 → Python） | ✅ |
| Phase 2 | 采集器扩展（进程/网络/资源） + 插件注册 + Unix Socket IPC + 测试 | ✅ |
| Phase 3 | ML 检测（DataRecorder → 特征提取 → IsolationForest → 告警） | ✅ |
| Phase 4 | 测试、性能优化、文档 | ❌ |

详见 [PLAN.md](PLAN.md)。

## 事件结构体 (bpf/common.h)

```c
struct event {              // 41 bytes packed
    __u64 timestamp_ns;     // bpf_ktime_get_ns()
    __u32 pid;
    __u32 cgroup_id;        // bpf_get_current_cgroup_id()
    __s32 syscall_id;       // raw_tp/sys_enter 的 ctx->id
    __s32 ret;              // 返回值（sys_exit, enter 时为 0）
    __u8 type;              // 0=syscall, 1=process
    char comm[16];          // bpf_get_current_comm()
};
```

```python
EVENT_FORMAT = struct.Struct("Q2I2iB16s")
# 8+4+4+4+4+1+16 = 41 字节
```

## 构建

```bash
make clean && make all
```

步骤：
1. `bpftool btf dump` → `build/vmlinux.h`
2. `clang -target bpf` → `build/syscall.bpf.o`
3. `bpftool gen skeleton` → `build/syscall.skel.h`
4. `gcc -lbpf -lelf -lz` → `build/loader`

## 依赖

- 系统: Linux 5.4+, BTF / CO-RE, Docker（可选，用于容器采集）
- 工具: clang, llvm, bpftool, cmake, git
- 库: libbpf (≥ 1.0), libelf, libz
- Python: scikit-learn, numpy, pandas, psutil（详见 `.venv`）

## 已知问题

1. libbpf 兼容性: Ubuntu 22.04 自带 0.5.0 与内核 6.8 BTF 不兼容，`setup.sh` 自动处理
2. 自捕获噪音: C 加载器会捕获自身的 write/mmap 调用
3. ring buffer 大小: 默认 256KB，高负载下需调大
4. clock 不匹配: BPF `bpf_ktime_get_ns()` = monotonic, Python `time.time_ns()` = realtime
