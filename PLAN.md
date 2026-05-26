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
│   ├── syscall.bpf.c        # raw_tp 钩子 + sched tracepoints
│   └── common.h             # 共享结构体定义（packed！）
├── src/                      # 用户态代码
│   ├── loader/
│   │   └── loader.c          # C 加载器（libbpf skeleton + stdout）
│   ├── collector/            # Python 采集模块
│   │   ├── __init__.py
│   │   ├── base.py           # 抽象基类 + 插件注册 + UnixSocketCollector
│   │   ├── syscall_collector.py  # 系统调用解析与格式化输出
│   │   ├── process_collector.py  # 进程事件（exec/fork/exit）
│   │   ├── network_collector.py  # 网络 syscall 过滤 + 聚合统计
│   │   └── resource_collector.py # cgroup 资源读取
│   ├── detector/             # ML 检测流水线
│   │   ├── recorder.py       # DataRecorder → 3 个 CSV
│   │   ├── features.py       # 特征提取（20 维 + 归一化）
│   │   ├── model.py          # AnomalyDetector（IsolationForest/PCA）
│   │   ├── train.py          # 训练脚本
│   │   └── detect.py         # 实时检测
│   └── main.py               # 入口：事件分发 + Unix socket 广播
├── scripts/                  # 辅助脚本
│   ├── sim_normal.sh         # 正常行为模拟（宿主机）
│   ├── sim_anomaly.sh        # 异常行为模拟（fork 炸弹/端口扫描等）
│   └── collect_container_data.sh  # Docker 容器数据采集
├── tests/                    # 测试
│   └── test_bpf_capture.sh   # 集成测试（8 项）
├── data/                     # CSV 数据输出目录
├── build/                    # 构建产物（已 gitignore）
├── Makefile                  # 构建系统
├── setup.sh                  # 环境一键安装
├── AGENTS.md                 # 上下文文件（等价于 CLAUDE.md）
├── CLAUDE.md                 # 上下文文件（等价于 AGENTS.md）
└── README.md                 # 项目说明
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

### Phase 2 — 完善采集 + 可扩展性 ✅（2026-05-25 完成）
- [x] 进程采集器：`sched_process_exec` / `fork` / `exit` tracepoints
- [x] 网络采集器：syscall 过滤 connect/accept/sendto/recvfrom
- [x] 资源采集器：读取 `/sys/fs/cgroup` 获取每个容器的 CPU/内存
- [x] 插件注册机制（`@register_collector` + `discover_collectors()`）
- [x] Unix Socket IPC（main.py 作为服务器广播 /tmp/ebpf_events.sock，外部进程通过 `UnixSocketCollector` 订阅）
- [x] 网络采集器添加 syscall 聚合统计（每 5s 汇总）
- [x] 测试脚本 `tests/test_bpf_capture.sh`（8 项测试全通过）

### Phase 3 — 异常检测 ✅（2026-05-26 完成）
- [x] `src/detector/recorder.py`：DataRecorder 插件，写入 3 个 CSV（raw_events、windows、resources）
- [x] 修复 CSV 刷出问题：去掉不可靠的 daemon flush 线程，改为 feed() 中同步刷窗口
- [x] `src/detector/features.py`：20 维 syscall 分类特征 + RobustScaler + 滚动窗口
- [x] `src/detector/model.py`：AnomalyDetector（IsolationForest / PCA 双模式）
- [x] `src/detector/train.py`：采集 → 训练 → 保存 model.joblib
- [x] `src/detector/detect.py`：RealTimeDetector，加载模型对新窗口评分输出 ALARM/OK
- [x] `scripts/sim_normal.sh`：正常行为模拟（文件 I/O、网络、进程、内存）
- [x] `scripts/sim_anomaly.sh`：异常行为模拟（fork 炸弹、写风暴、端口扫描、CPU 峰值）
- [x] `scripts/collect_container_data.sh`：启动 4 个真实 Docker 容器跑 workload → eBPF 监控 → 存 CSV → 清理
- [x] 修复 `_find_container_cgroups()`：支持 Docker 容器 cgroup（`system.slice/docker-*.scope/`）
- [x] 更新 README.md：容器采集方法、完整目录结构、训练/检测命令
- [x] 更新 AGENTS.md / CLAUDE.md：Phase 3 完成，容器采集脚本

### Phase 4 — 测试与优化（待开始）
- [ ] 收集更多容器场景数据（nginx、redis、python web app）
- [ ] 对比测试正常 vs 异常数据，计算准确率/召回率
- [ ] CPU 开销调优（采样率、聚合窗口）
- [ ] 完善文档（API 文档、部署说明）
- [ ] 容器互访检测（跨容器网络连接监控）

## 关键技术决策

1. **stdout pipe vs Unix Socket**：Phase 1 用简单的 stdout pipe。Phase 2 已升级到 Unix Socket 以支持多采集器。
2. **libbpf 1.4.7 源码编译**：Ubuntu 22.04 自带 libbpf 0.5.0 无法读取内核 6.8 的 BTF，必须从 GitHub 编译安装。
3. **Packed 结构体**：BPF 目标与 x86_64 可能对 struct 对齐规则不一致，`__attribute__((packed))` 强制完全一致。
4. **CO-RE + vmlinux.h**：通过 `bpftool btf dump` 从当前内核生成，确保跨内核版本的可移植性。
5. **无监督异常检测**：CSV 不标注正常/异常标签，IsolationForest 学习正常行为分布边界，偏离者标记为异常。
6. **窗口聚合**：1 秒窗口 + cgroup 分桶，17 个 syscall 分类 + 3 个进程事件 = 20 维特征向量。
