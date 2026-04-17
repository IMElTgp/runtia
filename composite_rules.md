# Composite Rules

本文件只保留当前 collector 已采集数据能支撑的 composite rule 文字逻辑。Signal schema、key/index、覆盖去重策略见 `composite_rule_design.md`。

## 当前数据边界

已采集：

- 线程身份：`Tid`、`Tgid`、`Comm`、`IsMainThread`。
- capability：`CapEff`、`CapPrm`、`CapAmb`、`CapInh`、`CapBnd`。
- seccomp：`SeccompMode`、`SeccompFilters`。
- namespace：`user`、`mnt`、`pid`。
- namespace owner：`mnt` / `pid` namespace 的 owner user namespace。
- mountinfo：每个 mount namespace 的挂载点、文件系统类型、source、mount options、super options。

## 当前可实现规则

| ID | 组合逻辑 | 结果风险 | 备注 |
|---|---|---|---|
| CR-001 | `CapEff` 中存在分数 4/5 capability + `SeccompMode == 0` | `HighRisk` | 通用兜底规则；表示高危有效权限与未过滤 syscall 面叠加。 |
| CR-002 | `CAP_SYS_ADMIN` in `CapEff` + `SeccompMode == 0` | `HighRisk` | 比 CR-001 更具体；如果还命中敏感 mount 规则，由更具体规则覆盖。 |
| CR-003 | `CAP_SYS_ADMIN` in `CapEff` + mount namespace 中 `/proc/sys` 或等价 sysctl 路径可写 | `Fatal` | 可写 sysctl 路径是具体高危内核配置对象；比单独 `CAP_SYS_ADMIN` 更严重。 |
| CR-004 | `CAP_SYS_ADMIN` in `CapEff` + mount namespace 中 `/sys`、`/sys/kernel`、`/sys/fs/cgroup` 等 sysfs 敏感路径可写 | `Fatal` | 可写 sysfs/cgroup 路径是具体高危内核对象；比单独 `CAP_SYS_ADMIN` 更严重。 |
| CR-005 | `CAP_DAC_OVERRIDE` 或 `CAP_DAC_READ_SEARCH` in `CapEff` + 敏感挂载可写 | `Fatal` for `/host`, `/rootfs`, `/etc`, `/var/run`, `/run`; otherwise `HighRisk` | 敏感挂载先按 mount point/source 粗判；明确宿主根、配置或运行时路径时升级为 `Fatal`。 |
| CR-006 | `CAP_MKNOD` in `CapEff` + mount namespace 中 `/dev` 或设备相关路径可写 | `HighRisk` | 基于 mountinfo 判断可写设备路径；当前不直接判 `Fatal`。 |
| CR-007 | `CAP_SYS_RAWIO` in `CapEff` + mount namespace 中 `/dev` 或设备相关路径可写 | `Fatal` | raw I/O 能力叠加可写设备路径时，应作为最高优先级处理。 |
| CR-008 | `CAP_SETFCAP` in `CapEff` + 存在 `rw` 且非 `noexec` 的挂载 | `HighRisk` | 表示可给可执行路径上的文件设置 capability。 |
| CR-009 | `CAP_SYS_PTRACE` in `CapEff` + 同一 PID namespace 中存在多个不同 `Tgid` | `HighRisk` | 表示可影响同一 pidns 内其他进程。 |
| CR-010 | `CAP_KILL` in `CapEff` + 同一 PID namespace 中存在多个不同 `Tgid` | `MediumRisk` | 表示可绕过 signal 权限检查并影响同一 pidns 内其他进程。 |
| CR-011 | 同一 `Tgid` 中，非主线程 `CapEff` 拥有主线程没有的 capability | 分数 4/5: `HighRisk`; 分数 3: `MediumRisk`; 分数 1/2: `LowRisk`/info | 表示同一进程内部权限分布异常。 |
| CR-012 | `CapPrm`/`CapAmb`/`CapInh` 中存在分数 4/5 capability + `SeccompMode == 0` | 分数 5: `HighRisk`/`MediumRisk`; 分数 4: `MediumRisk` | 如果同一 capability 已在 `CapEff` 中，由 CR-001/CR-002 覆盖。 |
