# capabilities（能力）

- 来源：`capabilities(7)` 和 `/usr/include/linux/capability.h`。
- capability 是按线程保存的位集合。`/proc/<pid>/task/<tid>/status` 会把它们暴露为十六进制掩码：
  - `CapInh`：可继承 capability。
  - `CapPrm`：已许可 capability。线程只有先拥有某个 permitted capability，才能把它变为 effective。
  - `CapEff`：当前生效 capability。内核权限检查使用这一组。
  - `CapBnd`：边界 capability。它限制 `execve` 期间可以获得的 capability。
  - `CapAmb`：环境 capability。对非特权程序执行 `execve` 时，这些 capability 可以保留。
- bit `0` 到 `/proc/sys/kernel/cap_last_cap` 表示当前内核支持的 capability。高于 `cap_last_cap` 的 bit 没有被当前运行的内核实现。
- bit 0：`CAP_CHOWN`，任意修改文件 UID/GID。
- bit 1：`CAP_DAC_OVERRIDE`，绕过文件读、写、执行的 DAC 权限检查。
- bit 2：`CAP_DAC_READ_SEARCH`，绕过文件读检查以及目录读/搜索检查。
- bit 3：`CAP_FOWNER`，绕过许多文件操作中的所有权检查，设置文件标志/ACL，忽略 sticky bit 删除检查，使用 `O_NOATIME`。
- bit 4：`CAP_FSETID`，在通常会被清除或拒绝的情况下保留/设置 set-user-ID 和 set-group-ID 位。
- bit 5：`CAP_KILL`，绕过发送信号时的权限检查。
- bit 6：`CAP_SETGID`，修改 GID 和 supplementary groups，通过 UNIX socket 伪造 GID 凭据，在 user namespace 中写 GID 映射。
- bit 7：`CAP_SETUID`，修改 UID，通过 UNIX socket 伪造 UID 凭据，在 user namespace 中写 UID 映射。
- bit 8：`CAP_SETPCAP`，在现代 file-capability 内核上调整 inheritable capabilities、从 bounding set 中删除 capability、修改 securebits。
- bit 9：`CAP_LINUX_IMMUTABLE`，设置 append-only 和 immutable inode 标志。
- bit 10：`CAP_NET_BIND_SERVICE`，绑定小于 1024 的特权 Internet 端口。
- bit 11：`CAP_NET_BROADCAST`，未使用；历史上用于 socket 广播和监听 multicast。
- bit 12：`CAP_NET_ADMIN`，执行网络管理操作，例如接口配置、防火墙/路由修改、TOS、混杂模式、multicast、特权 socket 选项。
- bit 13：`CAP_NET_RAW`，使用 raw socket 和 packet socket；为透明代理绑定任意地址。
- bit 14：`CAP_IPC_LOCK`，锁定内存并分配 huge pages。
- bit 15：`CAP_IPC_OWNER`，绕过 System V IPC 对象的权限检查。
- bit 16：`CAP_SYS_MODULE`，加载和卸载内核模块。
- bit 17：`CAP_SYS_RAWIO`，执行 raw I/O 操作，例如 I/O port、`/proc/kcore`、`/dev/mem`、MSR 设备、低地址映射和特权设备命令。
- bit 18：`CAP_SYS_CHROOT`，使用 `chroot`，并通过 `setns` 切换 mount namespace。
- bit 19：`CAP_SYS_PTRACE`，trace 和检查任意进程，包括内存访问以及相关调试操作。
- bit 20：`CAP_SYS_PACCT`，使用进程 accounting。
- bit 21：`CAP_SYS_ADMIN`，宽泛的系统管理 capability，包括 mount、namespace、许多特权 ioctl、syslog fallback、无需 `no_new_privs` 安装 seccomp filter，以及其他大量重载操作。
- bit 22：`CAP_SYS_BOOT`，重启系统，并通过 `kexec_load` 加载新内核。
- bit 23：`CAP_SYS_NICE`，修改 nice 值、调度策略/优先级、CPU affinity、I/O priority 和进程页面迁移。
- bit 24：`CAP_SYS_RESOURCE`，绕过或提高资源限制、quota、文件系统保留空间、pipe/message queue 限制以及相关资源控制。
- bit 25：`CAP_SYS_TIME`，设置系统时钟和硬件 real-time clock。
- bit 26：`CAP_SYS_TTY_CONFIG`，使用 `vhangup` 和特权 virtual terminal ioctl。
- bit 27：`CAP_MKNOD`，通过 `mknod` 创建设备等特殊文件。
- bit 28：`CAP_LEASE`，在任意文件上建立 lease。
- bit 29：`CAP_AUDIT_WRITE`，向内核 audit log 写记录。
- bit 30：`CAP_AUDIT_CONTROL`，启用、禁用和配置内核 auditing。
- bit 31：`CAP_SETFCAP`，在文件上设置任意 capability；某些新 user namespace 中的 UID 0 映射也需要它。
- bit 32：`CAP_MAC_OVERRIDE`，为 Smack 绕过 Mandatory Access Control 检查。
- bit 33：`CAP_MAC_ADMIN`，为 Smack 修改 Mandatory Access Control 配置/状态。
- bit 34：`CAP_SYSLOG`，执行特权 `syslog` 操作，并在 `kptr_restrict=1` 时查看内核地址。
- bit 35：`CAP_WAKE_ALARM`，设置可以唤醒系统的 timer。
- bit 36：`CAP_BLOCK_SUSPEND`，使用可以阻止系统 suspend 的功能。
- bit 37：`CAP_AUDIT_READ`，通过 multicast netlink 读取 audit log。
- bit 38：`CAP_PERFMON`，使用性能监控机制，例如 `perf_event_open` 以及影响性能的 BPF 操作。
- bit 39：`CAP_BPF`，执行特权 BPF 操作。
- bit 40：`CAP_CHECKPOINT_RESTORE`，使用 checkpoint/restore 操作，例如设置 `ns_last_pid`、使用 `clone3` 的 `set_tid`、读取其他进程的 `map_files` symlink。
- capability 限制优先级：
  - 5：最高优先级限制。默认禁止；如果出现在 `CapEff`、`CapPrm`、`CapAmb` 或 `CapBnd` 中，都应该产生强告警或要求明确豁免。
  - 4：强限制。只有特定工作负载明确需要时才允许；如果出现在 `CapEff` 中应产生高风险 finding。
  - 3：按场景限制。普通应用容器一般应删除；如果业务确实需要，可以在隔离条件明确时放宽。
  - 2：较低风险但仍应最小化。可以比 4/5 更宽松，但不应无理由保留。
  - 1：相对低风险或未使用。可以作为最晚处理的 capability，但仍遵循 least privilege。
  - 这个 ranking 是面向普通 Linux 应用容器的安全启发式，不是内核官方排序。同一个分数内按 bit 顺序列出，不表示同分能力之间还有严格强弱顺序。
- capability power ranking：

| bit | capability | 限制分数 | 限制建议 |
|---:|---|---:|---|
| 0 | `CAP_CHOWN` | 2 | 文件所有权修改能力；有可写 host mount 时风险升高。 |
| 1 | `CAP_DAC_OVERRIDE` | 5 | 绕过文件 DAC 读/写/执行检查；和敏感挂载组合时非常危险。 |
| 2 | `CAP_DAC_READ_SEARCH` | 5 | 绕过文件读和目录搜索检查，并涉及 `open_by_handle_at` 等能力；优先删除。 |
| 3 | `CAP_FOWNER` | 3 | 绕过文件所有者检查并修改文件元数据；普通应用不应默认保留。 |
| 4 | `CAP_FSETID` | 2 | 保留 setuid/setgid 位；可辅助权限路径，但单独爆炸半径较小。 |
| 5 | `CAP_KILL` | 2 | 绕过 signal 权限检查；如果共享 host PID namespace，风险升高。 |
| 6 | `CAP_SETGID` | 3 | 修改 GID/group 和 namespace GID 映射；非特权容器应谨慎保留。 |
| 7 | `CAP_SETUID` | 3 | 修改 UID 和 namespace UID 映射；可切换到 UID 0，普通服务应谨慎保留。 |
| 8 | `CAP_SETPCAP` | 4 | 修改 capability 相关状态和 securebits；会影响后续权限转换，应该强限制。 |
| 9 | `CAP_LINUX_IMMUTABLE` | 3 | 设置 immutable/append-only 标志；在可写挂载上可能造成持久化或 DoS。 |
| 10 | `CAP_NET_BIND_SERVICE` | 1 | 只用于绑定低端口；如果服务需要 80/443，可相对宽松。 |
| 11 | `CAP_NET_BROADCAST` | 1 | 当前未使用；通常没有必要保留，也不是主要风险点。 |
| 12 | `CAP_NET_ADMIN` | 5 | 控制网络接口、防火墙、路由和特权 socket 选项；如果共享 host netns 更危险。 |
| 13 | `CAP_NET_RAW` | 4 | 使用 raw/packet socket；可用于嗅探、伪造和扩大网络攻击面。 |
| 14 | `CAP_IPC_LOCK` | 3 | 锁内存和 huge pages；可能造成资源压力，也可能保护/隐藏敏感内存。 |
| 15 | `CAP_IPC_OWNER` | 3 | 绕过 System V IPC 权限检查；共享 IPC namespace 时风险更高。 |
| 16 | `CAP_SYS_MODULE` | 5 | 加载/卸载内核模块；等价于给内核加载代码，必须严格禁止。 |
| 17 | `CAP_SYS_RAWIO` | 5 | 访问 raw I/O、内核内存和设备低层接口；容器中应严格禁止。 |
| 18 | `CAP_SYS_CHROOT` | 3 | 使用 `chroot` 和 mount namespace `setns`；单独不是 root escape，但常作为组合风险。 |
| 19 | `CAP_SYS_PTRACE` | 5 | 读写/调试任意进程；共享 PID namespace 或同 UID 进程多时非常危险。 |
| 20 | `CAP_SYS_PACCT` | 2 | 修改进程 accounting；通常不需要，影响面相对较窄。 |
| 21 | `CAP_SYS_ADMIN` | 5 | 过度重载的系统管理能力；包括 mount、namespace、许多 ioctl 和其他高危操作，默认禁止。 |
| 22 | `CAP_SYS_BOOT` | 5 | reboot 和 `kexec_load`；可造成 host 级 DoS 或加载新内核，严格禁止。 |
| 23 | `CAP_SYS_NICE` | 3 | 修改调度、优先级、CPU affinity 和 I/O priority；主要风险是资源争用/DoS。 |
| 24 | `CAP_SYS_RESOURCE` | 4 | 提高/绕过资源限制、quota、pipe/mqueue 限制，并涉及 `PR_SET_MM`；强限制。 |
| 25 | `CAP_SYS_TIME` | 4 | 修改系统/硬件时钟；会影响日志、认证、证书和集群时间假设。 |
| 26 | `CAP_SYS_TTY_CONFIG` | 2 | 特权 TTY 操作；多数容器不需要，存在 TTY/控制台暴露时风险升高。 |
| 27 | `CAP_MKNOD` | 4 | 创建设备节点；如果设备 cgroup 或挂载配置不严，可成为访问宿主设备的路径。 |
| 28 | `CAP_LEASE` | 3 | 设置文件 lease；可能阻塞其他进程访问文件，普通应用少见。 |
| 29 | `CAP_AUDIT_WRITE` | 2 | 写 audit log；可能污染日志，但通常不直接扩大容器权限。 |
| 30 | `CAP_AUDIT_CONTROL` | 4 | 控制内核 auditing；可关闭/修改审计规则，应该强限制。 |
| 31 | `CAP_SETFCAP` | 4 | 给文件设置 capability，也影响某些 user namespace UID 0 映射；强限制。 |
| 32 | `CAP_MAC_OVERRIDE` | 4 | 绕过 Smack MAC；如果系统未使用 Smack，实际影响较小，但不能按默认安全处理。 |
| 33 | `CAP_MAC_ADMIN` | 4 | 管理 Smack MAC；如果系统未使用 Smack，实际影响较小，但不能按默认安全处理。 |
| 34 | `CAP_SYSLOG` | 3 | 特权 syslog 和内核地址可见性；主要是信息泄露和日志面风险。 |
| 35 | `CAP_WAKE_ALARM` | 2 | 设置唤醒系统的 timer；主要是电源/唤醒行为风险。 |
| 36 | `CAP_BLOCK_SUSPEND` | 2 | 阻止系统 suspend；主要是可用性/电源管理风险。 |
| 37 | `CAP_AUDIT_READ` | 3 | 读取 audit log；可能泄露 host 或其他 workload 的安全事件。 |
| 38 | `CAP_PERFMON` | 4 | 使用 perf 监控；可能泄露跨进程/跨容器信息，普通容器应删除。 |
| 39 | `CAP_BPF` | 5 | 特权 BPF；可观察或影响内核/网络路径，普通容器必须严格限制。 |
| 40 | `CAP_CHECKPOINT_RESTORE` | 4 | checkpoint/restore 相关进程能力；涉及 PID 控制和读取其他进程 `map_files`，强限制。 |
- main thread 和 common thread 的限制策略：
  - capability 检查是 per-thread 的。`IsMainThread` 只能作为报告证据和风险上下文，不能作为允许高危 capability 的理由。
  - main thread 拥有 capability 时，说明整个进程入口具备该权限；common thread 拥有 capability 时，说明任意执行到该线程的代码也可直接使用该权限。
  - common thread 不应比 main thread 拥有更多或更高分 capability。若非 main thread 的 `CapEff` 包含 main thread 没有的 capability，至少生成 MediumRisk；如果该 capability 分数为 4/5，生成 HighRisk。

| 限制分数 | main thread 的 `CapEff` | common thread 的 `CapEff` | `CapPrm`/`CapAmb`/`CapBnd` 中保留 |
|---:|---|---|---|
| 5 | 即使是 main thread 也必须强限制；默认 HighRisk，建议删除。 | 必须强限制；默认 HighRisk，如果还共享 host namespace/敏感 mount/device，可升级为 Fatal。 | 不应保留；`CapPrm`/`CapAmb` 生成 HighRisk，`CapBnd` 至少 MediumRisk。 |
| 4 | 即使是 main thread 也应限制；没有明确业务理由时 HighRisk。 | 必须限制；默认 HighRisk，尤其是 worker/handler 线程。 | 不应默认保留；`CapPrm`/`CapAmb` 至少 MediumRisk，`CapBnd` 记录为 MediumRisk 或 LowRisk，取决于是否有 file capability 路径。 |
| 3 | 普通应用容器默认限制；有明确需求时可降为 MediumRisk。 | 比 main thread 更严格；普通 common thread 中出现时生成 MediumRisk，如果它比 main thread 多则提高风险。 | 记录为 LowRisk/MediumRisk；如果存在可写 host mount、host namespace 或 setuid/file capability 路径，则提高风险。 |
| 2 | 可以相对宽松；通常生成 LowRisk 或 Informational。 | 可以相对宽松，但如果 common thread 比 main thread 多，记录 LowRisk。 | 通常 Informational；和 host PID/net/ipc namespace、敏感 mount、device 暴露组合时提高到 LowRisk/MediumRisk。 |
| 1 | 可以最宽松；通常只记录 Informational，必要时不生成 finding。 | 可以最宽松；如果不是异常增量，可以只记录 Informational。 | 只做 Informational 或不记录；但仍保留在原始 evidence 中。 |
- 哪些 capability 可以“放宽”：
  - 没有 capability 应被无条件自由分配；least privilege 仍然是默认策略。
  - 分数 1 可以作为默认最宽松组：`CAP_NET_BIND_SERVICE` 可因绑定低端口保留；`CAP_NET_BROADCAST` 当前未使用，保留意义不大但风险较低。
  - 分数 2 可以只做 LowRisk/Informational，但前提是没有共享 host namespace、没有可写敏感 host mount、没有 device 暴露，且 common thread 没有比 main thread 更多 capability。
  - 分数 3 不应自由分配。main thread 可因明确业务需求例外；common thread 应更严格。
  - 分数 4/5 不应自由分配。无论 main thread 还是 common thread，只要在 `CapEff` 中出现都应产生强 finding。
- 初始 analyzer 关注点：
  - 标记所有出现在 `CapEff` 中的 capability。
  - `CapEff` 中分数为 5 的 capability：生成 HighRisk finding，并建议从 `CapEff`、`CapPrm`、`CapAmb`、`CapBnd` 中删除，除非用户显式声明特权容器。
  - `CapEff` 中分数为 4 的 capability：生成 HighRisk 或 MediumRisk finding，取决于是否共享 host namespace、是否存在敏感 host mount、是否有 device 暴露。
  - `CapEff` 中分数为 3 的 capability：生成 MediumRisk finding；如果容器是普通应用服务，建议 drop。
  - `CapEff` 中分数为 1-2 的 capability：默认生成 LowRisk 或 Informational finding；如果和 host PID/net/ipc namespace、可写 host mount、device 暴露组合，则提高风险级别。
  - main thread 和 common thread 的差异用于调整风险，不用于豁免高危 capability。common thread 拥有分数 3/4/5 的 `CapEff`，或者拥有 main thread 没有的 `CapEff`，都应该提高优先级。
  - 如果某个 capability 不在 `CapEff` 中，但仍保留在 `CapPrm` 或 `CapAmb` 中，也要记录，因为它仍可能通过 capability 转换或 exec 转换变为 effective。
  - 单独记录过宽的 `CapBnd`。它本身不会授予 capability，但会为后续 `execve`/file-capability 获得 capability 留出空间。

# namespaces（命名空间）

# mount（挂载）

# seccomp
