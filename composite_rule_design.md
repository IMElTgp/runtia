# Composite Rule Design Notes

本文档解释 composite rule 怎么实现。实际规则列表见 `composite_rules.md`。

## 为什么需要 Signal

`Finding` 是最终报告给用户看的结果，不适合拿来互相组合。

例如这两个事实：

```text
线程 1234 有 CAP_SYS_ADMIN
线程 1234 所在 mount namespace 里 /proc/sys 可写
```

它们组合后才形成更强的结论：

```text
线程 1234 有 CAP_SYS_ADMIN，并且能看到可写的 /proc/sys。
```

这里前两个事实就是 `Signal`，最后的结论才是 `Finding`。

所以流程是：

```text
Snapshot 原始数据
  -> Signal 基础事实
  -> Composite Rule 组合基础事实
  -> Finding 最终报告
```

不要用 `Finding.Title` 或 `Finding.Summary` 做组合判断。它们是给人看的文字，不是给程序匹配用的稳定结构。

## Signal 分几种

当前代码采集到的东西主要有三类：

```text
线程自己的状态
namespace 自己的状态
线程和 namespace 的归属关系
```

前两类通常必须有。第三类可以做成独立 signal，也可以省略。

如果线程 signal 里已经直接带了 `UserNS`、`MntNS`、`PIDNS`，那就不需要额外生成“线程属于哪个 namespace”的 signal。当前 `target.Thread` 已经有这些字段，所以 MVP 可以先省略关系 signal。

### 1. 线程状态 Signal

这类 signal 描述“某个线程自己有什么状态”。

例子：

```text
线程 1234 有 CAP_SYS_ADMIN in CapEff
线程 1234 seccomp disabled
线程 1234 是主线程
线程 1235 是 worker 线程
```

建议的 signal kind：

| signal kind | 表示什么 |
|---|---|
| `thread.cap.effective` | 某线程的 `CapEff` 里有某个 capability。 |
| `thread.cap.available` | 某线程的 `CapPrm`、`CapAmb` 或 `CapInh` 里有某个 capability。 |
| `thread.cap.bounding` | 某线程只在 `CapBnd` 里保留某个 capability。 |
| `thread.seccomp.disabled` | 某线程 `SeccompMode == 0`。 |
| `thread.main` | 某线程是 main thread。 |
| `thread.worker` | 某线程不是 main thread。 |

这些 signal 至少应该带：

```text
tid
tgid
userns_inode
mntns_inode
pidns_inode
```

capability 相关 signal 还应该带：

```text
cap
cap_score
sets
```

其中 `sets` 用来记录证据，例如：

```text
["CapEff", "CapPrm", "CapBnd"]
```

### 2. Namespace 状态 Signal

这类 signal 描述“某个 namespace 自己有什么状态”。

例子：

```text
PID namespace 4026532410 里有多个进程
mount namespace 4026532409 里 /proc/sys 可写
mount namespace 4026532409 里 /sys 可写
mount namespace 4026532409 里 /dev 可写
```

建议的 signal kind：

| signal kind | 表示什么 |
|---|---|
| `ns.pid.multiple_tgid` | 同一个 PID namespace 中有多个不同 `Tgid`。 |
| `ns.mnt.sensitive_rw` | mount namespace 中存在敏感可写挂载。 |
| `ns.mnt.proc_sys_rw` | mount namespace 中 `/proc/sys` 或等价路径可写。 |
| `ns.mnt.sysfs_rw` | mount namespace 中 `/sys`、`/sys/kernel`、`/sys/fs/cgroup` 等路径可写。 |
| `ns.mnt.dev_rw` | mount namespace 中 `/dev` 或设备相关路径可写。 |
| `ns.mnt.rw_exec` | mount namespace 中存在 `rw` 且没有 `noexec` 的挂载。 |
| `ns.owner_userns` | 某个 `mnt` 或 `pid` namespace 的 owner user namespace 是哪个。 |

这些 signal 应该带对应的 namespace ID，例如：

```text
pidns_inode
mntns_inode
userns_inode
owner_userns_inode
```

mount 相关 signal 还应该带：

```text
mount_point
source
fs_type
mount_options
super_options
```

### 3. 线程属于哪个 Namespace 的 Signal，可选

这类 signal 描述“某个线程在哪个 namespace 里”。

它本身不代表风险，但它是组合规则里的桥。

如果线程 signal 自己已经带了 `userns_inode`、`mntns_inode`、`pidns_inode`，可以不生成这类 signal。

例子：

```text
线程 1234 在 mount namespace 4026532409
线程 1234 在 PID namespace 4026532410
线程 1234 在 user namespace 4026531837
```

建议的 signal kind：

| signal kind | 表示什么 |
|---|---|
| `rel.thread_in_userns` | 某线程属于某个 user namespace。 |
| `rel.thread_in_mntns` | 某线程属于某个 mount namespace。 |
| `rel.thread_in_pidns` | 某线程属于某个 PID namespace。 |
| `rel.thread_mntns_owner_userns` | 某线程所在 mount namespace 的 owner user namespace。 |
| `rel.thread_pidns_owner_userns` | 某线程所在 PID namespace 的 owner user namespace。 |

这些 signal 应该带：

```text
tid
userns_inode / mntns_inode / pidns_inode
owner_userns_inode
```

## 怎么组合 Signal

组合时不要全局两两比较所有 signal。

应该用 key 查找。

例如规则：

```text
CAP_SYS_ADMIN + writable /proc/sys
```

可以这样匹配：

```text
1. 找到 thread.cap.effective:
   tid=1234, cap=CAP_SYS_ADMIN, mntns_inode=4026532409

2. 用 mntns_inode=4026532409 找到 ns.mnt.proc_sys_rw

3. 两个事实连起来，生成最终 Finding
```

这不是 `O(n^2)` 两两比较，而是：

```text
遍历少量相关 signal + map 查询
```

## 建议的 Key

第一版可以用这些 key：

```text
tid:<tid>
tgid:<tgid>
cap:<cap_name>
pidns:<inode>
mntns:<inode>
userns:<inode>
owner_userns:<inode>
tid_ns:<tid>:<ns_type>
mntns_mount:<mntns_inode>:<mount_point>
```

例子：

```text
tid:1234
tgid:1200
cap:CAP_SYS_ADMIN
mntns:4026532409
pidns:4026532410
```

## 建议的索引

可以先用简单索引：

```go
type SignalIndex struct {
	ByKind       map[SignalKind][]*Signal
	ByKey        map[string][]*Signal
	ByKindAndKey map[SignalKind]map[string][]*Signal
}
```

含义：

```text
ByKind:
  按 signal 类型找。
  例如找所有 thread.cap.effective。

ByKey:
  按 key 找。
  例如找所有和 tid:1234 有关的 signal。

ByKindAndKey:
  同时按类型和 key 找。
  例如找 mntns:4026532409 里的 ns.mnt.proc_sys_rw。
```

## 去重

组合 finding 应该覆盖低级 signal，避免重复报告。

例如已经报了：

```text
CAP_SYS_ADMIN with writable /proc/sys
```

就不要再重复报：

```text
Effective CAP_SYS_ADMIN present
CAP_SYS_ADMIN without seccomp filtering
```

建议做法：

```text
1. 每个 signal 有稳定 ID。
2. composite rule 命中后，把用到的 signal ID 标记为 covered。
3. 最后生成普通基础 finding 时，跳过 covered signal。
```

如果两个组合 finding 描述的是不同路径，可以都保留。

例如：

```text
CAP_SYS_ADMIN with writable /proc/sys
CAP_DAC_OVERRIDE with sensitive writable mount
```

## Capability 去重

同一个 capability 可能同时出现在多个 capability set 中。

例如：

```text
CAP_SYS_ADMIN in CapEff
CAP_SYS_ADMIN in CapPrm
CAP_SYS_ADMIN in CapBnd
```

不要生成三个同级 signal。按这个优先级只生成一个主要 signal：

```text
CapEff
  > CapPrm / CapAmb / CapInh
  > CapBnd only
```

也就是：

```text
如果 capability 在 CapEff 中：
  生成 thread.cap.effective

否则如果 capability 在 CapPrm / CapAmb / CapInh 中：
  生成 thread.cap.available

否则如果 capability 只在 CapBnd 中：
  生成 thread.cap.bounding
```

其他 set 不丢掉，放进 `sets` 或 evidence 里。

## 例子：CR-005 怎么匹配

规则：

```text
CAP_DAC_OVERRIDE 或 CAP_DAC_READ_SEARCH in CapEff
+
敏感挂载可写
```

目标：

```text
如果敏感挂载是 /host、/rootfs、/etc、/var/run、/run，生成 Fatal。
否则生成 HighRisk。
```

假设 snapshot 中有：

```text
thread 1234:
  CapEff includes CAP_DAC_OVERRIDE
  MntNS inode = 4026532409

mount namespace 4026532409:
  mount point = /host
  mount options include rw
```

可以生成两个 signal。

第一个 signal：线程有 DAC bypass capability。

```text
kind: thread.cap.effective
tid: 1234
tgid: 1200
mntns_inode: 4026532409
cap: CAP_DAC_OVERRIDE
cap_score: 5
sets: ["CapEff"]
keys:
  tid:1234
  tgid:1200
  mntns:4026532409
  cap:CAP_DAC_OVERRIDE
```

第二个 signal：这个 mount namespace 有敏感可写挂载。

```text
kind: ns.mnt.sensitive_rw
mntns_inode: 4026532409
mount_point: /host
source: ...
fs_type: ...
keys:
  mntns:4026532409
  mntns_mount:4026532409:/host
```

匹配过程：

```text
1. 遍历 thread.cap.effective signal。

2. 只保留 cap 是 CAP_DAC_OVERRIDE 或 CAP_DAC_READ_SEARCH 的 signal。

3. 从 capability signal 里直接取 mntns_inode。

4. 用 mntns:<inode> 查 ns.mnt.sensitive_rw。

5. 找到后生成 composite finding。

6. 根据 mount_point 决定最终风险：
   /host、/rootfs、/etc、/var/run、/run => Fatal
   其他敏感挂载 => HighRisk
```

伪代码：

```go
func matchDACBypassSensitiveMount(idx *SignalIndex) []model.Finding {
	var findings []model.Finding

	for _, capSig := range idx.ByKind[SignalThreadCapEffective] {
		if capSig.Cap != CAP_DAC_OVERRIDE &&
			capSig.Cap != CAP_DAC_READ_SEARCH {
			continue
		}

		mntKey := nsKey("mnt", capSig.MntNSInode)
		mountSignals := idx.ByKindAndKey[SignalNSMntSensitiveRW][mntKey]

		for _, mountSig := range mountSignals {
			risk := HighRisk
			if isFatalSensitiveMount(mountSig.MountPoint) {
				risk = Fatal
			}

			findings = append(findings, model.Finding{
				Category:  "capabilities",
				RiskLevel: risk,
				Title:     "DAC bypass capability with sensitive writable mount",
				Summary:   "The thread has an effective DAC bypass capability and its mount namespace contains a sensitive writable mount.",
				Evidence:  append(capSig.Evidence, mountSig.Evidence...),
				MountPoint: mountSig.MountPoint,
			})
		}
	}

	return findings
}
```

路径判断不要用简单的 `strings.Contains`。应该按路径边界判断：

```go
func isFatalSensitiveMount(mountPoint string) bool {
	p := path.Clean(mountPoint)

	return pathIsOrUnder(p, "/host") ||
		pathIsOrUnder(p, "/rootfs") ||
		pathIsOrUnder(p, "/etc") ||
		pathIsOrUnder(p, "/var/run") ||
		pathIsOrUnder(p, "/run")
}

func pathIsOrUnder(p, base string) bool {
	p = path.Clean(p)
	base = path.Clean(base)

	return p == base || strings.HasPrefix(p, base+"/")
}
```

这个例子里不需要单独的 `rel.thread_in_mntns` signal，因为 capability signal 已经带了 `mntns_inode`。
