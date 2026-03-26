# 开发分层速查

## 主链路

```text
target -> collect -> model(snapshot) -> analyze -> model(finding) -> report
````

---

## target/

放：

* container id / pid / cgroup path → 统一解析成扫描目标
* 主进程 PID、容器 ID、容器名、runtime 类型等目标信息

不放：

* 风险判断
* `/proc` 细节解析
* 输出格式

---

## collect/

放：

* 读取 `/proc/<pid>/status`
* 读取 `/proc/<pid>/task/<tid>/status`
* 读取 `/proc/<pid>/ns/*`
* 读取 `/proc/<pid>/mountinfo`
* 解析 capability 原始值
* 解析 seccomp 原始值
* 解析 mountinfo 原始字段
* 获取 namespace 的 dev/ino/readlink

不放：

* 高危/中危/低危判断
* finding 生成
* 文本输出

---

## model/

放：

* `Target`
* `Snapshot`
* `NamespaceRef`
* `CapabilitySet`
* `SeccompState`
* `MountNode` / `MountTree`
* `Finding`

不放：

* 文件读取
* 规则判断
* 输出逻辑

---

## analyze/

放：

* 根据 Snapshot 判断 namespace 风险
* 根据 Snapshot 判断 capability 风险
* 根据 Snapshot 判断 seccomp 风险
* 根据 Snapshot 判断 mount 风险
* 组合规则判断
* 生成 `Finding`

不放：

* 直接读 `/proc`
* 直接输出文本
* CLI 参数处理

---

## report/

放：

* `[]Finding` -> 文本
* `[]Finding` -> JSON
* 严重级别排序
* 展示格式

不放：

* 读运行时信息
* 风险判断
* 目标解析

---

## 各核心对象

### Target

表示“扫谁”。

### Snapshot

表示“采到了什么事实”。

### Finding

表示“规则命中后产出的结构化告警”。

---

## 文件级速查

### `cmd/ctrisk/main.go`

* 入口

### `internal/app/run.go`

* 串主流程

### `internal/cli/flags.go`

* 参数定义

### `internal/cli/validate.go`

* 参数校验

### `internal/target/resolver.go`

* 选择按 container id 还是 pid 解析

### `internal/target/by_container_id.go`

* container id -> Target

### `internal/target/by_pid.go`

* pid -> Target

### `internal/collect/proc.go`

* procfs 读文件工具

### `internal/collect/process.go`

* 进程级采集

### `internal/collect/thread.go`

* 线程级采集

### `internal/collect/namespace.go`

* namespace 采集与标识信息提取

### `internal/collect/capability.go`

* capability 采集与解析

### `internal/collect/seccomp.go`

* seccomp 采集与解析

### `internal/collect/mount.go`

* mountinfo 采集与解析

### `internal/collect/runtime.go`

* 运行时补充信息采集

### `internal/model/target.go`

* Target 结构定义

### `internal/model/snapshot.go`

* Snapshot 结构定义

### `internal/model/namespace.go`

* NamespaceRef 结构定义

### `internal/model/capability.go`

* CapabilitySet 结构定义

### `internal/model/mount.go`

* MountNode / MountTree 结构定义

### `internal/model/seccomp.go`

* SeccompState 结构定义

### `internal/model/finding.go`

* Finding 结构定义

### `internal/analyze/analyzer.go`

* 调度所有规则

### `internal/analyze/namespace.go`

* namespace 规则

### `internal/analyze/capability.go`

* capability 规则

### `internal/analyze/seccomp.go`

* seccomp 规则

### `internal/analyze/mount.go`

* mount 规则

### `internal/analyze/correlate.go`

* 组合规则

### `internal/report/text.go`

* 文本渲染

### `internal/report/json.go`

* JSON 渲染

### `internal/report/severity.go`

* 严重级别定义

---

## 判断一句话该放哪

* “怎么找到这个容器对应的 PID” -> `target`
* “怎么读 `/proc/.../status`” -> `collect`
* “这个数据结构长什么样” -> `model`
* “共享宿主 pidns 算不算风险” -> `analyze`
* “这条风险怎么打印成终端文本” -> `report`

