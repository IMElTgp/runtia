package analyze

import (
	"fmt"

	"github.com/IMElTgp/container-runtime-analysis/internal/collect"
	"github.com/IMElTgp/container-runtime-analysis/internal/model"
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

// note: in the following comments, "main thread" refers to the main thread inside one thread group (process)

/**
 * internal/analyze/namespace.go
 * goal:
 * - to check whether there are threads inside container that share namespaces with the host
 * - to check whether there are non-main threads that stay in different namespaces from the main thread's namespaces
 */

/**
 * rules:
 * 1. thread's user namespace is shared with the host 						=> Fatal
 * 2. thread's non-user namespace is shared with the host 					=> HighRisk
 * 3. non-main thread's user namespace is different from main thread 		=> HighRisk
 * 4. non-main thread's pid namespace is different from main thread 		=> HighRisk
 * 5. thread's non-user namespace owner is not its user namespace 			=> HighRisk
 * 6. non-main thread's mnt namespace is different from main thread 		=> Info
 * 7. OwnerKnown == false 													=> Info
 */

// checkUserNamespaceSharing checks rule 1: sharing user ns with the host
func checkUserNamespaceSharing(thread model.ThreadSnapshot) *model.Signal {
	userns := thread.UserNS
	if userns.Dev == collect.HostUserNS.Dev && userns.Ino == collect.HostUserNS.Ino {
		return &model.Signal{
			Finding: model.Finding{
				Category:  "namespace",
				RiskLevel: Fatal,
				Title:     "Thread shares the host user namespace",
				Summary:   fmt.Sprintf("Thread %d shares the host user namespace, so user-ID mappings, capabilities, and namespace ownership semantics can apply with host-level meaning.", thread.Tid),
				Evidence: []string{
					fmt.Sprintf("Host user namespace dev=%d, ino=%d", collect.HostUserNS.Dev, collect.HostUserNS.Ino),
					fmt.Sprintf("Thread user namespace dev=%d, ino=%d", userns.Dev, userns.Ino),
				},
				RelativeNS:      &userns,
				RelativeThreads: collect.ThreadsForNS(userns),
				Recommendation:  "Place the workload in a private user namespace instead of sharing the host user namespace.",
			},
		}
	}
	return nil
}

// checkPIDNamespaceSharing checks rule 2: sharing non-user (pid) ns with the host
func checkPIDNamespaceSharing(thread model.ThreadSnapshot) *model.Signal {
	pidns := thread.PIDNS
	if pidns.Ino == collect.HostPIDNS.Ino && pidns.Dev == collect.HostPIDNS.Dev {
		return &model.Signal{
			Finding: model.Finding{
				Category:  "namespace",
				RiskLevel: HighRisk,
				Title:     "Thread shares the host PID namespace",
				Summary:   fmt.Sprintf("Thread %d shares the host PID namespace, so process visibility and signal scope extend to host processes instead of staying isolated to the container.", thread.Tid),
				Evidence: []string{
					fmt.Sprintf("Host PID namespace dev=%d, ino=%d", collect.HostPIDNS.Dev, collect.HostPIDNS.Ino),
					fmt.Sprintf("Thread PID namespace dev=%d, ino=%d", pidns.Dev, pidns.Ino),
				},
				RelativeNS:      &pidns,
				RelativeThreads: collect.ThreadsForNS(pidns),
				Recommendation:  "Place the workload in a private PID namespace instead of sharing the host PID namespace.",
			},
		}
	}
	return nil
}

// checkMntNamespaceSharing checks rule 2: sharing non-user (mnt) ns with the host
func checkMntNamespaceSharing(thread model.ThreadSnapshot) *model.Signal {
	mntns := thread.MntNS
	if mntns.Ino == collect.HostMntNS.Ino && mntns.Dev == collect.HostMntNS.Dev {
		return &model.Signal{
			Finding: model.Finding{
				Category:  "namespace",
				RiskLevel: HighRisk,
				Title:     "Thread shares the host mount namespace",
				Summary:   fmt.Sprintf("Thread %d shares the host mount namespace, so mount operations and filesystem view changes can affect the host directly.", thread.Tid),
				Evidence: []string{
					fmt.Sprintf("Host mount namespace dev=%d, ino=%d", collect.HostMntNS.Dev, collect.HostMntNS.Ino),
					fmt.Sprintf("Thread mount namespace dev=%d, ino=%d", mntns.Dev, mntns.Ino),
				},
				RelativeNS:      &mntns,
				RelativeThreads: collect.ThreadsForNS(mntns),
				Recommendation:  "Place the workload in a private mount namespace instead of sharing the host mount namespace.",
			},
		}
	}
	return nil
}

// checkUserNSDeviation checks rule 3: non-main thread's user namespace deviation from main thread
func checkUserNSDeviation(thread model.ThreadSnapshot, mainUserNS target.NSRef) *model.Signal {
	if thread.IsMainThread {
		return nil
	}
	userns := thread.UserNS
	if userns.Ino == mainUserNS.Ino && userns.Dev == mainUserNS.Dev {
		return nil
	}
	return &model.Signal{
		Finding: model.Finding{
			Category:  "namespace",
			RiskLevel: HighRisk,
			Title:     "Thread uses a different user namespace than its main thread",
			Summary:   fmt.Sprintf("Thread %d in thread group %d uses a different user namespace than its main thread, so identity mappings and capability checks can diverge within one process.", thread.Tid, thread.Tgid),
			Evidence: []string{
				fmt.Sprintf("Main thread (tid=%d) user namespace dev=%d, ino=%d", thread.Tgid, mainUserNS.Dev, mainUserNS.Ino),
				fmt.Sprintf("Thread user namespace dev=%d, ino=%d", userns.Dev, userns.Ino),
			},
			RelativeNS:      &userns,
			RelativeThreads: collect.ThreadsForNS(userns),
			Recommendation:  "Keep all threads in a thread group in the same user namespace unless the split is intentional and reviewed.",
		},
	}
}

// checkPIDNSDeviation checks rule 4: non-main thread's PID namespace deviation from main thread
func checkPIDNSDeviation(thread model.ThreadSnapshot, mainPIDNS target.NSRef) *model.Signal {
	if thread.IsMainThread {
		return nil
	}
	pidns := thread.PIDNS
	if pidns.Ino == mainPIDNS.Ino && pidns.Dev == mainPIDNS.Dev {
		return nil
	}
	return &model.Signal{
		Finding: model.Finding{
			Category:  "namespace",
			RiskLevel: HighRisk,
			Title:     "Thread uses a different PID namespace than its main thread",
			Summary:   fmt.Sprintf("Thread %d in thread group %d uses a different PID namespace than its main thread, so process visibility and signal scope can diverge within one process.", thread.Tid, thread.Tgid),
			Evidence: []string{
				fmt.Sprintf("Main thread (tid=%d) PID namespace dev=%d, ino=%d", thread.Tgid, mainPIDNS.Dev, mainPIDNS.Ino),
				fmt.Sprintf("Thread PID namespace dev=%d, ino=%d", pidns.Dev, pidns.Ino),
			},
			RelativeNS:      &pidns,
			RelativeThreads: collect.ThreadsForNS(pidns),
			Recommendation:  "Keep all threads in a thread group in the same PID namespace unless the split is intentional and reviewed.",
		},
	}
}

// checkMntNSDeviation checks rule 6: non-main thread's mnt namespace deviation from main thread
func checkMntNSDeviation(thread model.ThreadSnapshot, mainMntNS target.NSRef) *model.Signal {
	if thread.IsMainThread {
		return nil
	}
	mntns := thread.MntNS
	if mntns.Ino == mainMntNS.Ino && mntns.Dev == mainMntNS.Dev {
		return nil
	}
	return &model.Signal{
		Finding: model.Finding{
			Category:  "namespace",
			RiskLevel: Info,
			Title:     "Thread uses a different mount namespace than its main thread",
			Summary:   fmt.Sprintf("Thread %d in thread group %d uses a different mount namespace than its main thread, so filesystem view and mount operations can diverge within one process.", thread.Tid, thread.Tgid),
			Evidence: []string{
				fmt.Sprintf("Main thread (tid=%d) mount namespace dev=%d, ino=%d", thread.Tgid, mainMntNS.Dev, mainMntNS.Ino),
				fmt.Sprintf("Thread mount namespace dev=%d, ino=%d", mntns.Dev, mntns.Ino),
			},
			RelativeNS:      &mntns,
			RelativeThreads: collect.ThreadsForNS(mntns),
			Recommendation:  "Keep all threads in a thread group in the same mount namespace unless the split is intentional and reviewed.",
		},
	}
}

// checkOwnerUserNSExistence checks rule 7: whether the owner user ns of given ns exists
func checkOwnerUserNSExistence(thread model.ThreadSnapshot, ns target.NSRef) *model.Signal {
	if ns.Type == "" {
		return nil
	}
	if _, ok := collect.OwnerUserNSByNS[ns]; ok {
		return nil
	}

	nsName := ns.Type + " namespace"
	switch ns.Type {
	case "pid":
		nsName = "PID namespace"
	case "mnt":
		nsName = "mount namespace"
	}

	return &model.Signal{
		Finding: model.Finding{
			Category:  "namespace",
			RiskLevel: Info,
			Title:     fmt.Sprintf("Could not resolve the owner user namespace of the thread's %s", nsName),
			Summary:   fmt.Sprintf("The owner user namespace for thread %d's %s could not be resolved, so owner-based namespace checks for this namespace are incomplete.", thread.Tid, nsName),
			Evidence: []string{
				fmt.Sprintf("Thread %s dev=%d, ino=%d", nsName, ns.Dev, ns.Ino),
			},
			RelativeNS:      &ns,
			RelativeThreads: collect.ThreadsForNS(ns),
			Recommendation:  "Verify that the kernel and runtime expose namespace ownership correctly, and review this namespace manually if it is security-sensitive.",
		},
	}
}

// checkOwnerDeviation checks rule 5: whether the owner user ns of given ns is the same user ns as the thread's user ns
func checkOwnerDeviation(thread model.ThreadSnapshot, ns, targetUserNS target.NSRef) *model.Signal {
	if ns.Type == "" {
		return nil
	}
	ownerUserNS, ok := collect.OwnerUserNSByNS[ns]
	if !ok {
		return nil
	}
	if ownerUserNS.Ino == targetUserNS.Ino && ownerUserNS.Dev == targetUserNS.Dev {
		return nil
	}

	nsName := ns.Type + " namespace"
	switch ns.Type {
	case "pid":
		nsName = "PID namespace"
	case "mnt":
		nsName = "mount namespace"
	}

	return &model.Signal{
		Finding: model.Finding{
			Category:  "namespace",
			RiskLevel: HighRisk,
			Title:     fmt.Sprintf("Thread's %s is owned by a different user namespace", nsName),
			Summary:   fmt.Sprintf("Thread %d uses a %s whose owner user namespace differs from the thread's own user namespace, so namespace operations can be governed by a different capability context.", thread.Tid, nsName),
			Evidence: []string{
				fmt.Sprintf("Thread user namespace dev=%d, ino=%d", targetUserNS.Dev, targetUserNS.Ino),
				fmt.Sprintf("Thread %s dev=%d, ino=%d", nsName, ns.Dev, ns.Ino),
				fmt.Sprintf("Owner user namespace of the thread's %s dev=%d, ino=%d", nsName, ownerUserNS.Dev, ownerUserNS.Ino),
			},
			RelativeNS:      &ns,
			RelativeThreads: collect.ThreadsForNS(ns),
			Recommendation:  fmt.Sprintf("Keep the thread's %s owned by the same user namespace as the thread, unless this cross-user-namespace setup is intentional and reviewed.", nsName),
		},
	}
}

func appendSignalIfNonNil(signals []model.Signal, signal *model.Signal) []model.Signal {
	if signal == nil {
		return signals
	}
	return append(signals, *signal)
}

func (r *Rule) AnalyzeNamespaces() {
	for i := range r.Snapshot.Threads {
		thread := r.Snapshot.Threads[i]

		r.Signals = appendSignalIfNonNil(r.Signals, checkUserNamespaceSharing(thread))
		r.Signals = appendSignalIfNonNil(r.Signals, checkPIDNamespaceSharing(thread))
		r.Signals = appendSignalIfNonNil(r.Signals, checkMntNamespaceSharing(thread))
		if mainThread, ok := r.Snapshot.Threads[thread.Tgid]; ok {
			r.Signals = appendSignalIfNonNil(r.Signals, checkUserNSDeviation(thread, mainThread.UserNS))
			r.Signals = appendSignalIfNonNil(r.Signals, checkPIDNSDeviation(thread, mainThread.PIDNS))
			r.Signals = appendSignalIfNonNil(r.Signals, checkMntNSDeviation(thread, mainThread.MntNS))
		}
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerUserNSExistence(thread, thread.MntNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerUserNSExistence(thread, thread.PIDNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerDeviation(thread, thread.MntNS, thread.UserNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerDeviation(thread, thread.PIDNS, thread.UserNS))
	}
}
