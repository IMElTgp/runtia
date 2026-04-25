package analyze

import (
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
func checkUserNamespaceSharing(userns target.NSRef) *model.Signal {
	// TODO
	return nil
}

// checkNonUserNamespaceSharing checks rule 2: sharing non-user ns with the host
func checkNonUserNamespaceSharing(ns target.NSRef) *model.Signal {
	// TODO
	return nil
}

// checkUserNSDeviation checks rule 3: non-main thread's user namespace deviation from main thread
func checkUserNSDeviation(userns target.NSRef, mainUserNS target.NSRef) *model.Signal {
	if userns.Ino == mainUserNS.Ino && userns.Dev == mainUserNS.Dev {
		return nil
	}
	// TODO
	return nil
}

// checkPIDNSDeviation checks rule 4: non-main thread's PID namespace deviation from main thread
func checkPIDNSDeviation(pidns target.NSRef, mainPIDNS target.NSRef) *model.Signal {
	if pidns.Ino == mainPIDNS.Ino && pidns.Dev == mainPIDNS.Dev {
		return nil
	}
	// TODO
	return nil
}

// checkMntNSDeviation checks rule 6: non-main thread's mnt namespace deviation from main thread
func checkMntNSDeviation(mntns target.NSRef, mainMntNS target.NSRef) *model.Signal {
	// TODO
	return nil
}

// checkOwnerUserNSExistence checks rule 7: whether the owner user ns of given ns exists
func checkOwnerUserNSExistence(ns target.NSRef) *model.Signal {
	// TODO
	return nil
}

// checkOwnerDeviation checks rule 5: whether the owner user ns of given ns is the same user ns as the thread's user ns
func checkOwnerDeviation(ns, targetUserNS target.NSRef) *model.Signal {
	// TODO
	return nil
}

func appendSignalIfNonNil(signals []model.Signal, signal *model.Signal) []model.Signal {
	if signal == nil {
		return signals
	}
	return append(signals, *signal)
}

func (r *Rule) AnalyzeNamespaces() {
	for _, thread := range r.Snapshot.Threads {
		mainThread := r.Snapshot.Threads[thread.Tgid]

		r.Signals = appendSignalIfNonNil(r.Signals, checkUserNamespaceSharing(thread.UserNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkNonUserNamespaceSharing(thread.PIDNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkNonUserNamespaceSharing(thread.MntNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkUserNSDeviation(thread.UserNS, mainThread.UserNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkPIDNSDeviation(thread.PIDNS, mainThread.PIDNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkMntNSDeviation(thread.MntNS, mainThread.MntNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerUserNSExistence(thread.MntNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerUserNSExistence(thread.PIDNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerDeviation(thread.MntNS, thread.UserNS))
		r.Signals = appendSignalIfNonNil(r.Signals, checkOwnerDeviation(thread.PIDNS, thread.UserNS))
	}
}
