package analyze

import "github.com/IMElTgp/container-runtime-analysis/internal/model"

// seccomp, seccompFilters, NoNewPrivs

/**
 * rules:
 * 1. NoNewPrivs == false 						=> Info/MediumRisk (may involve compositing later)
 * 2. SeccompMode == 0 (No seccomp) 			=> HighRisk
 * 3. SeccompMode == 1 (strict seccomp) 		=> Info (may be too strict)
 * 4. SeccompMode == 2 && Seccomp_Filters == 0 	=> HighRisk (abnormal, may not be considered as risk?)
 */

// checkNoNewPrivs checks rule 1: NoNewPrivs is shut down
// not too risky itself; composition matters
func checkNoNewPrivs(noNewPrivs bool, thread model.ThreadSnapshot) *model.Signal {
	// TODO
	return nil
}

// switchSeccompMode is a distributer of seccompMode handlers
func switchSeccompMode(seccompMode int, thread model.ThreadSnapshot) *model.Signal {
	if seccompMode == 1 {
		return checkSeccompModeStrict(thread)
	} else if seccompMode == 0 {
		return checkSeccompModeShutDown(thread)
	}
	// seccompMode is good
	return nil
}

// checkSeccompModeShutDown checks rule 2: seccompMode shut down
func checkSeccompModeShutDown(thread model.ThreadSnapshot) *model.Signal {
	// TODO
	return nil
}

// checkSeccompModeStrict checks rule 3: seccomp too hard
func checkSeccompModeStrict(thread model.ThreadSnapshot) *model.Signal {
	// TODO
	return nil
}

// checkSeccompModeOnWithoutFilters checks rule 4 (an abnormal case): seccompMode is at
// filter mode (seccompMode == 2) but no filters
func checkSeccompModeOnWithoutFilters(seccompMode, seccompFilters int, thread model.ThreadSnapshot) *model.Signal {
	// TODO
	return nil
}

func (r *Rule) AnalyzeSeccomp() {
	// TODO
	for tid := range r.Snapshot.Threads {
		noNewPrivs := r.Snapshot.Threads[tid].NoNewPrivs
		seccompMode := r.Snapshot.Threads[tid].SeccompMode
		seccompFilters := r.Snapshot.Threads[tid].SeccompFilters
		thread := r.Snapshot.Threads[tid]

		r.Signals = appendSignalIfNonNil(r.Signals, checkNoNewPrivs(noNewPrivs, thread))
		r.Signals = appendSignalIfNonNil(r.Signals, switchSeccompMode(seccompMode, thread))
		r.Signals = appendSignalIfNonNil(r.Signals, checkSeccompModeOnWithoutFilters(seccompMode, seccompFilters, thread))
	}
}
