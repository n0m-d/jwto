package commands

import (
	"fmt"
	"runtime"
)

// MaxWorkers returns the upper worker limit for the current machine.
func MaxWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n < 1 {
		n = 1
	}
	return n * 4
}

// ResolveWorkers clamps the requested worker count to a safe range for this machine.
func ResolveWorkers(requested int) (int, bool, error) {
	if requested < 1 {
		return 0, false, fmt.Errorf("workers must be at least 1")
	}

	max := MaxWorkers()
	if requested > max {
		return max, true, nil
	}

	return requested, false, nil
}
