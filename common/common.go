package common

import (
	"time"
)

type TrafficConfig struct {
	// Generic for all cases
	Cache bool
	Multipath bool
	Output string
	Url string

	// For interactive
	RunTime time.Duration
}
