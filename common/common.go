package common

import (
	"time"
)

type TrafficConfig struct {
	// Generic for all cases
	Cache     bool
	MaxPathID uint8
	Output    string
	Url       string

	// For interactive
	RunTime time.Duration
}
