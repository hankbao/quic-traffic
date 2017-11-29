package common

import (
	"time"
)

type TrafficConfig struct {
	// Generic for all cases
	Cache     bool
	MaxPathID uint8
	NotifyID  string
	Output    string
	URL       string

	// For bulk
	PrintBody bool

	// For interactive
	RunTime time.Duration
}
