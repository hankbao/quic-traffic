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
	Url       string

	// For interactive
	RunTime time.Duration
}
