package common

import (
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

type TrafficConfig struct {
	// Generic for all cases
	Cache            bool
	MaxPathID        uint8
	MultipathService quic.MultipathServiceType
	NotifyID         string
	Output           string
	URL              string

	// For bulk
	PrintBody  bool
	PingCount  int
	PingWaitMs int

	// For interactive, qperf, stream
	RunTime time.Duration
}
