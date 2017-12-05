// +build darwin

package quictraffic

import (
	"strings"
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"
	quic "github.com/lucas-clemente/quic-go"

	bulk "bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	reqres "bitbucket.org/qdeconinck/quic-traffic/reqres/libclient"
	siri "bitbucket.org/qdeconinck/quic-traffic/siri/libclient"
)

// RunConfig provides needed configuration
type RunConfig interface {
	Cache() bool
	LogFile() string
	MaxPathID() int
	NotifyID() string
	Output() string
	PrintBody() bool
	Traffic() string
	URL() string
}

// Run the QUIC traffic experiment
func Run(runcfg RunConfig) string {
	output := runcfg.Output()
	if strings.HasPrefix(output, "file://") {
		output = output[7:]
	}
	cfg := common.TrafficConfig{
		Cache:     runcfg.Cache(),
		MaxPathID: uint8(runcfg.MaxPathID()),
		NotifyID:  runcfg.NotifyID(),
		Output:    output,
		PrintBody: runcfg.PrintBody(),
		URL:       runcfg.URL(),
		RunTime:   30 * time.Second,
	}
	logFile := runcfg.LogFile()
	if strings.HasPrefix(logFile, "file://") {
		logFile = logFile[7:]
	}

	quic.SetLoggerParams(logFile, time.Duration(1000)*time.Millisecond)

	var res string

	switch runcfg.Traffic() {
	case "bulk":
		res = bulk.Run(cfg)
	case "reqres":
		res = reqres.Run(cfg)
	case "siri":
		res = siri.Run(cfg)
	default:
		res = "Unknown traffic"
	}

	quic.StopLogger()

	return res
}

// NotifyReachability change for the notifyID
func NotifyReachability(notifyID string) {
	callback, ok := quic.GetNotifier(notifyID)
	if ok {
		print("Notifying ", notifyID)
		callback.Notify()
	}
}
