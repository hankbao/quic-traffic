package quictraffic

import (
	"strings"
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"
	quic "github.com/lucas-clemente/quic-go"

	bulk "bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	qperf "bitbucket.org/qdeconinck/quic-traffic/qperf/libclient"
	reqres "bitbucket.org/qdeconinck/quic-traffic/reqres/libclient"
	siri "bitbucket.org/qdeconinck/quic-traffic/siri/libclient"
	stream "bitbucket.org/qdeconinck/quic-traffic/stream/libclient"
)

// RunConfig provides needed configuration
type RunConfig interface {
	Cache() bool
	LogFile() string
	LogPeriodMs() int
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

	quic.SetLoggerParams(logFile, time.Duration(runcfg.LogPeriodMs())*time.Millisecond)

	var res string

	switch runcfg.Traffic() {
	case "bulk":
		res = bulk.Run(cfg)
	case "qperf":
		res = qperf.Run(cfg)
	case "reqres":
		res = reqres.Run(cfg)
	case "siri":
		res = siri.Run(cfg)
	case "stream":
		res = stream.Run(cfg)
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
