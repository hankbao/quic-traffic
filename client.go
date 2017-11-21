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

// Run the QUIC traffic experiment
func Run(traffic string, cache bool, maxPathID int, logFile string, output string, url string, notifyID string) string {
	cfg := common.TrafficConfig{
		Cache:     cache,
		MaxPathID: uint8(maxPathID),
		NotifyID:  notifyID,
		Output:    output,
		Url:       url,
		RunTime:   30 * time.Second,
	}
	if strings.HasPrefix(logFile, "file://") {
		logFile = logFile[7:]
	}

	quic.SetLoggerParams(logFile, time.Duration(1000)*time.Millisecond)

	var res string

	switch traffic {
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
