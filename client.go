package quictraffic

import (
	"time"
	"strings"

	"bitbucket.org/qdeconinck/quic-traffic/common"

	bulk "bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	reqres "bitbucket.org/qdeconinck/quic-traffic/reqres/libclient"
	siri "bitbucket.org/qdeconinck/quic-traffic/siri/libclient"

	quic "github.com/lucas-clemente/quic-go"
)

func Run(traffic string, cache bool, multipath bool, logFile string, output string, url string) string {
	cfg := common.TrafficConfig{
		Cache:     cache,
		Multipath: multipath,
		Output:    output,
		Url:       url,
		RunTime:   30 * time.Second,
	}
	if strings.HasPrefix(logFile, "file://") {
		logFile = logFile[7:]
	}
	quic.SetLoggerParams(logFile, time.Duration(10) * time.Millisecond)

	var res string = ""

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
