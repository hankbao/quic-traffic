package quictraffic

import (
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"

	bulk "bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	reqres "bitbucket.org/qdeconinck/quic-traffic/reqres/libclient"
	siri "bitbucket.org/qdeconinck/quic-traffic/siri/libclient"
)

func Run(traffic string, cache bool, multipath bool, output string, url string) string {
	cfg := common.TrafficConfig{
		Cache:     cache,
		Multipath: multipath,
		Output:    output,
		Url:       url,
		RunTime:   30 * time.Second,
	}

	switch traffic {
	case "bulk":
		return bulk.Run(cfg)
	case "reqres":
		return reqres.Run(cfg)
	case "siri":
		return siri.Run(cfg)
	default:
		return "Unknown traffic"
	}
}
