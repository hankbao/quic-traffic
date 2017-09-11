package quictraffic

import (
	"bitbucket.org/qdeconinck/quic-traffic/common"

	bulk "bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
)

func Run(traffic string, cache bool, multipath bool, output string, url string) string {
	cfg := common.TrafficConfig{
		Cache:     cache,
		Multipath: multipath,
		Output:    output,
		Url:       url,
	}

	switch traffic {
	case "bulk":
		return bulk.Run(cfg)
	default:
		return "Unknown traffic"
	}
}
