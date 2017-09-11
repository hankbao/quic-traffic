package quictraffic

import (
	"bitbucket.org/qdeconinck/quic-traffic/bulk/bulkclient"
)

func Run(cache bool, multipath bool, output string, url string) string {
	return bulkclient.Run(cache, multipath, output, url)
}
