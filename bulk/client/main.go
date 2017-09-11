package main

import (
	"flag"
	"fmt"

	"bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	"bitbucket.org/qdeconinck/quic-traffic/common"
)

func main() {
	multipath := flag.Bool("m", false, "multipath")
	output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	flag.Parse()
	urls := flag.Args()

	cfg := common.TrafficConfig{
		Cache:     *cache,
		Multipath: *multipath,
		Output:    *output,
		Url:       urls[0],
	}

	time := libclient.Run(cfg)
	fmt.Printf("%s", time)
}
