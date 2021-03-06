package main

import (
	"flag"
	"fmt"

	"bitbucket.org/qdeconinck/quic-traffic/bulk/libclient"
	"bitbucket.org/qdeconinck/quic-traffic/common"

	quic "github.com/lucas-clemente/quic-go"
)

func main() {
	multipath := flag.Bool("m", false, "multipath")
	output := flag.String("o", "", "logging output")
	cache := flag.Bool("c", false, "cache handshake information")
	pingCount := flag.Int("p", 0, "ping count")
	pingWait := flag.Int("w", 0, "ping wait time, in ms")
	handover := flag.Bool("h", false, "handover mode")
	flag.Parse()
	urls := flag.Args()

	var maxPathID uint8
	if *multipath {
		maxPathID = 255
	}

	multipathService := quic.Aggregate
	if *handover {
		multipathService = quic.Handover
	}

	cfg := common.TrafficConfig{
		Cache:            *cache,
		MaxPathID:        maxPathID,
		MultipathService: multipathService,
		Output:           *output,
		PingCount:        *pingCount,
		PingWaitMs:       *pingWait,
		URL:              urls[0],
	}

	time := libclient.Run(cfg)
	fmt.Printf("%s", time)
}
