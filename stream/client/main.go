package main

import (
	"flag"
	"fmt"
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"

	stream "bitbucket.org/qdeconinck/quic-traffic/stream/libclient"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial")
	runTimeF := flag.Duration("runTime", 30*time.Second, "Running time of test")
	multipath := flag.Bool("m", false, "multipath")
	flag.Parse()

	var maxPathID uint8 = 0
	if *multipath {
		maxPathID = 2
	}

	cfg := common.TrafficConfig{
		MaxPathID: maxPathID,
		URL:       *addrF,
		RunTime:   *runTimeF,
	}

	ret := stream.Run(cfg)
	fmt.Printf("%s", ret)
}
