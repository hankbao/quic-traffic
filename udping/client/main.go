package main

import (
	"flag"
	"fmt"
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"

	udping "bitbucket.org/qdeconinck/quic-traffic/udping/libclient"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial")
	runTimeF := flag.Duration("runTime", 30*time.Second, "Running time of test")
	flag.Parse()

	cfg := common.TrafficConfig{
		NotifyID: "myID",
		URL:      *addrF,
		RunTime:  *runTimeF,
	}

	go func() {
		time.Sleep(cfg.RunTime)
		udping.StopTraffic(cfg.NotifyID)
	}()

	ret := udping.Run(cfg)
	fmt.Printf("%s", ret)
}
