package main

import (
	"flag"
	"log"
	"net"
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to bind")
	flag.Parse()
	err := echoServer(*addrF)
	if err != nil {
		log.Printf("Got main error: %v\n", err)
	}
}

// Start a server that performs similar traffic to Siri servers
func echoServer(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	buffer := make([]byte, 12)
	for {
		_, retAddr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		listener.WriteToUDP(buffer, retAddr)
	}
	return err
}
