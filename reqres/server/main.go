package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

var addr = "localhost:4242"

const (
	MsgLen    = 750
	MinFields = 5
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to bind")
	flag.Parse()
	addr = *addrF
	err := echoServer()
	if err != nil {
		fmt.Printf("Got main error: %v\n", err)
	}
}

// Start a server that performs similar traffic to Siri servers
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			fmt.Printf("Got accept error: %v\n", err)
			continue
		}
		go handleClient(sess)
	}
	return err
}

func handleClient(sess quic.Session) {
	fmt.Printf("Accept new connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())
	stream, err := sess.AcceptStream()
	if err != nil {
		fmt.Printf("Got accept stream error: %v\n", err)
		return
	}
	buf := make([]byte, MsgLen)
serveLoop:
	for {
		read, err := io.ReadFull(stream, buf)
		if err != nil {
			stream.Close()
			break serveLoop
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		expectedReqSize, _ := strconv.Atoi(splitMsg[1])
		if read != expectedReqSize {
			stream.Close()
			fmt.Println("Did not read the expected size; " + strconv.Itoa(read) + " != " + splitMsg[1])
			break serveLoop
		}
		sleepTimeSec, _ := strconv.Atoi(splitMsg[3])
		if sleepTimeSec > 0 {
			time.Sleep(time.Duration(sleepTimeSec) * time.Second)
		}
		msgID := splitMsg[0]
		resSize, _ := strconv.Atoi(splitMsg[2])
		res := msgID + "&" + strings.Repeat("0", resSize-len(msgID)-2) + "\n"
		_, err = stream.Write([]byte(res))
		if err != nil {
			stream.Close()
			fmt.Printf("Got error: %v", err)
			break serveLoop
		}
	}
	fmt.Printf("Close connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
