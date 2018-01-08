package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

var addr = "localhost:4242"

const (
	MsgLen    = 2500
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
		log.Printf("Got main error: %v\n", err)
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
			return err
		}

		go handleClient(sess)
	}

	return err
}

func handleClient(sess quic.Session) {
	log.Printf("Accept connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())

	stream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("Got accept stream error: %v", err)
		return
	}
	buf := make([]byte, MsgLen)

serverLoop:
	for {
		read, err := io.ReadFull(stream, buf)
		if err != nil {
			stream.Close()
			log.Printf("Got error: %v\n", err)
			break serverLoop
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		expectedReqSize, _ := strconv.Atoi(splitMsg[1])
		if read != expectedReqSize {
			stream.Close()
			log.Printf("Did not read the expected size; %s != %s\n", strconv.Itoa(read), splitMsg[1])
			break serverLoop
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
			log.Printf("Got error: %v\n", err)
			break serverLoop
		}
	}

	log.Printf("Close connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())
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
