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
	"time"

	quic "github.com/lucas-clemente/quic-go"

	utils "bitbucket.org/qdeconinck/quic-traffic/utils"
)

var (
	addr     = "localhost:4242"
	maxTime  = 15 * time.Second
	print    bool
	readChan chan int
	stopChan chan struct{}
	stream   quic.Stream
	timer    *utils.Timer
)

const (
	BufLen = 8000000
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial (client) / to listen (server)")
	printF := flag.Bool("p", false, "Set this flag to print details for connections")
	timeF := flag.Duration("time", 15*time.Second, "Maximum time for tests")

	flag.Parse()

	addr = *addrF
	print = *printF
	maxTime = *timeF
	iperfServer()
}

func serverBandwidthTracker() {
	totalRead := 0
	secRead := 0
	log.Printf("IntervalInSec TransferredLastSecond GlobalBandwidth\n")
	startTime := time.Now()
	timer = utils.NewTimer()
	timer.Reset(startTime.Add(time.Second))
	for {
		select {
		case <-stopChan:
			log.Printf("- - - - - - - - - - - - - - -\n")
			log.Printf("totalReceived %d duration %s\n", totalRead, time.Since(startTime))
			return
		case read := <-readChan:
			totalRead += read
			secRead += read
			break
		case <-timer.Chan():
			timer.SetRead()
			elapsed := time.Since(startTime)
			if elapsed != 0 {
				log.Printf("%d-%d %d %d\n", elapsed/time.Second-1, elapsed/time.Second, secRead, totalRead*1000000000/int(time.Since(startTime)/time.Nanosecond))
			}
			secRead = 0
			timer.Reset(time.Now().Add(time.Second))
			break
		}
	}
}

func iperfServerHandleSession(sess quic.Session) {
	stream, err := sess.AcceptStream()
	if err != nil {
		log.Printf("Got accept stream error: %v\n", err)
		return
	}
	log.Println("Accept new connection from", sess.RemoteAddr())
	if print {
		go serverBandwidthTracker()
	}
	readChan = make(chan int, 10)
	stopChan = make(chan struct{})
	buf := make([]byte, BufLen)
	stream.SetDeadline(time.Now().Add(maxTime))
forLoop:
	for {
		read, err := io.ReadAtLeast(stream, buf, 1)
		if read == 0 && err == io.EOF {
			if print {
				stopChan <- struct{}{}
				time.Sleep(time.Second)
			}
			break forLoop
		}
		if err != nil {
			break forLoop
		}

		// TODO do something
		if print {
			readChan <- read
		}
	}
	log.Println("Connection terminated from", sess.RemoteAddr())
}

func iperfServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	for {
		sess, err := listener.Accept()
		if err != nil {
			log.Printf("Got accept error: %v\n", err)
			continue
		}
		go iperfServerHandleSession(sess)
	}
	return err
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	log.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
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
