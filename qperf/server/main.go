package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	utils "bitbucket.org/qdeconinck/quic-traffic/utils"
)

type clientHandler struct {
	id uint64

	readChan chan int
	stopChan chan struct{}
	timer    *utils.Timer

	download   bool
	stream     quic.Stream
	streamMeta quic.Stream
	sess       quic.Session
	firstByte  chan byte
	print      bool
	runTime    time.Duration
	startTime  time.Time
}

var (
	addr  = "localhost:4242"
	print bool
)

const (
	BufLen = 8000000
)

func myLogPrintf(id uint64, format string, v ...interface{}) {
	s := fmt.Sprintf("%x: ", id)
	log.Printf(s+format, v...)
}

func newClientHandler(sess quic.Session) *clientHandler {
	ch := &clientHandler{
		id:   uint64(mrand.Int63()),
		sess: sess,
	}
	ch.readChan = make(chan int, 10)
	ch.stopChan = make(chan struct{})
	ch.firstByte = make(chan byte, 2)
	// by default
	ch.runTime = 15 * time.Second
	return ch
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial (client) / to listen (server)")
	printF := flag.Bool("p", false, "Set this flag to print details for connections")

	flag.Parse()

	addr = *addrF
	print = *printF
	iperfServer()
}

func (ch *clientHandler) serverBandwidthTracker() {
	totalRead := 0
	secRead := 0
	log.Printf("IntervalInSec TransferredLastSecond GlobalBandwidth\n")
	startTime := time.Now()
	ch.timer = utils.NewTimer()
	ch.timer.Reset(startTime.Add(time.Second))
	for {
		select {
		case <-ch.stopChan:
			log.Printf("- - - - - - - - - - - - - - -\n")
			log.Printf("totalReceived %d duration %s\n", totalRead, time.Since(startTime))
			return
		case read := <-ch.readChan:
			totalRead += read
			secRead += read
			break
		case <-ch.timer.Chan():
			ch.timer.SetRead()
			elapsed := time.Since(startTime)
			if elapsed != 0 {
				log.Printf("%d-%d %d %d\n", elapsed/time.Second-1, elapsed/time.Second, secRead, totalRead*1000000000/int(time.Since(startTime)/time.Nanosecond))
			}
			secRead = 0
			ch.timer.Reset(time.Now().Add(time.Second))
			break
		}
	}
}

func (ch *clientHandler) startStreamMeta() {
	var err error
	ch.streamMeta, err = ch.sess.AcceptStream()
	if err != nil {
		log.Printf("Got accept stream meta error: %v\n", err)
		return
	}
	buf := make([]byte, 9)
	_, _ = io.ReadFull(ch.streamMeta, buf)
	runTimeNs := binary.BigEndian.Uint64(buf[1:9])
	// Add 1 second to be more gentle
	ch.runTime = time.Duration(runTimeNs) + time.Second
	println("Got from stream meta", buf[0], ch.runTime)
	ch.firstByte <- buf[0]
}

func (ch *clientHandler) listenForStream() {
	// Cope with old versions
	buf := make([]byte, 1)
	_, _ = io.ReadFull(ch.stream, buf)
	println("Got from stream", buf[0])
	ch.firstByte <- buf[0]
}

// Return true if it is download traffic
func (ch *clientHandler) handleFirstPkt() bool {
	go ch.startStreamMeta()
	go ch.listenForStream()
	select {
	case data := <-ch.firstByte:
		if data == 'D' {
			return true
		}
		return false
	}
}

func (ch *clientHandler) iperfServerHandleSession() {
	var err error
	ch.stream, err = ch.sess.AcceptStream()
	if err != nil {
		log.Printf("Got accept stream error: %v\n", err)
		return
	}
	log.Println("Accept new connection from", ch.sess.RemoteAddr())
	// From interoperability point of view, we are ready for both down and up perf
	_ = ch.handleFirstPkt()
	if print {
		go ch.serverBandwidthTracker()
	}
	buf := make([]byte, BufLen)
	ch.stream.SetDeadline(time.Now().Add(ch.runTime))
forLoop:
	for {
		read, err := io.ReadAtLeast(ch.stream, buf, 1)
		if read == 0 && err == io.EOF {
			if ch.print {
				ch.stopChan <- struct{}{}
				time.Sleep(time.Second)
			}
			break forLoop
		}
		if err != nil {
			break forLoop
		}

		// TODO do something
		if ch.print {
			ch.readChan <- read
		}
	}
	log.Println("Connection terminated from", ch.sess.RemoteAddr())
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
		ch := newClientHandler(sess)
		go ch.iperfServerHandleSession()
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
