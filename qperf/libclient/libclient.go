package libclient

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"bitbucket.org/qdeconinck/quic-traffic/common"
	utils "bitbucket.org/qdeconinck/quic-traffic/utils"
)

var (
	addr      = "localhost:4242"
	multipath = false
	timer     *utils.Timer
	readChan  chan int
	ret       string
	stopChan  chan struct{}
	stream    quic.Stream
)

const (
	BufLen = 8000000
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func Run(cfg common.TrafficConfig) string {
	if cfg.Output != "" {
		logfile, err := os.Create(cfg.Output)
		if err != nil {
			return err.Error()
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	quicConfig := &quic.Config{
		MaxPathID:      cfg.MaxPathID,
		NotifyID:       cfg.NotifyID,
		CacheHandshake: cfg.Cache,
	}

	flag.Parse()

	addr = cfg.URL
	var err error

	err = iperfClient(quicConfig, 10*time.Second)

	if err != nil {
		return err.Error()
	}

	return ret
}

func clientBandwidthTracker(startTime time.Time) {
	var totalSent quic.ByteCount
	var lastTotalSent quic.ByteCount
	var totalRetrans quic.ByteCount
	var lastTotalRetrans quic.ByteCount
	ret += fmt.Sprintf("IntervalInSec TransferredLastSecond GlobalBandwidth RetransmittedLastSecond\n")
	timer = utils.NewTimer()
	timer.Reset(startTime.Add(time.Second))
	for {
		select {
		case <-stopChan:
			ret += fmt.Sprintf("- - - - - - - - - - - - - - -\n")
			ret += fmt.Sprintf("totalSent %d duration %s totalRetrans %d\n", totalSent, time.Since(startTime), totalRetrans)
			return
		case <-timer.Chan():
			timer.SetRead()
			elapsed := time.Since(startTime)
			totalSent = stream.GetBytesSent()
			totalRetrans = stream.GetBytesRetrans()
			if elapsed != 0 {
				ret += fmt.Sprintf("%d-%d %d %d %d\n", elapsed/time.Second-1, elapsed/time.Second, totalSent-lastTotalSent, totalSent*1000000000/quic.ByteCount(time.Since(startTime)/time.Nanosecond), totalRetrans-lastTotalRetrans)
			}
			lastTotalSent = totalSent
			lastTotalRetrans = totalRetrans
			timer.Reset(time.Now().Add(time.Second))
			break
		}
	}
}

func iperfClient(quicConfig *quic.Config, maxTime time.Duration) error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, quicConfig)
	if err != nil {
		return err
	}

	stream, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	message := strings.Repeat("0123456789", 400000)
	startTime := time.Now()
	go clientBandwidthTracker(startTime)
	stopChan = make(chan struct{})
	stream.SetDeadline(time.Now().Add(maxTime))

	for {
		elapsed := time.Since(startTime)
		if elapsed >= maxTime {
			stopChan <- struct{}{}
			stream.Close()
			time.Sleep(time.Second)
			return nil
		}
		_, err := stream.Write([]byte(message))
		if err != nil {
			panic(err)
		}
	}

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
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
