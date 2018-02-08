package libclient

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"bitbucket.org/qdeconinck/quic-traffic/common"
)

const (
	intervalTime = 400 * time.Millisecond
	maxID        = 100
)

var (
	addr        = "localhost:4242"
	buffer      *bytes.Buffer
	counter     int
	counterLock sync.Mutex
	delays      []time.Duration
	messageID   int
	missed      int
	printChan   chan struct{}
	querySize   = 750
	resSize     = 750
	runTime     = 14 * time.Second
	sentTime    map[int]time.Time
	startTime   time.Time
	stream      quic.Stream
)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func Run(cfg common.TrafficConfig) string {
	buffer = new(bytes.Buffer)
	delays = make([]time.Duration, 0)
	sentTime = make(map[int]time.Time)
	printChan = make(chan struct{}, 1)
	addr = cfg.URL
	printChan <- struct{}{}
	err := clientMain(cfg)
	buffer.WriteString(fmt.Sprintf("Exiting client main with error %v\n", err))
	return printer()
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func printer() string {
	<-printChan
	buffer.WriteString(fmt.Sprintf("Missed: %d\n", missed))
	for _, d := range delays {
		buffer.WriteString(fmt.Sprintf("%d\n", int64(d/time.Millisecond)))
	}
	time.Sleep(time.Second)
	return buffer.String()
}

func sendMessage() error {
	if stream == nil {
		return errors.New("Closed stream")
	}
	sentTime[messageID] = time.Now()
	startString := strconv.Itoa(messageID) + "&" + strconv.Itoa(querySize) + "&" + strconv.Itoa(resSize) + "&" + "0" + "&"
	messageID = (messageID + 1) % maxID
	msg := startString + strings.Repeat("0", querySize-len(startString))
	_, err := stream.Write([]byte(msg))
	return err
}

func clientSender() {
	stream.SetDeadline(time.Now().Add(runTime))
sendLoop:
	for {
		if stream == nil {
			break sendLoop
		}
		if time.Since(startTime) >= runTime {
			stream.Close()
			break sendLoop
		} else {
			err := sendMessage()
			if err != nil {
				stream.Close()
				break sendLoop
			}
		}
		time.Sleep(intervalTime)
	}
}

func clientMain(cfg common.TrafficConfig) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfgClient := &quic.Config{
		MaxPathID:        cfg.MaxPathID,
		MultipathService: cfg.MultipathService,
		NotifyID:         cfg.NotifyID,
	}
	fmt.Println("Trying to connect...")
	// TODO: specify address
	session, err := quic.DialAddr(addr, tlsConfig, cfgClient)
	if err != nil {
		return err
	}
	fmt.Println("Connected")
	startTime = time.Now()
	stream, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	go clientSender()

	buf := make([]byte, resSize)
listenLoop:
	for {
		if stream == nil {
			break listenLoop
		}
		read, err := io.ReadFull(stream, buf)
		receivedTime := time.Now()
		if err != nil {
			return err
		}
		if read != resSize {
			return errors.New("Read does not match resSize")
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		msgID, _ := strconv.Atoi(splitMsg[0])
		sent, ok := sentTime[msgID]
		if !ok {
			continue
		}
		delays = append(delays, receivedTime.Sub(sent))
		delete(sentTime, msgID)
		counterLock.Lock()
		counter -= querySize
		counterLock.Unlock()
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
