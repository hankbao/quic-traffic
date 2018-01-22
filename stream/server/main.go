package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

const (
	InitialBufLen = 1000
	MinChunkSize  = 20
)

var (
	addr               = "localhost:4242"
	chunkClientSize    = 2000
	chunkServerSize    = 2000
	delays             []time.Duration
	delaysLock         sync.Mutex
	intervalServerTime = 100 * time.Millisecond
	maxID              = 10000
	nxtAckMsgID        = 1
	nxtMessageID       int
	runTime            = 30 * time.Second
	sentTime           map[int]time.Time
	startTime          time.Time
	streamDown         quic.Stream
	streamUp           quic.Stream
)

func myLogPrintf(id uint64, format string, v ...interface{}) {
	s := fmt.Sprintf("%x: ", id)
	log.Printf(s+format, v...)
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to bind")
	flag.Parse()
	addr = *addrF
	delays = make([]time.Duration, 0)
	sentTime = make(map[int]time.Time)
	err := streamServer()
	if err != nil {
		log.Printf("Got main error: %v\n", err)
	}
}

// Start a server that performs similar traffic to Siri servers
func streamServer() error {
	mrand.Seed(time.Now().UTC().UnixNano())
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
		go handleClient(sess, uint64(mrand.Int63()))
	}
	return err
}

func sendInitialAck() error {
	if streamDown == nil {
		return errors.New("Closed down stream")
	}
	_, err := streamDown.Write([]byte("A&0"))
	return err
}

func sendAck(msgID int) error {
	if streamUp == nil {
		return errors.New("Closed down stream")
	}
	msg := "A&" + strconv.Itoa(msgID+1)
	_, err := streamUp.Write([]byte(msg))
	return err
}

func sendData() error {
	if streamDown == nil {
		return errors.New("Closed down stream")
	}
	delaysLock.Lock()
	startString := "D&" + strconv.Itoa(nxtMessageID) + "&" + strconv.Itoa(chunkClientSize) + "&"
	delaysStr := ""
	for _, d := range delays {
		delaysStr += strconv.FormatInt(int64(d), 10) + "&"
	}
	delays = delays[:0]
	delaysLock.Unlock()
	msg := startString + delaysStr + strings.Repeat("0", chunkClientSize-len(startString)-len(delaysStr))
	sentTime[nxtMessageID] = time.Now()
	_, err := streamDown.Write([]byte(msg))
	nxtMessageID = (nxtMessageID + 1) % maxID
	return err
}

func parseFormatStartPacket(id uint64, splitMsg []string) bool {
	var err error
	//S&{maxID}&{runTime}&{chunkClientSize}&{chunkServerSize}&{intervalServerTime}
	if len(splitMsg) != 6 {
		myLogPrintf(id, "Invalid size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "S" {
		myLogPrintf(id, "Invalid prefix: %s", splitMsg[0])
		return false
	}
	maxID, err = strconv.Atoi(splitMsg[1])
	if err != nil || maxID <= 0 {
		myLogPrintf(id, "Invalid maxID: %s", splitMsg[1])
		return false
	}
	runTimeInt, err := strconv.ParseInt(splitMsg[2], 10, 64)
	if err != nil || runTimeInt < 0 {
		myLogPrintf(id, "Invalid runTime: %s", splitMsg[2])
		return false
	}
	runTime = time.Duration(runTimeInt)
	chunkClientSize, err = strconv.Atoi(splitMsg[3])
	if err != nil || chunkClientSize < MinChunkSize {
		myLogPrintf(id, "Invalid chunkClientSize: %s", splitMsg[3])
		return false
	}
	chunkServerSize, err = strconv.Atoi(splitMsg[4])
	if err != nil || chunkServerSize < MinChunkSize {
		myLogPrintf(id, "Invalid chunkServerSize: %s", splitMsg[4])
		return false
	}
	intervalServerTimeInt, err := strconv.ParseInt(splitMsg[5], 10, 64)
	if err != nil || intervalServerTimeInt <= 0 {
		myLogPrintf(id, "Invalid intervalServerTime: %s with error: %v", splitMsg[5], err)
		return false
	}
	intervalServerTime = time.Duration(intervalServerTimeInt)

	return true
}

func checkFormatClientData(msg string, splitMsg []string) bool {
	// D&{ID}&{SIZE}&{padding}
	if len(splitMsg) < 4 {
		return false
	}
	if splitMsg[0] != "D" {
		return false
	}
	msgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || msgID < 0 || msgID >= maxID {
		return false
	}
	size, err := strconv.Atoi(splitMsg[2])
	if err != nil || size != chunkClientSize {
		return false
	}

	return true
}

func serverSenderDown() {
	if runTime > 0 {
		streamDown.SetDeadline(time.Now().Add(runTime))
	}
sendLoop:
	for {
		if streamDown == nil {
			break sendLoop
		}
		if time.Since(startTime) >= runTime {
			streamUp.Close()
			break sendLoop
		} else {
			err := sendData()
			if err != nil {
				streamUp.Close()
				break sendLoop
			}
		}
		time.Sleep(intervalServerTime)
	}
}

func checkFormatClientAck(id uint64, splitMsg []string) bool {
	if len(splitMsg) != 2 {
		myLogPrintf(id, "Wrong size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "A" {
		myLogPrintf(id, "Wrong prefix: %s", splitMsg[0])
		return false
	}
	ackMsgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || ackMsgID != nxtAckMsgID {
		myLogPrintf(id, "Wrong ackMsgID: %s, expected %d", splitMsg[1], nxtAckMsgID)
		return false
	}

	return true
}

func serverReceiverDown(id uint64) {
	buf := make([]byte, InitialBufLen)
listenLoop:
	for {
		if streamDown == nil {
			myLogPrintf(id, "Closed down stream\n")
			break listenLoop
		}
		read, err := io.ReadAtLeast(streamDown, buf, 3)
		rcvTime := time.Now()
		if err != nil {
			myLogPrintf(id, "Error when reading acks in down stream: %v\n", err)
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !checkFormatClientAck(id, splitMsg) {
			myLogPrintf(id, "Error with ack format from client in down\n")
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
		ackedMsgID := ackMsgID - 1
		sent, ok := sentTime[ackMsgID-1]
		if !ok {
			continue
		}
		delaysLock.Lock()
		delays = append(delays, rcvTime.Sub(sent))
		delaysLock.Unlock()
		delete(sentTime, ackedMsgID)
		nxtAckMsgID++
	}
}

func handleClient(sess quic.Session, id uint64) {
	var err error
	myLogPrintf(id, "Accept new connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())
	streamDown, err = sess.AcceptStream()
	if err != nil {
		myLogPrintf(id, "Got accept down stream error: %v\n", err)
		return
	}

	buf := make([]byte, InitialBufLen)
	// FIXME timeout
	read, err := io.ReadAtLeast(streamDown, buf, 11)
	if err != nil {
		myLogPrintf(id, "Read error when starting: %v\n", err)
		streamDown.Close()
		return
	}
	msg := string(buf[:read])
	splitMsg := strings.Split(msg, "&")
	// First collect the parameters of the stream traffic
	if !parseFormatStartPacket(id, splitMsg) {
		myLogPrintf(id, "Invalid format for start packet\n")
		streamDown.Close()
		return
	}

	myLogPrintf(id, "Start packet ok, %d %s %d %d %s\n", maxID, runTime, chunkClientSize, chunkServerSize, intervalServerTime)
	if sendInitialAck() != nil {
		myLogPrintf(id, "Error when sending initial ack on down stream\n")
		streamDown.Close()
		return
	}

	streamUp, err = sess.AcceptStream()
	if err != nil {
		myLogPrintf(id, "Got accept up stream error: %v\n", err)
		streamDown.Close()
		return
	}

	startTime = time.Now()
	go serverSenderDown()
	go serverReceiverDown(id)

	if runTime > 0 {
		streamUp.SetDeadline(time.Now().Add(runTime))
	}
	buf = make([]byte, chunkClientSize)

serveLoop:
	for {
		read, err := io.ReadFull(streamUp, buf)
		if err != nil {
			myLogPrintf(id, "Error when reading up stream: %v\n", err)
			streamUp.Close()
			break serveLoop
		}
		if read != chunkClientSize {
			myLogPrintf(id, "Did not read the expected size on up stream; %d != %d\n", read, chunkClientSize)
			streamUp.Close()
			break serveLoop
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !checkFormatClientData(msg, splitMsg) {
			myLogPrintf(id, "Unexpected format of data packet from client")
			streamUp.Close()
			break serveLoop
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if err = sendAck(msgID); err != nil {
			myLogPrintf(id, "Encountered error when sending ACK on up stream: %v\n")
			streamUp.Close()
			break serveLoop
		}
	}
	myLogPrintf(id, "Close connection on %v from %v\n", sess.LocalAddr(), sess.RemoteAddr())
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
