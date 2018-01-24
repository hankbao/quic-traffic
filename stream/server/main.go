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
	addr = "localhost:4242"
)

type clientHandler struct {
	id uint64

	ackSize            int
	addr               string
	clientChunkSize    int
	serverChunkSize    int
	delays             []time.Duration
	delaysLock         sync.Mutex
	intervalServerTime time.Duration
	maxID              int
	nxtAckMsgID        int
	nxtMessageID       int
	runTime            time.Duration
	sentTime           map[int]time.Time
	sess               quic.Session
	startTime          time.Time
	streamDown         quic.Stream
	streamUp           quic.Stream
}

func myLogPrintf(id uint64, format string, v ...interface{}) {
	s := fmt.Sprintf("%x: ", id)
	log.Printf(s+format, v...)
}

func newClientHandler(sess quic.Session) *clientHandler {
	ch := &clientHandler{
		id:          uint64(mrand.Int63()),
		sess:        sess,
		nxtAckMsgID: 1,
	}
	ch.delays = make([]time.Duration, 0)
	ch.sentTime = make(map[int]time.Time)
	return ch
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to bind")
	flag.Parse()
	addr = *addrF
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
		ch := newClientHandler(sess)
		go ch.handle()
	}
	return err
}

func (ch *clientHandler) sendInitialAck() error {
	if ch.streamDown == nil {
		return errors.New("Closed down stream")
	}
	_, err := ch.streamDown.Write([]byte("A&0"))
	return err
}

func (ch *clientHandler) sendAck(msgID int) error {
	if ch.streamUp == nil {
		return errors.New("Closed up stream")
	}
	msgIDStr := strconv.Itoa(msgID + 1)
	msg := "A&" + strings.Repeat("0", ch.ackSize-2-len(msgIDStr)) + msgIDStr
	_, err := ch.streamUp.Write([]byte(msg))
	return err
}

func (ch *clientHandler) sendData() error {
	if ch.streamDown == nil {
		return errors.New("Closed down stream")
	}
	ch.delaysLock.Lock()
	startString := "D&" + strconv.Itoa(ch.nxtMessageID) + "&" + strconv.Itoa(ch.clientChunkSize) + "&"
	delaysStr := ""
	for _, d := range ch.delays {
		delaysStr += strconv.FormatInt(int64(d), 10) + "&"
	}
	ch.delays = ch.delays[:0]
	ch.delaysLock.Unlock()
	msg := startString + delaysStr + strings.Repeat("0", ch.clientChunkSize-len(startString)-len(delaysStr))
	ch.sentTime[ch.nxtMessageID] = time.Now()
	_, err := ch.streamDown.Write([]byte(msg))
	ch.nxtMessageID = (ch.nxtMessageID + 1) % ch.maxID
	return err
}

func (ch *clientHandler) parseFormatStartPacket(splitMsg []string) bool {
	var err error
	//S&{maxID}&{runTime}&{clientChunkSize}&{serverChunkSize}&{intervalServerTime}
	if len(splitMsg) != 7 {
		myLogPrintf(ch.id, "Invalid size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "S" {
		myLogPrintf(ch.id, "Invalid prefix: %s", splitMsg[0])
		return false
	}
	ch.maxID, err = strconv.Atoi(splitMsg[1])
	if err != nil || ch.maxID <= 0 {
		myLogPrintf(ch.id, "Invalid maxID: %s", splitMsg[1])
		return false
	}
	ch.ackSize, err = strconv.Atoi(splitMsg[2])
	if err != nil || ch.ackSize != len(strconv.Itoa(ch.maxID-1))+2 {
		myLogPrintf(ch.id, "Invalid ackSize: %s", splitMsg[2])
		return false
	}
	runTimeInt, err := strconv.ParseInt(splitMsg[3], 10, 64)
	if err != nil || runTimeInt < 0 {
		myLogPrintf(ch.id, "Invalid runTime: %s", splitMsg[2])
		return false
	}
	ch.runTime = time.Duration(runTimeInt)
	ch.clientChunkSize, err = strconv.Atoi(splitMsg[4])
	if err != nil || ch.clientChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid clientChunkSize: %s", splitMsg[3])
		return false
	}
	ch.serverChunkSize, err = strconv.Atoi(splitMsg[5])
	if err != nil || ch.serverChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid serverChunkSize: %s", splitMsg[4])
		return false
	}
	intervalServerTimeInt, err := strconv.ParseInt(splitMsg[6], 10, 64)
	if err != nil || intervalServerTimeInt <= 0 {
		myLogPrintf(ch.id, "Invalid intervalServerTime: %s with error: %v", splitMsg[5], err)
		return false
	}
	ch.intervalServerTime = time.Duration(intervalServerTimeInt)

	return true
}

func (ch *clientHandler) checkFormatClientData(msg string, splitMsg []string) bool {
	// D&{ID}&{SIZE}&{padding}
	if len(splitMsg) < 4 {
		return false
	}
	if splitMsg[0] != "D" {
		return false
	}
	msgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || msgID < 0 || msgID >= ch.maxID {
		return false
	}
	size, err := strconv.Atoi(splitMsg[2])
	if err != nil || size != ch.clientChunkSize {
		return false
	}

	return true
}

func (ch *clientHandler) serverSenderDown() {
	if ch.runTime > 0 {
		ch.streamDown.SetDeadline(time.Now().Add(ch.runTime))
	}
sendLoop:
	for {
		if ch.streamDown == nil {
			ch.sess.Close(errors.New("Closed down stream"))
			break sendLoop
		}
		if time.Since(ch.startTime) >= ch.runTime {
			ch.sess.Close(nil)
			break sendLoop
		} else {
			err := ch.sendData()
			if err != nil {
				ch.sess.Close(err)
				break sendLoop
			}
		}
		time.Sleep(ch.intervalServerTime)
	}
}

func (ch *clientHandler) checkFormatClientAck(splitMsg []string) bool {
	if len(splitMsg) != 2 {
		myLogPrintf(ch.id, "Wrong size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "A" {
		myLogPrintf(ch.id, "Wrong prefix: %s", splitMsg[0])
		return false
	}
	ackMsgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || ackMsgID != ch.nxtAckMsgID {
		myLogPrintf(ch.id, "Wrong ackMsgID: %s, expected %d", splitMsg[1], ch.nxtAckMsgID)
		return false
	}

	return true
}

func (ch *clientHandler) serverReceiverDown() {
	buf := make([]byte, ch.ackSize)
listenLoop:
	for {
		if ch.streamDown == nil {
			myLogPrintf(ch.id, "Closed down stream\n")
			ch.sess.Close(errors.New("Closed down stream"))
			break listenLoop
		}
		read, err := io.ReadFull(ch.streamDown, buf)
		rcvTime := time.Now()
		if err != nil {
			myLogPrintf(ch.id, "Error when reading acks in down stream: %v\n", err)
			ch.sess.Close(err)
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !ch.checkFormatClientAck(splitMsg) {
			myLogPrintf(ch.id, "Error with ack format from client in down\n")
			ch.sess.Close(errors.New("Error with ack format from client in down"))
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
		ackedMsgID := ackMsgID - 1
		sent, ok := ch.sentTime[ackMsgID-1]
		if !ok {
			continue
		}
		ch.delaysLock.Lock()
		ch.delays = append(ch.delays, rcvTime.Sub(sent))
		ch.delaysLock.Unlock()
		delete(ch.sentTime, ackedMsgID)
		ch.nxtAckMsgID++
	}
}

func (ch *clientHandler) handle() {
	var err error
	myLogPrintf(ch.id, "Accept new connection on %v from %v\n", ch.sess.LocalAddr(), ch.sess.RemoteAddr())
	ch.streamDown, err = ch.sess.AcceptStream()
	if err != nil {
		myLogPrintf(ch.id, "Got accept down stream error: %v\n", err)
		ch.sess.Close(err)
		return
	}

	buf := make([]byte, InitialBufLen)
	// FIXME timeout
	read, err := io.ReadAtLeast(ch.streamDown, buf, 11)
	if err != nil {
		myLogPrintf(ch.id, "Read error when starting: %v\n", err)
		ch.sess.Close(err)
		return
	}
	msg := string(buf[:read])
	splitMsg := strings.Split(msg, "&")
	// First collect the parameters of the stream traffic
	if !ch.parseFormatStartPacket(splitMsg) {
		myLogPrintf(ch.id, "Invalid format for start packet\n")
		ch.sess.Close(errors.New("Invalid format for start packet"))
		return
	}

	myLogPrintf(ch.id, "Start packet ok, %d %d %s %d %d %s\n", ch.maxID, ch.ackSize, ch.runTime, ch.clientChunkSize, ch.serverChunkSize, ch.intervalServerTime)
	if ch.sendInitialAck() != nil {
		myLogPrintf(ch.id, "Error when sending initial ack on down stream\n")
		ch.sess.Close(errors.New("Error when sending initial ack on down stream"))
		return
	}

	ch.streamUp, err = ch.sess.AcceptStream()
	if err != nil {
		myLogPrintf(ch.id, "Got accept up stream error: %v\n", err)
		ch.sess.Close(err)
		return
	}

	ch.startTime = time.Now()
	go ch.serverSenderDown()
	go ch.serverReceiverDown()

	if ch.runTime > 0 {
		ch.streamUp.SetDeadline(time.Now().Add(ch.runTime))
	}
	buf = make([]byte, ch.clientChunkSize)

serveLoop:
	for {
		read, err := io.ReadFull(ch.streamUp, buf)
		if err != nil {
			myLogPrintf(ch.id, "Error when reading up stream: %v\n", err)
			ch.sess.Close(err)
			break serveLoop
		}
		if read != ch.clientChunkSize {
			myLogPrintf(ch.id, "Did not read the expected size on up stream; %d != %d\n", read, ch.clientChunkSize)
			ch.sess.Close(errors.New("Did not read the expected size on up stream"))
			break serveLoop
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !ch.checkFormatClientData(msg, splitMsg) {
			myLogPrintf(ch.id, "Unexpected format of data packet from client")
			ch.sess.Close(errors.New("Unexpected format of data packet from client"))
			break serveLoop
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if err = ch.sendAck(msgID); err != nil {
			myLogPrintf(ch.id, "Encountered error when sending ACK on up stream: %v\n")
			ch.sess.Close(err)
			break serveLoop
		}
	}
	myLogPrintf(ch.id, "Close connection on %v from %v\n", ch.sess.LocalAddr(), ch.sess.RemoteAddr())
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
