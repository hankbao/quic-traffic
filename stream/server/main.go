package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
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

	addr                 string
	uploadChunkSize      uint32
	downloadChunkSize    uint32
	delays               []time.Duration
	delaysLock           sync.Mutex
	downloadIntervalTime time.Duration
	nxtAckMsgID          uint32
	nxtMessageID         uint32
	runTime              time.Duration
	sentTime             map[uint32]time.Time
	sess                 quic.Session
	startTime            time.Time
	streamDown           quic.Stream
	streamUp             quic.Stream
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
	ch.sentTime = make(map[uint32]time.Time)
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
	var err error
	mrand.Seed(time.Now().UTC().UnixNano())
	for {
		listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
		if err != nil {
			return err
		}
	listenLoop:
		for {
			sess, err := listener.Accept()
			if err != nil {
				log.Printf("Got accept error: %v\n", err)
				break listenLoop
			}
			ch := newClientHandler(sess)
			go ch.handle()
		}
	}
	return err
}

// [Length(4)|'A'(1)|ackMsgID(4)]
func (ch *clientHandler) sendInitialAck() error {
	if ch.streamDown == nil {
		return errors.New("Closed down stream")
	}
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, 5)
	data[4] = 'A'
	binary.BigEndian.PutUint32(data[5:9], 0)
	_, err := ch.streamDown.Write(data)
	return err
}

// [Length(4)|'A'(1)|ackMsgID(4)]
func (ch *clientHandler) sendAck(msgID uint32) error {
	if ch.streamUp == nil {
		return errors.New("Closed up stream")
	}
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, 5)
	data[4] = 'A'
	binary.BigEndian.PutUint32(data[5:9], msgID+1)
	_, err := ch.streamUp.Write(data)
	return err
}

// [Length(4)|'D'(1)|msgID(4)|NumDelays(4)|{list of previous delays (8)}|padding]
func (ch *clientHandler) sendData() error {
	if ch.streamDown == nil {
		return errors.New("Closed down stream")
	}
	data := make([]byte, ch.downloadChunkSize)
	binary.BigEndian.PutUint32(data, ch.downloadChunkSize-4)
	data[4] = 'D'
	binary.BigEndian.PutUint32(data[5:9], ch.nxtMessageID)
	i := 0
	ch.delaysLock.Lock()
	for _, d := range ch.delays {
		startIndex := 13 + i*8
		if uint32(startIndex) <= ch.downloadChunkSize-8 {
			binary.BigEndian.PutUint64(data[startIndex:startIndex+8], uint64(d))
			i++
		}
	}
	ch.delays = ch.delays[:0]
	ch.delaysLock.Unlock()
	// Don't forget to indicate how many delays were written
	binary.BigEndian.PutUint32(data[9:13], uint32(i))

	sentTime := time.Now()
	_, err := ch.streamDown.Write(data)
	ch.nxtMessageID++
	ch.delaysLock.Lock()
	ch.sentTime[ch.nxtMessageID] = sentTime
	ch.delaysLock.Unlock()
	return err
}

// [Length(4)|'S'(1)|runTimeNs(8)|uploadChunkSize(4)|downloadChunkSize(4)|downloadIntervalTimeNs(8)]
func (ch *clientHandler) parseFormatStartPacket(data []byte) bool {
	startLen := binary.BigEndian.Uint32(data)
	if startLen != 25 {
		myLogPrintf(ch.id, "Invalid size: %d", startLen)
		return false
	}
	if data[4] != 'S' {
		myLogPrintf(ch.id, "Invalid prefix: %s", data[4])
		return false
	}
	runTimeNs := binary.BigEndian.Uint64(data[5:13])
	ch.runTime = time.Duration(runTimeNs)
	ch.uploadChunkSize = binary.BigEndian.Uint32(data[13:17])
	if ch.uploadChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid uploadChunkSize: %d", ch.uploadChunkSize)
		return false
	}
	ch.downloadChunkSize = binary.BigEndian.Uint32(data[17:21])
	if ch.downloadChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid downloadChunkSize: %d", ch.downloadChunkSize)
		return false
	}
	downloadIntervalTimeNs := binary.BigEndian.Uint64(data[21:29])
	ch.downloadIntervalTime = time.Duration(downloadIntervalTimeNs)

	return true
}

// [Length(4)|'D'(1)|msgID(4)|padding]
func (ch *clientHandler) checkFormatClientData(data []byte) (uint32, bool) {
	dataLen := binary.BigEndian.Uint32(data)
	if dataLen != ch.uploadChunkSize-4 {
		return 0, false
	}
	if data[4] != 'D' {
		return 0, false
	}
	msgID := binary.BigEndian.Uint32(data[5:9])

	return msgID, true
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
		if ch.runTime > 0 && time.Since(ch.startTime) >= ch.runTime {
			ch.sess.Close(nil)
			break sendLoop
		} else {
			err := ch.sendData()
			if err != nil {
				ch.sess.Close(err)
				break sendLoop
			}
		}
		time.Sleep(ch.downloadIntervalTime)
	}
}

// [Length(4)|'A'(1)|msgID (4)]
func (ch *clientHandler) checkFormatClientAck(data []byte) (uint32, bool) {
	ackLen := binary.BigEndian.Uint32(data)
	if ackLen != 5 {
		myLogPrintf(ch.id, "Wrong ACK size: %d", ackLen)
		return 0, false
	}
	if data[4] != 'A' {
		myLogPrintf(ch.id, "Wrong prefix: %s", data[4])
		return 0, false
	}

	ackMsgID := binary.BigEndian.Uint32(data[5:9])
	if ackMsgID != ch.nxtAckMsgID {
		myLogPrintf(ch.id, "Wrong ackMsgID: %d, expected %d", ackMsgID, ch.nxtAckMsgID)
		return ackMsgID, false
	}

	return ackMsgID, true
}

func (ch *clientHandler) serverReceiverDown() {
	// An ACK is 9 byte long
	buf := make([]byte, 9)
listenLoop:
	for {
		if ch.streamDown == nil {
			myLogPrintf(ch.id, "Closed down stream\n")
			ch.sess.Close(errors.New("Closed down stream"))
			break listenLoop
		}
		_, err := io.ReadFull(ch.streamDown, buf)
		rcvTime := time.Now()
		if err != nil {
			myLogPrintf(ch.id, "Error when reading acks in down stream: %v\n", err)
			ch.sess.Close(err)
			break listenLoop
		}
		ackMsgID, ok := ch.checkFormatClientAck(buf)
		if !ok {
			myLogPrintf(ch.id, "Error with ack format from client in down\n")
			ch.sess.Close(errors.New("Error with ack format from client in down"))
			break listenLoop
		}
		ackedMsgID := ackMsgID - 1
		ch.nxtAckMsgID++
		ch.delaysLock.Lock()
		sent, ok := ch.sentTime[ackedMsgID]
		if !ok {
			ch.delaysLock.Unlock()
			continue
		}
		ch.delays = append(ch.delays, rcvTime.Sub(sent))
		delete(ch.sentTime, ackedMsgID)
		ch.delaysLock.Unlock()
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

	bufLen := make([]byte, 4)
	// FIXME timeout
	_, err = io.ReadFull(ch.streamDown, bufLen)
	if err != nil {
		myLogPrintf(ch.id, "Read error when starting: %v\n", err)
		ch.sess.Close(err)
		return
	}
	bufLength := binary.BigEndian.Uint32(bufLen)
	buf := make([]byte, bufLength)
	_, err = io.ReadFull(ch.streamDown, buf)
	if err != nil {
		myLogPrintf(ch.id, "Read error when starting: %v\n", err)
		ch.sess.Close(err)
		return
	}
	data := append(bufLen, buf...)
	// First collect the parameters of the stream traffic
	if !ch.parseFormatStartPacket(data) {
		myLogPrintf(ch.id, "Invalid format for start packet\n")
		ch.sess.Close(errors.New("Invalid format for start packet"))
		return
	}

	myLogPrintf(ch.id, "Start packet ok, %s %d %d %s\n", ch.runTime, ch.uploadChunkSize, ch.downloadChunkSize, ch.downloadIntervalTime)
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
	buf = make([]byte, ch.uploadChunkSize)

serveLoop:
	for {
		read, err := io.ReadFull(ch.streamUp, buf)
		if err != nil {
			myLogPrintf(ch.id, "Error when reading up stream: %v\n", err)
			ch.sess.Close(err)
			break serveLoop
		}
		if read != int(ch.uploadChunkSize) {
			myLogPrintf(ch.id, "Did not read the expected size on up stream; %d != %d\n", read, ch.uploadChunkSize)
			ch.sess.Close(errors.New("Did not read the expected size on up stream"))
			break serveLoop
		}
		msgID, ok := ch.checkFormatClientData(buf)
		if !ok {
			myLogPrintf(ch.id, "Unexpected format of data packet from client")
			ch.sess.Close(errors.New("Unexpected format of data packet from client"))
			break serveLoop
		}
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
