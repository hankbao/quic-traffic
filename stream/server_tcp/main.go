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
	"net"
	"sync"
	"time"
)

const (
	InitialBufLen = 1000
	MinChunkSize  = 20
)

type clientHandler struct {
	id     uint64
	connID uint64

	addr                 string
	connDown             *net.TCPConn
	connUp               *net.TCPConn
	connUpChan           chan *net.TCPConn
	uploadChunkSize      uint32
	downloadChunkSize    uint32
	delays               []time.Duration
	delaysLock           sync.Mutex
	downloadIntervalTime time.Duration
	nxtAckMsgID          uint32
	nxtMessageID         uint32
	runTime              time.Duration
	sentTime             map[uint32]time.Time
	startTime            time.Time
}

var (
	addr               = "localhost:4242"
	clientHandlers     = make(map[uint64]*clientHandler)
	clientHandlersLock sync.RWMutex
)

func myLogPrintf(id uint64, format string, v ...interface{}) {
	s := fmt.Sprintf("%x: ", id)
	log.Printf(s+format, v...)
}

func newClientHandler(connDown *net.TCPConn) *clientHandler {
	ch := &clientHandler{
		id:          uint64(mrand.Int63()),
		connDown:    connDown,
		nxtAckMsgID: 1,
	}
	ch.delays = make([]time.Duration, 0)
	ch.sentTime = make(map[uint32]time.Time)
	ch.connUpChan = make(chan *net.TCPConn)
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

// [Length(4)|'S'(1)|connID(8)|runTimeNs(8)|uploadChunkSize(4)|downloadChunkSize(4)|downloadIntervalTimeNs(8)]
func (ch *clientHandler) parseFormatStartPacket(data []byte) bool {
	startLen := binary.BigEndian.Uint32(data)
	if startLen != 33 {
		myLogPrintf(ch.id, "Invalid size: %d", startLen)
		return false
	}
	if data[4] != 'S' {
		myLogPrintf(ch.id, "Invalid prefix: %s", data[4])
		return false
	}
	ch.connID = binary.BigEndian.Uint64(data[5:13])
	runTimeNs := binary.BigEndian.Uint64(data[13:21])
	ch.runTime = time.Duration(runTimeNs)
	ch.uploadChunkSize = binary.BigEndian.Uint32(data[21:25])
	if ch.uploadChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid uploadChunkSize: %d", ch.uploadChunkSize)
		return false
	}
	ch.downloadChunkSize = binary.BigEndian.Uint32(data[25:29])
	if ch.downloadChunkSize < MinChunkSize {
		myLogPrintf(ch.id, "Invalid downloadChunkSize: %d", ch.downloadChunkSize)
		return false
	}
	downloadIntervalTimeNs := binary.BigEndian.Uint64(data[29:37])
	ch.downloadIntervalTime = time.Duration(downloadIntervalTimeNs)

	return true
}

// [Length(4)|'U'(1)|connID(8)]
func parseFirstUploadPacket(data []byte) (uint64, bool) {
	startLen := binary.BigEndian.Uint32(data)
	if startLen != 9 {
		log.Printf("Invalid size: %d", startLen)
		return 0, false
	}
	if data[4] != 'U' {
		log.Printf("Invalid prefix: %d", data[4])
		return 0, false
	}
	connID := binary.BigEndian.Uint64(data[5:13])

	return connID, true
}

func parseFirstPacket(tcpConn *net.TCPConn, data []byte) bool {
	// First packet either is a start packet (S prefix) or an upload packet (U prefix)
	if data[4] == 'S' {
		ch := newClientHandler(tcpConn)
		if !ch.parseFormatStartPacket(data) {
			log.Printf("Error when parsing start packet\n")
			return false
		}
		myLogPrintf(ch.id, "Start packet ok, %d %s %d %d %s\n", ch.connID, ch.runTime, ch.uploadChunkSize, ch.downloadChunkSize, ch.downloadIntervalTime)
		if ch.sendInitialAck() != nil {
			myLogPrintf(ch.id, "Error when sending initial ack on down connection\n")
			return false
		}
		clientHandlersLock.Lock()
		clientHandlers[ch.connID] = ch
		clientHandlersLock.Unlock()
		go ch.handle()
		return true
	}
	if data[4] == 'U' {
		connID, ok := parseFirstUploadPacket(data)
		if !ok {
			log.Printf("Error when parsing start packet\n")
			return false
		}
		clientHandlersLock.Lock()
		defer clientHandlersLock.Unlock()
		ch, ok := clientHandlers[connID]
		if !ok {
			log.Printf("No client handler with connection ID %v\n", connID)
			return false
		}
		// It worked! The connection here is the upload one, no need to ACK
		myLogPrintf(ch.id, "Found upload connection of %d\n", ch.connID)
		// Remove the ch from clientHandlers to avoid issues
		delete(clientHandlers, connID)
		ch.connUpChan <- tcpConn
		close(ch.connUpChan)
		return true
	}
	log.Printf("Unknown prefix for first packet: %v\n", data[4])
	log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	tcpConn.Close()
	return false
}

func handleFirstPacket(tcpConn *net.TCPConn) {
	var err error
	log.Printf("Accept new connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())

	tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
	bufLenWithPrefix := make([]byte, 5)
	_, err = io.ReadFull(tcpConn, bufLenWithPrefix)
	if err != nil {
		log.Printf("Read error when starting: %v\n", err)
		log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
		tcpConn.Close()
		return
	}
	var remainingBuf []byte
	if bufLenWithPrefix[4] == 'S' {
		remainingBuf = make([]byte, 32) // 37 - 5
	} else if bufLenWithPrefix[4] == 'U' {
		remainingBuf = make([]byte, 8) // 13 - 5
	} else {
		log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
		tcpConn.Close()
		return
	}
	_, err = io.ReadFull(tcpConn, remainingBuf)
	if err != nil {
		log.Printf("Read error when starting: %v\n", err)
		log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
		tcpConn.Close()
		return
	}
	data := append(bufLenWithPrefix, remainingBuf...)
	if !parseFirstPacket(tcpConn, data) {
		log.Printf("Invalid format for start packet\n")
		log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
		tcpConn.Close()
		return
	}
}

// Start a server that performs similar traffic to Siri servers
func streamServer() error {
	mrand.Seed(time.Now().UTC().UnixNano())
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("Got accept error: %v\n", err)
			continue
		}
		go handleFirstPacket(tcpConn)
	}
	return err
}

// [Length(4)|'A'(1)|ackMsgID(4)]
func (ch *clientHandler) sendInitialAck() error {
	if ch.connDown == nil {
		return errors.New("Closed down conn")
	}
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, 5)
	data[4] = 'A'
	binary.BigEndian.PutUint32(data[5:9], 0)
	_, err := ch.connDown.Write(data)
	return err
}

// [Length(4)|'A'(1)|ackMsgID(4)]
func (ch *clientHandler) sendAck(msgID uint32) error {
	if ch.connUp == nil {
		return errors.New("Closed up stream")
	}
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, 5)
	data[4] = 'A'
	binary.BigEndian.PutUint32(data[5:9], msgID+1)
	_, err := ch.connUp.Write(data)
	return err
}

// [Length(4)|'D'(1)|msgID(4)|NumDelays(4)|{list of previous delays (8)}|padding]
func (ch *clientHandler) sendData() error {
	if ch.connDown == nil {
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
	msgID := ch.nxtMessageID
	_, err := ch.connDown.Write(data)
	ch.nxtMessageID++
	ch.delaysLock.Lock()
	ch.sentTime[msgID] = sentTime
	ch.delaysLock.Unlock()
	return err
}

// [Length(4)|'D'(1)|msgID(4)|padding]
func (ch *clientHandler) checkFormatClientData(data []byte) (uint32, bool) {
	dataLen := binary.BigEndian.Uint32(data)
	if dataLen != ch.uploadChunkSize-4 {
		myLogPrintf(ch.id, "DataLen of %d while expecting %d\n", dataLen, ch.uploadChunkSize-4)
		return 0, false
	}
	if data[4] != 'D' {
		myLogPrintf(ch.id, "Prefix is %d while expecting %d\n", data[4], 'D')
		return 0, false
	}
	msgID := binary.BigEndian.Uint32(data[5:9])

	return msgID, true
}

func (ch *clientHandler) serverSenderDown() {
	if ch.runTime > 0 {
		ch.connDown.SetDeadline(time.Now().Add(ch.runTime))
	} else {
		print("No deadline")
		ch.connDown.SetDeadline(time.Time{})
	}
sendLoop:
	for {
		if ch.connDown == nil {
			break sendLoop
		}
		if ch.runTime > 0 && time.Since(ch.startTime) >= ch.runTime {
			break sendLoop
		} else {
			err := ch.sendData()
			if err != nil {
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
		if ch.connDown == nil {
			myLogPrintf(ch.id, "Closed down stream\n")
			break listenLoop
		}
		_, err := io.ReadFull(ch.connDown, buf)
		rcvTime := time.Now()
		if err != nil {
			myLogPrintf(ch.id, "Error when reading acks in down stream: %v\n", err)
			break listenLoop
		}
		ackMsgID, ok := ch.checkFormatClientAck(buf)
		if !ok {
			myLogPrintf(ch.id, "Error with ack format from client in down\n")
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
	if ch.connDown != nil {
		ch.connDown.Close()
	}
}

func (ch *clientHandler) handle() {
	ch.connUp = <-ch.connUpChan
	myLogPrintf(ch.id, "Starting traffic")
	ch.startTime = time.Now()
	go ch.serverSenderDown()
	go ch.serverReceiverDown()

	if ch.runTime > 0 {
		ch.connUp.SetDeadline(time.Now().Add(ch.runTime))
	} else {
		print("No deadline")
		ch.connUp.SetDeadline(time.Time{})
	}
	buf := make([]byte, ch.uploadChunkSize)

serveLoop:
	for {
		read, err := io.ReadFull(ch.connUp, buf)
		if err != nil {
			myLogPrintf(ch.id, "Error when reading up stream: %v\n", err)
			ch.connUp.Close()
			break serveLoop
		}
		if read != int(ch.uploadChunkSize) {
			myLogPrintf(ch.id, "Did not read the expected size on up stream; %d != %d\n", read, ch.uploadChunkSize)
			ch.connUp.Close()
			break serveLoop
		}
		msgID, ok := ch.checkFormatClientData(buf)
		if !ok {
			myLogPrintf(ch.id, "Unexpected format of data packet from client")
			ch.connUp.Close()
			break serveLoop
		}
		if err = ch.sendAck(msgID); err != nil {
			myLogPrintf(ch.id, "Encountered error when sending ACK on up stream: %v\n")
			ch.connUp.Close()
			break serveLoop
		}
	}
	myLogPrintf(ch.id, "Close connection on %v from %v\n", ch.connUp.LocalAddr(), ch.connUp.RemoteAddr())
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
