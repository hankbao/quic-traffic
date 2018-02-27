package libclient

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"bitbucket.org/qdeconinck/quic-traffic/common"
)

/*
	/!\ Length does not includes itself, so a packet has always a min length of 4 bytes

  Format start packet of client:
  [Length(4)|'S'(1)|runTimeNs(8)|uploadChunkSize(4)|downloadChunkSize(4)|downloadIntervalTimeNs(8)]
  Format data of client:
  [Length(4)|'D'(1)|msgID(4)|padding]
  Format data of server:
  [Length(4)|'D'(1)|msgID(4)|NumDelays(4)|{list of previous delays (8)}|padding]
  Format ACK:
  [Length(4)|'A'(1)|msgID (4)]
*/

const (
	uploadIntervalTimeCst   = 100 * time.Millisecond
	downloadIntervalTimeCst = 100 * time.Millisecond
	maxIDCst                = 10000
)

type tsDelay struct {
	ts    time.Time
	delay time.Duration
}

type serverHandler struct {
	addr                 string
	buffer               *bytes.Buffer
	uploadChunkSize      uint32
	downloadChunkSize    uint32
	counterDown          int
	counterUp            int
	counterLock          sync.Mutex
	delaysDown           []tsDelay
	delaysUp             []tsDelay
	delaysLock           sync.Mutex
	uploadIntervalTime   time.Duration
	downloadIntervalTime time.Duration
	nxtAckMsgID          uint32
	nxtMessageID         uint32
	printChan            chan struct{}
	runTime              time.Duration
	sentTime             map[uint32]time.Time
	sess                 quic.Session
	startTime            time.Time
	streamDown           quic.Stream
	streamUp             quic.Stream

	// Specific to in-progress results
	newDelaysDown []tsDelay
	newDelaysUp   []tsDelay
	newDelaysLock sync.RWMutex
	newDown       chan tsDelay
	newUp         chan tsDelay
	request       chan struct{}
	response      chan string
	closed        chan struct{}
	closeLock     sync.Mutex
}

var (
	handlers     = make(map[string]*serverHandler)
	handlersLock sync.RWMutex
)

func GetProgressResults(notifyID string) string {
	handlersLock.RLock()
	defer handlersLock.RUnlock()
	hl, ok := handlers[notifyID]
	if ok {
		select {
		case hl.request <- struct{}{}:
			return <-hl.response
		default:
			return ""
		}
	}
	return ""
}

func StopStream(notifyID string) {
	handlersLock.RLock()
	defer handlersLock.RUnlock()
	hl, ok := handlers[notifyID]
	if ok {
		hl.closeSession(nil)
	}
}

func (sh *serverHandler) closeSession(err error) {
	sh.closeLock.Lock()
	defer sh.closeLock.Unlock()
	// Also close the chan
	select {
	case <-sh.closed:
		// Nothing to do
	default:
		close(sh.closed)
		if sh.sess != nil {
			sh.sess.Close(err)
		}
	}
}

func (sh *serverHandler) initProgressWorker() {
	sh.newDelaysDown = make([]tsDelay, 0)
	sh.newDelaysUp = make([]tsDelay, 0)
	sh.newDown = make(chan tsDelay, 5)
	sh.newUp = make(chan tsDelay, 5)
	sh.request = make(chan struct{})
	sh.response = make(chan string)
	sh.closed = make(chan struct{})
}

func (sh *serverHandler) progressWorker() {
workerLoop:
	for {
		select {
		case d := <-sh.newDown:
			sh.newDelaysDown = append(sh.newDelaysDown, d)
		case u := <-sh.newUp:
			sh.newDelaysUp = append(sh.newDelaysUp, u)
		case <-sh.request:
			buf := new(bytes.Buffer)
			buf.WriteString(fmt.Sprintf("Up: %d\n", len(sh.newDelaysUp)))
			for _, d := range sh.newDelaysUp {
				buf.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
			}
			buf.WriteString(fmt.Sprintf("Down: %d\n", len(sh.newDelaysDown)))
			for _, d := range sh.newDelaysDown {
				buf.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
			}
			sh.newDelaysUp = sh.newDelaysUp[:0]
			sh.newDelaysDown = sh.newDelaysDown[:0]
			sh.response <- buf.String()
		case <-sh.closed:
			break workerLoop
		}
	}
}

// End of in-progress results

// Run starts a client that opens two streams, a uplink and a downlink streams.
// It first negotiates the parameters on the downlink stream, then both hosts
// start to send packets at a regular rate in a streaming fashion, the client
// over the uplink stream, the server over the downlink one.
func Run(cfg common.TrafficConfig) string {
	sh := &serverHandler{
		addr:                 cfg.URL,
		buffer:               new(bytes.Buffer),
		delaysDown:           make([]tsDelay, 0),
		delaysUp:             make([]tsDelay, 0),
		printChan:            make(chan struct{}, 1),
		runTime:              cfg.RunTime,
		sentTime:             make(map[uint32]time.Time),
		uploadIntervalTime:   uploadIntervalTimeCst,
		downloadIntervalTime: downloadIntervalTimeCst,
		uploadChunkSize:      2000,
		downloadChunkSize:    2000,
	}
	// A new closed should be put here
	handlersLock.Lock()
	handlers[cfg.NotifyID] = sh
	handlersLock.Unlock()
	sh.printChan <- struct{}{}
	sh.initProgressWorker()
	go sh.progressWorker()
	err := sh.handle(cfg)
	fmt.Println("Out of handle")
	sh.buffer.WriteString(fmt.Sprintf("Exiting client main with error %v\n", err))
	sh.closeSession(err)
	handlersLock.Lock()
	delete(handlers, cfg.NotifyID)
	handlersLock.Unlock()
	fmt.Println("Just to print out")
	return sh.printer()
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func (sh *serverHandler) printer() string {
	<-sh.printChan
	sh.delaysLock.Lock()
	sh.counterLock.Lock()
	sh.buffer.WriteString(fmt.Sprintf("Up: %d\n", len(sh.delaysUp)))
	for _, d := range sh.delaysUp {
		sh.buffer.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
	}
	sh.buffer.WriteString(fmt.Sprintf("Down: %d\n", len(sh.delaysDown)))
	for _, d := range sh.delaysDown {
		sh.buffer.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
	}
	sh.counterLock.Unlock()
	sh.delaysLock.Unlock()
	time.Sleep(time.Second)
	return sh.buffer.String()
}

// [Length(4)|'A'(1)|msgID (4)]
func (sh *serverHandler) sendAck(msgID uint32) error {
	if sh.streamDown == nil {
		return errors.New("Closed down stream")
	}
	data := make([]byte, 9)
	binary.BigEndian.PutUint32(data, 5)
	data[4] = 'A'
	binary.BigEndian.PutUint32(data[5:9], msgID+1)
	_, err := sh.streamDown.Write(data)
	return err
}

// [Length(4)|'D'(1)|msgID(4)|padding]
func (sh *serverHandler) sendData() error {
	if sh.streamUp == nil {
		return errors.New("Closed up stream")
	}
	data := make([]byte, sh.uploadChunkSize)
	binary.BigEndian.PutUint32(data, sh.uploadChunkSize-4)
	data[4] = 'D'
	binary.BigEndian.PutUint32(data[5:9], sh.nxtMessageID)
	sentTime := time.Now()
	_, err := sh.streamUp.Write(data)
	sh.delaysLock.Lock()
	sh.sentTime[sh.nxtMessageID] = sentTime
	sh.delaysLock.Unlock()
	sh.nxtMessageID++
	return err
}

// [Length(4)|'S'(1)|runTimeNs(8)|uploadChunkSize(4)|downloadChunkSize(4)|downloadIntervalTimeNs(8)]
func (sh *serverHandler) sendStartPkt() error {
	if sh.streamDown == nil {
		return errors.New("Closed up stream")
	}
	data := make([]byte, 29)
	binary.BigEndian.PutUint32(data, 25)
	data[4] = 'S'
	binary.BigEndian.PutUint64(data[5:13], uint64(sh.runTime))
	binary.BigEndian.PutUint32(data[13:17], sh.uploadChunkSize)
	binary.BigEndian.PutUint32(data[17:21], sh.downloadChunkSize)
	binary.BigEndian.PutUint64(data[21:29], uint64(sh.downloadIntervalTime))
	_, err := sh.streamDown.Write(data)
	return err
}

func (sh *serverHandler) clientSenderUp() {
	if sh.runTime > 0 {
		sh.streamUp.SetDeadline(time.Now().Add(sh.runTime))
	}
	var err error
sendLoop:
	for {
		if sh.streamUp == nil {
			break sendLoop
		}
		if sh.runTime > 0 && time.Since(sh.startTime) >= sh.runTime {
			break sendLoop
		} else {
			err = sh.sendData()
			if err != nil {
				break sendLoop
			}
		}
		time.Sleep(sh.uploadIntervalTime)
	}
}

// [Length(4)|'A'(1)|ackMsgID(4)]
func (sh *serverHandler) checkFormatServerAck(data []byte) (uint32, bool) {
	lenAck := binary.BigEndian.Uint32(data)
	if lenAck != 5 {
		fmt.Println("Wrong size:", lenAck)
		return 0, false
	}
	if data[4] != 'A' {
		fmt.Println("Wrong prefix:", data[4])
		return 0, false
	}
	ackMsgID := binary.BigEndian.Uint32(data[5:9])
	if ackMsgID != sh.nxtAckMsgID {
		fmt.Println("Wrong ack num:", ackMsgID, "but expects", sh.nxtAckMsgID)
		return ackMsgID, false
	}

	return ackMsgID, true
}

func (sh *serverHandler) clientReceiverUp() {
	// The ACK size should always be 9
	buf := make([]byte, 9)
	// 0 has been done previously
	sh.nxtAckMsgID = 1
	//var err error
listenLoop:
	for {
		if sh.streamUp == nil {
			//err = errors.New("No up stream")
			break listenLoop
		}
		_, err := io.ReadFull(sh.streamUp, buf)
		rcvTime := time.Now()
		if err != nil {
			break listenLoop
		}
		ackMsgID, ok := sh.checkFormatServerAck(buf)
		if !ok {
			err = errors.New("Invalid format of ack from server in up stream")
			break listenLoop
		}
		ackedMsgID := ackMsgID - 1
		sh.delaysLock.Lock()
		sent, ok := sh.sentTime[ackMsgID-1]
		if !ok {
			sh.delaysLock.Unlock()
			continue
		}
		tsD := tsDelay{ts: rcvTime, delay: rcvTime.Sub(sent)}
		sh.delaysUp = append(sh.delaysUp, tsD)
		select {
		case sh.newUp <- tsD:
		case <-sh.closed: // Yep, we might be stuck in a deadlock otherwise...
		}
		sh.delaysLock.Unlock()
		delete(sh.sentTime, ackedMsgID)
		sh.nxtAckMsgID++

		sh.counterLock.Lock()
		sh.counterUp++
		sh.counterLock.Unlock()
	}
}

// [Length(4)|'D'(1)|msgID(4)|NumDelays(4)|{list of previous delays (8)}|padding]
func (sh *serverHandler) checkFormatServerData(data []byte) (uint32, bool) {
	lenData := binary.BigEndian.Uint32(data)
	if lenData != sh.downloadChunkSize-4 {
		print(lenData, sh.downloadChunkSize-4)
		return 0, false
	}
	if data[4] != 'D' {
		print(data[4])
		return 0, false
	}
	msgID := binary.BigEndian.Uint32(data[5:9])

	return msgID, true
}

func (sh *serverHandler) handle(cfg common.TrafficConfig) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfgClient := &quic.Config{
		MaxPathID:        cfg.MaxPathID,
		MultipathService: cfg.MultipathService,
		NotifyID:         cfg.NotifyID,
	}
	fmt.Println("Trying to connect...")
	var err error
	// TODO: specify address
	sh.sess, err = quic.DialAddr(sh.addr, tlsConfig, cfgClient)
	if err != nil {
		return err
	}
	fmt.Println("Connected")
	sh.streamDown, err = sh.sess.OpenStreamSync()
	if err != nil {
		return err
	}

	if sh.streamDown == nil {
		return errors.New("Closed down stream when starting")
	}
	if err = sh.sendStartPkt(); err != nil {
		return errors.New("Experienced error when sending start packet")
	}

	buf := make([]byte, 9)
	// FIXME timeout
	_, err = io.ReadFull(sh.streamDown, buf)
	if err != nil {
		return errors.New("Read error when starting")
	}
	ackLen := binary.BigEndian.Uint32(buf)
	if ackLen != 5 {
		return errors.New("Unexpected ack length for initial ack")
	}
	if buf[4] != 'A' {
		return errors.New("Unexpected prefix for initial ack")
	}
	msgID := binary.BigEndian.Uint32(buf[5:9])
	if msgID != 0 {
		return errors.New("Unexpected message ID for initial ack: " + strconv.Itoa(int(msgID)))
	}

	sh.streamUp, err = sh.sess.OpenStreamSync()
	if err != nil {
		return err
	}

	sh.startTime = time.Now()
	go sh.clientSenderUp()
	go sh.clientReceiverUp()

	rand.Seed(time.Now().UTC().UnixNano())
	time.Sleep(time.Duration(rand.Int()%10000) * time.Microsecond)

	if sh.runTime > 0 {
		sh.streamDown.SetDeadline(time.Now().Add(sh.runTime))
	}

	bufLen := make([]byte, 4)
	buf = make([]byte, sh.downloadChunkSize-4)

	for {
		if sh.streamDown == nil {
			return errors.New("Stream down is nil")
		}
		_, err := io.ReadFull(sh.streamDown, bufLen)
		if err != nil {
			return err
		}
		toRead := binary.BigEndian.Uint32(bufLen)
		read, err := io.ReadFull(sh.streamDown, buf)
		if err != nil {
			return err
		}
		if read != int(toRead) {
			println(read, toRead)
			return errors.New("Length field does not match the read amount of bytes")
		}
		data := append(bufLen, buf...)
		msgID, ok := sh.checkFormatServerData(data)
		if !ok {
			return errors.New("Unexpected format of data packet from server")
		}
		if err = sh.sendAck(msgID); err != nil {
			return err
		}
		// Now perform delay extraction, to avoid adding extra estimated delay
		sh.delaysLock.Lock()
		numDelays := binary.BigEndian.Uint32(data[9:13])
		for i := 0; i < int(numDelays); i++ {
			startIndex := 13 + 8*i
			delayNs := binary.BigEndian.Uint64(data[startIndex : startIndex+8])
			tsD := tsDelay{ts: time.Now(), delay: time.Duration(delayNs)}
			sh.delaysDown = append(sh.delaysDown, tsD)
			select {
			case sh.newDown <- tsD:
			case <-sh.closed: // Yep, we might be stuck in a deadlock otherwise...
			}
		}
		sh.delaysLock.Unlock()
		sh.counterLock.Lock()
		sh.counterDown++
		sh.counterLock.Unlock()
	}
	return nil
}
