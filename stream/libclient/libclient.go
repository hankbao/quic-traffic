package libclient

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"bitbucket.org/qdeconinck/quic-traffic/common"
)

/*
  Format start packet of client:
  S&{maxID}&{ackSize}&{runTime}&{uploadChunkSize}&{downloadChunkSize}&{downloadIntervalTime}
  Format data of client:
  D&{ID}&{SIZE}&{padding}
  Format data of server:
  D&{ID}&{SIZE}&{list of previous delays ended by &}{padding}
  Format ACK:
  A&{next ID waited}
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
	ackSize              int
	addr                 string
	buffer               *bytes.Buffer
	uploadChunkSize      int
	downloadChunkSize    int
	counterDown          int
	counterUp            int
	counterLock          sync.Mutex
	delaysDown           []tsDelay
	delaysUp             []tsDelay
	delaysLock           sync.Mutex
	uploadIntervalTime   time.Duration
	downloadIntervalTime time.Duration
	maxID                int
	nxtAckMsgID          int
	nxtMessageID         int
	printChan            chan struct{}
	runTime              time.Duration
	sentTime             map[int]time.Time
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
		sentTime:             make(map[int]time.Time),
		maxID:                maxIDCst,
		uploadIntervalTime:   uploadIntervalTimeCst,
		downloadIntervalTime: downloadIntervalTimeCst,
		uploadChunkSize:      2000,
		downloadChunkSize:    2000,
	}
	// A new closed should be put here
	handlersLock.Lock()
	handlers[cfg.NotifyID] = sh
	handlersLock.Unlock()
	sh.ackSize = 2 + len(strconv.Itoa(sh.maxID-1))
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

func (sh *serverHandler) sendAck(msgID int) error {
	if sh.streamDown == nil {
		return errors.New("Closed down stream")
	}
	msgIDStr := strconv.Itoa(msgID + 1)
	msg := "A&" + strings.Repeat("0", sh.ackSize-2-len(msgIDStr)) + msgIDStr
	_, err := sh.streamDown.Write([]byte(msg))
	return err
}

func (sh *serverHandler) sendData() error {
	if sh.streamUp == nil {
		return errors.New("Closed up stream")
	}
	startString := "D&" + strconv.Itoa(sh.nxtMessageID) + "&" + strconv.Itoa(sh.uploadChunkSize) + "&"
	msg := startString + strings.Repeat("0", sh.uploadChunkSize-len(startString))
	sentTime := time.Now()
	_, err := sh.streamUp.Write([]byte(msg))
	sh.delaysLock.Lock()
	sh.sentTime[sh.nxtMessageID] = sentTime
	sh.delaysLock.Unlock()
	sh.nxtMessageID = (sh.nxtMessageID + 1) % sh.maxID
	return err
}

func (sh *serverHandler) sendStartPkt() error {
	if sh.streamDown == nil {
		return errors.New("Closed up stream")
	}
	msg := "S&" + strconv.Itoa(sh.maxID) + "&" + strconv.Itoa(sh.ackSize) + "&" + strconv.FormatInt(int64(sh.runTime), 10) + "&" + strconv.Itoa(sh.uploadChunkSize) + "&" + strconv.Itoa(sh.downloadChunkSize) + "&" + strconv.FormatInt(int64(sh.downloadIntervalTime), 10)
	_, err := sh.streamDown.Write([]byte(msg))
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

func (sh *serverHandler) checkFormatServerAck(splitMsg []string) bool {
	if len(splitMsg) != 2 {
		fmt.Println("Wrong size:", len(splitMsg))
		return false
	}
	if splitMsg[0] != "A" {
		fmt.Println("Wrong prefix:", splitMsg[0])
		return false
	}
	ackMsgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || ackMsgID != sh.nxtAckMsgID {
		fmt.Println("Wrong ack num:", splitMsg[1], "but expects", sh.nxtAckMsgID)
		return false
	}

	return true
}

func (sh *serverHandler) clientReceiverUp() {
	buf := make([]byte, sh.ackSize)
	// 0 has been done previously
	sh.nxtAckMsgID = 1
	//var err error
listenLoop:
	for {
		if sh.streamUp == nil {
			//err = errors.New("No up stream")
			break listenLoop
		}
		read, err := io.ReadFull(sh.streamUp, buf)
		rcvTime := time.Now()
		if err != nil {
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerAck(splitMsg) {
			err = errors.New("Invalid format of ack from server in up stream")
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
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

func (sh *serverHandler) checkFormatServerData(msg string, splitMsg []string) bool {
	//D&{ID}&{SIZE}&{list of previous delays ended by &}{padding}
	if len(splitMsg) < 4 {
		return false
	}
	if splitMsg[0] != "D" {
		return false
	}
	msgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || msgID < 0 || msgID >= sh.maxID {
		return false
	}
	size, err := strconv.Atoi(splitMsg[2])
	if err != nil || size != sh.downloadChunkSize {
		return false
	}

	return true
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

	buf := make([]byte, 3)
	// FIXME timeout
	_, err = io.ReadFull(sh.streamDown, buf)
	if err != nil {
		return errors.New("Read error when starting")
	}
	msg := string(buf)
	if msg != "A&0" {
		return errors.New("Unexpected server answer when starting")
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

	buf = make([]byte, sh.downloadChunkSize)

	for {
		if sh.streamDown == nil {
			return errors.New("Stream down is nil")
		}
		read, err := io.ReadFull(sh.streamDown, buf)
		if err != nil {
			return err
		}
		if read != sh.downloadChunkSize {
			return errors.New("Read does not match downloadChunkSize")
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerData(msg, splitMsg) {
			return errors.New("Unexpected format of data packet from server")
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if err = sh.sendAck(msgID); err != nil {
			return err
		}
		// Now perform delay extraction, to avoid adding extra estimated delay
		sh.delaysLock.Lock()
		for i := 3; i < len(splitMsg)-1; i++ {
			durInt, err := strconv.ParseInt(splitMsg[i], 10, 64)
			if err != nil {
				sh.delaysLock.Unlock()
				return errors.New("Unparseable delay from server")
			}
			tsD := tsDelay{ts: time.Now(), delay: time.Duration(durInt)}
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
