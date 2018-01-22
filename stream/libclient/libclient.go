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
  S&{maxID}&{runTime}&{chunkClientSize}&{chunkServerSize}&{intervalServerTime}
  Format data of client:
  D&{ID}&{SIZE}&{padding}
  Format data of server:
  D&{ID}&{SIZE}&{list of previous delays ended by &}{padding}
  Format ACK:
  A&{next ID waited}
*/

const (
	intervalClientTimeCst = 100 * time.Millisecond
	intervalServerTimeCst = 100 * time.Millisecond
	maxIDCst              = 10000
)

type serverHandler struct {
	addr               string
	buffer             *bytes.Buffer
	chunkClientSize    int
	chunkServerSize    int
	counterDown        int
	counterUp          int
	counterLock        sync.Mutex
	delaysDown         []time.Duration
	delaysUp           []time.Duration
	delaysLock         sync.Mutex
	intervalClientTime time.Duration
	intervalServerTime time.Duration
	maxID              int
	nxtAckMsgID        int
	nxtMessageID       int
	printChan          chan struct{}
	runTime            time.Duration
	sentTime           map[int]time.Time
	sess               quic.Session
	startTime          time.Time
	streamDown         quic.Stream
	streamUp           quic.Stream
}

// Specific to in-progress results
type tsDelay struct {
	ts    time.Time
	delay time.Duration
}

var (
	newDelaysDown []tsDelay
	newDelaysUp   []tsDelay
	newDelaysLock sync.RWMutex
	newDown       chan tsDelay
	newUp         chan tsDelay
	request       chan struct{}
	response      chan string
)

func GetProgressResults() string {
	request <- struct{}{}
	return <-response
}

func initProgressWorker() {
	newDelaysDown = make([]tsDelay, 0)
	newDelaysUp = make([]tsDelay, 0)
	newDown = make(chan tsDelay, 5)
	newUp = make(chan tsDelay, 5)
	request = make(chan struct{})
	response = make(chan string)
}

func progressWorker() {
	select {
	case d := <-newDown:
		newDelaysDown = append(newDelaysDown, d)
	case u := <-newUp:
		newDelaysUp = append(newDelaysUp, u)
	case <-request:
		buf := new(bytes.Buffer)
		buf.WriteString(fmt.Sprintf("Up: %d\n", len(newDelaysUp)))
		for _, d := range newDelaysUp {
			buf.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
		}
		buf.WriteString(fmt.Sprintf("Down: %d\n", len(newDelaysDown)))
		for _, d := range newDelaysDown {
			buf.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
		}
		newDelaysUp = newDelaysUp[:0]
		newDelaysDown = newDelaysDown[:0]
		response <- buf.String()
	}
}

// End of in-progress results

// Run starts a client that opens two streams, a uplink and a downlink streams.
// It first negotiates the parameters on the downlink stream, then both hosts
// start to send packets at a regular rate in a streaming fashion, the client
// over the uplink stream, the server over the downlink one.
func Run(cfg common.TrafficConfig) string {
	sh := &serverHandler{
		addr:       cfg.URL,
		buffer:     new(bytes.Buffer),
		delaysDown: make([]time.Duration, 0),
		delaysUp:   make([]time.Duration, 0),
		printChan:  make(chan struct{}, 1),
		runTime:    cfg.RunTime,
		sentTime:   make(map[int]time.Time),
	}
	sh.printChan <- struct{}{}
	initProgressWorker()
	go progressWorker()
	err := sh.handle(cfg)
	sh.buffer.WriteString(fmt.Sprintf("Exiting client main with error %v\n", err))
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
	sh.buffer.WriteString(fmt.Sprintf("Up: %d\n", sh.counterUp))
	for _, d := range sh.delaysUp {
		sh.buffer.WriteString(fmt.Sprintf("%d\n", int64(d/time.Microsecond)))
	}
	sh.buffer.WriteString(fmt.Sprintf("Down: %d\n", sh.counterDown))
	for _, d := range sh.delaysDown {
		sh.buffer.WriteString(fmt.Sprintf("%d\n", int64(d/time.Microsecond)))
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
	msg := "A&" + strconv.Itoa(msgID+1)
	_, err := sh.streamDown.Write([]byte(msg))
	return err
}

func (sh *serverHandler) sendData() error {
	if sh.streamUp == nil {
		return errors.New("Closed up stream")
	}
	startString := "D&" + strconv.Itoa(sh.nxtMessageID) + "&" + strconv.Itoa(sh.chunkClientSize) + "&"
	msg := startString + strings.Repeat("0", sh.chunkClientSize-len(startString))
	sh.sentTime[sh.nxtMessageID] = time.Now()
	_, err := sh.streamUp.Write([]byte(msg))
	sh.nxtMessageID = (sh.nxtMessageID + 1) % sh.maxID
	return err
}

func (sh *serverHandler) sendStartPkt() error {
	if sh.streamDown == nil {
		return errors.New("Closed up stream")
	}
	msg := "S&" + strconv.Itoa(sh.maxID) + "&" + strconv.FormatInt(int64(sh.runTime), 10) + "&" + strconv.Itoa(sh.chunkClientSize) + "&" + strconv.Itoa(sh.chunkServerSize) + "&" + strconv.FormatInt(int64(sh.intervalServerTime), 10)
	_, err := sh.streamDown.Write([]byte(msg))
	return err
}

func (sh *serverHandler) clientSenderUp() {
	if sh.runTime > 0 {
		sh.streamUp.SetDeadline(time.Now().Add(sh.runTime))
	}
sendLoop:
	for {
		if sh.streamUp == nil {
			break sendLoop
		}
		if time.Since(sh.startTime) >= sh.runTime {
			sh.streamUp.Close()
			break sendLoop
		} else {
			err := sh.sendData()
			if err != nil {
				sh.streamUp.Close()
				break sendLoop
			}
		}
		time.Sleep(sh.intervalClientTime)
	}
}

func (sh *serverHandler) checkFormatServerAck(splitMsg []string) bool {
	if len(splitMsg) != 2 {
		println("Wrong size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "A" {
		println("Wrong prefix: %s", splitMsg[0])
		return false
	}
	ackMsgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || ackMsgID != sh.nxtAckMsgID {
		println("Wrong ack num: %s but expects %d", splitMsg[1], sh.nxtAckMsgID)
		return false
	}

	return true
}

func (sh *serverHandler) clientReceiverUp() {
	buf := make([]byte, 1000)
	// 0 has been done previously
	sh.nxtAckMsgID = 1
listenLoop:
	for {
		if sh.streamUp == nil {
			break listenLoop
		}
		read, err := io.ReadAtLeast(sh.streamUp, buf, 3)
		rcvTime := time.Now()
		if err != nil {
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerAck(splitMsg) {
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
		ackedMsgID := ackMsgID - 1
		sent, ok := sh.sentTime[ackMsgID-1]
		if !ok {
			continue
		}
		sh.delaysLock.Lock()
		sh.delaysUp = append(sh.delaysUp, rcvTime.Sub(sent))
		newUp <- tsDelay{ts: rcvTime, delay: rcvTime.Sub(sent)}
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
	if err != nil || size != sh.chunkServerSize {
		return false
	}

	return true
}

func (sh *serverHandler) handle(cfg common.TrafficConfig) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfgClient := &quic.Config{
		MaxPathID: cfg.MaxPathID,
		NotifyID:  cfg.NotifyID,
	}
	fmt.Println("Trying to connect...")
	// TODO: specify address
	session, err := quic.DialAddr(sh.addr, tlsConfig, cfgClient)
	if err != nil {
		return err
	}
	fmt.Println("Connected")
	sh.streamDown, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	if sh.streamDown == nil {
		return errors.New("Closed down stream when starting")
	}
	if sh.sendStartPkt() != nil {
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

	sh.streamUp, err = session.OpenStreamSync()
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

	buf = make([]byte, sh.chunkServerSize)

listenLoop:
	for {
		if sh.streamDown == nil {
			break listenLoop
		}
		read, err := io.ReadFull(sh.streamDown, buf)
		if err != nil {
			return err
		}
		if read != sh.chunkServerSize {
			return errors.New("Read does not match chunkServerSize")
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerData(msg, splitMsg) {
			return errors.New("Unexpected format of data packet from server")
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if sh.sendAck(msgID) != nil {
			return errors.New("Got error when sending ack on down stream")
		}
		// Now perform delay extraction, to avoid adding extra estimated delay
		sh.delaysLock.Lock()
		for i := 3; i < len(splitMsg)-1; i++ {
			durInt, err := strconv.ParseInt(splitMsg[i], 10, 64)
			if err != nil {
				sh.delaysLock.Unlock()
				return errors.New("Unparseable delay from server")
			}
			sh.delaysDown = append(sh.delaysDown, time.Duration(durInt))
			newDown <- tsDelay{ts: time.Now(), delay: time.Duration(durInt)}
		}
		sh.delaysLock.Unlock()
		sh.counterLock.Lock()
		sh.counterDown++
		sh.counterLock.Unlock()
	}
	return nil
}
