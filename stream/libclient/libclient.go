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
	intervalClientTime = 100 * time.Millisecond
	intervalServerTime = 100 * time.Millisecond
	maxID              = 10000
)

var (
	addr            = "localhost:4242"
	buffer          *bytes.Buffer
	chunkClientSize = 2000
	chunkServerSize = 2000
	counterDown     int
	counterUp       int
	counterLock     sync.Mutex
	delaysDown      []time.Duration
	delaysUp        []time.Duration
	delaysLock      sync.Mutex
	nxtAckMsgID     int
	nxtMessageID    int
	printChan       chan struct{}
	runTime         = 14 * time.Second
	sentTime        map[int]time.Time
	startTime       time.Time
	streamDown      quic.Stream
	streamUp        quic.Stream
)

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
	buffer = new(bytes.Buffer)
	delaysDown = make([]time.Duration, 0)
	delaysUp = make([]time.Duration, 0)
	sentTime = make(map[int]time.Time)
	printChan = make(chan struct{}, 1)
	addr = cfg.URL
	runTime = cfg.RunTime
	printChan <- struct{}{}
	initProgressWorker()
	go progressWorker()
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
	delaysLock.Lock()
	counterLock.Lock()
	buffer.WriteString(fmt.Sprintf("Up: %d\n", counterUp))
	for _, d := range delaysUp {
		buffer.WriteString(fmt.Sprintf("%d\n", int64(d/time.Microsecond)))
	}
	buffer.WriteString(fmt.Sprintf("Down: %d\n", counterDown))
	for _, d := range delaysDown {
		buffer.WriteString(fmt.Sprintf("%d\n", int64(d/time.Microsecond)))
	}
	counterLock.Unlock()
	delaysLock.Unlock()
	time.Sleep(time.Second)
	return buffer.String()
}

func sendAck(msgID int) error {
	if streamDown == nil {
		return errors.New("Closed down stream")
	}
	msg := "A&" + strconv.Itoa(msgID+1)
	_, err := streamDown.Write([]byte(msg))
	return err
}

func sendData() error {
	if streamUp == nil {
		return errors.New("Closed up stream")
	}
	startString := "D&" + strconv.Itoa(nxtMessageID) + "&" + strconv.Itoa(chunkClientSize) + "&"
	msg := startString + strings.Repeat("0", chunkClientSize-len(startString))
	sentTime[nxtMessageID] = time.Now()
	_, err := streamUp.Write([]byte(msg))
	nxtMessageID = (nxtMessageID + 1) % maxID
	return err
}

func sendStartPkt() error {
	if streamDown == nil {
		return errors.New("Closed up stream")
	}
	msg := "S&" + strconv.Itoa(maxID) + "&" + strconv.FormatInt(int64(runTime), 10) + "&" + strconv.Itoa(chunkClientSize) + "&" + strconv.Itoa(chunkServerSize) + "&" + strconv.FormatInt(int64(intervalServerTime), 10)
	_, err := streamDown.Write([]byte(msg))
	return err
}

func clientSenderUp() {
	if runTime > 0 {
		streamUp.SetDeadline(time.Now().Add(runTime))
	}
sendLoop:
	for {
		if streamUp == nil {
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
		time.Sleep(intervalClientTime)
	}
}

func checkFormatServerAck(splitMsg []string) bool {
	if len(splitMsg) != 2 {
		println("Wrong size: %d", len(splitMsg))
		return false
	}
	if splitMsg[0] != "A" {
		println("Wrong prefix: %s", splitMsg[0])
		return false
	}
	ackMsgID, err := strconv.Atoi(splitMsg[1])
	if err != nil || ackMsgID != nxtAckMsgID {
		println("Wrong ack num: %s but expects %d", splitMsg[1], nxtAckMsgID)
		return false
	}

	return true
}

func clientReceiverUp() {
	buf := make([]byte, 1000)
	// 0 has been done previously
	nxtAckMsgID = 1
listenLoop:
	for {
		if streamUp == nil {
			break listenLoop
		}
		read, err := io.ReadAtLeast(streamUp, buf, 3)
		rcvTime := time.Now()
		if err != nil {
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !checkFormatServerAck(splitMsg) {
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
		ackedMsgID := ackMsgID - 1
		sent, ok := sentTime[ackMsgID-1]
		if !ok {
			continue
		}
		delaysLock.Lock()
		delaysUp = append(delaysUp, rcvTime.Sub(sent))
		newUp <- tsDelay{ts: rcvTime, delay: rcvTime.Sub(sent)}
		delaysLock.Unlock()
		delete(sentTime, ackedMsgID)
		nxtAckMsgID++

		counterLock.Lock()
		counterUp++
		counterLock.Unlock()
	}
}

func checkFormatServerData(msg string, splitMsg []string) bool {
	//D&{ID}&{SIZE}&{list of previous delays ended by &}{padding}
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
	if err != nil || size != chunkServerSize {
		return false
	}

	return true
}

func clientMain(cfg common.TrafficConfig) error {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	cfgClient := &quic.Config{
		MaxPathID: cfg.MaxPathID,
		NotifyID:  cfg.NotifyID,
	}
	fmt.Println("Trying to connect...")
	// TODO: specify address
	session, err := quic.DialAddr(addr, tlsConfig, cfgClient)
	if err != nil {
		return err
	}
	fmt.Println("Connected")
	streamDown, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	if streamDown == nil {
		return errors.New("Closed down stream when starting")
	}
	if sendStartPkt() != nil {
		return errors.New("Experienced error when sending start packet")
	}

	buf := make([]byte, 3)
	// FIXME timeout
	_, err = io.ReadFull(streamDown, buf)
	if err != nil {
		return errors.New("Read error when starting")
	}
	msg := string(buf)
	if msg != "A&0" {
		return errors.New("Unexpected server answer when starting")
	}

	streamUp, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	startTime = time.Now()
	go clientSenderUp()
	go clientReceiverUp()

	rand.Seed(time.Now().UTC().UnixNano())
	time.Sleep(time.Duration(rand.Int()%10000) * time.Microsecond)

	if runTime > 0 {
		streamDown.SetDeadline(time.Now().Add(runTime))
	}

	buf = make([]byte, chunkServerSize)

listenLoop:
	for {
		if streamDown == nil {
			break listenLoop
		}
		read, err := io.ReadFull(streamDown, buf)
		if err != nil {
			return err
		}
		if read != chunkServerSize {
			return errors.New("Read does not match chunkServerSize")
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !checkFormatServerData(msg, splitMsg) {
			return errors.New("Unexpected format of data packet from server")
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if sendAck(msgID) != nil {
			return errors.New("Got error when sending ack on down stream")
		}
		// Now perform delay extraction, to avoid adding extra estimated delay
		delaysLock.Lock()
		for i := 3; i < len(splitMsg)-1; i++ {
			durInt, err := strconv.ParseInt(splitMsg[i], 10, 64)
			if err != nil {
				delaysLock.Unlock()
				return errors.New("Unparseable delay from server")
			}
			delaysDown = append(delaysDown, time.Duration(durInt))
			newDown <- tsDelay{ts: time.Now(), delay: time.Duration(durInt)}
		}
		delaysLock.Unlock()
		counterLock.Lock()
		counterDown++
		counterLock.Unlock()
	}
	return nil
}
