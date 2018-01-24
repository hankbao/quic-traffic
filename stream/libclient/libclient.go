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
  S&{maxID}&{runTime}&{uploadChunkSize}&{downloadChunkSize}&{downloadIntervalTime}
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
}

// Specific to in-progress results

var (
	newDelaysDown []tsDelay
	newDelaysUp   []tsDelay
	newDelaysLock sync.RWMutex
	newDown       chan tsDelay
	newUp         chan tsDelay
	request       chan struct{}
	response      chan string
	closed        chan struct{}
)

func GetProgressResults() string {
	select {
	case request <- struct{}{}:
		return <-response
	default:
		return ""
	}
}

func initProgressWorker() {
	newDelaysDown = make([]tsDelay, 0)
	newDelaysUp = make([]tsDelay, 0)
	newDown = make(chan tsDelay, 5)
	newUp = make(chan tsDelay, 5)
	request = make(chan struct{})
	response = make(chan string)
	closed = make(chan struct{})
}

func progressWorker() {
workerLoop:
	for {
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
		case <-closed:
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
	sh.ackSize = 2 + len(strconv.Itoa(sh.maxID-1))
	sh.printChan <- struct{}{}
	initProgressWorker()
	go progressWorker()
	err := sh.handle(cfg)
	sh.buffer.WriteString(fmt.Sprintf("Exiting client main with error %v\n", err))
	close(closed)
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
	sh.sentTime[sh.nxtMessageID] = time.Now()
	_, err := sh.streamUp.Write([]byte(msg))
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
sendLoop:
	for {
		if sh.streamUp == nil {
			break sendLoop
		}
		if time.Since(sh.startTime) >= sh.runTime {
			sh.streamUp.Close()
			sh.sess.Close(nil)
			break sendLoop
		} else {
			err := sh.sendData()
			if err != nil {
				sh.streamUp.Close()
				sh.sess.Close(err)
				break sendLoop
			}
		}
		time.Sleep(sh.uploadIntervalTime)
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
	buf := make([]byte, sh.ackSize)
	// 0 has been done previously
	sh.nxtAckMsgID = 1
listenLoop:
	for {
		if sh.streamUp == nil {
			sh.sess.Close(errors.New("No up stream"))
			break listenLoop
		}
		read, err := io.ReadFull(sh.streamUp, buf)
		rcvTime := time.Now()
		if err != nil {
			sh.sess.Close(err)
			break listenLoop
		}
		msg := string(buf[:read])
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerAck(splitMsg) {
			sh.sess.Close(errors.New("Invalid format of ack from server in up stream"))
			break listenLoop
		}
		ackMsgID, _ := strconv.Atoi(splitMsg[1])
		ackedMsgID := ackMsgID - 1
		sent, ok := sh.sentTime[ackMsgID-1]
		if !ok {
			continue
		}
		sh.delaysLock.Lock()
		tsD := tsDelay{ts: rcvTime, delay: rcvTime.Sub(sent)}
		sh.delaysUp = append(sh.delaysUp, tsD)
		select {
		case newUp <- tsD:
		case <-closed: // Yep, we might be stuck in a deadlock otherwise...
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
		MaxPathID: cfg.MaxPathID,
		NotifyID:  cfg.NotifyID,
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
		sh.sess.Close(err)
		return err
	}

	if sh.streamDown == nil {
		err = errors.New("Closed down stream when starting")
		sh.sess.Close(err)
		return err
	}
	if err = sh.sendStartPkt(); err != nil {
		sh.sess.Close(err)
		return errors.New("Experienced error when sending start packet")
	}

	buf := make([]byte, 3)
	// FIXME timeout
	_, err = io.ReadFull(sh.streamDown, buf)
	if err != nil {
		sh.sess.Close(err)
		return errors.New("Read error when starting")
	}
	msg := string(buf)
	if msg != "A&0" {
		err = errors.New("Unexpected server answer when starting")
		sh.sess.Close(err)
		return err
	}

	sh.streamUp, err = sh.sess.OpenStreamSync()
	if err != nil {
		sh.sess.Close(err)
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

listenLoop:
	for {
		if sh.streamDown == nil {
			sh.sess.Close(errors.New("Stream down is nil"))
			break listenLoop
		}
		read, err := io.ReadFull(sh.streamDown, buf)
		if err != nil {
			sh.sess.Close(err)
			return err
		}
		if read != sh.downloadChunkSize {
			err := errors.New("Read does not match downloadChunkSize")
			sh.sess.Close(err)
			return err
		}
		msg := string(buf)
		splitMsg := strings.Split(msg, "&")
		if !sh.checkFormatServerData(msg, splitMsg) {
			err := errors.New("Unexpected format of data packet from server")
			sh.sess.Close(err)
			return err
		}
		msgID, _ := strconv.Atoi(splitMsg[1])
		if err2 := sh.sendAck(msgID); err != nil {
			println(err2)
			err := errors.New("Got error when sending ack on down stream")
			sh.sess.Close(err)
			return err
		}
		// Now perform delay extraction, to avoid adding extra estimated delay
		sh.delaysLock.Lock()
		for i := 3; i < len(splitMsg)-1; i++ {
			durInt, err := strconv.ParseInt(splitMsg[i], 10, 64)
			if err != nil {
				sh.delaysLock.Unlock()
				err := errors.New("Unparseable delay from server")
				sh.sess.Close(err)
				return err
			}
			tsD := tsDelay{ts: time.Now(), delay: time.Duration(durInt)}
			sh.delaysDown = append(sh.delaysDown, tsD)
			select {
			case newDown <- tsD:
			case <-closed: // Yep, we might be stuck in a deadlock otherwise...
			}
		}
		sh.delaysLock.Unlock()
		sh.counterLock.Lock()
		sh.counterDown++
		sh.counterLock.Unlock()
	}
	sh.sess.Close(nil)
	return nil
}
