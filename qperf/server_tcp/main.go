package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	utils "bitbucket.org/qdeconinck/quic-traffic/utils"
)

type clientHandler struct {
	id     uint64
	connID uint64

	readChan chan int
	stopChan chan struct{}
	timer    *utils.Timer

	download     bool
	metaConn     *net.TCPConn
	dataConn     *net.TCPConn
	dataConnChan chan *net.TCPConn
	print        bool
	runTime      time.Duration
	startTime    time.Time
}

var (
	addr  = "localhost:4242"
	print bool

	clientHandlers     = make(map[uint64]*clientHandler)
	clientHandlersLock sync.RWMutex
)

const (
	BufLen = 8000000
)

func myLogPrintf(id uint64, format string, v ...interface{}) {
	s := fmt.Sprintf("%x: ", id)
	log.Printf(s+format, v...)
}

func newClientHandler(metaConn *net.TCPConn, download bool) *clientHandler {
	ch := &clientHandler{
		id:       uint64(mrand.Int63()),
		metaConn: metaConn,
		download: download,
		print:    print,
	}
	ch.dataConnChan = make(chan *net.TCPConn)
	ch.readChan = make(chan int, 10)
	ch.stopChan = make(chan struct{})
	return ch
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	addrF := flag.String("addr", "localhost:4242", "Address to dial (client) / to listen (server)")
	printF := flag.Bool("p", false, "Set this flag to print details for connections")

	flag.Parse()

	addr = *addrF
	print = *printF
	iperfServer()
}

func (ch *clientHandler) serverBandwidthTracker() {
	totalRead := 0
	secRead := 0
	log.Printf("IntervalInSec TransferredLastSecond GlobalBandwidth\n")
	startTime := time.Now()
	ch.timer = utils.NewTimer()
	ch.timer.Reset(startTime.Add(time.Second))
	for {
		select {
		case <-ch.stopChan:
			log.Printf("- - - - - - - - - - - - - - -\n")
			log.Printf("totalReceived %d duration %s\n", totalRead, time.Since(startTime))
			return
		case read := <-ch.readChan:
			totalRead += read
			secRead += read
			break
		case <-ch.timer.Chan():
			ch.timer.SetRead()
			elapsed := time.Since(startTime)
			if elapsed != 0 {
				log.Printf("%d-%d %d %d\n", elapsed/time.Second-1, elapsed/time.Second, secRead, totalRead*1000000000/int(time.Since(startTime)/time.Nanosecond))
			}
			secRead = 0
			ch.timer.Reset(time.Now().Add(time.Second))
			break
		}
	}
}

// [Length(4)|'S'(1)|connID(8)|runTimeNs(8)|uploadChunkSize(4)|downloadChunkSize(4)|downloadIntervalTimeNs(8)]
func (ch *clientHandler) parseFormatMetaPacket(data []byte) bool {
	startLen := binary.BigEndian.Uint32(data)
	if startLen != 18 {
		myLogPrintf(ch.id, "Invalid size: %d", startLen)
		return false
	}
	if data[4] != 'M' {
		myLogPrintf(ch.id, "Invalid prefix: %s", data[4])
		return false
	}
	ch.connID = binary.BigEndian.Uint64(data[6:14])
	runTimeNs := binary.BigEndian.Uint64(data[14:22])
	// Add one second to be more gentle
	ch.runTime = time.Duration(runTimeNs) + time.Second

	return true
}

// [Length(4)|'D'(1)|connID(8)]
func parseFirstDataPacket(data []byte) (uint64, bool) {
	startLen := binary.BigEndian.Uint32(data)
	if startLen != 9 {
		log.Printf("Invalid size: %d", startLen)
		return 0, false
	}
	if data[4] != 'D' {
		log.Printf("Invalid prefix: %d", data[4])
		return 0, false
	}
	connID := binary.BigEndian.Uint64(data[5:13])

	return connID, true
}

// ['1'(1)]
func (ch *clientHandler) sendInitialAck() error {
	if ch.metaConn == nil {
		return errors.New("Closed down conn")
	}
	data := make([]byte, 1)
	data[0] = '1'
	_, err := ch.metaConn.Write(data)
	return err
}

func parseFirstPacket(tcpConn *net.TCPConn, data []byte) bool {
	// First packet either is a meta packet (M prefix) or an data packet (D prefix)
	if data[4] == 'M' {
		download := data[5] == 'D'
		ch := newClientHandler(tcpConn, download)
		if !ch.parseFormatMetaPacket(data) {
			log.Printf("Error when parsing start packet\n")
			return false
		}
		myLogPrintf(ch.id, "Start packet ok, %d %s\n", ch.connID, ch.runTime)
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
	if data[4] == 'D' {
		connID, ok := parseFirstDataPacket(data)
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
		myLogPrintf(ch.id, "Found data connection of %d\n", ch.connID)
		// Remove the ch from clientHandlers to avoid issues
		delete(clientHandlers, connID)
		ch.dataConnChan <- tcpConn
		close(ch.dataConnChan)
		return true
	}
	log.Printf("Unknown prefix for first packet: %v\n", data[4])
	tcpConn.Close()
	return false
}

func handleFirstPacket(tcpConn *net.TCPConn) {
	var err error
	log.Printf("Accept new connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
	tcpConn.SetDeadline(time.Now().Add(5 * time.Second))

	// Format is fixed:
	// Meta conn: [Length(4)|'M'(1)|{'D' or 'U'(1)}|connID(8)|runTimeNs(8)]
	// Data conn: [Length(4)|'D'(1)|connID(8)]
	bufLenWithPrefix := make([]byte, 5)
	_, err = io.ReadFull(tcpConn, bufLenWithPrefix)
	if err != nil {
		log.Printf("Read error when starting: %v\n", err)
		log.Printf("Close connection on %v from %v\n", tcpConn.LocalAddr(), tcpConn.RemoteAddr())
		tcpConn.Close()
		return
	}
	var remainingBuf []byte
	if bufLenWithPrefix[4] == 'M' {
		remainingBuf = make([]byte, 17) // 22 - 5
	} else if bufLenWithPrefix[4] == 'D' {
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

func iperfServer() error {
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

func (ch *clientHandler) handle() {
	ch.dataConn = <-ch.dataConnChan
	myLogPrintf(ch.id, "Starting traffic")
	ch.startTime = time.Now()
	if ch.print {
		go ch.serverBandwidthTracker()
	}
	buf := make([]byte, BufLen)
	if ch.runTime > 0 {
		ch.metaConn.SetDeadline(time.Now().Add(ch.runTime))
		ch.dataConn.SetDeadline(time.Now().Add(ch.runTime))
	}
forLoop:
	for {
		read, err := io.ReadAtLeast(ch.dataConn, buf, 1)
		if read == 0 && err == io.EOF {
			if ch.print {
				ch.stopChan <- struct{}{}
				time.Sleep(time.Second)
			}
			break forLoop
		}
		if err != nil {
			break forLoop
		}

		// TODO do something
		if ch.print {
			ch.readChan <- read
		}
	}
	ch.dataConn.Close()
	ch.metaConn.Close()
	log.Println("Connection terminated from", ch.dataConn.RemoteAddr())
}
