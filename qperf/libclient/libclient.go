package libclient

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"bitbucket.org/qdeconinck/quic-traffic/common"
	utils "bitbucket.org/qdeconinck/quic-traffic/utils"
)

type serverHandler struct {
	download   bool
	timer      *utils.Timer
	notifyID   string
	readChan   chan int
	ret        string
	runTime    time.Duration
	startTime  time.Time
	stopChan   chan struct{}
	stream     quic.Stream
	streamMeta quic.Stream
}

var (
	addr     = "localhost:4242"
	handlers = make(map[string]*serverHandler)
	mutex    sync.RWMutex
)

const (
	BufLen = 8000000
)

func newServerHandler(runTime time.Duration) *serverHandler {
	ch := &serverHandler{}
	ch.readChan = make(chan int, 10)
	ch.stopChan = make(chan struct{})
	ch.runTime = runTime
	return ch
}

// GetResults of iperf so far
func GetResults(notifyID string) string {
	mutex.RLock()
	defer mutex.RUnlock()
	sh, ok := handlers[notifyID]
	if !ok {
		return ""
	}
	return sh.ret
}

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func Run(cfg common.TrafficConfig) string {
	if cfg.Output != "" {
		logfile, err := os.Create(cfg.Output)
		if err != nil {
			return err.Error()
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	quicConfig := &quic.Config{
		MaxPathID:        cfg.MaxPathID,
		MultipathService: cfg.MultipathService,
		NotifyID:         cfg.NotifyID,
		CacheHandshake:   cfg.Cache,
	}

	flag.Parse()

	addr = cfg.URL
	var err error

	// FIXME not collecting download. This is make on purpose: traffic is not ready yet...
	sh := newServerHandler(cfg.RunTime)
	mutex.Lock()
	handlers[cfg.NotifyID] = sh
	mutex.Unlock()
	err = sh.iperfClient(quicConfig)
	mutex.Lock()
	delete(handlers, cfg.NotifyID)
	mutex.Unlock()

	if err != nil {
		return err.Error()
	}

	return sh.ret
}

func (sh *serverHandler) printIntervalLine(lastTotalSent quic.ByteCount, lastTotalRetrans quic.ByteCount) (quic.ByteCount, quic.ByteCount) {
	elapsed := time.Since(sh.startTime)
	totalSent := sh.stream.GetBytesSent()
	totalRetrans := sh.stream.GetBytesRetrans()
	if elapsed != 0 {
		sh.ret += fmt.Sprintf("%d-%d %d %d %d\n", elapsed/time.Second-1, elapsed/time.Second, totalSent-lastTotalSent, totalSent*1000000000/quic.ByteCount(time.Since(sh.startTime)/time.Nanosecond), totalRetrans-lastTotalRetrans)
	}
	return totalSent, totalRetrans
}

func (sh *serverHandler) clientBandwidthTracker() {
	var lastTotalSent quic.ByteCount
	var lastTotalRetrans quic.ByteCount
	sh.ret += fmt.Sprintf("IntervalInSec TransferredLastSecond GlobalBandwidth RetransmittedLastSecond\n")
	sh.timer = utils.NewTimer()
	sh.timer.Reset(sh.startTime.Add(time.Second))
	for {
		select {
		case <-sh.stopChan:
			totalSent, totalRetrans := sh.printIntervalLine(lastTotalSent, lastTotalRetrans)
			sh.ret += fmt.Sprintf("- - - - - - - - - - - - - - -\n")
			sh.ret += fmt.Sprintf("totalSent %d duration %s totalRetrans %d\n", totalSent, time.Since(sh.startTime), totalRetrans)
			return
		case <-sh.timer.Chan():
			sh.timer.SetRead()
			lastTotalSent, lastTotalRetrans = sh.printIntervalLine(lastTotalSent, lastTotalRetrans)
			sh.timer.Reset(time.Now().Add(time.Second))
			break
		}
	}
}

func (sh *serverHandler) iperfClient(quicConfig *quic.Config) error {
	session, err := quic.DialAddr(addr, &tls.Config{InsecureSkipVerify: true}, quicConfig)
	if err != nil {
		return err
	}

	sh.stream, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	sh.streamMeta, err = session.OpenStreamSync()
	if err != nil {
		return err
	}

	data := make([]byte, 9)
	if sh.download {
		data[0] = 'D'
	} else {
		data[0] = 'U'
	}
	binary.BigEndian.PutUint64(data[1:9], uint64(sh.runTime))
	sh.streamMeta.Write(data)

	message := strings.Repeat("0123456789", 400000)
	sh.startTime = time.Now()
	go sh.clientBandwidthTracker()
	sh.stopChan = make(chan struct{})
	sh.stream.SetDeadline(time.Now().Add(sh.runTime))

	for {
		elapsed := time.Since(sh.startTime)
		if elapsed >= sh.runTime {
			sh.stopChan <- struct{}{}
			sh.stream.Close()
			time.Sleep(time.Second)
			return nil
		}
		_, err := sh.stream.Write([]byte(message))
		if err != nil {
			if err.Error() == "deadline exceeded" {
				// Let the time to the test to end
				sh.stopChan <- struct{}{}
				time.Sleep(time.Second)
				return nil
			}
			return err
		}
	}

	return nil
}
