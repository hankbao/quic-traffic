package libclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"bitbucket.org/qdeconinck/quic-traffic/common"
	"github.com/tevino/abool"
)

const (
	intervalTimeCst = 100 * time.Millisecond
)

type tsDelay struct {
	ts    time.Time
	delay time.Duration
}

type serverHandler struct {
	addr         string
	buffer       *bytes.Buffer
	delays       []tsDelay
	delaysLock   sync.Mutex
	intervalTime time.Duration
	locAddr      *net.UDPAddr
	nxtMessageID uint32
	remAddr      *net.UDPAddr
	sentTime     map[uint32]time.Time
	stop         *abool.AtomicBool
	udpConn      *net.UDPConn
	wifiProbe    bool
}

var (
	handlers     = make(map[string]*serverHandler)
	handlersLock sync.RWMutex
)

// StopTraffic of UDP probes
func StopTraffic(notifyID string) {
	handlersLock.RLock()
	defer handlersLock.RUnlock()
	sh, ok := handlers[notifyID]
	if !ok {
		return
	}
	sh.stop.Set()
}

// Run udping
func Run(cfg common.TrafficConfig) string {
	sh := &serverHandler{
		addr:         cfg.URL,
		buffer:       new(bytes.Buffer),
		delays:       make([]tsDelay, 0),
		sentTime:     make(map[uint32]time.Time),
		intervalTime: intervalTimeCst,
		stop:         abool.New(),
		wifiProbe:    cfg.WifiProbe,
	}
	handlersLock.Lock()
	handlers[cfg.NotifyID] = sh
	handlersLock.Unlock()
	sh.handle(cfg)
	handlersLock.Lock()
	delete(handlers, cfg.NotifyID)
	handlersLock.Unlock()
	return sh.printer()
}

func (sh *serverHandler) printer() string {
	sh.delaysLock.Lock()
	for _, d := range sh.delays {
		sh.buffer.WriteString(fmt.Sprintf("%d,%d\n", d.ts.UnixNano(), int64(d.delay/time.Microsecond)))
	}
	sh.delaysLock.Unlock()
	return sh.buffer.String()
}

func (sh *serverHandler) isProbingInterface(i net.Interface) bool {
	return (sh.wifiProbe && strings.HasPrefix(i.Name, "en")) || (!sh.wifiProbe && strings.HasPrefix(i.Name, "pdp_ip"))
}

func (sh *serverHandler) determineLocalAddr() *net.UDPAddr {
	ifaces, err := net.Interfaces()
	if err != nil {
		println(err.Error())
		return nil
	}
	for _, i := range ifaces {
		// We first need to check if the interface is on
		if !strings.Contains(i.Flags.String(), "up") {
			continue
		}
		if sh.isProbingInterface(i) {
			addrs, err := i.Addrs()
			if err != nil {
				println(err.Error())
				continue
			}
			if len(addrs) == 0 {
				println("Don't have any address...")
				continue
			}
			// Addresses are stored in increasing importance
		ipLoop:
			for k := len(addrs) - 1; k >= 0; k-- {
				ip, _, err := net.ParseCIDR(addrs[k].String())
				addrStr := ip.String() + ":0"
				if ip.To4() == nil {
					ip = ip.To16()
					// It's a v6, but it is valid?
					if ip[0] >= 0xfd {
						continue ipLoop
					}
					addrStr = "[" + ip.String() + "]:0"
				}
				addr, err := net.ResolveUDPAddr("udp", addrStr)
				if err != nil {
					println(err.Error())
					continue ipLoop
				}
				return addr
			}
		}
	}
	return nil
}

func (sh *serverHandler) receiveLoop() {
	buffer := make([]byte, 12)
	for !sh.stop.IsSet() {
		if sh.udpConn == nil {
			// Little wait to avoid 100 % active run
			time.Sleep(200 * time.Microsecond)
			continue
		}
		read, err := sh.udpConn.Read(buffer)
		rcvTime := time.Now()
		if err != nil || read != 12 {
			continue
		}
		msgID := binary.BigEndian.Uint32(buffer[0:4])
		sentTimeUnix := binary.BigEndian.Uint64(buffer[4:12])
		if msgID >= sh.nxtMessageID {
			// Not possible; continue
			println(msgID, sh.nxtMessageID)
			continue
		}
		sentTime := time.Unix(0, int64(sentTimeUnix))
		delay := rcvTime.Sub(sentTime)
		sh.delays = append(sh.delays, tsDelay{ts: sentTime, delay: delay})
	}
}

func (sh *serverHandler) handle(cfg common.TrafficConfig) {
	var err error
	sh.remAddr, err = net.ResolveUDPAddr("udp", sh.addr)
	if err != nil {
		println(err.Error())
		return
	}
	sh.locAddr = sh.determineLocalAddr()
	if sh.locAddr == nil {
		println("Cannot determine my address")
		return
	}
	sh.udpConn, err = net.DialUDP("udp", sh.locAddr, sh.remAddr)
	if err != nil {
		println(err.Error())
		return
	}
	go sh.receiveLoop()
	for !sh.stop.IsSet() {
		if sh.udpConn != nil {
			data := make([]byte, 12)
			binary.BigEndian.PutUint32(data[0:4], sh.nxtMessageID)
			binary.BigEndian.PutUint64(data[4:12], uint64(time.Now().UnixNano()))
			sh.udpConn.Write(data)
		}
		sh.nxtMessageID++
		time.Sleep(sh.intervalTime)
		newLocAddr := sh.determineLocalAddr()
		if sh.locAddr != newLocAddr {
			if sh.udpConn != nil {
				sh.udpConn.Close()
				sh.udpConn = nil
			}
			sh.locAddr = nil
			if newLocAddr != nil {
				sh.udpConn, err = net.DialUDP("udp", newLocAddr, sh.remAddr)
				if err == nil && sh.udpConn != nil {
					sh.locAddr = newLocAddr
				}
			}
		}
	}
	if sh.udpConn != nil {
		sh.udpConn.Close()
		sh.udpConn = nil
	}
}
