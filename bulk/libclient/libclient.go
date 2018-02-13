package libclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	quic "github.com/lucas-clemente/quic-go"

	"github.com/lucas-clemente/quic-go/h2quic"

	"bitbucket.org/qdeconinck/quic-traffic/common"
)

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

	roundTripper := &h2quic.RoundTripper{
		QuicConfig:      quicConfig,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	defer roundTripper.Close()

	hclient := &http.Client{
		Transport: roundTripper,
	}

	pingCount := 0
	pingWait := time.Second

	if cfg.PingCount > 0 && cfg.PingWaitMs > 0 {
		pingCount = cfg.PingCount
		pingWait = time.Duration(cfg.PingWaitMs) * time.Millisecond
	}

	var wg sync.WaitGroup

	wg.Add(1)
	log.Printf("GET %s", cfg.URL)
	var elapsedStr = "-1.0s"
	go func(addr string) {
		for i := 0; i <= pingCount; i++ {
			if i > 0 {
				time.Sleep(pingWait)
			}
			start := time.Now()
			rsp, err := hclient.Get(addr)
			if err != nil {
				log.Printf("ERROR: %s", err)
				wg.Done()
				return
			}

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				log.Printf("ERROR: %s", err)
				wg.Done()
				return
			}
			elapsed := time.Since(start)
			if i <= 1 {
				// If ping, ignore first request as it will contains additional delay
				elapsedStr = fmt.Sprintf("%s", elapsed)
			} else {
				elapsedStr += fmt.Sprintf("\n%s", elapsed)
			}

			rsp.Body.Close()
			if cfg.PrintBody {
				log.Printf("%s", body)
			}
		}
		wg.Done()
	}(cfg.URL)
	wg.Wait()

	return elapsedStr
}
