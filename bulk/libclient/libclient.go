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
		CreatePaths: cfg.Multipath,
		CacheHandshake: cfg.Cache,
	}

	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{QuicConfig: quicConfig, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	var wg sync.WaitGroup

	wg.Add(1)
	log.Printf("GET %s", cfg.Url)
	var elapsedStr string
	go func(addr string) {
		start := time.Now()
		rsp, err := hclient.Get(addr)
		if err != nil {
			panic(err)
		}

		body := &bytes.Buffer{}
		_, err = io.Copy(body, rsp.Body)
		if err != nil {
			panic(err)
		}
		elapsed := time.Since(start)
		elapsedStr = fmt.Sprintf("%s", elapsed)
		rsp.Body.Close()
		wg.Done()
	}(cfg.Url)
	wg.Wait()

	return elapsedStr
}
