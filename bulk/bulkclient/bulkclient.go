package bulkclient

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
)

func Run(cache bool, multipath bool, output string, url string) string {
	if output != "" {
		logfile, err := os.Create(output)
		if err != nil {
			return err.Error()
		}
		defer logfile.Close()
		log.SetOutput(logfile)
	}

	quicConfig := &quic.Config{
		CreatePaths: multipath,
		CacheHandshake: cache,
	}

	hclient := &http.Client{
		Transport: &h2quic.RoundTripper{QuicConfig: quicConfig, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	var wg sync.WaitGroup

	wg.Add(1)
	log.Printf("GET %s", url)
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
	}(url)
	wg.Wait()

	return elapsedStr
}
